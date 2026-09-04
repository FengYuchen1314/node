import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

import { BadRequestException, Injectable } from '@nestjs/common';

import { CamouflageDomainSchema, TAnyTlsConfig } from '@libs/contracts/models';

import { AsnLmdbService } from '../asn-lmdb/asn-lmdb.service';
import {
    CamouflageDomainDnsObservation,
    CamouflageDomainDnsService,
} from './camouflage-domain-dns.service';
import { CamouflageDomainNetworkService } from './camouflage-domain-network.service';
import { detectCloudflareSignals } from './cloudflare-signals';
import { canonicalizeIp, isAddressInCidrs, isPublicUnicastAddress } from './ip-address';

type RecordValue = Record<string, unknown>;
interface Endpoint {
    names: string[];
    address: string;
    port: number;
}
interface Batch {
    signal: AbortSignal;
    dns: Map<string, Promise<CamouflageDomainDnsObservation>>;
}

/** Live deployment guard, not a mainland-reachability claim or a cached domain allow-list. */
@Injectable()
export class CamouflageRuntimePolicy {
    constructor(
        private readonly dns: CamouflageDomainDnsService,
        private readonly network: CamouflageDomainNetworkService,
        private readonly asn: AsnLmdbService,
    ) {}

    async assertAnyTls(config: TAnyTlsConfig): Promise<void> {
        await this.batch(async (batch) => {
            for (const listener of config.listeners)
                await this.endpoint(
                    {
                        names: [listener.camouflage.serverName],
                        address: listener.camouflage.address,
                        port: listener.camouflage.port,
                    },
                    batch,
                );
        });
    }

    async prepareXray(input: RecordValue): Promise<{ config: RecordValue; fingerprint: string }> {
        const config = structuredClone(input);
        const bindings: unknown[] = [];
        await this.batch(async (batch) => {
            if (!Array.isArray(config.inbounds)) return;
            for (const inbound of config.inbounds) {
                const stream = record(record(inbound)?.streamSettings);
                if (String(stream?.security ?? '').toLowerCase() !== 'reality') continue;
                const reality = record(stream?.realitySettings);
                if (!reality) throw new Error('REALITY settings are required.');
                if (
                    reality.target !== undefined &&
                    reality.dest !== undefined &&
                    reality.target !== reality.dest
                )
                    throw new Error('Ambiguous REALITY target/dest.');
                const target = parseCamouflageTarget(reality.target ?? reality.dest);
                const names = reality.serverNames;
                if (!Array.isArray(names) || !names.length || names.length > 32)
                    throw new Error('REALITY requires 1 to 32 exact server names.');
                const normalized = [
                    ...new Set(names.map((name) => CamouflageDomainSchema.parse(name))),
                ];
                const address = await this.endpoint({ ...target, names: normalized }, batch);
                // Preserve the alias accepted by existing profiles, but prevent runtime re-resolution.
                const pinned = `${isIP(address) === 6 ? `[${address}]` : address}:${target.port}`;
                if (reality.target !== undefined) reality.target = pinned;
                if (reality.dest !== undefined) reality.dest = pinned;
                reality.serverNames = normalized;
                bindings.push({ tag: record(inbound)?.tag, names: normalized, target: pinned });
            }
        });
        return {
            config,
            fingerprint: createHash('sha256').update(JSON.stringify(bindings)).digest('hex'),
        };
    }

    private async endpoint(endpoint: Endpoint, batch: Batch): Promise<string> {
        if (!Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535)
            throw new Error('Invalid camouflage endpoint port.');
        const names = endpoint.names.map((name) => CamouflageDomainSchema.parse(name));
        const nameAnswers = await Promise.all(names.map((name) => this.resolve(name, batch)));
        const target = isIP(endpoint.address)
            ? {
                  addresses: [canonicalizeIp(endpoint.address)],
                  cnameChain: [],
                  containsBogon: !isPublicUnicastAddress(endpoint.address),
              }
            : await this.resolve(CamouflageDomainSchema.parse(endpoint.address), batch);
        this.assertDns(target);
        // An AnyTLS pinned IP or a REALITY target must also serve the requested identity. Checking
        // every SNI's DNS prevents a CF hostname being smuggled in beside a non-CF target address.
        for (const answer of nameAnswers) this.assertDns(answer);
        for (const address of [...target.addresses].sort(
            (a, b) => isIP(a) - isIP(b) || a.localeCompare(b),
        )) {
            try {
                for (const name of names) {
                    if (batch.signal.aborted) throw new Error('Camouflage validation deadline.');
                    const observation = await this.network.probe(
                        name,
                        address,
                        batch.signal,
                        endpoint.port,
                    );
                    if (
                        detectCloudflareSignals({
                            addresses: [address],
                            cnameChain: [],
                            asn13335Matched: false,
                            serverHeader: observation.http.serverHeader,
                            cfRayPresent: observation.http.cfRayPresent,
                        }).length
                    )
                        throw new CloudflareEndpointError();
                    const notAfter = Date.parse(observation.tls.certificate.notAfter);
                    if (
                        observation.tls.version !== 'TLSv1.3' ||
                        observation.tls.keyExchangeGroup !== 'X25519' ||
                        observation.http.negotiatedProtocol !== 'h2' ||
                        observation.http.redirectCount ||
                        !observation.tls.certificate.sanMatches ||
                        !Number.isFinite(notAfter) ||
                        notAfter < Date.now() + 14 * 86400000
                    )
                        throw new Error(
                            'The camouflage endpoint does not meet certificate/redirect requirements.',
                        );
                }
                return address;
            } catch (error) {
                // A positive CF signal excludes the entire domain. Never try a different address to
                // turn a known Cloudflare domain into a success.
                if (error instanceof CloudflareEndpointError) throw error;
                if (batch.signal.aborted) throw error;
            }
        }
        throw new Error(
            'No camouflage endpoint completed verified TLS 1.3/X25519/HTTP2 validation.',
        );
    }

    private resolve(name: string, batch: Batch): Promise<CamouflageDomainDnsObservation> {
        if (!batch.dns.has(name)) {
            if (
                detectCloudflareSignals({
                    addresses: [],
                    cnameChain: [name],
                    serverHeader: null,
                    asn13335Matched: false,
                }).length
            )
                throw new CloudflareEndpointError();
            batch.dns.set(
                name,
                this.dns.resolve(name, batch.signal).then((result) => {
                    this.assertDns(result);
                    return result;
                }),
            );
        }
        return batch.dns.get(name)!;
    }

    private assertDns(answer: CamouflageDomainDnsObservation): void {
        if (
            !answer.addresses.length ||
            answer.containsBogon ||
            answer.addresses.some((ip) => !isPublicUnicastAddress(ip))
        )
            throw new Error('Camouflage DNS must contain only public unicast addresses.');
        const prefixes = this.asn.getByAsn(13335);
        const asnMatched =
            !!prefixes &&
            answer.addresses.some((address) =>
                isAddressInCidrs(address, isIP(address) === 4 ? prefixes.ipv4 : prefixes.ipv6),
            );
        if (
            detectCloudflareSignals({
                addresses: answer.addresses,
                cnameChain: answer.cnameChain,
                asn13335Matched: asnMatched,
                serverHeader: null,
            }).length
        )
            throw new CloudflareEndpointError();
    }

    private async batch<T>(operation: (batch: Batch) => Promise<T>): Promise<T> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 30000);
        timer.unref();
        try {
            return await operation({ signal: controller.signal, dns: new Map() });
        } catch (error) {
            // No user configuration, PEM material, native output or raw DNS errors in API responses.
            throw new BadRequestException(
                error instanceof CloudflareEndpointError
                    ? 'Cloudflare CDN camouflage is forbidden.'
                    : 'Camouflage validation could not establish an allowed public endpoint; configuration was not accepted.',
            );
        } finally {
            clearTimeout(timer);
            controller.abort();
        }
    }
}

class CloudflareEndpointError extends Error {}

export function parseCamouflageTarget(value: unknown): { address: string; port: number } {
    if (typeof value !== 'string')
        throw new Error('A hostname/IP and port are required for REALITY.');
    const match = /^(?:\[([0-9a-fA-F:]+)\]|([^\s:/\\@?#]+)):(\d+)$/.exec(value);
    if (!match) throw new Error('Invalid REALITY camouflage target.');
    const address = match[1] ?? match[2];
    const port = Number(match[3]);
    if (!Number.isInteger(port) || port < 1 || port > 65535)
        throw new Error('Invalid REALITY target port.');
    return {
        address: isIP(address) ? canonicalizeIp(address) : CamouflageDomainSchema.parse(address),
        port,
    };
}
function record(value: unknown): RecordValue | undefined {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? (value as RecordValue)
        : undefined;
}
