import { createHash } from 'node:crypto';

import { HttpStatus, Injectable, Logger } from '@nestjs/common';

import {
    CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS,
    CamouflageDomainAgentValidationReportSchema,
    TCamouflageDomainAgentValidationReport,
    TCamouflageDomainAgentValidationRequest,
} from '@libs/contracts/models';

import { AsnLmdbService } from '../asn-lmdb/asn-lmdb.service';
import { CamouflageDomainDnsService } from './camouflage-domain-dns.service';
import {
    CamouflageDomainNetworkObservation,
    CamouflageDomainNetworkService,
} from './camouflage-domain-network.service';
import { CamouflageDomainError } from './camouflage-domain.error';
import { detectCloudflareSignals } from './cloudflare-signals';
import { isAddressInCidrs } from './ip-address';

const TOTAL_VALIDATION_TIMEOUT_MS = 15_000;
const MAX_CONCURRENT_VALIDATIONS = 2;
const CLOUDFLARE_ASN = 13_335;

@Injectable()
export class CamouflageDomainService {
    private readonly logger = new Logger(CamouflageDomainService.name);
    private readonly activeDomains = new Set<string>();
    private activeValidations = 0;

    constructor(
        private readonly dns: CamouflageDomainDnsService,
        private readonly network: CamouflageDomainNetworkService,
        private readonly asn: AsnLmdbService,
    ) {}

    public async validate(
        request: TCamouflageDomainAgentValidationRequest,
    ): Promise<TCamouflageDomainAgentValidationReport> {
        this.acquire(request.domain);
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), TOTAL_VALIDATION_TIMEOUT_MS);
        timeout.unref();
        try {
            const dns = await this.dns.resolve(request.domain, controller.signal);
            if (dns.containsBogon) {
                throw new CamouflageDomainError(
                    'DNS_BOGON',
                    'The domain resolves to a non-public or reserved address.',
                    HttpStatus.UNPROCESSABLE_ENTITY,
                );
            }

            const observation = await this.probeOneResolvedAddress(
                request.domain,
                dns.addresses,
                controller.signal,
            );
            const asn13335Matched = this.matchesCloudflareAsn(dns.addresses);
            const cloudflareSignals = detectCloudflareSignals({
                addresses: dns.addresses,
                cnameChain: dns.cnameChain,
                serverHeader: observation.http.serverHeader,
                asn13335Matched,
            });
            const cloudflareDetected = cloudflareSignals.length > 0;
            const authoritativeCloudflareProvider = cloudflareSignals.some(
                (signal) =>
                    signal === CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS.ASN ||
                    signal === CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS.IP_RANGE,
            );
            const edgeAsn = asn13335Matched ? 'AS13335' : null;
            const report: TCamouflageDomainAgentValidationReport = {
                domain: request.domain,
                expectedRegion: request.expectedRegion,
                checkedAt: new Date().toISOString(),
                dns: {
                    addresses: dns.addresses,
                    cnameChain: dns.cnameChain,
                    fingerprint: buildDnsFingerprint(
                        request.domain,
                        dns.addresses,
                        dns.cnameChain,
                        edgeAsn,
                    ),
                    containsBogon: false,
                },
                edge: {
                    provider: authoritativeCloudflareProvider ? 'Cloudflare' : null,
                    asn: edgeAsn,
                    observedRegion: null,
                },
                cloudflare: {
                    detected: cloudflareDetected,
                    signals: cloudflareSignals,
                },
                tls: observation.tls,
                http: observation.http,
                mainlandProbes: [],
            };
            return CamouflageDomainAgentValidationReportSchema.parse(report);
        } catch (error: unknown) {
            const classified = classifyValidationError(error, controller.signal.aborted);
            this.logger.warn(`Camouflage-domain validation failed (${classified.code}).`);
            throw classified;
        } finally {
            clearTimeout(timeout);
            controller.abort();
            this.release(request.domain);
        }
    }

    private acquire(domain: string): void {
        if (
            this.activeValidations >= MAX_CONCURRENT_VALIDATIONS ||
            this.activeDomains.has(domain)
        ) {
            throw new CamouflageDomainError(
                'BUSY',
                'A camouflage-domain validation is already in progress.',
                HttpStatus.TOO_MANY_REQUESTS,
            );
        }
        this.activeValidations += 1;
        this.activeDomains.add(domain);
    }

    private release(domain: string): void {
        this.activeValidations = Math.max(0, this.activeValidations - 1);
        this.activeDomains.delete(domain);
    }

    private async probeOneResolvedAddress(
        domain: string,
        addresses: readonly string[],
        signal: AbortSignal,
    ): Promise<CamouflageDomainNetworkObservation> {
        let lastError: CamouflageDomainError | undefined;
        for (const address of addresses) {
            try {
                return await this.network.probe(domain, address, signal);
            } catch (error: unknown) {
                lastError = classifyValidationError(error, signal.aborted);
            }
        }
        throw (
            lastError ??
            new CamouflageDomainError(
                'TLS_NEGOTIATION_FAILED',
                'No resolved address completed the secure validation probe.',
                HttpStatus.BAD_GATEWAY,
            )
        );
    }

    private matchesCloudflareAsn(addresses: readonly string[]): boolean {
        const prefixes = this.asn.getByAsn(CLOUDFLARE_ASN);
        if (!prefixes) return false;
        try {
            return addresses.some((address) =>
                isAddressInCidrs(address, address.includes(':') ? prefixes.ipv6 : prefixes.ipv4),
            );
        } catch {
            this.logger.warn('The local AS13335 prefix data is invalid; ASN evidence was omitted.');
            return false;
        }
    }
}

export function buildDnsFingerprint(
    domain: string,
    addresses: readonly string[],
    cnameChain: readonly string[],
    edgeAsn: string | null,
): string {
    const encoding = JSON.stringify({
        version: 1,
        domain,
        addresses: [...addresses].sort(),
        cnameChain: [...cnameChain],
        edgeAsn: edgeAsn ?? 'unknown',
    });
    return createHash('sha256').update(encoding, 'utf8').digest('hex');
}

function classifyValidationError(error: unknown, timedOut: boolean): CamouflageDomainError {
    if (timedOut) {
        return new CamouflageDomainError(
            'VALIDATION_TIMEOUT',
            'Camouflage-domain validation timed out.',
            HttpStatus.GATEWAY_TIMEOUT,
        );
    }
    if (error instanceof CamouflageDomainError) return error;
    return new CamouflageDomainError(
        'HTTP_REQUEST_FAILED',
        'Camouflage-domain validation failed.',
        HttpStatus.BAD_GATEWAY,
    );
}
