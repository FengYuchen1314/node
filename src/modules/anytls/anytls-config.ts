import { createPrivateKey, X509Certificate } from 'node:crypto';
import { networkInterfaces } from 'node:os';

import { Injectable } from '@nestjs/common';

import { AnyTlsConfigSchema, TAnyTlsConfig } from '@libs/contracts/models';

import { detectCloudflareSignals } from '../camouflage-domain/cloudflare-signals';
import { canonicalizeEndpointAddress as endpointAddress } from '../camouflage-domain/ip-address';

export interface AnyTlsRenderOptions {
    statsPort: number;
    controlPort: number;
    controlSecret: string;
    nodePort: number;
}

export function validateAnyTlsConfig(input: unknown, options: AnyTlsRenderOptions): TAnyTlsConfig {
    const config = AnyTlsConfigSchema.parse(input);
    const reserved = new Set([
        options.statsPort,
        options.controlPort,
        options.nodePort,
        80,
        443,
        2019,
        18080,
        18443,
    ]);
    if (
        options.statsPort === options.controlPort ||
        options.statsPort === options.nodePort ||
        options.controlPort === options.nodePort
    )
        throw new Error('AnyTLS management ports overlap.');
    for (const port of [options.statsPort, options.controlPort]) {
        if (
            !Number.isInteger(port) ||
            port < 1024 ||
            port > 65535 ||
            [2019, 18080, 18443].includes(port)
        )
            throw new Error('Invalid AnyTLS management port.');
    }
    const allPorts = new Set([
        ...reserved,
        ...config.listeners.flatMap((listener) => [listener.wrapperPort, listener.innerPort]),
    ]);
    const local = localAddresses();
    for (const listener of config.listeners) {
        // This synchronous guard also applies to saved-state restoration. DNS/ASN live validation
        // still belongs at the managed deployment boundary; a supplied CF address must never pass.
        if (
            detectCloudflareSignals({
                addresses: [endpointAddress(listener.camouflage.address)],
                cnameChain: [listener.camouflage.serverName, listener.camouflage.address],
                asn13335Matched: false,
                serverHeader: null,
            }).length
        )
            throw new Error('Cloudflare CDN endpoints cannot be used for AnyTLS camouflage.');
        if (reserved.has(listener.wrapperPort) || reserved.has(listener.innerPort))
            throw new Error('AnyTLS listener overlaps a management port.');
        const address = endpointAddress(listener.camouflage.address);
        if (
            (local.has(address) || address.startsWith('127.')) &&
            allPorts.has(listener.camouflage.port)
        )
            throw new Error('AnyTLS handshake loops back to a local proxy or management listener.');
        try {
            const leaf = new X509Certificate(listener.tls.certificate);
            const ca = new X509Certificate(listener.tls.caCertificate);
            const key = createPrivateKey(listener.tls.privateKey);
            const now = Date.now();
            for (const certificate of [leaf, ca]) {
                if (
                    Date.parse(certificate.validFrom) > now ||
                    Date.parse(certificate.validTo) <= now
                )
                    throw new Error('Expired or not-yet-valid certificate.');
            }
            if (
                leaf.ca ||
                !ca.ca ||
                !leaf.verify(ca.publicKey) ||
                !leaf.checkIssued(ca) ||
                !leaf.checkPrivateKey(key) ||
                !leaf.checkHost(listener.tls.serverName, { subject: 'never' })
            )
                throw new Error('Invalid inner identity.');
            if (!leaf.keyUsage?.includes('1.3.6.1.5.5.7.3.1'))
                throw new Error('A server-auth certificate is required.');
        } catch {
            // Do not expose PEM/key fragments or parser diagnostics in API/log output.
            throw new Error(`AnyTLS listener ${listener.id} has an invalid TLS identity.`);
        }
    }
    return config;
}

@Injectable()
export class AnyTlsConfigRenderer {
    render(
        input: unknown,
        options: AnyTlsRenderOptions,
    ): { config: TAnyTlsConfig; outer: Record<string, unknown>; inner: Record<string, unknown> } {
        const config = validateAnyTlsConfig(input, options);
        const local = [...localAddresses()].map(
            (address) => `${address}/${address.includes(':') ? 128 : 32}`,
        );
        return {
            config,
            outer: {
                mode: 'rule',
                'log-level': 'warning',
                ipv6: false,
                'geo-auto-update': false,
                profile: { 'store-selected': false, 'store-fake-ip': false },
                dns: { enable: false },
                sniffer: { enable: false },
                rules: ['MATCH,REJECT'],
                listeners: config.listeners.map((listener) => ({
                    name: listener.tag,
                    type: 'anytls',
                    listen: '127.0.0.1',
                    port: listener.wrapperPort,
                    users: { transport: listener.wrapperPassword },
                    rule: listener.id,
                    'shadow-tls': {
                        enable: true,
                        version: 3,
                        'strict-mode': true,
                        users: [{ name: 'transport', password: listener.shadowPassword }],
                        handshake: {
                            dest: `${listener.camouflage.address.includes(':') ? `[${listener.camouflage.address}]` : listener.camouflage.address}:${listener.camouflage.port}`,
                            proxy: 'DIRECT',
                        },
                    },
                })),
                'sub-rules': Object.fromEntries(
                    config.listeners.map((listener) => [
                        listener.id,
                        [
                            `AND,((NETWORK,TCP),(IP-CIDR,127.0.0.1/32),(DST-PORT,${listener.innerPort})),DIRECT`,
                            'MATCH,REJECT',
                        ],
                    ]),
                ),
            },
            inner: {
                log: { level: 'warn', timestamp: false },
                dns: { servers: [{ type: 'local', tag: 'system' }] },
                inbounds: config.listeners.map((listener) => ({
                    type: 'anytls',
                    tag: listener.tag,
                    listen: '127.0.0.1',
                    listen_port: listener.innerPort,
                    users: listener.users,
                    tls: {
                        enabled: true,
                        min_version: '1.3',
                        server_name: listener.tls.serverName,
                        certificate: `${listener.tls.certificate.trim()}\n${listener.tls.caCertificate.trim()}\n`,
                        key: listener.tls.privateKey,
                    },
                })),
                outbounds: [{ type: 'direct', tag: 'anytls-egress' }],
                route: {
                    default_domain_resolver: 'system',
                    final: 'anytls-egress',
                    rules: [
                        // Authenticated subscribers must not be able to manipulate the local stats API,
                        // reach the panel's private services or chain back to this same physical server.
                        { action: 'resolve', server: 'system' },
                        { ip_is_private: true, action: 'reject' },
                        { ip_cidr: local, action: 'reject' },
                    ],
                },
                experimental: {
                    v2ray_api: {
                        listen: `127.0.0.1:${options.statsPort}`,
                        stats: {
                            enabled: true,
                            users: [
                                ...new Set(
                                    config.listeners.flatMap((listener) =>
                                        listener.users.map((user) => user.name),
                                    ),
                                ),
                            ],
                        },
                    },
                    clash_api: {
                        external_controller: `127.0.0.1:${options.controlPort}`,
                        secret: options.controlSecret,
                    },
                },
            },
        };
    }
}

function localAddresses(): Set<string> {
    const values = new Set(['127.0.0.1', '::1', '0.0.0.0', '::']);
    for (const entries of Object.values(networkInterfaces()))
        for (const entry of entries ?? []) values.add(endpointAddress(entry.address.split('%')[0]));
    return values;
}
