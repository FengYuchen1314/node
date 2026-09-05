import { CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS } from '@libs/contracts/models';

import { isAddressInCidrs } from './ip-address';

/**
 * Pinned from Cloudflare's authoritative list. Changes must be reviewed rather than fetched at
 * request time so validation remains deterministic and never leaks candidate domains.
 */
export const CLOUDFLARE_IP_RANGES_METADATA = {
    source: 'https://www.cloudflare.com/ips/',
    observedUpdatedAt: '2023-09-28',
    version: '2023-09-28.1',
} as const;

export const CLOUDFLARE_IPV4_RANGES = [
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '108.162.192.0/18',
    '131.0.72.0/22',
    '141.101.64.0/18',
    '162.158.0.0/15',
    '172.64.0.0/13',
    '173.245.48.0/20',
    '188.114.96.0/20',
    '190.93.240.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
] as const;

export const CLOUDFLARE_IPV6_RANGES = [
    '2400:cb00::/32',
    '2606:4700::/32',
    '2803:f800::/32',
    '2405:b500::/32',
    '2405:8100::/32',
    '2a06:98c0::/29',
    '2c0f:f248::/32',
] as const;

export const CLOUDFLARE_IP_RANGES = [...CLOUDFLARE_IPV4_RANGES, ...CLOUDFLARE_IPV6_RANGES] as const;

export type CloudflareSignal =
    (typeof CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS)[keyof typeof CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS];

export interface CloudflareSignalInput {
    addresses: readonly string[];
    asn13335Matched: boolean;
    cnameChain: readonly string[];
    serverHeader: string | null;
    cfRayPresent?: boolean;
}

export function detectCloudflareSignals(input: CloudflareSignalInput): CloudflareSignal[] {
    const signals: CloudflareSignal[] = [];
    if (input.asn13335Matched) signals.push(CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS.ASN);
    if (input.addresses.some((address) => isAddressInCidrs(address, CLOUDFLARE_IP_RANGES))) {
        signals.push(CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS.IP_RANGE);
    }
    if (input.cnameChain.some(isCloudflareHostname)) {
        signals.push(CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS.CNAME);
    }
    if (input.cfRayPresent || /\bcloudflare\b/i.test(input.serverHeader ?? '')) {
        signals.push(CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS.HTTP_HEADER);
    }
    return signals;
}

function isCloudflareHostname(hostname: string): boolean {
    // Cloudflare-hosted Pages / Workers / public R2 endpoints are also forbidden, including
    // custom hostnames whose CNAME points at these services. DNS nameservers alone are not input.
    return /(^|\.)(?:cloudflare\.(?:com|net)|cloudflare-dns\.com|pages\.dev|workers\.dev|r2\.dev)\.?$/i.test(
        hostname,
    );
}
