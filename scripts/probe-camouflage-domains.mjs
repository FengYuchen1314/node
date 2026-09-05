// Read-only, point-in-time discovery. This never marks a domain eligible in the panel.
import { Resolver } from 'node:dns/promises';
import { connect as http2Connect } from 'node:http2';
import { BlockList, isIP } from 'node:net';
import { resolve } from 'node:path';
import { connect as tlsConnect } from 'node:tls';
import { fileURLToPath, domainToASCII } from 'node:url';
import { parseArgs } from 'node:util';

const forbidden = new BlockList();
// Rechecked against Cloudflare's official ips-v4 / ips-v6 lists on 2026-09-05.
const cloudflare = new BlockList();
for (const cidr of [
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22',
    '2400:cb00::/32',
    '2606:4700::/32',
    '2803:f800::/32',
    '2405:b500::/32',
    '2405:8100::/32',
    '2a06:98c0::/29',
    '2c0f:f248::/32',
]) {
    const [ip, prefix] = cidr.split('/');
    cloudflare.addSubnet(ip, Number(prefix), isIP(ip) === 4 ? 'ipv4' : 'ipv6');
}

export function cloudflareDnsSignals(addresses, cnames) {
    const signals = [];
    if (addresses.some((ip) => isIP(ip) && cloudflare.check(ip, isIP(ip) === 4 ? 'ipv4' : 'ipv6')))
        signals.push('IP_RANGE');
    if (
        cnames.some((name) =>
            /(^|\.)(?:cloudflare\.(?:com|net)|cloudflare-dns\.com|pages\.dev|workers\.dev|r2\.dev)\.?$/i.test(
                name,
            ),
        )
    )
        signals.push('CNAME');
    return signals;
}
for (const cidr of [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.0.0.0/24',
    '192.0.2.0/24',
    '192.88.99.0/24',
    '192.168.0.0/16',
    '198.18.0.0/15',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '224.0.0.0/4',
    '240.0.0.0/4',
]) {
    const [ip, prefix] = cidr.split('/');
    forbidden.addSubnet(ip, Number(prefix), 'ipv4');
}

export function isPublicV4(ip) {
    return isIP(ip) === 4 && !forbidden.check(ip, 'ipv4');
}

export function normalizeDomain(input) {
    const domain = domainToASCII(input.trim().toLowerCase().replace(/\.$/, ''));
    if (
        !domain ||
        domain.length > 253 ||
        !domain.includes('.') ||
        isIP(domain) ||
        !domain.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
    )
        throw new Error('A DNS hostname, not an IP, URL or command option, is required.');
    return domain;
}

export async function lookupOrigin(resolver, ip) {
    if (!isPublicV4(ip)) return null;
    try {
        const records = await resolver.resolveTxt(
            `${ip.split('.').reverse().join('.')}.origin.asn.cymru.com`,
        );
        const value = records
            .map((parts) => parts.join(''))
            .find((text) => /^\d+(?: \d+)*\s*\|/.test(text));
        if (!value) return null;
        const [numbers, prefix, registryCountry, registry] = value
            .split('|')
            .map((part) => part.trim());
        return {
            asns: numbers.split(/\s+/).map((number) => `AS${number}`),
            prefix,
            registryCountry,
            registry,
            source: 'Team Cymru DNS origin mapping',
        };
    } catch {
        return null;
    }
}

// Connect only to an already resolved public IPv4 address, but validate the original DNS name.
// TLS and the HTTP/2 HEAD request share that socket. No proxy environment or redirect is used.
export function probeAddress(domain, address) {
    if (!isPublicV4(address)) return Promise.reject(new Error('DNS_BOGON'));
    return new Promise((resolveProbe) => {
        let socket;
        let session;
        let request;
        let finished = false;
        let tls = null;
        let receivedHeaders = null;
        let bytes = 0;
        const finish = (result) => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            request?.destroy();
            session?.destroy();
            socket?.destroy();
            resolveProbe({ address, tls, ...result });
        };
        const failed = (error) =>
            finish({
                reachable: false,
                error: String(error?.code ?? error?.message ?? 'NETWORK_ERROR').slice(0, 160),
            });
        const timer = setTimeout(() => finish({ reachable: false, error: 'TIMEOUT' }), 8000);
        try {
            socket = tlsConnect({
                host: address,
                port: 443,
                family: 4,
                servername: domain,
                rejectUnauthorized: true,
                minVersion: 'TLSv1.3',
                maxVersion: 'TLSv1.3',
                ecdhCurve: 'X25519',
                ALPNProtocols: ['h2'],
            });
            socket.on('error', failed);
            socket.once('secureConnect', () => {
                try {
                    const cert = socket.getPeerX509Certificate();
                    const key = socket.getEphemeralKeyInfo();
                    if (
                        !cert ||
                        !cert.checkHost(domain, {
                            subject: 'never',
                            partialWildcards: false,
                            multiLabelWildcards: false,
                        })
                    )
                        throw new Error('CERTIFICATE_SAN_MISMATCH');
                    tls = {
                        version: socket.getProtocol(),
                        alpn: socket.alpnProtocol,
                        keyExchangeGroup: key?.name ?? null,
                        certificateNotAfter: new Date(cert.validTo).toISOString(),
                        certificateSha256: cert.fingerprint256.replaceAll(':', ''),
                        sanMatches: true,
                    };
                    if (
                        !socket.authorized ||
                        tls.version !== 'TLSv1.3' ||
                        tls.alpn !== 'h2' ||
                        tls.keyExchangeGroup !== 'X25519'
                    )
                        throw new Error('TLS_REQUIREMENTS_NOT_MET');
                    session = http2Connect(`https://${domain}`, {
                        createConnection: () => socket,
                        maxHeaderListPairs: 64,
                        maxSessionMemory: 1,
                        settings: { enablePush: false },
                    });
                    session.on('error', failed);
                    session.on('stream', (stream) => stream.close());
                    request = session.request({
                        ':method': 'HEAD',
                        ':path': '/',
                        ':authority': domain,
                        'user-agent': 'Remnawave-Camouflage-Discovery/1',
                    });
                    request.on('error', failed);
                    request.once('response', (headers) => {
                        receivedHeaders = {
                            status: Number(headers[':status']),
                            server: String(headers.server ?? '').slice(0, 512),
                            location: String(headers.location ?? '').slice(0, 2048),
                            cfRayPresent: headers['cf-ray'] !== undefined,
                        };
                    });
                    request.on('data', (data) => {
                        bytes += data.length;
                        if (bytes > 65536)
                            finish({ reachable: false, error: 'RESPONSE_TOO_LARGE' });
                    });
                    request.once('end', () => {
                        if (
                            !receivedHeaders ||
                            receivedHeaders.status < 100 ||
                            receivedHeaders.status > 599
                        )
                            return finish({ reachable: false, error: 'INVALID_HTTP_RESPONSE' });
                        finish({ reachable: true, http: receivedHeaders });
                    });
                    request.end();
                } catch (error) {
                    failed(error);
                }
            });
        } catch (error) {
            failed(error);
        }
    });
}

async function resolveCnameChain(resolver, domain) {
    const chain = [];
    const seen = new Set([domain]);
    let current = domain;
    for (let depth = 0; depth <= 16; depth++) {
        let records;
        try {
            records = await resolver.resolveCname(current);
        } catch (error) {
            if (['ENODATA', 'ENOTFOUND'].includes(error?.code)) return chain;
            throw error;
        }
        if (!records.length) return chain;
        if (records.length !== 1 || depth === 16) throw new Error('DNS_CNAME_LIMIT');
        current = normalizeDomain(records[0]);
        if (seen.has(current)) throw new Error('DNS_CNAME_CYCLE');
        chain.push(current);
        // An exclusion is already conclusive; there is no need to contact more DNS names.
        if (cloudflareDnsSignals([], chain).length) return chain;
        seen.add(current);
    }
    return chain;
}

export async function probeDomain(resolver, input) {
    const domain = normalizeDomain(input);
    const checkedAt = new Date().toISOString();
    const [a, aaaa, cnames] = await Promise.allSettled([
        resolver.resolve4(domain),
        resolver.resolve6(domain),
        resolveCnameChain(resolver, domain),
    ]);
    const addresses = a.status === 'fulfilled' ? [...new Set(a.value)].sort() : [];
    const dns = {
        ipv4: addresses,
        ipv6: aaaa.status === 'fulfilled' ? aaaa.value : [],
        cnames: cnames.status === 'fulfilled' ? cnames.value : [],
        error: a.status === 'rejected' ? String(a.reason?.code ?? 'DNS_FAILED') : null,
        errors: Object.fromEntries(
            [
                ['A', a],
                ['AAAA', aaaa],
                ['CNAME', cnames],
            ]
                .filter(([, result]) => result.status === 'rejected')
                .map(([family, result]) => [
                    family,
                    String(result.reason?.code ?? result.reason?.message ?? 'DNS_FAILED').slice(
                        0,
                        100,
                    ),
                ]),
        ),
    };
    const base = { domain, checkedAt, dns, attempts: [], automaticallyEligible: false };
    const dnsSignals = cloudflareDnsSignals([...addresses, ...dns.ipv6], [domain, ...dns.cnames]);
    if (dnsSignals.length)
        return { ...base, outcome: 'CLOUDFLARE_EXCLUDED', cloudflareSignals: dnsSignals };
    if (
        [a, aaaa, cnames].some(
            (result) =>
                result.status === 'rejected' &&
                !['ENODATA', 'ENOTFOUND'].includes(result.reason?.code),
        )
    )
        return { ...base, outcome: 'DNS_INCOMPLETE' };
    if (!addresses.length) return { ...base, outcome: 'NO_IPV4_ADDRESS' };
    if (addresses.some((ip) => !isPublicV4(ip))) return { ...base, outcome: 'DNS_BOGON' };
    const attempts = [];
    for (const address of addresses.slice(0, 4)) {
        const origin = await lookupOrigin(resolver, address);
        if (origin?.asns.includes('AS13335')) {
            attempts.push({
                address,
                origin,
                reachable: false,
                error: 'CLOUDFLARE_EXCLUDED',
                cloudflareSignals: ['ASN'],
            });
            continue;
        }
        const attempt = await probeAddress(domain, address);
        const cloudflareSignals = [];
        if (origin?.asns.includes('AS13335')) cloudflareSignals.push('ASN');
        if (/\bcloudflare\b/i.test(attempt.http?.server ?? '') || attempt.http?.cfRayPresent)
            cloudflareSignals.push('HTTP_HEADER');
        attempts.push({ ...attempt, origin, cloudflareSignals });
    }
    return {
        ...base,
        attempts,
        omittedIpv4Count: Math.max(0, addresses.length - attempts.length),
        outcome: attempts.some((attempt) => attempt.cloudflareSignals.length)
            ? 'CLOUDFLARE_EXCLUDED'
            : attempts.some((attempt) => attempt.reachable)
              ? 'REACHABLE_FROM_THIS_PROBE'
              : 'NO_SUCCESSFUL_ATTEMPT',
    };
}

async function main() {
    const { values } = parseArgs({
        options: {
            domains: { type: 'string' },
            'probe-id': { type: 'string' },
            'declared-country': { type: 'string' },
            'declared-public-ip': { type: 'string' },
        },
        strict: true,
    });
    const domains = [...new Set((values.domains ?? '').split(',').map(normalizeDomain))];
    if (
        !/^[A-Za-z0-9_-]{1,64}$/.test(values['probe-id'] ?? '') ||
        !/^[A-Z]{2}$/.test(values['declared-country'] ?? '') ||
        !isPublicV4(values['declared-public-ip'] ?? '') ||
        domains.length > 100
    )
        throw new Error(
            'Explicit probe identity, country, public IPv4 and at most 100 domains are required.',
        );
    const resolver = new Resolver({ timeout: 2000, tries: 1 });
    process.stdout.write(
        JSON.stringify({
            kind: 'probe',
            schemaVersion: 1,
            probeId: values['probe-id'],
            declaredCountry: values['declared-country'],
            declaredPublicIp: values['declared-public-ip'],
            sourceOrigin: await lookupOrigin(resolver, values['declared-public-ip']),
            startedAt: new Date().toISOString(),
            nodeVersion: process.version,
            method: 'PINNED_IPV4_TLS13_X25519_H2_HEAD',
            limitations: [
                'Operator-declared location; public egress IP not independently observed.',
                'IPv4 only; at most four A records per domain; one vantage point and one observation time.',
                'Reachability is not attribution of a failure to GFW, non-Cloudflare proof or automatic panel eligibility.',
            ],
        }) + '\n',
    );
    let index = 0;
    await Promise.all(
        Array.from({ length: 2 }, async () => {
            while (index < domains.length) {
                const domain = domains[index++];
                process.stdout.write(
                    JSON.stringify({ kind: 'domain', ...(await probeDomain(resolver, domain)) }) +
                        '\n',
                );
            }
        }),
    );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
    main().catch((error) => {
        process.stderr.write(`${error.message}\n`);
        process.exitCode = 1;
    });
