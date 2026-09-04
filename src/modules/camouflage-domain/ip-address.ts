import { isIP } from 'node:net';

interface ParsedIpAddress {
    canonical: string;
    family: 4 | 6;
    value: bigint;
}

const IPV4_BOGONS = [
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
] as const;

const IPV6_BOGONS = [
    '::/96',
    '::ffff:0:0/96',
    '64:ff9b::/96',
    '64:ff9b:1::/48',
    '100::/64',
    '2001::/23',
    '2001:db8::/32',
    '2002::/16',
    '3fff::/20',
    '5f00::/16',
    'fc00::/7',
    'fe80::/10',
    'fec0::/10',
    'ff00::/8',
] as const;

const BOGON_RANGES = [...IPV4_BOGONS, ...IPV6_BOGONS].map(parseCidr);

export function canonicalizeIp(address: string): string {
    return parseIp(address).canonical;
}

export function isPublicUnicastAddress(address: string): boolean {
    const parsed = parseIp(address);
    return !BOGON_RANGES.some((range) => containsAddress(range, parsed));
}

export function isAddressInCidrs(address: string, cidrs: readonly string[]): boolean {
    const parsed = parseIp(address);
    return cidrs.some((cidr) => containsAddress(parseCidr(cidr), parsed));
}

export function compareIpAddresses(left: string, right: string): number {
    const parsedLeft = parseIp(left);
    const parsedRight = parseIp(right);
    if (parsedLeft.family !== parsedRight.family) return parsedLeft.family - parsedRight.family;
    if (parsedLeft.value < parsedRight.value) return -1;
    if (parsedLeft.value > parsedRight.value) return 1;
    return 0;
}

function parseCidr(cidr: string): ParsedIpAddress & { prefix: number } {
    const [address, rawPrefix, ...extra] = cidr.split('/');
    if (!address || !rawPrefix || extra.length !== 0) throw new Error(`Invalid CIDR ${cidr}.`);
    const parsed = parseIp(address);
    const prefix = Number(rawPrefix);
    const width = parsed.family === 4 ? 32 : 128;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > width) {
        throw new Error(`Invalid CIDR prefix ${cidr}.`);
    }
    return { ...parsed, prefix };
}

function containsAddress(
    range: ParsedIpAddress & { prefix: number },
    address: ParsedIpAddress,
): boolean {
    if (range.family !== address.family) return false;
    const width = range.family === 4 ? 32 : 128;
    const shift = BigInt(width - range.prefix);
    return range.value >> shift === address.value >> shift;
}

function parseIp(address: string): ParsedIpAddress {
    const family = isIP(address);
    if (family === 4) {
        const octets = address.split('.').map(Number);
        const value = octets.reduce((result, octet) => (result << 8n) | BigInt(octet), 0n);
        return { family: 4, value, canonical: octets.join('.') };
    }
    if (family !== 6 || address.includes('%')) throw new Error('Invalid IP address.');

    const hextets = parseIpv6Hextets(address.toLowerCase());
    const value = hextets.reduce((result, hextet) => (result << 16n) | BigInt(hextet), 0n);
    return { family: 6, value, canonical: formatIpv6(hextets) };
}

function parseIpv6Hextets(address: string): number[] {
    let expanded = address;
    const lastColon = expanded.lastIndexOf(':');
    const ipv4Tail = expanded.slice(lastColon + 1);
    if (ipv4Tail.includes('.')) {
        if (isIP(ipv4Tail) !== 4) throw new Error('Invalid IPv4-mapped IPv6 address.');
        const octets = ipv4Tail.split('.').map(Number);
        const replacement = `${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
        expanded = `${expanded.slice(0, lastColon + 1)}${replacement}`;
    }

    const doubleColonParts = expanded.split('::');
    if (doubleColonParts.length > 2) throw new Error('Invalid IPv6 address.');
    const left = splitHextets(doubleColonParts[0]);
    const right = splitHextets(doubleColonParts[1]);
    if (doubleColonParts.length === 1) {
        if (left.length !== 8) throw new Error('Invalid IPv6 address.');
        return left;
    }
    const missing = 8 - left.length - right.length;
    if (missing < 1) throw new Error('Invalid IPv6 address.');
    return [...left, ...Array.from({ length: missing }, () => 0), ...right];
}

function splitHextets(part: string | undefined): number[] {
    if (!part) return [];
    return part.split(':').map((hextet) => {
        if (!/^[a-f0-9]{1,4}$/.test(hextet)) throw new Error('Invalid IPv6 address.');
        return Number.parseInt(hextet, 16);
    });
}

function formatIpv6(hextets: number[]): string {
    let bestStart = -1;
    let bestLength = 0;
    for (let index = 0; index < hextets.length;) {
        if (hextets[index] !== 0) {
            index += 1;
            continue;
        }
        let end = index;
        while (end < hextets.length && hextets[end] === 0) end += 1;
        if (end - index > bestLength && end - index >= 2) {
            bestStart = index;
            bestLength = end - index;
        }
        index = end;
    }

    if (bestStart === -1) return hextets.map((value) => value.toString(16)).join(':');
    const left = hextets
        .slice(0, bestStart)
        .map((value) => value.toString(16))
        .join(':');
    const right = hextets
        .slice(bestStart + bestLength)
        .map((value) => value.toString(16))
        .join(':');
    if (!left && !right) return '::';
    if (!left) return `::${right}`;
    if (!right) return `${left}::`;
    return `${left}::${right}`;
}
