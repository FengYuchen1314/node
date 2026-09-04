import { Resolver } from 'node:dns/promises';

import { HttpStatus, Injectable } from '@nestjs/common';

import { CamouflageDomainSchema } from '@libs/contracts/models';

import { CamouflageDomainError } from './camouflage-domain.error';
import { canonicalizeIp, compareIpAddresses, isPublicUnicastAddress } from './ip-address';

const MAX_RESOLVED_ADDRESSES = 8;
const MAX_CNAME_DEPTH = 16;

export interface CamouflageDomainDnsObservation {
    addresses: string[];
    cnameChain: string[];
    containsBogon: boolean;
}

@Injectable()
export class CamouflageDomainDnsService {
    public async resolve(
        domain: string,
        signal: AbortSignal,
    ): Promise<CamouflageDomainDnsObservation> {
        const resolver = new Resolver();
        const [ipv4, ipv6, cnameChain] = await Promise.all([
            resolveAddressFamily(() => resolver.resolve4(domain), signal),
            resolveAddressFamily(() => resolver.resolve6(domain), signal),
            resolveCnameChain(resolver, domain, signal),
        ]);
        const addresses = [...new Set([...ipv4, ...ipv6].map(canonicalizeIp))].sort(
            compareIpAddresses,
        );
        if (addresses.length === 0) {
            throw new CamouflageDomainError(
                'DNS_RESOLUTION_FAILED',
                'The domain did not resolve to an A or AAAA address.',
                HttpStatus.BAD_GATEWAY,
            );
        }
        if (addresses.length > MAX_RESOLVED_ADDRESSES) {
            throw new CamouflageDomainError(
                'DNS_LIMIT_EXCEEDED',
                `The domain resolved to more than ${MAX_RESOLVED_ADDRESSES} addresses.`,
                HttpStatus.UNPROCESSABLE_ENTITY,
            );
        }
        return {
            addresses,
            cnameChain,
            containsBogon: addresses.some((address) => !isPublicUnicastAddress(address)),
        };
    }
}

async function resolveAddressFamily(
    query: () => Promise<string[]>,
    signal: AbortSignal,
): Promise<string[]> {
    try {
        return await raceWithAbort(query(), signal);
    } catch (error: unknown) {
        if (isNoDnsData(error)) return [];
        if (error instanceof CamouflageDomainError) throw error;
        return [];
    }
}

async function resolveCnameChain(
    resolver: Resolver,
    domain: string,
    signal: AbortSignal,
): Promise<string[]> {
    const chain: string[] = [];
    const seen = new Set([domain]);
    let current = domain;

    for (let depth = 0; depth <= MAX_CNAME_DEPTH; depth += 1) {
        let records: string[];
        try {
            records = await raceWithAbort(resolver.resolveCname(current), signal);
        } catch (error: unknown) {
            if (isNoDnsData(error)) return chain;
            if (error instanceof CamouflageDomainError) throw error;
            throw new CamouflageDomainError(
                'DNS_RESOLUTION_FAILED',
                'CNAME resolution failed.',
                HttpStatus.BAD_GATEWAY,
            );
        }
        if (records.length === 0) return chain;
        if (records.length !== 1 || depth === MAX_CNAME_DEPTH) {
            throw new CamouflageDomainError(
                'DNS_LIMIT_EXCEEDED',
                'The CNAME chain is ambiguous or too deep.',
                HttpStatus.UNPROCESSABLE_ENTITY,
            );
        }
        const parsed = CamouflageDomainSchema.safeParse(records[0]);
        if (!parsed.success || seen.has(parsed.data)) {
            throw new CamouflageDomainError(
                'DNS_RESOLUTION_FAILED',
                'The CNAME chain is invalid or cyclic.',
                HttpStatus.UNPROCESSABLE_ENTITY,
            );
        }
        current = parsed.data;
        seen.add(current);
        chain.push(current);
    }
    return chain;
}

export function raceWithAbort<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
    if (signal.aborted) return Promise.reject(timeoutError());
    return new Promise<T>((resolve, reject) => {
        const abort = () => reject(timeoutError());
        signal.addEventListener('abort', abort, { once: true });
        operation.then(
            (value) => {
                signal.removeEventListener('abort', abort);
                resolve(value);
            },
            (error: unknown) => {
                signal.removeEventListener('abort', abort);
                reject(error);
            },
        );
    });
}

function timeoutError(): CamouflageDomainError {
    return new CamouflageDomainError(
        'VALIDATION_TIMEOUT',
        'Camouflage-domain validation timed out.',
        HttpStatus.GATEWAY_TIMEOUT,
    );
}

function isNoDnsData(error: unknown): boolean {
    if (!error || typeof error !== 'object' || !('code' in error)) return false;
    const code = (error as NodeJS.ErrnoException).code;
    return code === 'ENODATA' || code === 'ENOTFOUND';
}
