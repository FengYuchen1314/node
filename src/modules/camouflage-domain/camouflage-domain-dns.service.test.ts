import assert from 'node:assert/strict';
import { test } from 'node:test';

import { CamouflageDomainDnsService, resolveAddressFamily } from './camouflage-domain-dns.service';
import { CamouflageDomainError } from './camouflage-domain.error';

test('only authoritative DNS absence may become an empty address family', async () => {
    for (const code of [
        'ENODATA',
        'ENOTFOUND',
        'ETIMEOUT',
        'ESERVFAIL',
        'ECONNREFUSED',
        'ECANCELLED',
    ]) {
        const result = resolveAddressFamily(async () => {
            throw Object.assign(new Error('DNS fixture'), { code });
        }, new AbortController().signal);
        if (['ENODATA', 'ENOTFOUND'].includes(code)) assert.deepEqual(await result, []);
        else
            await assert.rejects(
                result,
                (error: unknown) =>
                    error instanceof CamouflageDomainError &&
                    error.code === 'DNS_RESOLUTION_FAILED',
            );
    }
});

test('already aborted DNS validation never starts a resolver', async () => {
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
        new CamouflageDomainDnsService().resolve('example.com', controller.signal),
        (error: unknown) =>
            error instanceof CamouflageDomainError && error.code === 'VALIDATION_TIMEOUT',
    );
});
