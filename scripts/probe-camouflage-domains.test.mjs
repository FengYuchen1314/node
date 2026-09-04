import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
    cloudflareDnsSignals,
    isPublicV4,
    normalizeDomain,
    probeDomain,
} from './probe-camouflage-domains.mjs';

test('probe rejects URL/option/IP injection and normalizes IDNA hostnames', () => {
    assert.equal(normalizeDomain(' EXAMPLE.com. '), 'example.com');
    for (const value of [
        'https://example.com',
        '--insecure',
        '127.0.0.1',
        'name..test',
        'name;id.test',
        '[::1]',
    ])
        assert.throws(() => normalizeDomain(value));
});

test('probe never dials private, reserved, multicast or mapped addresses', () => {
    for (const ip of [
        '127.0.0.1',
        '10.1.2.3',
        '169.254.169.254',
        '100.64.1.1',
        '224.0.0.1',
        '192.0.2.1',
        '::ffff:7f00:1',
    ])
        assert.equal(isPublicV4(ip), false);
    assert.equal(isPublicV4('42.192.61.137'), true);
});

test('a mixed public/private DNS answer fails before any socket or ASN lookup', async () => {
    const result = await probeDomain(
        {
            resolve4: async () => ['42.192.61.137', '127.0.0.1'],
            resolve6: async () => [],
            resolveCname: async () => [],
        },
        'example.com',
    );
    assert.equal(result.outcome, 'DNS_BOGON');
    assert.deepEqual(result.attempts, []);
    assert.equal(result.automaticallyEligible, false);
});

test('DNS failure stays explicit instead of becoming a successful mainland observation', async () => {
    const fail = async () => {
        throw Object.assign(new Error('failed'), { code: 'ENOTFOUND' });
    };
    const result = await probeDomain(
        { resolve4: fail, resolve6: fail, resolveCname: fail },
        'missing.test',
    );
    assert.equal(result.outcome, 'NO_IPV4_ADDRESS');
    assert.equal(result.dns.error, 'ENOTFOUND');
    assert.equal(result.automaticallyEligible, false);
});

test('Cloudflare on either address family or its CNAME path is a hard exclusion', async () => {
    assert.deepEqual(cloudflareDnsSignals(['104.16.1.2', '2606:4700::1'], []), ['IP_RANGE']);
    assert.deepEqual(cloudflareDnsSignals(['42.192.61.137'], ['edge.cloudflare.net.']), ['CNAME']);
    assert.deepEqual(cloudflareDnsSignals(['42.192.61.137'], ['notcloudflare.com']), []);
    const result = await probeDomain(
        {
            resolve4: async () => ['104.16.1.2'],
            resolve6: async () => [],
            resolveCname: async () => [],
        },
        'example.com',
    );
    assert.equal(result.outcome, 'CLOUDFLARE_EXCLUDED');
    assert.deepEqual(result.attempts, []);
    assert.equal(result.automaticallyEligible, false);
});

test('Cloudflare ASN excludes an address even when it is outside the pinned CDN ranges', async () => {
    const result = await probeDomain(
        {
            resolve4: async () => ['8.8.8.8'],
            resolve6: async () => [],
            resolveCname: async () => [],
            resolveTxt: async () => [['13335 | 8.8.8.0/24 | US | arin | 2000-01-01']],
        },
        'example.com',
    );
    assert.equal(result.outcome, 'CLOUDFLARE_EXCLUDED');
    assert.equal(result.attempts[0].error, 'CLOUDFLARE_EXCLUDED');
    assert.equal(result.automaticallyEligible, false);
});
