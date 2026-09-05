import assert from 'node:assert/strict';
import { test } from 'node:test';

import { CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS } from '@libs/contracts/models';

import { CLOUDFLARE_IP_RANGES_METADATA, detectCloudflareSignals } from './cloudflare-signals';

test('Cloudflare detection uses pinned IP, ASN, CNAME and HTTP signals', () => {
    assert.deepEqual(
        detectCloudflareSignals({
            addresses: ['104.16.0.1'],
            asn13335Matched: true,
            cnameChain: ['edge.cloudflare.net'],
            serverHeader: 'cloudflare',
        }),
        [
            CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS.ASN,
            CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS.IP_RANGE,
            CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS.CNAME,
            CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS.HTTP_HEADER,
        ],
    );
    assert.equal(CLOUDFLARE_IP_RANGES_METADATA.source, 'https://www.cloudflare.com/ips/');
});

test('Cloudflare name and header heuristics avoid substring-only false positives', () => {
    assert.deepEqual(
        detectCloudflareSignals({
            addresses: ['8.8.8.8'],
            asn13335Matched: false,
            cnameChain: ['notcloudflare.net.example.com'],
            serverHeader: 'notcloudflareish',
        }),
        [],
    );
});

test('CF-Ray alone excludes an otherwise unrecognized Cloudflare endpoint', () => {
    assert.deepEqual(
        detectCloudflareSignals({
            addresses: ['8.8.8.8'],
            asn13335Matched: false,
            cnameChain: [],
            serverHeader: 'nginx',
            cfRayPresent: true,
        }),
        [CAMOUFLAGE_DOMAIN_CLOUDFLARE_SIGNALS.HTTP_HEADER],
    );
});

test('Cloudflare-hosted service names and CNAME targets use exact DNS suffixes', () => {
    for (const suffix of [
        'cloudflare.com',
        'cloudflare.net',
        'cloudflare-dns.com',
        'pages.dev',
        'workers.dev',
        'r2.dev',
    ]) {
        for (const hostname of [suffix, `tenant.${suffix}`, `TENANT.${suffix.toUpperCase()}.`])
            assert.deepEqual(
                detectCloudflareSignals({
                    addresses: [],
                    cnameChain: [hostname],
                    asn13335Matched: false,
                    serverHeader: null,
                }),
                ['CNAME'],
            );
        for (const hostname of [`not${suffix}`, `${suffix}.example.com`])
            assert.deepEqual(
                detectCloudflareSignals({
                    addresses: [],
                    cnameChain: [hostname],
                    asn13335Matched: false,
                    serverHeader: null,
                }),
                [],
            );
    }
});
