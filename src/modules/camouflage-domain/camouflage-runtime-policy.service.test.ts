import assert from 'node:assert/strict';
import { test } from 'node:test';

import { TAnyTlsConfig } from '@libs/contracts/models';

import { AsnLmdbService } from '../asn-lmdb/asn-lmdb.service';
import {
    CamouflageDomainDnsObservation,
    CamouflageDomainDnsService,
} from './camouflage-domain-dns.service';
import {
    CamouflageDomainNetworkObservation,
    CamouflageDomainNetworkService,
} from './camouflage-domain-network.service';
import {
    CamouflageRuntimePolicy,
    parseCamouflageTarget,
} from './camouflage-runtime-policy.service';

const address = '93.184.215.14';
const dnsResult = (addresses = [address]): CamouflageDomainDnsObservation => ({
    addresses,
    cnameChain: [],
    containsBogon: false,
});
const observation = (): CamouflageDomainNetworkObservation => ({
    tls: {
        version: 'TLSv1.3',
        cipherSuite: 'TLS_AES_128_GCM_SHA256',
        keyExchangeGroup: 'X25519',
        certificate: {
            sanMatches: true,
            sans: ['camouflage.test'],
            notBefore: new Date(Date.now() - 86400000).toISOString(),
            notAfter: new Date(Date.now() + 60 * 86400000).toISOString(),
        },
    },
    http: {
        negotiatedProtocol: 'h2',
        statusCode: 200,
        redirectCount: 0,
        serverHeader: null,
        locationHeader: null,
    },
});
const input = (target = 'camouflage.test:443') => ({
    inbounds: [
        {
            tag: 'VLESS',
            protocol: 'vless',
            port: 443,
            streamSettings: {
                security: 'reality',
                realitySettings: { target, serverNames: ['camouflage.test'] },
            },
        },
    ],
});
function fake(
    options: {
        dns?: (domain: string) => Promise<CamouflageDomainDnsObservation>;
        probe?: (
            domain: string,
            ip: string,
            signal: AbortSignal,
            port?: number,
        ) => Promise<CamouflageDomainNetworkObservation>;
        asn?: { ipv4: string[]; ipv6: string[] };
    } = {},
) {
    const calls: Array<{ name: string; ip: string; port: number | undefined }> = [];
    return {
        calls,
        policy: new CamouflageRuntimePolicy(
            {
                resolve: options.dns ?? (async () => dnsResult()),
            } as unknown as CamouflageDomainDnsService,
            {
                probe: async (name: string, ip: string, signal: AbortSignal, port?: number) => {
                    calls.push({ name, ip, port });
                    return options.probe ? options.probe(name, ip, signal, port) : observation();
                },
            } as unknown as CamouflageDomainNetworkService,
            { getByAsn: () => options.asn ?? null } as unknown as AsnLmdbService,
        ),
    };
}

test('REALITY target is pinned after verification, preserving the original config and all SNIs', async () => {
    const { policy, calls } = fake();
    const config = input('target.test:8443');
    config.inbounds[0].streamSettings.realitySettings.serverNames.push('second.test');
    const result = await policy.prepareXray(config);
    assert.equal(config.inbounds[0].streamSettings.realitySettings.target, 'target.test:8443');
    const prepared = result.config as typeof config;
    assert.equal(prepared.inbounds[0].streamSettings.realitySettings.target, `${address}:8443`);
    assert.deepEqual(calls, [
        { name: 'camouflage.test', ip: address, port: 8443 },
        { name: 'second.test', ip: address, port: 8443 },
    ]);
});

test('DNS changes are rechecked on the next start and change the pinned configuration fingerprint', async () => {
    let ip = address;
    const { policy } = fake({ dns: async () => dnsResult([ip]) });
    const first = await policy.prepareXray(input());
    ip = '93.184.215.15';
    const second = await policy.prepareXray(input());
    assert.notEqual(first.fingerprint, second.fingerprint);
});

test('CF IPv4, IPv6, CNAME and ASN signals reject a whole domain before network probing', async () => {
    for (const options of [
        { dns: async () => dnsResult(['104.16.0.1']) },
        { dns: async () => dnsResult([address, '2606:4700::1']) },
        { dns: async () => ({ ...dnsResult(), cnameChain: ['edge.cloudflare.net'] }) },
        { asn: { ipv4: ['93.184.215.0/24'], ipv6: [] } },
    ]) {
        const { policy, calls } = fake(options);
        await assert.rejects(policy.prepareXray(input()), /Cloudflare CDN/);
        assert.equal(calls.length, 0);
    }
});

test('a CF secondary SNI cannot hide behind a non-CF target or primary SNI', async () => {
    const { policy, calls } = fake({
        dns: async (name) => dnsResult(name === 'second.test' ? ['104.16.0.1'] : [address]),
    });
    const config = input();
    config.inbounds[0].streamSettings.realitySettings.serverNames.push('second.test');
    await assert.rejects(policy.prepareXray(config), /Cloudflare CDN/);
    assert.equal(calls.length, 0);
});

test('CF-Ray forbids fallback to another otherwise reachable IP', async () => {
    const { policy, calls } = fake({
        dns: async () => dnsResult([address, '93.184.215.15']),
        probe: async () => {
            const value = observation();
            value.http.cfRayPresent = true;
            return value;
        },
    });
    await assert.rejects(policy.prepareXray(input()), /Cloudflare CDN/);
    assert.equal(calls.length, 1);
});

test('failed DNS, nonpublic destinations and unverified TLS fail closed without leaking raw errors', async () => {
    const { policy, calls } = fake({
        dns: async () => {
            throw new Error('sensitive raw DNS diagnostic');
        },
    });
    await assert.rejects(
        policy.prepareXray(input()),
        (error: Error) =>
            /configuration was not accepted/.test(error.message) &&
            !/sensitive/.test(error.message),
    );
    assert.equal(calls.length, 0);
    const other = fake();
    for (const ip of ['127.0.0.1', '169.254.169.254', '::ffff:127.0.0.1'])
        await assert.rejects(
            other.policy.prepareXray(input(`${ip.includes(':') ? `[${ip}]` : ip}:443`)),
        );
    assert.equal(other.calls.length, 0);
    for (const bad of ['redirect', 'san', 'expiry', 'tls']) {
        const fixture = fake({
            probe: async () => {
                const value = observation();
                if (bad === 'redirect') value.http.redirectCount = 1;
                if (bad === 'san') value.tls.certificate.sanMatches = false;
                if (bad === 'expiry') value.tls.certificate.notAfter = 'invalid';
                if (bad === 'tls') value.tls.version = 'TLSv1.2';
                return value;
            },
        });
        await assert.rejects(fixture.policy.prepareXray(input()));
    }
});

test('AnyTLS checks the pinned public endpoint and does not provide a private fixture bypass', async () => {
    const { policy, calls } = fake();
    const config = {
        listeners: [{ camouflage: { serverName: 'camouflage.test', address, port: 443 } }],
    } as TAnyTlsConfig;
    await policy.assertAnyTls(config);
    assert.deepEqual(calls, [{ name: 'camouflage.test', ip: address, port: 443 }]);
    config.listeners[0].camouflage.address = '127.0.0.1';
    await assert.rejects(policy.assertAnyTls(config));
});

test('non-REALITY configs do not trigger camouflage checks; target parsing rejects ambiguous destinations', async () => {
    const { policy, calls } = fake();
    const config = { inbounds: [{ protocol: 'socks', port: 1234 }] };
    assert.deepEqual((await policy.prepareXray(config)).config, config);
    assert.equal(calls.length, 0);
    for (const target of [
        '443',
        '/tmp/socket',
        'https://example.com:443',
        'user@example.com:443',
        'example.com:0',
        'example.com:65536',
    ])
        assert.throws(() => parseCamouflageTarget(target));
    assert.deepEqual(parseCamouflageTarget('[2606:4700::1]:443'), {
        address: '2606:4700::1',
        port: 443,
    });
    const ambiguous = input();
    Object.assign(ambiguous.inbounds[0].streamSettings.realitySettings, { dest: 'other.test:443' });
    await assert.rejects(policy.prepareXray(ambiguous));
});
