import assert from 'node:assert/strict';
import { test } from 'node:test';

import { HttpStatus } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';

import { JwtDefaultGuard } from '@common/guards/jwt-guards';
import { REST_API } from '@libs/contracts/api';
import { CamouflageDomainAgentValidationRequestSchema } from '@libs/contracts/models';

import { AsnLmdbService } from '../asn-lmdb/asn-lmdb.service';
import {
    CamouflageDomainDnsObservation,
    CamouflageDomainDnsService,
} from './camouflage-domain-dns.service';
import {
    CamouflageDomainNetworkObservation,
    CamouflageDomainNetworkService,
} from './camouflage-domain-network.service';
import { CamouflageDomainController } from './camouflage-domain.controller';
import { CamouflageDomainError } from './camouflage-domain.error';
import { CamouflageDomainService, buildDnsFingerprint } from './camouflage-domain.service';

const REQUEST = CamouflageDomainAgentValidationRequestSchema.parse({
    domain: 'example.com',
    expectedRegion: 'LOS_ANGELES',
    requirements: {
        tlsVersion: 'TLSv1.3',
        httpProtocol: 'h2',
        keyExchangeGroup: 'X25519',
        minimumCertificateValidityDays: 14,
        maximumRedirects: 0,
        minimumDistinctMainlandProbeAsns: 2,
        maximumMainlandEvidenceAgeHours: 24,
        rejectCloudflare: true,
        requireCertificateSanMatch: true,
    },
});

const NETWORK_OBSERVATION: CamouflageDomainNetworkObservation = {
    tls: {
        version: 'TLSv1.3',
        cipherSuite: 'TLS_AES_128_GCM_SHA256',
        keyExchangeGroup: 'X25519',
        certificate: {
            sans: ['example.com'],
            sanMatches: true,
            notBefore: '2026-08-01T00:00:00.000Z',
            notAfter: '2026-11-01T00:00:00.000Z',
        },
    },
    http: {
        negotiatedProtocol: 'h2',
        statusCode: 200,
        redirectCount: 0,
        serverHeader: null,
        locationHeader: null,
    },
};

test('a successful validation reports only observed evidence and no mainland claims', async () => {
    const service = createService({
        dns: publicDns(),
        network: async () => NETWORK_OBSERVATION,
    });

    const report = await service.validate(REQUEST);

    assert.deepEqual(report.edge, {
        provider: null,
        asn: null,
        observedRegion: null,
    });
    assert.deepEqual(report.cloudflare, { detected: false, signals: [] });
    assert.deepEqual(report.mainlandProbes, []);
    assert.equal(report.dns.containsBogon, false);
    assert.equal(
        report.dns.fingerprint,
        buildDnsFingerprint('example.com', ['93.184.216.34'], [], null),
    );
});

test('bogon DNS answers are rejected before any connection attempt', async () => {
    let networkCalls = 0;
    const service = createService({
        dns: {
            addresses: ['127.0.0.1'],
            cnameChain: [],
            containsBogon: true,
        },
        network: async () => {
            networkCalls += 1;
            return NETWORK_OBSERVATION;
        },
    });

    await assert.rejects(
        service.validate(REQUEST),
        (error: unknown) => error instanceof CamouflageDomainError && error.code === 'DNS_BOGON',
    );
    assert.equal(networkCalls, 0);
});

test('each resolved IP is tried directly without re-resolving after a failed handshake', async () => {
    const attempted: string[] = [];
    const service = createService({
        dns: {
            addresses: ['8.8.8.8', '9.9.9.9'],
            cnameChain: [],
            containsBogon: false,
        },
        network: async (_domain, address) => {
            attempted.push(address);
            if (address === '8.8.8.8') {
                throw new CamouflageDomainError(
                    'TLS_NEGOTIATION_FAILED',
                    'TLS failed.',
                    HttpStatus.BAD_GATEWAY,
                );
            }
            return NETWORK_OBSERVATION;
        },
    });

    await service.validate(REQUEST);
    assert.deepEqual(attempted, ['8.8.8.8', '9.9.9.9']);
});

test('Cloudflare provider and ASN require authoritative IP/LMDB evidence', async () => {
    const cloudflareDns: CamouflageDomainDnsObservation = {
        addresses: ['104.16.0.1'],
        cnameChain: ['edge.cloudflare.net'],
        containsBogon: false,
    };
    const observedViaCloudflare = {
        ...NETWORK_OBSERVATION,
        http: { ...NETWORK_OBSERVATION.http, serverHeader: 'cloudflare' },
    };
    const withAsn = createService({
        dns: cloudflareDns,
        network: async () => observedViaCloudflare,
        asn13335: { ipv4: ['104.16.0.0/13'], ipv6: [] },
    });

    const report = await withAsn.validate(REQUEST);
    assert.equal(report.edge.provider, 'Cloudflare');
    assert.equal(report.edge.asn, 'AS13335');
    assert.deepEqual(report.cloudflare.signals, ['ASN', 'IP_RANGE', 'CNAME', 'HTTP_HEADER']);

    const heuristicOnly = createService({
        dns: {
            addresses: ['8.8.8.8'],
            cnameChain: ['edge.cloudflare.net'],
            containsBogon: false,
        },
        network: async () => observedViaCloudflare,
    });
    const heuristicReport = await heuristicOnly.validate(REQUEST);
    assert.equal(heuristicReport.edge.provider, null);
    assert.equal(heuristicReport.edge.asn, null);
    assert.deepEqual(heuristicReport.cloudflare.signals, ['CNAME', 'HTTP_HEADER']);
});

test('same-domain validation is locked while the first request is in flight', async () => {
    let releaseDns: ((value: CamouflageDomainDnsObservation) => void) | undefined;
    const dnsPending = new Promise<CamouflageDomainDnsObservation>((resolve) => {
        releaseDns = resolve;
    });
    const service = createService({
        dns: () => dnsPending,
        network: async () => NETWORK_OBSERVATION,
    });

    const first = service.validate(REQUEST);
    await assert.rejects(
        service.validate(REQUEST),
        (error: unknown) => error instanceof CamouflageDomainError && error.code === 'BUSY',
    );
    releaseDns?.(publicDns());
    await first;
});

test('CF-Ray evidence reaches the strict Panel report without changing its wire schema', async () => {
    const service = createService({
        dns: publicDns(),
        network: async () => ({
            ...NETWORK_OBSERVATION,
            http: { ...NETWORK_OBSERVATION.http, cfRayPresent: true },
        }),
    });
    const report = await service.validate(REQUEST);
    assert.deepEqual(report.cloudflare, { detected: true, signals: ['HTTP_HEADER'] });
    assert.equal(Object.hasOwn(report.http, 'cfRayPresent'), false);
});

test('request contract is strict and normalizes IDNA before any network use', () => {
    assert.equal(
        CamouflageDomainAgentValidationRequestSchema.parse({
            ...REQUEST,
            domain: '例子.测试',
        }).domain,
        'xn--fsqu00a.xn--0zwm56d',
    );
    assert.equal(
        CamouflageDomainAgentValidationRequestSchema.safeParse({
            ...REQUEST,
            unexpected: true,
        }).success,
        false,
    );
});

test('the fixed route is protected by the existing Panel-to-Node JWT guard', () => {
    assert.equal(REST_API.CAMOUFLAGE_DOMAIN.VALIDATE, '/node/camouflage-domain/validate');
    const guards = Reflect.getMetadata(GUARDS_METADATA, CamouflageDomainController) as unknown[];
    assert.ok(guards.includes(JwtDefaultGuard));
});

test('DNS fingerprints are deterministic and use the exact unknown ASN marker', () => {
    const unknown = buildDnsFingerprint(
        'example.com',
        ['2606:4700::1111', '1.1.1.1'],
        ['edge.example.net'],
        null,
    );
    assert.equal(
        unknown,
        buildDnsFingerprint(
            'example.com',
            ['1.1.1.1', '2606:4700::1111'],
            ['edge.example.net'],
            null,
        ),
    );
    assert.notEqual(
        unknown,
        buildDnsFingerprint(
            'example.com',
            ['1.1.1.1', '2606:4700::1111'],
            ['edge.example.net'],
            'AS13335',
        ),
    );
});

interface ServiceFakes {
    asn13335?: { ipv4: string[]; ipv6: string[] } | null;
    dns: CamouflageDomainDnsObservation | (() => Promise<CamouflageDomainDnsObservation>);
    network: (
        domain: string,
        address: string,
        signal: AbortSignal,
    ) => Promise<CamouflageDomainNetworkObservation>;
}

function createService(fakes: ServiceFakes): CamouflageDomainService {
    const dns = {
        resolve: async () =>
            typeof fakes.dns === 'function' ? fakes.dns() : Promise.resolve(fakes.dns),
    } as CamouflageDomainDnsService;
    const network = { probe: fakes.network } as CamouflageDomainNetworkService;
    const asn = {
        getByAsn: () => fakes.asn13335 ?? null,
    } as unknown as AsnLmdbService;
    return new CamouflageDomainService(dns, network, asn);
}

function publicDns(): CamouflageDomainDnsObservation {
    return {
        addresses: ['93.184.216.34'],
        cnameChain: [],
        containsBogon: false,
    };
}
