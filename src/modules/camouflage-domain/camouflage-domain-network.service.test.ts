import type { TLSSocket } from 'node:tls';

import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';

import {
    TlsConnectFunction,
    buildHttpObservation,
    openBoundTlsSocket,
    readTlsObservation,
} from './camouflage-domain-network.service';
import { CamouflageDomainError } from './camouflage-domain.error';

test('TLS connection is pinned to the resolved IP while preserving domain SNI', async () => {
    let captured: Parameters<TlsConnectFunction>[0] | undefined;
    const connect: TlsConnectFunction = (options) => {
        captured = options;
        throw new Error('stop after observing options');
    };

    await assert.rejects(
        openBoundTlsSocket('example.com', '93.184.216.34', new AbortController().signal, connect),
        (error: unknown) => error instanceof CamouflageDomainError,
    );
    assert.equal(captured?.host, '93.184.216.34');
    assert.equal(captured?.servername, 'example.com');
    assert.equal(captured?.rejectUnauthorized, true);
    assert.equal(captured?.minVersion, 'TLSv1.3');
    assert.equal(captured?.maxVersion, 'TLSv1.3');
    assert.equal(captured?.ecdhCurve, 'X25519');
    assert.deepEqual(captured?.ALPNProtocols, ['h2']);
});

test('an aborted TLS connection fails closed as a validation timeout', async () => {
    const fake = new FakeTlsSocket();
    const controller = new AbortController();
    const pending = openBoundTlsSocket(
        'example.com',
        '93.184.216.34',
        controller.signal,
        () => fake as unknown as TLSSocket,
    );
    controller.abort();
    await assert.rejects(
        pending,
        (error: unknown) =>
            error instanceof CamouflageDomainError && error.code === 'VALIDATION_TIMEOUT',
    );
    assert.equal(fake.destroyedByValidator, true);
});

test('TLS evidence requires trust, TLS1.3, h2, X25519 and a matching SAN', () => {
    const valid = fakeNegotiatedSocket();
    const observation = readTlsObservation(valid as unknown as TLSSocket, 'example.com');
    assert.equal(observation.version, 'TLSv1.3');
    assert.equal(observation.keyExchangeGroup, 'X25519');
    assert.equal(observation.certificate.sanMatches, true);

    assertTlsFailure({ ...valid, getProtocol: () => 'TLSv1.2' }, 'TLS_1_3_REQUIRED');
    assertTlsFailure({ ...valid, alpnProtocol: 'http/1.1' }, 'HTTP_2_REQUIRED');
    assertTlsFailure({ ...valid, getEphemeralKeyInfo: () => ({}) }, 'X25519_UNVERIFIED');
    assertTlsFailure(
        {
            ...valid,
            getPeerX509Certificate: () => ({
                ...valid.getPeerX509Certificate(),
                checkHost: () => undefined,
            }),
        },
        'CERTIFICATE_SAN_MISMATCH',
    );
    assertTlsFailure({ ...valid, authorized: false }, 'TLS_TRUST_FAILED');
});

test('HTTP evidence never follows redirects and treats Location as a redirect signal', () => {
    assert.deepEqual(
        buildHttpObservation('h2', {
            ':status': 200,
            server: 'nginx',
            location: '/elsewhere',
        }),
        {
            negotiatedProtocol: 'h2',
            cfRayPresent: false,
            statusCode: 200,
            redirectCount: 1,
            serverHeader: 'nginx',
            locationHeader: '/elsewhere',
        },
    );
    assert.equal(buildHttpObservation('h2', { ':status': 302 }).redirectCount, 1);
    assert.throws(
        () => buildHttpObservation('h2', { ':status': 200, location: 'x'.repeat(2_049) }),
        (error: unknown) =>
            error instanceof CamouflageDomainError && error.code === 'HTTP_REQUEST_FAILED',
    );
});

test('CF-Ray remains a Cloudflare signal even with a masked or absent Server header', () => {
    for (const value of ['', 'fixture-ray-id']) {
        assert.equal(
            buildHttpObservation('h2', { ':status': 200, 'cf-ray': value }).cfRayPresent,
            true,
        );
    }
});

function assertTlsFailure(socket: object, code: string): void {
    assert.throws(
        () => readTlsObservation(socket as TLSSocket, 'example.com'),
        (error: unknown) => error instanceof CamouflageDomainError && error.code === code,
    );
}

function fakeNegotiatedSocket() {
    const certificate = {
        subjectAltName: 'DNS:example.com, DNS:www.example.com',
        validFrom: 'Aug  1 00:00:00 2026 GMT',
        validTo: 'Nov  1 00:00:00 2026 GMT',
        checkHost: (domain: string) => (domain === 'example.com' ? domain : undefined),
    };
    return {
        authorized: true,
        alpnProtocol: 'h2',
        getProtocol: () => 'TLSv1.3',
        getEphemeralKeyInfo: () => ({ type: 'ECDH', name: 'X25519', size: 253 }),
        getCipher: () => ({
            name: 'TLS_AES_128_GCM_SHA256',
            standardName: 'TLS_AES_128_GCM_SHA256',
        }),
        getPeerX509Certificate: () => certificate,
    };
}

class FakeTlsSocket extends EventEmitter {
    public destroyedByValidator = false;

    public setTimeout(): this {
        return this;
    }

    public destroy(): this {
        this.destroyedByValidator = true;
        return this;
    }
}
