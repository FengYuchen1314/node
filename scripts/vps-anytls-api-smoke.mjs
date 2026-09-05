// Full Agent HTTPS/JWT API smoke. Native client traffic is covered separately by the portable
// runtime suite; this script verifies the complete image, controller wiring and durable intent.
import assert from 'node:assert/strict';
import { sign, randomBytes } from 'node:crypto';
import { resolve4 } from 'node:dns/promises';
import { once } from 'node:events';
import { readFile, writeFile } from 'node:fs/promises';
import { request } from 'node:https';
import { connect } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

const read = (name) => readFile(`/test/${name}`, 'utf8');
const phase = process.argv[2];
if (phase === 'setup') {
    const payload = {
        caCertPem: await read('certs/ca.crt'),
        nodeCertPem: await read('certs/server.crt'),
        nodeKeyPem: await read('certs/server.key'),
        jwtPublicKey: await read('certs/jwt.pub'),
    };
    await writeFile(
        '/test/agent.env',
        [
            'NODE_PORT=28443',
            'ANYTLS_ENABLED=true',
            'NFTABLES_LOGGING=false',
            `SECRET_KEY=${Buffer.from(JSON.stringify(payload)).toString('base64')}`,
        ].join('\n') + '\n',
        { mode: 0o600 },
    );
    const config = { version: 1, listeners: [] };
    for (const [id, tag, sni, wrapperPort, innerPort] of [
        ['11111111-1111-4111-8111-111111111111', 'A', 'lax1.vultrobjects.com', 14001, 16001],
        ['22222222-2222-4222-8222-222222222222', 'B', 'sjc1.vultrobjects.com', 14002, 16002],
    ])
        config.listeners.push({
            id,
            tag,
            wrapperPort,
            innerPort,
            // Setup only resolves the fixture. The real Agent must perform live DNS/CF/TLS checks;
            // no test CA, private address or allow-unverified option is supplied to that guard.
            camouflage: { serverName: sni, address: (await resolve4(sni))[0], port: 443 },
            wrapperPassword: randomBytes(32).toString('hex'),
            shadowPassword: randomBytes(32).toString('hex'),
            tls: {
                serverName: 'inner.test',
                certificate: await read('inner-certs/inner.crt'),
                privateKey: await read('inner-certs/inner.key'),
                caCertificate: await read('inner-certs/ca.crt'),
            },
            users: [{ name: tag, password: randomBytes(32).toString('hex') }],
        });
    await writeFile('/test/fixture.json', JSON.stringify(config), { mode: 0o600 });
    process.exit(0);
}
const config = JSON.parse(await read('fixture.json'));
if (phase === 'seed-unsafe-state') {
    // Run only while this disposable Agent container is stopped. This emulates an old saved
    // configuration; the next real bootstrap must refuse to restore its unverified endpoint.
    const path = '/test/state/anytls/runtime.json';
    const state = JSON.parse(await readFile(path, 'utf8'));
    assert.equal(state.desired, null);
    state.desired = structuredClone(config);
    state.desired.listeners[0].camouflage.serverName = 'unverified.invalid';
    await writeFile(path, JSON.stringify(state), { mode: 0o600 });
    process.exit(0);
}
assert(['initial', 'restored', 'stopped', 'unsafe-restored'].includes(phase));
const ca = await read('certs/ca.crt');
const cert = await read('certs/client.crt');
const key = await read('certs/client.key');
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const unsigned = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ sub: 'anytls-api-smoke', exp: Math.floor(Date.now() / 1000) + 900 })}`;
const jwt = `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), await read('certs/jwt.key')).toString('base64url')}`;

async function api(path, body, auth = 'valid', scope = 'anytls') {
    return new Promise((resolve, reject) => {
        const req = request(
            {
                hostname: '127.0.0.1',
                port: 28443,
                path: `/node/${scope}/${path}`,
                method: body === undefined ? 'GET' : 'POST',
                ca,
                timeout: body === undefined ? 5000 : 45000,
                ...(auth === 'no-mtls' ? {} : { cert, key }),
                headers: {
                    'Content-Type': 'application/json',
                    ...(auth === 'no-jwt'
                        ? {}
                        : { Authorization: `Bearer ${auth === 'bad-jwt' ? 'invalid' : jwt}` }),
                },
            },
            (res) => {
                let text = '';
                res.on('data', (chunk) => {
                    text += chunk;
                    if (text.length > 1024 * 1024) req.destroy(new Error('Oversized Agent reply'));
                });
                res.once('error', reject);
                res.once('end', () => {
                    try {
                        resolve({ status: res.statusCode, body: JSON.parse(text) });
                    } catch {
                        reject(new Error(`Non-JSON Agent response (${res.statusCode})`));
                    }
                });
            },
        );
        req.once('error', reject);
        req.once('timeout', () => req.destroy(new Error('Agent API deadline')));
        req.end(body === undefined ? undefined : JSON.stringify(body));
    });
}
async function status() {
    const result = await api('status');
    assert.equal(result.status, 200);
    assert.equal(result.body.response.available, true);
    return result.body.response;
}
async function ready() {
    let lastError;
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
        const result = await status().catch((error) => {
            lastError = error;
            return null;
        });
        if (result) return result;
        await delay(500);
    }
    throw new Error('Full Agent image did not become ready', { cause: lastError });
}
async function portOpen(port) {
    const socket = connect(port, '127.0.0.1');
    socket.setTimeout(1000, () => socket.destroy(new Error('Socket deadline')));
    try {
        await once(socket, 'connect');
        return true;
    } catch {
        return false;
    } finally {
        socket.destroy();
    }
}
async function assertPorts(expected) {
    for (const port of [14001, 14002, 16001, 16002, 15998, 15999])
        assert.equal(await portOpen(port), expected, `Unexpected listener state on ${port}`);
}

async function rejectedConfigurationPreservesRuntime(running) {
    for (const change of [
        { address: '104.16.0.1' },
        { address: '2606:4700::1' },
        { serverName: 'www.cloudflare.com' },
        { serverName: 'tenant.pages.dev' },
        { serverName: 'tenant.workers.dev' },
        { serverName: 'bucket.r2.dev' },
        { address: '127.0.0.1' },
        { serverName: 'unverified.invalid' },
    ]) {
        const invalid = structuredClone(config);
        Object.assign(invalid.listeners[0].camouflage, change);
        assert.equal((await api('start', invalid)).status, 400);
        const observed = await status();
        assert.equal(observed.isStarted, running);
        assert.equal(observed.desiredListeners, running ? 2 : 0);
        await assertPorts(running);
    }
    process.stdout.write(
        `PASS: CF IPv4/IPv6/hostname, private IP and failed live DNS rejected (${running ? 'existing listeners preserved' : 'no listeners created'})\n`,
    );
}

const initial = await ready();
if (phase === 'initial') {
    assert.equal(initial.isStarted, false);
    for (const auth of ['no-jwt', 'bad-jwt']) {
        // The upstream JWT guard deliberately destroys the socket instead of exposing a 401.
        for (const [path, body] of [
            ['status', undefined],
            ['start', config],
            ['stop', {}],
            ['stats', {}],
        ])
            await assert.rejects(api(path, body, auth), (error) => error.code === 'ECONNRESET');
        assert.equal((await status()).isStarted, false);
    }
    await assert.rejects(api('status', undefined, 'no-mtls'));
    await assertPorts(false);
    process.stdout.write(
        'PASS: mTLS/JWT reject unauthorized API access without starting listeners\n',
    );
    await rejectedConfigurationPreservesRuntime(false);
    const cfReport = await api(
        'validate',
        {
            domain: 'www.cloudflare.com',
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
        },
        'valid',
        'camouflage-domain',
    );
    assert.equal(cfReport.status, 201);
    assert.equal(cfReport.body.response.cloudflare.detected, true);
    assert(cfReport.body.response.cloudflare.signals.includes('HTTP_HEADER'));
    assert.equal(Object.hasOwn(cfReport.body.response.http, 'cfRayPresent'), false);
    await assertPorts(false);
    process.stdout.write(
        'PASS: complete authenticated domain API reports live Cloudflare HTTP evidence\n',
    );
    for (const [target, serverName, expected] of [
        ['104.16.0.1:443', 'www.cloudflare.com', /Cloudflare CDN/],
        ['lax1.vultrobjects.com:443', 'tenant.pages.dev', /Cloudflare CDN/],
        ['lax1.vultrobjects.com:443', 'tenant.workers.dev', /Cloudflare CDN/],
        ['lax1.vultrobjects.com:443', 'bucket.r2.dev', /Cloudflare CDN/],
        ['lax1.vultrobjects.com:443', 'unverified.invalid', /configuration was not accepted/],
    ]) {
        const rejected = await api(
            'start',
            {
                internals: { forceRestart: true, hashes: { emptyConfig: 'fixture', inbounds: [] } },
                xrayConfig: {
                    inbounds: [
                        {
                            tag: 'CAMOUFLAGE_REJECTION_TEST',
                            protocol: 'vless',
                            port: 14100,
                            listen: '127.0.0.1',
                            streamSettings: {
                                security: 'reality',
                                realitySettings: { target, serverNames: [serverName] },
                            },
                        },
                    ],
                },
            },
            'valid',
            'xray',
        );
        // Existing Xray API reports a failed start inside its normal response contract.
        assert.equal(rejected.status, 201);
        assert.equal(rejected.body.response.isStarted, false);
        assert.match(rejected.body.response.error, expected);
        assert.equal(await portOpen(14100), false);
    }
    process.stdout.write(
        'PASS: complete Xray API rejects Cloudflare and unverified REALITY before core startup\n',
    );
    const started = await api('start', config);
    assert.equal(started.status, 201);
    assert.equal(started.body.response.operation, 'STARTED');
    assert.equal(started.body.response.isStarted, true);
    await assertPorts(true);
    assert.equal((await status()).desiredListeners, 2);
    assert.equal((await api('start', config)).body.response.operation, 'UNCHANGED');
    await rejectedConfigurationPreservesRuntime(true);
    const bad = structuredClone(config);
    bad.listeners[1].camouflage.serverName = bad.listeners[0].camouflage.serverName;
    assert.equal((await api('start', bad)).status, 400);
    assert.equal((await api('stats', { reset: 'true' })).status, 400);
    assert.equal((await status()).desiredListeners, 2);
    assert.equal((await status()).isStarted, true);
    assert.deepEqual((await api('stats', { reset: true })).body.response.users, []);
    process.stdout.write(
        'PASS: complete image API, mTLS/JWT, strict DTOs, native cores and unchanged reconciliation\n',
    );
} else if (phase === 'restored') {
    assert.equal(initial.isStarted, true);
    assert.equal(initial.desiredListeners, 2);
    await assertPorts(true);
    assert.deepEqual((await api('stats', { reset: true })).body.response.users, []);
    const stopped = await api('stop', {});
    assert.equal(stopped.status, 201);
    assert.equal(stopped.body.response.isStopped, true);
    await assertPorts(false);
    assert.equal((await status()).desiredListeners, 0);
    process.stdout.write(
        'PASS: full Agent restart restores desired listeners; explicit API stop closes all private ports\n',
    );
} else if (phase === 'stopped') {
    assert.equal(initial.isStarted, false);
    assert.equal(initial.desiredListeners, 0);
    await assertPorts(false);
    process.stdout.write(
        'PASS: a second full Agent restart cannot revive explicitly stopped listeners\n',
    );
} else {
    assert.equal(initial.available, true);
    assert.equal(initial.isStarted, false);
    assert.equal(initial.desiredListeners, 2);
    assert.equal(initial.error, 'Saved AnyTLS configuration could not be restored safely.');
    await assertPorts(false);
    assert.equal((await api('stop', {})).body.response.isStopped, true);
    assert.equal((await status()).desiredListeners, 0);
    process.stdout.write(
        'PASS: unsafe saved camouflage fails closed on real bootstrap while authenticated management remains available\n',
    );
}
