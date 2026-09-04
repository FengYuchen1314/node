// Full Agent HTTPS/JWT API smoke. Native client traffic is covered separately by the portable
// runtime suite; this script verifies the complete image, controller wiring and durable intent.
import assert from 'node:assert/strict';
import { sign, randomBytes } from 'node:crypto';
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
        ['11111111-1111-4111-8111-111111111111', 'A', 'camouflage.test', 14001, 16001],
        ['22222222-2222-4222-8222-222222222222', 'B', 'camouflage-alt.test', 14002, 16002],
    ])
        config.listeners.push({
            id,
            tag,
            wrapperPort,
            innerPort,
            camouflage: { serverName: sni, address: '127.0.0.1', port: 18400 },
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
assert(['initial', 'restored', 'stopped'].includes(phase));
const config = JSON.parse(await read('fixture.json'));
const ca = await read('certs/ca.crt');
const cert = await read('certs/client.crt');
const key = await read('certs/client.key');
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const unsigned = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ sub: 'anytls-api-smoke', exp: Math.floor(Date.now() / 1000) + 900 })}`;
const jwt = `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), await read('certs/jwt.key')).toString('base64url')}`;

async function api(path, body, auth = 'valid') {
    return new Promise((resolve, reject) => {
        const req = request(
            {
                hostname: '127.0.0.1',
                port: 28443,
                path: `/node/anytls/${path}`,
                method: body === undefined ? 'GET' : 'POST',
                ca,
                timeout: 15000,
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
    for (let attempt = 0; attempt < 90; attempt++) {
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
    const started = await api('start', config);
    assert.equal(started.status, 201);
    assert.equal(started.body.response.operation, 'STARTED');
    assert.equal(started.body.response.isStarted, true);
    await assertPorts(true);
    assert.equal((await status()).desiredListeners, 2);
    assert.equal((await api('start', config)).body.response.operation, 'UNCHANGED');
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
} else {
    assert.equal(initial.isStarted, false);
    assert.equal(initial.desiredListeners, 0);
    await assertPorts(false);
    process.stdout.write(
        'PASS: a second full Agent restart cannot revive explicitly stopped listeners\n',
    );
}
