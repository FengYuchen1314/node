// Complete Actions-built Agent + native HAProxy/Caddy/core API acceptance.
// Includes real encrypted TCP client traffic; public ACME and panel billing are separate.
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { once } from 'node:events';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { request } from 'node:https';
import { connect } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

import { sendNativeAnyTlsTraffic } from './vps-anytls-client-smoke.mjs';

const read = (name) => readFile(`/test/${name}`, 'utf8');
const phase = process.argv[2];
if (phase === 'setup') {
    const fixture = JSON.parse(await read('fixture.json'));
    fixture.listeners[0].users[0].name = '42';
    const { privateKey } = generateKeyPairSync('x25519');
    const body = {
        internals: {
            forceRestart: true,
            hashes: {
                emptyConfig: 'joint-fixture',
                inbounds: [{ tag: 'VLESS', usersCount: 0, hash: 'empty' }],
            },
        },
        xrayConfig: {
            log: { loglevel: 'warning' },
            inbounds: [
                {
                    tag: 'VLESS',
                    listen: '127.0.0.1',
                    port: 14443,
                    protocol: 'vless',
                    settings: { clients: [], decryption: 'none' },
                    streamSettings: {
                        network: 'tcp',
                        security: 'reality',
                        sockopt: { acceptProxyProtocol: true },
                        realitySettings: {
                            target: `${fixture.listeners[1].camouflage.serverName}:443`,
                            serverNames: [fixture.listeners[1].camouflage.serverName],
                            privateKey: privateKey.export({ format: 'jwk' }).d,
                            shortIds: ['1234567890abcdef'],
                        },
                    },
                },
            ],
            outbounds: [{ tag: 'direct', protocol: 'freedom' }],
        },
        anyTlsConfig: { version: 1, listeners: [fixture.listeners[0]] },
        edgePlan: {
            version: 1,
            publicHttpPort: 80,
            publicHttpsPort: 443,
            caddyHttpTarget: '127.0.0.1:18080',
            caddyHttpsTarget: '127.0.0.1:18443',
            management: null,
            website: null,
            routes: [
                {
                    sni: fixture.listeners[1].camouflage.serverName,
                    inboundTag: 'VLESS',
                    targetHost: '127.0.0.1',
                    targetPort: 14443,
                    sendProxyV2: true,
                },
                {
                    sni: fixture.listeners[0].camouflage.serverName,
                    inboundTag: fixture.listeners[0].tag,
                    targetHost: '127.0.0.1',
                    targetPort: 14001,
                    sendProxyV2: false,
                },
            ],
        },
    };
    await writeFile('/test/coordinated.json', JSON.stringify(body), { mode: 0o600 });
    await appendFile(
        '/test/agent.env',
        'EDGE_ENABLED=true\nEDGE_CONFIG_DIR=/test/edge\nEDGE_HAPROXY_MASTER_SOCKET=/test/edge/run/master.sock\n',
    );
    await mkdir('/test/edge/run', { recursive: true, mode: 0o700 });
    await writeFile(
        '/test/edge/haproxy.cfg',
        `global
    master-worker
    user haproxy
    group haproxy
defaults
    mode tcp
    timeout connect 5s
    timeout client 5s
    timeout server 5s
frontend bootstrap_https
    bind :443
    default_backend bootstrap_caddy
backend bootstrap_caddy
    server caddy 127.0.0.1:18443
`,
        { mode: 0o600 },
    );
    await writeFile(
        '/test/edge/Caddyfile',
        `{
    admin 127.0.0.1:2019
    auto_https off
}
http://127.0.0.1:18080, http://127.0.0.1:18443 {
    respond "Not configured" 404
}
`,
        { mode: 0o600 },
    );
    process.exit(0);
}
assert(['initial', 'reboot', 'stopped'].includes(phase));
const fixture = JSON.parse(await read('coordinated.json'));
const ca = await read('certs/ca.crt');
const cert = await read('certs/client.crt');
const key = await read('certs/client.key');
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const unsigned = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ sub: 'coordinated-api-smoke', exp: Math.floor(Date.now() / 1000) + 900 })}`;
const jwt = `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), await read('certs/jwt.key')).toString('base64url')}`;

async function api(scope, path, body, auth = true) {
    return new Promise((resolve, reject) => {
        const req = request(
            {
                hostname: '127.0.0.1',
                port: 28443,
                path: `/node/${scope}/${path}`,
                method: body === undefined ? 'GET' : 'POST',
                ca,
                cert,
                key,
                timeout: 120000,
                headers: {
                    'Content-Type': 'application/json',
                    ...(auth ? { Authorization: `Bearer ${jwt}` } : {}),
                },
            },
            (response) => {
                let text = '';
                response.on('data', (chunk) => {
                    text += chunk;
                    if (text.length > 1 << 20) req.destroy(new Error('Oversized API response'));
                });
                response.once('error', reject);
                response.once('end', () => {
                    try {
                        resolve({ status: response.statusCode, body: JSON.parse(text) });
                    } catch {
                        reject(new Error('Non-JSON API response'));
                    }
                });
            },
        );
        req.once('error', reject);
        req.once('timeout', () => req.destroy(new Error('Coordinated API deadline')));
        req.end(body === undefined ? undefined : JSON.stringify(body));
    });
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
async function assertRuntime(running, routes = running ? 2 : 0) {
    const status = await api('anytls', 'status');
    assert.equal(status.status, 200);
    assert.equal(status.body.response.isStarted, running);
    for (const port of [14001, 14443, 16001, 15998, 15999])
        assert.equal(await portOpen(port), running, `Unexpected private port ${port}`);
    const plan = JSON.parse(await read('edge/edge-plan.json').catch(() => '{"routes":[]}'));
    assert.equal(plan.routes.length, routes);
    return status.body.response;
}
async function start(body = fixture) {
    const result = await api('xray', 'start', body);
    assert.equal(result.status, 201, 'Coordinated API did not accept the request');
    assert.equal(result.body.response.isStarted, true, 'Coordinated core startup failed');
}
async function assertUsage(previous) {
    const result = await api('anytls', 'usage');
    assert.equal(result.status, 200);
    const usage = result.body.response;
    assert.equal(usage.available, true);
    assert.equal(usage.version, 1);
    assert.match(usage.epoch, /^[a-f0-9-]{36}$/);
    assert(Array.isArray(usage.users));
    if (previous) assert.deepEqual(usage, previous);
    assert.equal((await api('anytls', 'stats', { reset: true })).status, 400);
    return usage;
}
const deadline = Date.now() + 60000;
while (true) {
    const ready = await api('edge', 'status').catch(() => null);
    if (ready?.body.response.available) break;
    assert(Date.now() < deadline, 'Full Agent and edge did not become ready');
    await delay(300);
}
assert.deepEqual((await api('anytls', 'capabilities')).body.response, {
    available: true,
    coordinatedStartVersion: 1,
});
if (phase === 'initial') {
    await assert.rejects(api('anytls', 'capabilities', undefined, false));
    await assert.rejects(api('anytls', 'usage', undefined, false));
    for (const [scope, path] of [
        ['handler', 'add-user'],
        ['handler', 'add-users'],
        ['handler', 'remove-user'],
        ['handler', 'remove-users'],
        ['plugin', 'sync'],
    ]) {
        const rejected = await api(scope, path, {});
        assert.equal(rejected.status, 400);
        assert.match(rejected.body.message, /complete coordinated/);
    }
    assert.equal((await api('anytls', 'start', fixture.anyTlsConfig)).status, 400);
    assert.equal((await api('anytls', 'stop', {})).status, 400);
    const omitted = structuredClone(fixture);
    delete omitted.anyTlsConfig;
    assert.equal((await api('xray', 'start', omitted)).status, 400);
    await assertRuntime(false);
    const cf = structuredClone(fixture);
    cf.anyTlsConfig.listeners[0].camouflage.address = '104.16.0.1';
    assert.equal((await api('xray', 'start', cf)).status, 400);
    await assertRuntime(false);
    await start();
    await assertRuntime(true);
    const emptyUsage = await assertUsage();
    assert.deepEqual(emptyUsage.users, []);
    await assertUsage(emptyUsage);
    await sendNativeAnyTlsTraffic(fixture.anyTlsConfig.listeners[0]);
    const usage = await assertUsage();
    assert.equal(usage.epoch, emptyUsage.epoch);
    assert.equal(usage.users.length, 1);
    assert.equal(usage.users[0].username, '42');
    assert(BigInt(usage.users[0].uplink) > 0n);
    assert(BigInt(usage.users[0].downlink) > 0n);
    await assertUsage(usage);
    await writeFile('/test/usage-snapshot.json', JSON.stringify(usage), { mode: 0o600 });
    assert.equal((await api('xray', 'start', cf)).status, 400);
    await assertRuntime(true);
    // Native Xray rejects this AFTER preflight, exercising real controller/core rollback.
    const invalid = structuredClone(fixture);
    invalid.xrayConfig.outbounds[0].protocol = 'not-a-real-protocol';
    assert.equal((await api('xray', 'start', invalid)).status, 500);
    await assertRuntime(true);
    // Ports move between cores; the old generations must release BOTH ports first.
    const swapped = structuredClone(fixture);
    swapped.xrayConfig.inbounds[0].port = 14001;
    swapped.anyTlsConfig.listeners[0].wrapperPort = 14443;
    swapped.edgePlan.routes[0].targetPort = 14001;
    swapped.edgePlan.routes[1].targetPort = 14443;
    await start(swapped);
    await assertRuntime(true);
    assert.deepEqual(JSON.parse(await read('edge/edge-plan.json')).routes, swapped.edgePlan.routes);
    await start();
    await assertRuntime(true);
    await assertUsage(usage);
    process.stdout.write(
        'PASS: authenticated joint API, native cores, CF rejection, failed-core rollback and cross-runtime port replacement\n',
    );
    process.stdout.write(
        'PASS: real encrypted Mihomo TCP over shared 443 produces durable non-reset per-user API counters\n',
    );
} else if (phase === 'reboot') {
    await assertUsage(JSON.parse(await read('usage-snapshot.json')));
    const status = await assertRuntime(false);
    assert.equal(status.desiredListeners, 1);
    assert.match(status.error, /Awaiting coordinated/);
    await start();
    await assertRuntime(true);
    const empty = structuredClone(fixture);
    empty.anyTlsConfig.listeners = [];
    empty.edgePlan.routes = [empty.edgePlan.routes[0]];
    await start(empty);
    assert.equal((await api('anytls', 'status')).body.response.desiredListeners, 0);
    assert.equal(await portOpen(14001), false);
    assert.equal(await portOpen(14443), true);
    assert.equal(JSON.parse(await read('edge/edge-plan.json')).routes.length, 1);
    const stopped = await api('xray', 'stop');
    assert.equal(stopped.body.response.isStopped, true);
    await assertRuntime(false);
    await assertUsage(JSON.parse(await read('usage-snapshot.json')));
    process.stdout.write(
        'PASS: reboot withdraws stale admission; explicit reconciliation, AnyTLS removal and joint stop succeed\n',
    );
} else {
    assert.equal((await assertRuntime(false)).desiredListeners, 0);
    await assertUsage(JSON.parse(await read('usage-snapshot.json')));
    process.stdout.write(
        'PASS: stopped joint generation is not revived by another full Agent restart\n',
    );
}
