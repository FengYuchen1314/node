/* eslint-disable no-console -- Standalone smoke-test progress, never credentials. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes, sign } from 'node:crypto';
import { once } from 'node:events';
import { readFile, writeFile, open } from 'node:fs/promises';
import { request } from 'node:https';
import { connect } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { connect as tlsConnect } from 'node:tls';

const dir = '/test';
const phase = process.argv[2];
const read = (name) => readFile(`${dir}/${name}`, 'utf8');
const save = (name, value) => writeFile(`${dir}/${name}`, JSON.stringify(value), { mode: 0o600 });
if (phase === 'setup') {
    const payload = {
        caCertPem: await read('certs/ca.crt'),
        nodeCertPem: await read('certs/server.crt'),
        nodeKeyPem: await read('certs/server.key'),
        jwtPublicKey: await read('certs/jwt.pub'),
    };
    await writeFile(
        `${dir}/agent.env`,
        [
            'NODE_PORT=28443',
            'MIERU_ENABLED=true',
            'NFTABLES_LOGGING=false',
            `SECRET_KEY=${Buffer.from(JSON.stringify(payload)).toString('base64')}`,
        ].join('\n') + '\n',
        { mode: 0o600 },
    );
    const users = ['1', '2', '3', 'shared'].map((name) => ({
        name,
        password: randomBytes(24).toString('hex'),
    }));
    await save('fixture.json', users);
    process.exit(0);
}
const users = JSON.parse(await read('fixture.json'));
const [alice, bob, replacement, shared] = users;
const ca = await read('certs/ca.crt');
const cert = await read('certs/client.crt');
const key = await read('certs/client.key');
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const unsigned = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ sub: 'smoke', exp: Math.floor(Date.now() / 1000) + 1800 })}`;
const jwt = `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), await read('certs/jwt.key')).toString('base64url')}`;

async function api(path, body, authorized = true) {
    return new Promise((resolve, reject) => {
        const req = request(
            {
                hostname: '127.0.0.1',
                port: 28443,
                path: `/node/${path}`,
                method: body === undefined ? 'GET' : 'POST',
                ca,
                cert,
                key,
                timeout: 10_000,
                headers: {
                    ...(authorized ? { Authorization: `Bearer ${jwt}` } : {}),
                    'Content-Type': 'application/json',
                },
            },
            (res) => {
                let text = '';
                res.on('data', (chunk) => {
                    text += chunk;
                });
                res.once('error', reject);
                res.once('end', () => {
                    try {
                        resolve({ status: res.statusCode, value: JSON.parse(text) });
                    } catch {
                        reject(new Error(`Non-JSON Agent reply (${res.statusCode})`));
                    }
                });
            },
        );
        req.once('error', reject);
        req.once('timeout', () => req.destroy(new Error('Agent API timeout')));
        req.end(body === undefined ? undefined : JSON.stringify(body));
    });
}
async function ready() {
    for (let i = 0; i < 90; i++) {
        const result = await api('mieru/status').catch(() => null);
        if (result?.status === 200 && result.value.response?.isAvailable)
            return result.value.response;
        await delay(500);
    }
    throw new Error('Agent did not become ready');
}
const config = (firstUsers, both = true) => ({
    kind: 'ISOLATED_LISTENERS',
    instances: [
        {
            id: '11111111-1111-4111-8111-111111111111',
            config: {
                portBindings: [{ port: 24443, protocol: 'TCP' }],
                users: firstUsers,
                loggingLevel: 'ERROR',
            },
        },
        ...(both
            ? [
                  {
                      id: '22222222-2222-4222-8222-222222222222',
                      config: {
                          portBindings: [{ port: 25443, protocol: 'TCP' }],
                          users: [bob, shared],
                          loggingLevel: 'ERROR',
                      },
                  },
              ]
            : []),
    ],
});
async function apply(value) {
    const result = await api('mieru/start', { config: value });
    assert.equal(result.status, 201);
    assert.equal(
        result.value.response.isStarted,
        true,
        result.value.response.error ?? 'Agent did not start',
    );
}
async function stats(reset) {
    const result = await api('stats/get-users-stats', { reset });
    assert.equal(result.status, 201);
    assert.ok(Array.isArray(result.value.response.users));
    return result.value.response.users;
}
async function socketOpen(port) {
    const socket = connect({ host: '127.0.0.1', port });
    socket.setTimeout(1_000, () => socket.destroy(new Error('TCP timeout')));
    try {
        await once(socket, 'connect');
        return true;
    } catch {
        return false;
    } finally {
        socket.destroy();
    }
}

// Real upstream Mieru client, one disposable process per credential/port pair.
async function proxy(user, port, expected) {
    const filename = `${dir}/client.json`;
    await writeFile(
        filename,
        JSON.stringify({
            profiles: [
                {
                    profileName: 'smoke',
                    user,
                    servers: [
                        { ipAddress: '127.0.0.1', portBindings: [{ port, protocol: 'TCP' }] },
                    ],
                },
            ],
            activeProfile: 'smoke',
            socks5Port: 10880,
            socks5ListenLAN: false,
            loggingLevel: 'ERROR',
            advancedSettings: { noCheckUpdate: true },
        }),
        { mode: 0o600 },
    );
    const log = await open(`${dir}/client.log`, 'a', 0o600);
    const child = spawn(`${dir}/bin/mieru`, ['run'], {
        env: { ...process.env, MIERU_CONFIG_JSON_FILE: filename },
        stdio: ['ignore', log.fd, log.fd],
    });
    const exited = once(child, 'exit');
    try {
        let listening = false;
        for (let i = 0; i < 60 && child.exitCode === null; i++) {
            if (await socketOpen(10880)) {
                listening = true;
                break;
            }
            await delay(100);
        }
        assert.ok(listening, 'Mieru client failed to start (see private client.log)');
        if (expected) await throughSocks();
        else
            await assert.rejects(
                throughSocks,
                'Credential unexpectedly crossed listener permissions',
            );
    } finally {
        child.kill('SIGTERM');
        const timer = setTimeout(() => child.kill('SIGKILL'), 3_000);
        await exited;
        clearTimeout(timer);
        await log.close();
    }
}
async function throughSocks() {
    const socket = connect({ host: '127.0.0.1', port: 10880 });
    // Handle both handshake and TLS errors without unhandled events.
    socket.on('error', () => {});
    const timer = setTimeout(() => socket.destroy(new Error('Proxy handshake timed out')), 7_000);
    let tls;
    try {
        await once(socket, 'connect');
        const take = async (n) => {
            let value;
            while ((value = socket.read(n)) === null) {
                if (socket.destroyed || socket.readableEnded)
                    throw new Error('SOCKS connection ended');
                await once(socket, 'readable');
            }
            return value;
        };
        socket.write(Buffer.from([5, 1, 0]));
        assert.deepEqual(await take(2), Buffer.from([5, 0]));
        const domain = Buffer.from('example.com');
        socket.write(
            Buffer.concat([
                Buffer.from([5, 1, 0, 3, domain.length]),
                domain,
                Buffer.from([1, 187]),
            ]),
        );
        const reply = await take(4);
        assert.equal(reply[1], 0, 'SOCKS rejected the destination');
        const size = reply[3] === 1 ? 4 : reply[3] === 4 ? 16 : (await take(1))[0];
        await take(size + 2);
        clearTimeout(timer);
        tls = tlsConnect({ socket, servername: 'example.com', rejectUnauthorized: true });
        tls.setTimeout(10_000, () => tls.destroy(new Error('HTTPS probe timed out')));
        await once(tls, 'secureConnect');
        tls.write('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n');
        let response = '';
        for await (const chunk of tls) {
            response += chunk;
            if (response.length > 262144) throw new Error('Unexpectedly large probe response');
        }
        assert.match(response, /^HTTP\/1\.[01] 200 /);
    } finally {
        clearTimeout(timer);
        tls?.destroy();
        socket.destroy();
    }
}

const current = await ready();
// The upstream guard deliberately destroys unauthorized sockets instead of
// exposing a normal HTTP response; preserve and verify that behavior.
await assert.rejects(api('mieru/status', undefined, false), { code: 'ECONNRESET' });
if (phase === 'initial') {
    await apply(config([alice, shared]));
    // The first poll establishes the migration-safe baseline; exercise transfer
    // deltas after initialization, rather than treating historical totals as new.
    await stats(true);
    await proxy(alice, 24443, true);
    await proxy(bob, 25443, true);
    await proxy(shared, 24443, true);
    await proxy(shared, 25443, true);
    await proxy(alice, 25443, false);
    await proxy(bob, 24443, false);
    const before = await stats(true);
    for (const user of [alice, bob, shared]) {
        const records = before.filter((record) => record.username === user.name);
        assert.equal(records.length, 1, 'Accounting must aggregate each logical user exactly once');
        assert.ok(records[0].uplink > 0 && records[0].downlink > 0);
    }
    console.log(
        'PASS: mTLS/JWT, two real listeners, cross-credential rejection, shared-user accounting',
    );
    await apply(config([replacement], false));
    assert.equal(await socketOpen(25443), false);
    await proxy(alice, 24443, false);
    await proxy(replacement, 24443, true);
    await stats(true);
    console.log('PASS: user revocation and deleted-listener shutdown');
} else if (phase === 'restored') {
    assert.equal(current.state, 'RUNNING');
    assert.equal(await socketOpen(25443), false);
    // Baselines survive Agent restart; do not report old transfer again.
    const repeated = await stats(true);
    assert.equal(repeated.length, 0, 'Already billed traffic was reported again after restart');
    await proxy(replacement, 24443, true);
    const fresh = await stats(true);
    assert.ok(fresh.some((record) => record.username === replacement.name && record.downlink > 0));
    const stopped = await api('mieru/stop');
    assert.equal(stopped.value.response.isStopped, true);
    assert.equal(await socketOpen(24443), false);
    console.log(
        'PASS: desired config restored, billing baselines persisted, explicit stop confirmed',
    );
} else if (phase === 'stopped') {
    assert.equal(current.state, 'IDLE');
    assert.equal(await socketOpen(24443), false);
    assert.equal(await socketOpen(25443), false);
    console.log('PASS: explicitly stopped listeners do not revive after Agent restart');
} else throw new Error('Unknown smoke phase');
