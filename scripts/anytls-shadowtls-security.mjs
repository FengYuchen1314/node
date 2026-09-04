// Security proof only: not a managed Agent runtime or a production subscription generator.
// Runs the unmodified, pinned Mihomo binary at both ends on isolated loopback fixtures.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import { connect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { createServer as createTlsServer } from 'node:tls';

const binary = process.env.RW_MIHOMO_BINARY;
const certDir = process.env.RW_ANYTLS_CERT_DIR;
assert(binary && certDir, 'Provide RW_MIHOMO_BINARY and fresh RW_ANYTLS_CERT_DIR fixtures');
assert.equal(process.platform, 'linux');
const baseConfig = {
    mode: 'rule',
    'log-level': 'info',
    ipv6: false,
    'geo-auto-update': false,
    profile: { 'store-selected': false, 'store-fake-ip': false },
    dns: { enable: false },
    sniffer: { enable: false },
    rules: ['MATCH,REJECT'],
};

class Reader {
    data = Buffer.alloc(0);
    ended = false;
    error = null;
    wake = null;

    constructor(socket) {
        socket.on('data', (chunk) => {
            this.data = Buffer.concat([this.data, chunk]);
            if (this.data.length > 2 ** 20) socket.destroy(new Error('Fixture response too large'));
            this.wake?.();
        });
        socket.on('error', (error) => {
            this.error = error;
            this.wake?.();
        });
        socket.on('close', () => {
            this.ended = true;
            this.wake?.();
        });
    }

    async take(length) {
        while (this.data.length < length) {
            if (this.error) throw this.error;
            if (this.ended) throw new Error('Connection closed before expected bytes');
            await new Promise((resolve) => {
                this.wake = resolve;
            });
        }
        const result = this.data.subarray(0, length);
        this.data = this.data.subarray(length);
        return result;
    }

    async rest() {
        while (!this.ended && !this.error) {
            await new Promise((resolve) => {
                this.wake = resolve;
            });
        }
        if (this.error) throw this.error;
        return this.data.toString('utf8');
    }
}

async function request(socksPort, destinationPort, marker, host = '127.0.0.1') {
    const socket = connect({ host: '127.0.0.1', port: socksPort });
    const reader = new Reader(socket);
    const timer = setTimeout(() => socket.destroy(new Error('Fixture request deadline')), 6000);
    try {
        await once(socket, 'connect');
        socket.write(Buffer.from([5, 1, 0]));
        assert.deepEqual(await reader.take(2), Buffer.from([5, 0]));
        const address = Buffer.from(host);
        const port = Buffer.alloc(2);
        port.writeUInt16BE(destinationPort);
        socket.write(Buffer.concat([Buffer.from([5, 1, 0, 3, address.length]), address, port]));
        const reply = await reader.take(4);
        assert.equal(reply[1], 0, 'SOCKS request rejected');
        if (reply[3] === 1) await reader.take(4);
        else if (reply[3] === 4) await reader.take(16);
        else if (reply[3] === 3) await reader.take((await reader.take(1))[0]);
        else throw new Error('Invalid SOCKS reply');
        await reader.take(2);
        // Repetition crosses AnyTLS frames and TCP segments, making the positive control robust.
        const body = marker.repeat(512);
        socket.write(
            `POST /fixture HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
        );
        return await reader.rest();
    } finally {
        clearTimeout(timer);
        socket.destroy();
    }
}

test(
    'Mihomo AnyTLS / ShadowTLS confidentiality and fail-closed proof',
    { timeout: 180000 },
    async (t) => {
        const taskDir = await mkdtemp(join(tmpdir(), 'rw-anytls-security-'));
        const processes = new Set();
        const sockets = new Set();
        const servers = new Set();
        const logs = [];
        const track = (socket) => {
            sockets.add(socket);
            socket.on('error', () => {});
            socket.on('close', () => sockets.delete(socket));
            return socket;
        };
        async function listen(server) {
            servers.add(server);
            server.on('connection', track);
            server.listen(0, '127.0.0.1');
            await once(server, 'listening');
            return server.address().port;
        }
        async function reservePort() {
            const server = createServer();
            const port = await listen(server);
            await new Promise((resolve) => server.close(resolve));
            servers.delete(server);
            return port;
        }
        async function stop(child) {
            if (!processes.has(child)) return;
            const exited = once(child, 'exit');
            child.kill('SIGTERM');
            const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
            await exited;
            clearTimeout(timer);
            processes.delete(child);
        }
        async function start(name, config, ports) {
            const dir = join(taskDir, name);
            await mkdir(dir, { mode: 0o700 });
            const path = join(dir, 'config.json');
            await writeFile(path, JSON.stringify(config), { mode: 0o600 });
            const checked = spawnSync(binary, ['-t', '-d', dir, '-f', path], {
                encoding: 'utf8',
                timeout: 15000,
            });
            assert.equal(
                checked.status,
                0,
                `${name} native configuration check failed: ${checked.stderr}${checked.stdout}`,
            );
            const child = spawn(binary, ['-d', dir, '-f', path], {
                stdio: ['ignore', 'pipe', 'pipe'],
            });
            processes.add(child);
            child.on('exit', () => processes.delete(child));
            let output = '';
            for (const stream of [child.stdout, child.stderr])
                stream.on('data', (chunk) => {
                    output = (output + chunk.toString()).slice(-12000);
                });
            logs.push(() => `${name}: ${output}`);
            child.on('error', () => {});
            const deadline = Date.now() + 12000;
            for (const port of ports) {
                while (true) {
                    assert(processes.has(child), `${name} stopped unexpectedly: ${output}`);
                    try {
                        const socket = track(connect(port, '127.0.0.1'));
                        await once(socket, 'connect');
                        socket.destroy();
                        break;
                    } catch {
                        assert(Date.now() < deadline, `${name} did not listen: ${output}`);
                        await delay(50);
                    }
                }
            }
            return child;
        }

        try {
            const [ca, camouflageCert, camouflageKey, innerCert, innerKey] = await Promise.all(
                ['ca.crt', 'camouflage.crt', 'camouflage.key', 'inner.crt', 'inner.key'].map(
                    (file) => readFile(join(certDir, file), 'utf8'),
                ),
            );
            // Pin the CA, not the leaf: Mihomo validates the chain, expiry and DNS name for a CA pin.
            const fingerprint = new X509Certificate(ca).fingerprint256.replaceAll(':', '');
            const camouflage = createTlsServer(
                {
                    cert: camouflageCert,
                    key: camouflageKey,
                    minVersion: 'TLSv1.3',
                    maxVersion: 'TLSv1.3',
                },
                (socket) => {
                    track(socket);
                    socket.on('data', () =>
                        socket.end(
                            'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK',
                        ),
                    );
                },
            );
            camouflage.on('tlsClientError', () => {});
            const camouflagePort = await listen(camouflage);
            const requests = [];
            const responseMarker = `RESPONSE-${randomBytes(24).toString('hex')}`;
            const targetPort = await listen(
                createHttpServer((req, res) => {
                    let body = '';
                    req.on('data', (chunk) => {
                        body += chunk;
                        if (body.length > 100000) req.destroy();
                    });
                    req.on('end', () => {
                        requests.push(body);
                        res.writeHead(200, { 'Content-Type': 'text/plain', Connection: 'close' });
                        res.end(responseMarker.repeat(512));
                    });
                }),
            );
            const innerPort = await reservePort();
            const outerPort = await reservePort();
            const controlPort = await reservePort();
            const outerPassword = randomBytes(24).toString('hex');
            const innerPassword = randomBytes(24).toString('hex');
            const shadowPassword = randomBytes(24).toString('hex');
            const shadowListener = (name, port, rule) => ({
                name,
                type: 'anytls',
                listen: '127.0.0.1',
                port,
                rule,
                users: { wrapper: outerPassword },
                'shadow-tls': {
                    enable: true,
                    version: 3,
                    'strict-mode': true,
                    users: [{ name: 'wrapper', password: shadowPassword }],
                    // The built-in handshake dialer otherwise follows the global reject rule.
                    handshake: { dest: `127.0.0.1:${camouflagePort}`, proxy: 'DIRECT' },
                },
            });
            const exactTcpTarget = (port) =>
                `AND,((NETWORK,TCP),(IP-CIDR,127.0.0.1/32),(DST-PORT,${port})),DIRECT`;
            // Separate logical runtimes: the inner egress is not an accidental loop back into
            // the outer process. Do not disable Mihomo's loopback protection to make this pass.
            await start(
                'inner-server',
                {
                    ...baseConfig,
                    listeners: [
                        {
                            name: 'inner',
                            type: 'anytls',
                            listen: '127.0.0.1',
                            port: innerPort,
                            rule: 'inner-only-fixture',
                            users: { subscriber: innerPassword },
                            certificate: innerCert,
                            'private-key': innerKey,
                        },
                    ],
                    'sub-rules': {
                        'inner-only-fixture': [exactTcpTarget(targetPort), 'MATCH,REJECT'],
                    },
                },
                [innerPort],
            );
            await start(
                'outer-server',
                {
                    ...baseConfig,
                    listeners: [
                        shadowListener('outer', outerPort, 'outer-only-inner'),
                        // Deliberately unencrypted, isolated positive control. Never ship this listener.
                        shadowListener('insecure-control', controlPort, 'inner-only-fixture'),
                    ],
                    'sub-rules': {
                        'outer-only-inner': [exactTcpTarget(innerPort), 'MATCH,REJECT'],
                        'inner-only-fixture': [exactTcpTarget(targetPort), 'MATCH,REJECT'],
                    },
                },
                [outerPort, controlPort],
            );

            let capture = [];
            let capturedBytes = 0;
            let tapTarget = outerPort;
            const tapPort = await listen(
                createServer((downstream) => {
                    const upstream = track(connect(tapTarget, '127.0.0.1'));
                    const connection = { upload: [], download: [] };
                    capture.push(connection);
                    const collect = (key, chunk) => {
                        capturedBytes += chunk.length;
                        if (capturedBytes > 8 * 2 ** 20)
                            return downstream.destroy(new Error('Wire capture limit'));
                        connection[key].push(Buffer.from(chunk));
                    };
                    downstream.on('data', (chunk) => collect('upload', chunk));
                    upstream.on('data', (chunk) => collect('download', chunk));
                    downstream.on('error', () => upstream.destroy());
                    upstream.on('error', () => downstream.destroy());
                    downstream.pipe(upstream);
                    upstream.pipe(downstream);
                }),
            );
            const wireContains = (marker, direction) =>
                capture.some((connection) =>
                    Buffer.concat(connection[direction]).includes(Buffer.from(marker)),
                );
            async function clientCase(name, options = {}) {
                capture = [];
                capturedBytes = 0;
                tapTarget = options.control ? controlPort : outerPort;
                const port = await reservePort();
                const wrapper = {
                    name: 'private-wrapper',
                    type: 'anytls',
                    server: '127.0.0.1',
                    port: tapPort,
                    password: outerPassword,
                    sni: 'camouflage.test',
                    fingerprint,
                    'skip-cert-verify': false,
                    'client-fingerprint': 'chrome',
                    'shadow-tls-opts': { version: 3, password: shadowPassword },
                    ...options.wrapper,
                };
                const inner = {
                    name: 'visible-node',
                    type: 'anytls',
                    server: '127.0.0.1',
                    port: innerPort,
                    password: innerPassword,
                    sni: 'inner.test',
                    fingerprint,
                    'skip-cert-verify': false,
                    'dialer-proxy': 'private-wrapper',
                    ...options.inner,
                };
                const child = await start(
                    name,
                    {
                        ...baseConfig,
                        'socks-port': port,
                        'bind-address': '127.0.0.1',
                        proxies: options.wrapperOnly ? [wrapper] : [wrapper, inner],
                        rules: [
                            `MATCH,${options.wrapperOnly ? 'private-wrapper' : 'visible-node'}`,
                        ],
                    },
                    [port],
                );
                const marker = `REQUEST-${randomBytes(24).toString('hex')}`;
                const before = requests.length;
                let response = '';
                try {
                    response = await request(port, targetPort, marker, options.host);
                } catch (error) {
                    if (!options.deny) {
                        t.diagnostic(logs.map((get) => get()).join('\n'));
                        throw error;
                    }
                } finally {
                    await stop(child);
                }
                if (options.deny) {
                    assert(
                        !response.includes(responseMarker),
                        `${name}: rejected path reached application`,
                    );
                    assert.equal(
                        requests.length,
                        before,
                        `${name}: rejected path leaked an HTTP request`,
                    );
                } else {
                    assert.match(response, /^HTTP\/1\.1 200 /);
                    assert(response.includes(responseMarker));
                    assert.equal(requests.length, before + 1);
                    assert(requests.at(-1).includes(marker));
                    assert(capturedBytes > 1000, 'Wire capture must observe the real path');
                    assert.equal(
                        wireContains(marker, 'upload'),
                        !!options.control,
                        'Unexpected upload confidentiality',
                    );
                    assert.equal(
                        wireContains(responseMarker, 'download'),
                        !!options.control,
                        'Unexpected download confidentiality',
                    );
                }
            }

            await t.test(
                'positive control exposes plaintext in native inline AnyTLS + ShadowTLS',
                () => clientCase('control', { control: true, wrapperOnly: true }),
            );
            await t.test(
                'verified inner TLS encrypts both directions through native Mihomo ShadowTLS',
                () => clientCase('encrypted'),
            );
            await t.test('wrong inner CA pin fails closed', () =>
                clientCase('wrong-inner-pin', {
                    deny: true,
                    inner: { fingerprint: 'ab'.repeat(32) },
                }),
            );
            await t.test('wrong inner certificate name fails closed', () =>
                clientCase('wrong-inner-name', { deny: true, inner: { sni: 'wrong.test' } }),
            );
            await t.test('wrong inner AnyTLS password fails closed', () =>
                clientCase('wrong-inner-password', {
                    deny: true,
                    inner: { password: randomBytes(24).toString('hex') },
                }),
            );
            await t.test('wrong ShadowTLS password fails closed', () =>
                clientCase('wrong-shadow-password', {
                    deny: true,
                    wrapper: {
                        'shadow-tls-opts': {
                            version: 3,
                            password: randomBytes(24).toString('hex'),
                        },
                    },
                }),
            );
            await t.test('wrong outer certificate CA pin fails closed', () =>
                clientCase('wrong-outer-pin', {
                    deny: true,
                    wrapper: { fingerprint: 'cd'.repeat(32) },
                }),
            );
            await t.test('wrapper alone cannot bypass inner encryption', () =>
                clientCase('wrapper-bypass', { deny: true, wrapperOnly: true }),
            );
            await t.test('wrapper hostname cannot bypass the destination-port restriction', () =>
                clientCase('hostname-bypass', { deny: true, wrapperOnly: true, host: 'localhost' }),
            );
            // Recheck the same server after rejected attempts, with fresh sessions.
            await t.test('valid encrypted path still works after rejected attempts', () =>
                clientCase('encrypted-again'),
            );
        } catch (error) {
            // Runtime logs contain only randomly generated fixture identities, never real subscriber data.
            t.diagnostic(logs.map((get) => get()).join('\n'));
            throw error;
        } finally {
            await Promise.all([...processes].map(stop));
            for (const socket of sockets) socket.destroy();
            await Promise.all(
                [...servers].map((server) => new Promise((resolve) => server.close(resolve))),
            );
            // Only the exact mkdtemp directory owned by this test is removed.
            await rm(taskDir, { recursive: true, force: true });
        }
    },
);
