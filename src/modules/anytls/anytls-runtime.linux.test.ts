import assert from 'node:assert/strict';
import { spawn, ChildProcess } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import { connect, createServer, Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { createServer as createTlsServer } from 'node:tls';

import { TypedConfigService } from '@common/config/app-config';
import { TAnyTlsConfig } from '@libs/contracts/models';

import { AnyTlsConfigRenderer, AnyTlsRenderOptions, validateAnyTlsConfig } from './anytls-config';
import { AnyTlsRuntimeIO } from './anytls-runtime.io';
import { AnyTlsRuntimeService } from './anytls-runtime.service';
import { AnyTlsRuntimeStore, privateJson } from './anytls-runtime.store';
import { AnyTlsStatsClient } from './anytls-stats.client';

test(
    'managed AnyTLS runtime: native clients, listener isolation, accounting, rollback and restart',
    {
        skip: process.platform !== 'linux' || process.env.RW_ANYTLS_RUNTIME_INTEGRATION !== '1',
        timeout: 150000,
    },
    async (t) => {
        const directory = await mkdtemp(join(tmpdir(), 'rw-anytls-managed-'));
        const [ca, certificate, key, camouflageCert, camouflageKey] = await Promise.all(
            ['ca.crt', 'inner.crt', 'inner.key', 'camouflage.crt', 'camouflage.key'].map((file) =>
                readFile(join(process.env.RW_ANYTLS_CERT_DIR!, file), 'utf8'),
            ),
        );
        const fingerprint = new X509Certificate(ca).fingerprint256.replaceAll(':', '');
        const sockets = new Set<Socket>();
        const clients = new Set<ChildProcess>();
        const services: AnyTlsRuntimeService[] = [];
        const keep = (socket: Socket) => {
            sockets.add(socket);
            socket.on('error', () => {});
            socket.on('close', () => sockets.delete(socket));
            return socket;
        };
        const responseBody = 'managed-runtime-response-'.repeat(100);
        let receivedRequests = 0;
        let finishedResponses = 0;
        const target = createHttpServer((request, response) => {
            receivedRequests++;
            response.once('finish', () => finishedResponses++);
            request.resume();
            request.on('end', () => {
                response.writeHead(200, {
                    'Content-Length': Buffer.byteLength(responseBody),
                    Connection: 'close',
                });
                response.end(responseBody);
            });
        });
        target.on('connection', keep);
        const targetPort = await listen(target);
        const camouflage = createTlsServer(
            {
                cert: camouflageCert,
                key: camouflageKey,
                minVersion: 'TLSv1.3',
                maxVersion: 'TLSv1.3',
            },
            (socket) => {
                keep(socket);
                socket.on('data', () =>
                    socket.end(
                        'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK',
                    ),
                );
            },
        );
        camouflage.on('connection', keep);
        camouflage.on('tlsClientError', () => {});
        const camouflagePort = await listen(camouflage);
        // The production renderer denies private egress. The test seam permits one owned HTTP fixture
        // before those rules; it is not configurable through the Agent API or persisted desired state.
        class FixtureRenderer extends AnyTlsConfigRenderer {
            override render(input: unknown, options: AnyTlsRenderOptions) {
                const rendered = super.render(input, options);
                (rendered.inner.route as { rules: unknown[] }).rules.unshift({
                    ip_cidr: ['127.0.0.1/32'],
                    port: [targetPort],
                    action: 'route',
                    outbound: 'anytls-egress',
                });
                return rendered;
            }
        }
        const ports = new Set<number>([targetPort, camouflagePort]);
        const allocate = async () => {
            let port: number;
            do {
                port = await unusedPort();
            } while (ports.has(port));
            ports.add(port);
            return port;
        };
        const values = {
            ANYTLS_ENABLED: true,
            ANYTLS_STATE_DIR: join(directory, 'state'),
            ANYTLS_STATS_PORT: await allocate(),
            ANYTLS_CONTROL_PORT: await allocate(),
            NODE_PORT: await allocate(),
            ANYTLS_MIHOMO_PATH: process.env.RW_MIHOMO_BINARY,
            ANYTLS_SINGBOX_PATH: process.env.RW_ANYTLS_INNER_BINARY,
            ANYTLS_SUPERVISOR_PATH: process.env.RW_ANYTLS_SUPERVISOR_BINARY,
        };
        const env = {
            getOrThrow: (key: keyof typeof values) => {
                assert.notEqual(values[key], undefined);
                return values[key];
            },
        } as unknown as TypedConfigService;
        const config: TAnyTlsConfig = { version: 1, listeners: [] };
        for (const [id, tag, sni, user, secret] of [
            ['11111111-1111-4111-8111-111111111111', 'A', 'camouflage.test', 'alice', 'a'],
            ['22222222-2222-4222-8222-222222222222', 'B', 'camouflage-alt.test', 'bob', 'b'],
        ])
            config.listeners.push({
                id,
                tag,
                wrapperPort: await allocate(),
                innerPort: await allocate(),
                camouflage: { serverName: sni, address: '127.0.0.1', port: camouflagePort },
                wrapperPassword: `wrapper-${secret.repeat(48)}`,
                shadowPassword: `shadow-${secret.repeat(48)}`,
                tls: { serverName: 'inner.test', certificate, privateKey: key, caCertificate: ca },
                users: [
                    { name: user, password: secret.repeat(48) },
                    { name: 'shared', password: 's'.repeat(48) },
                ],
            });
        const makeRuntime = () => {
            const renderer = new FixtureRenderer();
            const io = new AnyTlsRuntimeIO(env, renderer, new AnyTlsStatsClient());
            const store = new AnyTlsRuntimeStore(env);
            const runtime = new AnyTlsRuntimeService(env, io, store);
            services.push(runtime);
            return { runtime, io, store };
        };
        async function client(
            index: number,
            password: string,
            target = targetPort,
        ): Promise<string> {
            const listener = config.listeners[index];
            const beforeRequests = receivedRequests;
            const beforeResponses = finishedResponses;
            const socksPort = await allocate();
            const path = join(directory, `client-${socksPort}`, 'client.json');
            await privateJson(path, {
                mode: 'rule',
                'log-level': 'warning',
                'socks-port': socksPort,
                'bind-address': '127.0.0.1',
                'geo-auto-update': false,
                dns: { enable: false },
                proxies: [
                    {
                        name: 'wrapper',
                        type: 'anytls',
                        server: '127.0.0.1',
                        port: listener.wrapperPort,
                        password: listener.wrapperPassword,
                        sni: listener.camouflage.serverName,
                        fingerprint,
                        'shadow-tls-opts': { version: 3, password: listener.shadowPassword },
                        'skip-cert-verify': false,
                    },
                    {
                        name: 'node',
                        type: 'anytls',
                        server: '127.0.0.1',
                        port: listener.innerPort,
                        password,
                        sni: 'inner.test',
                        fingerprint,
                        'dialer-proxy': 'wrapper',
                        'skip-cert-verify': false,
                    },
                ],
                rules: ['MATCH,node'],
            });
            const child = spawn(
                process.env.RW_MIHOMO_BINARY!,
                ['-d', join(directory, `client-${socksPort}`), '-f', path],
                { stdio: ['ignore', 'pipe', 'pipe'] },
            );
            clients.add(child);
            let output = '';
            child.stderr?.on('data', (data) => {
                output = (output + String(data)).slice(-4096);
            });
            child.stdout?.on('data', (data) => {
                output = (output + String(data)).slice(-4096);
            });
            try {
                await waitPort(socksPort, child);
                return await socksHttp(socksPort, target);
            } catch (error) {
                if (
                    target === targetPort &&
                    listener.users.some((user) => user.password === password)
                ) {
                    t.diagnostic(
                        `listener=${listener.tag} fixtureRequests=${receivedRequests - beforeRequests} fixtureResponses=${finishedResponses - beforeResponses}`,
                    );
                    t.diagnostic(output);
                }
                throw error;
            } finally {
                await stopChild(child);
                clients.delete(child);
            }
        }
        t.after(async () => {
            for (const child of clients) await stopChild(child);
            for (const runtime of services) await runtime.onModuleDestroy().catch(() => undefined);
            for (const socket of sockets) socket.destroy();
            await Promise.all(
                [target, camouflage].map(
                    (server) => new Promise<void>((resolve) => server.close(() => resolve())),
                ),
            );
            await rm(directory, { recursive: true, force: true });
        });
        const first = makeRuntime();
        await first.runtime.onModuleInit();
        const generations = async () =>
            (await readdir(values.ANYTLS_STATE_DIR)).filter((name) =>
                name.startsWith('generation-'),
            );
        await t.test(
            'native config rejects wrong TLS identity, loops and control port overlap before starting',
            async () => {
                const options = {
                    statsPort: values.ANYTLS_STATS_PORT,
                    controlPort: values.ANYTLS_CONTROL_PORT,
                    nodePort: values.NODE_PORT,
                    controlSecret: 'test',
                };
                assert.doesNotThrow(() => validateAnyTlsConfig(config, options));
                for (const mutate of [
                    (input: TAnyTlsConfig) => {
                        input.listeners[0].tls.serverName = 'wrong.test';
                    },
                    (input: TAnyTlsConfig) => {
                        input.listeners[0].camouflage.port = input.listeners[0].innerPort;
                    },
                    (input: TAnyTlsConfig) => {
                        input.listeners[0].camouflage.address = '::ffff:7f00:1';
                        input.listeners[0].camouflage.port = input.listeners[0].innerPort;
                    },
                    (input: TAnyTlsConfig) => {
                        input.listeners[0].innerPort = values.ANYTLS_STATS_PORT;
                    },
                ]) {
                    const input = structuredClone(config);
                    mutate(input);
                    await assert.rejects(first.runtime.apply(input));
                    assert.equal(first.io.isRunning(), false);
                }
            },
        );
        await t.test(
            'two managed listeners accept only their authorized users and aggregate a shared user',
            async () => {
                assert.equal((await first.runtime.apply(config)).isStarted, true);
                const activeFiles = await generations();
                assert.equal(activeFiles.length, 1);
                assert.equal((await first.runtime.apply(config)).operation, 'UNCHANGED');
                assert.deepEqual(await generations(), activeFiles);
                assert((await client(0, 'a'.repeat(48))).includes(responseBody));
                assert((await client(1, 'b'.repeat(48))).includes(responseBody));
                await assert.rejects(client(0, 'b'.repeat(48)));
                await assert.rejects(client(1, 'a'.repeat(48)));
                assert((await client(0, 's'.repeat(48))).includes(responseBody));
                assert((await client(1, 's'.repeat(48))).includes(responseBody));
                const users = await first.runtime.users(true);
                assert.deepEqual(users.map((user) => user.username).sort(), [
                    'alice',
                    'bob',
                    'shared',
                ]);
                assert(
                    users.find((user) => user.username === 'shared')!.downlink >=
                        2 * Buffer.byteLength(responseBody),
                );
                assert.deepEqual(await first.runtime.users(true), []);
            },
        );
        await t.test(
            'short HTTP responses survive immediate target close across fresh sessions',
            async () => {
                // No retries: exercise the CI-observed empty-response case without delaying target FIN.
                for (let attempt = 0; attempt < 12; attempt++) {
                    const response = await client(attempt % 2, 's'.repeat(48));
                    assert.equal(response.slice(response.indexOf('\r\n\r\n') + 4), responseBody);
                }
                await first.runtime.users(true);
            },
        );
        await t.test(
            'authenticated users cannot access the local control or statistics service',
            async () => {
                await assert.rejects(client(0, 'a'.repeat(48), values.ANYTLS_CONTROL_PORT));
                await assert.rejects(client(0, 'a'.repeat(48), values.ANYTLS_STATS_PORT));
                assert.equal(first.io.isRunning(), true);
            },
        );
        await t.test(
            'occupied port update restores the prior runtime and keeps counters',
            async () => {
                const collision = createServer();
                const occupied = await listen(collision);
                try {
                    const invalid = structuredClone(config);
                    invalid.listeners[0].wrapperPort = occupied;
                    await assert.rejects(first.runtime.apply(invalid), /restored/);
                } finally {
                    await new Promise<void>((resolve) => collision.close(() => resolve()));
                }
                assert((await client(0, 'a'.repeat(48))).includes(responseBody));
                await first.runtime.users(true);
                assert.equal((await generations()).length, 1);
            },
        );
        await t.test(
            'removing a user and listener revokes access without losing retired counters',
            async () => {
                const reduced = structuredClone(config);
                reduced.listeners = [reduced.listeners[0]];
                reduced.listeners[0].users = [{ name: 'shared', password: 's'.repeat(48) }];
                await first.runtime.apply(reduced);
                assert.equal((await generations()).length, 1);
                await assert.rejects(client(0, 'a'.repeat(48)));
                await assert.rejects(client(1, 'b'.repeat(48)));
                assert((await client(0, 's'.repeat(48))).includes(responseBody));
                const billed = await first.runtime.users(true);
                assert(billed.some((user) => user.username === 'shared' && user.downlink > 0));
            },
        );
        await t.test(
            'Agent restart restores desired state without replaying billed traffic; explicit stop stays stopped',
            async () => {
                await first.runtime.onModuleDestroy();
                assert.deepEqual(await generations(), []);
                const second = makeRuntime();
                await second.runtime.onModuleInit();
                assert.equal((await second.runtime.status()).isStarted, true);
                assert.deepEqual(await second.runtime.users(true), []);
                assert((await client(0, 's'.repeat(48))).includes(responseBody));
                assert((await second.runtime.users(true)).some((user) => user.downlink > 0));
                await second.runtime.stop();
                assert.deepEqual(await generations(), []);
                await second.runtime.onModuleDestroy();
                const third = makeRuntime();
                await third.runtime.onModuleInit();
                assert.equal((await third.runtime.status()).isStarted, false);
                assert.equal((await third.store.load()).desired, null);
            },
        );
    },
);

test(
    'supervisor stops its exact core after parent EOF or a supervisor SIGKILL',
    {
        skip: process.platform !== 'linux' || process.env.RW_ANYTLS_RUNTIME_INTEGRATION !== '1',
        timeout: 30000,
    },
    async () => {
        for (const killSupervisor of [false, true]) {
            const port = await unusedPort();
            const core = `require('node:net').createServer().listen(${port}, '127.0.0.1')`;
            const binary = process.env.RW_ANYTLS_SUPERVISOR_BINARY!;
            const parentCode = `const {spawn}=require('node:child_process'); const child=spawn(${JSON.stringify(binary)}, ['--binary',process.execPath,'--','-e',${JSON.stringify(core)}], {stdio:['pipe','ignore','ignore']}); child.on('exit',()=>process.exit());`;
            const parent = killSupervisor
                ? spawn(binary, ['--binary', process.execPath, '--', '-e', core], {
                      stdio: ['pipe', 'ignore', 'ignore'],
                  })
                : spawn(process.execPath, ['-e', parentCode], {
                      stdio: ['pipe', 'ignore', 'ignore'],
                  });
            try {
                await waitPort(port, parent);
                const exited = once(parent, 'exit');
                parent.kill('SIGKILL');
                await exited;
                const deadline = Date.now() + 7000;
                while (true) {
                    const socket = connect(port, '127.0.0.1');
                    try {
                        await once(socket, 'connect');
                        socket.destroy();
                    } catch {
                        socket.destroy();
                        break;
                    }
                    assert(Date.now() < deadline, 'An orphaned core survived its owner');
                    await delay(50);
                }
            } finally {
                await stopChild(parent);
            }
        }
    },
);

async function listen(server: ReturnType<typeof createServer>): Promise<number> {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    return (server.address() as { port: number }).port;
}
async function unusedPort(): Promise<number> {
    const server = createServer();
    const port = await listen(server);
    await new Promise<void>((resolve) => server.close(() => resolve()));
    return port;
}
async function stopChild(child: ChildProcess): Promise<void> {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const exited = once(child, 'exit');
    child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    try {
        await exited;
    } finally {
        clearTimeout(timer);
    }
}
async function waitPort(port: number, child: ChildProcess): Promise<void> {
    const end = Date.now() + 10000;
    while (true) {
        if (Date.now() > end || child.exitCode !== null)
            throw new Error('Mihomo client failed to start');
        const socket = connect(port, '127.0.0.1');
        try {
            await once(socket, 'connect');
            socket.destroy();
            return;
        } catch {
            socket.destroy();
            await delay(50);
        }
    }
}
async function socksHttp(socksPort: number, port: number): Promise<string> {
    const socket = connect(socksPort, '127.0.0.1');
    socket.on('error', () => {});
    const timer = setTimeout(() => socket.destroy(new Error('Request deadline')), 6000);
    let bytes = Buffer.alloc(0);
    let closed = false;
    let error: Error | undefined;
    let wake: (() => void) | undefined;
    socket.on('data', (data) => {
        bytes = Buffer.concat([bytes, data]);
        wake?.();
    });
    socket.on('error', (value) => {
        error = value;
        wake?.();
    });
    socket.on('close', () => {
        closed = true;
        wake?.();
    });
    const take = async (count: number) => {
        while (bytes.length < count) {
            if (error) throw error;
            if (closed) throw new Error('Connection rejected');
            await new Promise<void>((resolve) => {
                wake = resolve;
            });
        }
        const result = bytes.subarray(0, count);
        bytes = bytes.subarray(count);
        return result;
    };
    try {
        await once(socket, 'connect');
        socket.write(Buffer.from([5, 1, 0]));
        assert.deepEqual(await take(2), Buffer.from([5, 0]));
        const dest = Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, 0, 0]);
        dest.writeUInt16BE(port, 8);
        socket.write(dest);
        const reply = await take(4);
        assert.equal(reply[1], 0);
        if (reply[3] === 1) await take(6);
        else if (reply[3] === 4) await take(18);
        else if (reply[3] === 3) await take((await take(1))[0] + 2);
        else throw new Error('Invalid SOCKS reply');
        socket.write(
            'GET /managed-fixture HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n',
        );
        while (!closed && !error)
            await new Promise<void>((resolve) => {
                wake = resolve;
            });
        if (error) throw error;
        const response = bytes.toString('utf8');
        assert.match(response, /^HTTP\/1\.1 200 /);
        return response;
    } finally {
        clearTimeout(timer);
        socket.destroy();
    }
}
