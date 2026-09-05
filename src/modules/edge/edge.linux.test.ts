import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { connect as tlsConnect } from 'node:tls';
import { promisify } from 'node:util';

import { TypedConfigService } from '@common/config/app-config';
import { TNodeEdgePlan } from '@libs/contracts/models';

import { renderCaddyfile, renderHaproxy } from './edge-config';
import { EdgeConfigIO } from './edge-config.io';

const exec = promisify(execFile);
const HAPROXY =
    'haproxy:3.2.23-alpine3.24@sha256:6343ce34a132a5dceaa24767d739df2bd519f8f7c1079ae39e4821334e8eb42e';
const CADDY =
    'caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648';
const empty: TNodeEdgePlan = {
    version: 1,
    publicHttpPort: 80,
    publicHttpsPort: 443,
    caddyHttpTarget: '127.0.0.1:18080',
    caddyHttpsTarget: '127.0.0.1:18443',
    routes: [],
    management: null,
    website: null,
};

test(
    'Linux edge validates mixed SNI header modes, rollback, trusted HTTPS and website reverse proxy',
    {
        skip: process.platform !== 'linux' || process.env.RW_EDGE_INTEGRATION !== '1',
        timeout: 180_000,
    },
    async (context) => {
        const directory = await mkdtemp(join(tmpdir(), 'rw-edge-'));
        const run = join(directory, 'run');
        await mkdir(run, { mode: 0o700 });
        await writeFile(join(directory, 'haproxy.cfg'), renderHaproxy(empty), { mode: 0o600 });
        await writeFile(join(directory, 'Caddyfile'), renderCaddyfile(empty), { mode: 0o600 });
        const prefix = `rw-edge-${randomUUID()}`;
        const haproxyName = `${prefix}-haproxy`;
        const caddyName = `${prefix}-caddy`;
        let completed = false;
        context.after(async () => {
            for (const name of [haproxyName, caddyName]) {
                if (!completed) {
                    const logs = await exec('docker', ['logs', name]).catch(() => ({
                        stdout: '',
                        stderr: '',
                    }));
                    context.diagnostic(`${name}: ${logs.stdout}\n${logs.stderr}`);
                }
                await exec('docker', ['rm', '-f', '-v', name]).catch(() => undefined);
            }
            await rm(directory, { force: true, recursive: true });
        });
        await Promise.all(
            [HAPROXY, CADDY].map((image) => exec('docker', ['pull', image], { timeout: 120_000 })),
        );
        await exec('docker', [
            'run',
            '-d',
            '--name',
            caddyName,
            '--network',
            'host',
            '--user',
            '0:0',
            '-v',
            `${directory}/Caddyfile:/etc/caddy/Caddyfile:ro`,
            CADDY,
            'caddy',
            'run',
            '--config',
            '/etc/caddy/Caddyfile',
            '--adapter',
            'caddyfile',
        ]);
        await exec('docker', [
            'run',
            '-d',
            '--name',
            haproxyName,
            '--network',
            'host',
            '--user',
            '0:0',
            '-v',
            `${directory}:/usr/local/etc/haproxy:ro`,
            '-v',
            `${run}:/run/edge`,
            HAPROXY,
            'haproxy',
            '-W',
            '-db',
            '-f',
            '/usr/local/etc/haproxy/haproxy.cfg',
            '-S',
            `/run/edge/master.sock,uid,${process.getuid!()},gid,${process.getgid!()},mode,600`,
        ]);
        const values: Record<string, string> = {
            EDGE_CONFIG_DIR: directory,
            EDGE_HAPROXY_MASTER_SOCKET: join(run, 'master.sock'),
            EDGE_CADDY_ADMIN_URL: 'http://127.0.0.1:2019',
        };
        const io = new EdgeConfigIO({
            getOrThrow: (key: string) => values[key],
        } as unknown as TypedConfigService);
        await eventually(async () => {
            const status = await io.status();
            return status.haproxy && status.caddy;
        });

        const first = await proxyTarget('one.example.com');
        const second = await proxyTarget('two.example.com');
        // A byte-level wrapper stand-in, not a real AnyTLS server. Confidentiality/authentication
        // are covered by the separate native AnyTLS suite; this checks the shared-443 boundary.
        const wrapper = await proxyTarget('anytls.example.com', false);
        context.after(async () => {
            await first.close();
            await second.close();
            await wrapper.close();
        });
        const plan: TNodeEdgePlan = {
            ...empty,
            routes: [first, second, wrapper].map((target, index) => ({
                sni: target.sni,
                targetHost: '127.0.0.1',
                targetPort: target.port,
                sendProxyV2: target.sendProxyV2,
                inboundTag: `inbound_${index}`,
            })),
        };
        await io.begin(await io.snapshot());
        await io.apply(plan);
        await io.commit();
        await first.probe();
        await second.probe();
        await wrapper.probe();

        // Exercise HAProxy's rejection path even if a future renderer emits bad syntax.
        await io.begin(await io.snapshot());
        await assert.rejects(
            io.apply({ ...plan, routes: [{ ...plan.routes[0], sni: 'invalid\nnot-a-directive' }] }),
            /rejected/,
        );
        await io.recover();
        assert.deepEqual((await io.readPlan())?.routes, plan.routes);
        await first.probe();
        await second.probe();
        await wrapper.probe();

        const upstream = createHttpServer((_request, response) => {
            response.end('website-upstream');
        });
        await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
        context.after(() => new Promise<void>((resolve) => upstream.close(() => resolve())));
        const webPlan = {
            ...plan,
            website: {
                domains: ['website.example.invalid'],
                upstream: `http://127.0.0.1:${(upstream.address() as { port: number }).port}`,
            },
        };
        const adapted = await fetch('http://127.0.0.1:2019/adapt', {
            method: 'POST',
            headers: { 'Content-Type': 'text/caddyfile', Origin: 'http://127.0.0.1:2019' },
            body: renderCaddyfile(webPlan),
        });
        assert.equal(adapted.status, 200, await adapted.clone().text());
        const { result } = (await adapted.json()) as { result: Record<string, any> };
        // No public ACME requests for test names: use only an ephemeral container-local CA.
        result.apps.tls ??= {};
        result.apps.tls.automation = { policies: [{ issuers: [{ module: 'internal' }] }] };
        const loaded = await fetch('http://127.0.0.1:2019/load', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Origin: 'http://127.0.0.1:2019' },
            body: JSON.stringify(result),
        });
        assert.equal(loaded.status, 200, await loaded.text());
        const redirect = await new Promise<{ status: number; location?: string }>(
            (resolve, reject) => {
                // Use the low-level client to preserve the virtual-host override;
                // recent Node fetch versions derive Host from the URL instead.
                const request = httpRequest(
                    {
                        hostname: '127.0.0.1',
                        port: 80,
                        path: '/path?q=1',
                        headers: { Host: 'website.example.invalid' },
                        timeout: 3_000,
                    },
                    (response) => {
                        response.resume();
                        response.once('end', () =>
                            resolve({
                                status: response.statusCode!,
                                location: response.headers.location,
                            }),
                        );
                        response.once('error', reject);
                    },
                );
                request.once('error', reject);
                request.once('timeout', () =>
                    request.destroy(new Error('HTTP redirect probe timed out.')),
                );
                request.end();
            },
        );
        assert.equal(redirect.status, 308);
        assert.equal(redirect.location, 'https://website.example.invalid/path?q=1');
        let ca: string | undefined;
        await eventually(async () => {
            ca = (
                await exec('docker', [
                    'exec',
                    caddyName,
                    'cat',
                    '/data/caddy/pki/authorities/local/root.crt',
                ])
            ).stdout;
            return (await httpsGet(ca)).body === 'website-upstream';
        });
        // Neither an untrusted issuer nor a mismatched SNI may pass the website TLS probe.
        await assert.rejects(httpsGet(), /certificate|self.signed|verify/i);
        await assert.rejects(httpsGet(ca, 'wrong.example.invalid'), /certificate|tls|handshake/i);
        assert.equal((await httpsGet(ca)).body, 'website-upstream');
        await first.probe();
        await second.probe();
        await wrapper.probe();
        const active = (await (
            await fetch('http://127.0.0.1:2019/config/', {
                headers: { Origin: 'http://127.0.0.1:2019' },
            })
        ).json()) as Record<string, any>;
        for (const server of Object.values(active.apps.http.servers) as Array<{
            listen: string[];
        }>) {
            assert.ok(server.listen.every((address) => address.startsWith('127.0.0.1:')));
        }
        // A joint-runtime crash may not replay the old proxy admission journal. Exercise the
        // production IO against both native processes, preserving the actual private-CA website.
        const checkpoint = { ...(await io.snapshot()), plan: webPlan };
        await io.begin(checkpoint);
        await io.recover(true);
        assert.deepEqual((await io.readPlan())?.routes, []);
        assert.equal((await httpsGet(ca)).body, 'website-upstream');
        await first.blocked();
        await second.blocked();
        await wrapper.blocked();
        await io.begin(checkpoint);
        await io.restore(checkpoint);
        await first.probe();
        await second.probe();
        await wrapper.probe();
        assert.equal((await httpsGet(ca)).body, 'website-upstream');
        completed = true;
    },
);

async function eventually(check: () => Promise<boolean>): Promise<void> {
    for (let attempt = 0; attempt < 100; attempt++) {
        if (await check().catch(() => false)) return;
        await delay(100);
    }
    throw new Error('Expected edge state was not reached.');
}

async function proxyTarget(sni: string, sendProxyV2 = true) {
    let observed: (() => void) | undefined;
    let receivedHellos = 0;
    const sockets = new Set<import('node:net').Socket>();
    const server = createServer((socket) => {
        sockets.add(socket);
        socket.once('close', () => sockets.delete(socket));
        socket.on('error', () => undefined);
        let data = Buffer.alloc(0);
        socket.on('data', (chunk: Buffer) => {
            data = Buffer.concat([data, chunk]);
            if (data.length < 16) return;
            const length = sendProxyV2 ? 16 + data.readUInt16BE(14) : 0;
            if (data.length <= length || !data.includes(Buffer.from(sni))) return;
            if (sendProxyV2)
                assert.equal(data.subarray(0, 12).toString('hex'), '0d0a0d0a000d0a515549540a');
            assert.equal(data[length], 0x16);
            receivedHellos++;
            observed?.();
            socket.destroy();
        });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    return {
        sni,
        sendProxyV2,
        port: (server.address() as { port: number }).port,
        async blocked() {
            const before = receivedHellos;
            const client = tlsConnect({ host: '127.0.0.1', port: 443, servername: sni });
            client.setTimeout(5_000, () =>
                client.destroy(new Error('Rejected SNI probe deadline')),
            );
            try {
                await new Promise<void>((resolve, reject) => {
                    client.once('error', () => resolve());
                    client.once('secureConnect', () =>
                        reject(new Error('Withdrawn proxy unexpectedly accepted TLS')),
                    );
                });
                assert.equal(receivedHellos, before, 'Withdrawn SNI reached its old proxy target');
            } finally {
                client.destroy();
            }
        },
        async probe() {
            let timer: NodeJS.Timeout | undefined;
            const received = new Promise<void>((resolve, reject) => {
                observed = resolve;
                timer = setTimeout(
                    () => reject(new Error(`SNI ${sni} was not routed to its listener.`)),
                    5_000,
                );
            });
            const client = tlsConnect({
                host: '127.0.0.1',
                port: 443,
                servername: sni,
                rejectUnauthorized: false,
            });
            client.on('error', () => undefined);
            try {
                await received;
            } finally {
                clearTimeout(timer);
                client.destroy();
                observed = undefined;
            }
        },
        async close() {
            for (const socket of sockets) socket.destroy();
            await new Promise<void>((resolve) => server.close(() => resolve()));
        },
    };
}

async function httpsGet(
    ca?: string,
    servername = 'website.example.invalid',
): Promise<{ body: string }> {
    return new Promise((resolve, reject) => {
        const request = httpsRequest(
            {
                hostname: '127.0.0.1',
                port: 443,
                servername,
                headers: { Host: 'website.example.invalid' },
                ca,
                rejectUnauthorized: true,
                timeout: 3_000,
            },
            (response) => {
                let body = '';
                response.on('data', (chunk: Buffer) => {
                    body += chunk.toString();
                });
                response.once('end', () => resolve({ body }));
            },
        );
        request.once('error', reject);
        request.once('timeout', () => request.destroy(new Error('HTTPS probe timed out.')));
        request.end();
    });
}
