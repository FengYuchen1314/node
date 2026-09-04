import { ChildProcess, execFile, spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdir, open, readFile, unlink } from 'node:fs/promises';
import { createServer, connect } from 'node:net';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';

import { Injectable } from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';
import { TAnyTlsConfig } from '@libs/contracts/models';

import { AnyTlsConfigRenderer, AnyTlsRenderOptions } from './anytls-config';
import { hasCode, privateJson } from './anytls-runtime.store';
import { AnyTlsCounters, AnyTlsStatsClient } from './anytls-stats.client';

interface Child {
    child: ChildProcess;
    done: Promise<void>;
    exited: boolean;
}
export interface PreparedAnyTls {
    config: TAnyTlsConfig;
    directory: string;
    options: AnyTlsRenderOptions;
}
const execFileAsync = promisify(execFile);

@Injectable()
export class AnyTlsRuntimeIO {
    private children = new Map<string, Child>();
    private prepared: PreparedAnyTls | undefined;
    private readonly stateDir: string;
    private readonly supervisor: string;
    private readonly outer: string;
    private readonly inner: string;
    private leaseOwned = false;

    constructor(
        private readonly env: TypedConfigService,
        private readonly renderer: AnyTlsConfigRenderer,
        private readonly stats: AnyTlsStatsClient,
    ) {
        this.stateDir = env.getOrThrow('ANYTLS_STATE_DIR');
        this.supervisor = env.getOrThrow('ANYTLS_SUPERVISOR_PATH');
        this.outer = env.getOrThrow('ANYTLS_MIHOMO_PATH');
        this.inner = env.getOrThrow('ANYTLS_SINGBOX_PATH');
    }

    isRunning(): boolean {
        return ['outer', 'inner'].every((name) => {
            const child = this.children.get(name);
            return child && !child.exited;
        });
    }
    hasChildren(): boolean {
        return this.children.size > 0;
    }

    async acquire(): Promise<void> {
        if (this.leaseOwned) return;
        await mkdir(this.stateDir, { recursive: true, mode: 0o700 });
        const path = join(this.stateDir, 'owner.pid');
        try {
            const file = await open(path, 'wx', 0o600);
            try {
                await file.writeFile(String(process.pid));
                await file.sync();
            } finally {
                await file.close();
            }
            this.leaseOwned = true;
        } catch (error) {
            if (!hasCode(error, 'EEXIST')) throw error;
            const owner = await readFile(path, 'utf8');
            if (!/^[1-9]\d{0,9}$/.test(owner)) throw new Error('Invalid AnyTLS owner record.');
            // Never kill a PID from disk, even if a previous process reused that PID.
            try {
                process.kill(Number(owner), 0);
            } catch (check) {
                if (hasCode(check, 'ESRCH')) {
                    await unlink(path);
                    return this.acquire();
                }
                throw check;
            }
            throw new Error('Another Agent owns the AnyTLS runtime.');
        }
    }

    async release(): Promise<void> {
        if (this.hasChildren()) throw new Error('Cannot release a live AnyTLS runtime.');
        if (this.leaseOwned) {
            await unlink(join(this.stateDir, 'owner.pid'));
            this.leaseOwned = false;
        }
    }

    private options(): AnyTlsRenderOptions {
        return {
            statsPort: this.env.getOrThrow('ANYTLS_STATS_PORT'),
            controlPort: this.env.getOrThrow('ANYTLS_CONTROL_PORT'),
            nodePort: this.env.getOrThrow('NODE_PORT'),
            controlSecret: randomBytes(32).toString('hex'),
        };
    }

    validate(input: unknown): TAnyTlsConfig {
        return this.renderer.render(input, this.options()).config;
    }

    async prepare(input: unknown): Promise<PreparedAnyTls> {
        const options = this.options();
        const rendered = this.renderer.render(input, options);
        const directory = join(this.stateDir, `generation-${randomUUID()}`);
        await privateJson(join(directory, 'outer.json'), rendered.outer);
        await privateJson(join(directory, 'inner.json'), rendered.inner);
        try {
            await execFileAsync(
                this.outer,
                ['-t', '-d', directory, '-f', join(directory, 'outer.json')],
                { timeout: 15000, maxBuffer: 256 * 1024, windowsHide: true },
            );
            await execFileAsync(
                this.inner,
                ['check', '-D', directory, '-c', join(directory, 'inner.json')],
                { timeout: 15000, maxBuffer: 256 * 1024, windowsHide: true },
            );
        } catch {
            throw new Error('Native AnyTLS configuration validation failed.');
        }
        return { config: rendered.config, directory, options };
    }

    async start(prepared: PreparedAnyTls): Promise<void> {
        if (this.hasChildren()) throw new Error('The previous AnyTLS runtime is still owned.');
        await this.acquire();
        const ports = [
            prepared.options.statsPort,
            prepared.options.controlPort,
            ...prepared.config.listeners.flatMap((listener) => [
                listener.wrapperPort,
                listener.innerPort,
            ]),
        ];
        // An unrelated process must not be mistaken for successful startup/readiness.
        for (const port of ports) await assertUnusedPort(port);
        this.prepared = prepared;
        try {
            await this.spawn(
                'inner',
                this.inner,
                ['run', '-D', prepared.directory, '-c', join(prepared.directory, 'inner.json')],
                [
                    prepared.options.statsPort,
                    prepared.options.controlPort,
                    ...prepared.config.listeners.map((listener) => listener.innerPort),
                ],
            );
            await this.control('GET');
            await this.stats.read(prepared.options.statsPort);
            await this.spawn(
                'outer',
                this.outer,
                ['-d', prepared.directory, '-f', join(prepared.directory, 'outer.json')],
                prepared.config.listeners.map((listener) => listener.wrapperPort),
            );
        } catch {
            // Keep owned children available to the runtime's final-counter/rollback path.
            throw new Error('AnyTLS startup failed.');
        }
    }

    async snapshot(): Promise<AnyTlsCounters> {
        if (!this.prepared || !this.isRunning()) throw new Error('AnyTLS runtime is not healthy.');
        return this.stats.read(this.prepared.options.statsPort);
    }

    async retire(): Promise<AnyTlsCounters> {
        if (!this.prepared || !this.hasChildren()) return {};
        const innerAlive = this.children.get('inner')?.exited === false;
        await this.terminate('outer');
        if (!innerAlive) {
            await this.abort();
            throw new Error('AnyTLS core exited before final statistics could be collected.');
        }
        // Stop admitting new encrypted sessions, close all existing inner streams, then capture
        // final cumulative counters before terminating the inner process. Never reset the core.
        await this.control('DELETE');
        const deadline = Date.now() + 5000;
        while ((await this.control('GET')).length) {
            if (Date.now() > deadline) throw new Error('AnyTLS streams did not drain.');
            await delay(50);
        }
        const counters = await this.stats.read(this.prepared.options.statsPort);
        await this.terminate('inner');
        this.prepared = undefined;
        return counters;
    }

    async abort(): Promise<void> {
        const results = await Promise.allSettled(
            ['outer', 'inner'].map((name) => this.terminate(name)),
        );
        if (results.some((result) => result.status === 'rejected'))
            throw new Error('AnyTLS processes could not be stopped.');
        this.prepared = undefined;
    }

    private async control(method: 'GET' | 'DELETE'): Promise<unknown[]> {
        if (!this.prepared) throw new Error('No AnyTLS control endpoint.');
        const { controlPort, controlSecret } = this.prepared.options;
        const response = await fetch(`http://127.0.0.1:${controlPort}/connections`, {
            method,
            headers: { Authorization: `Bearer ${controlSecret}` },
            signal: AbortSignal.timeout(5000),
            redirect: 'error',
        });
        if (!response.ok) throw new Error('AnyTLS session control failed.');
        if (method === 'DELETE') {
            await response.body?.cancel();
            return [];
        }
        const data = (await response.json()) as { connections?: unknown[] };
        if (data.connections === null) return [];
        if (!Array.isArray(data.connections)) throw new Error('Invalid AnyTLS session status.');
        return data.connections;
    }

    private async spawn(
        name: string,
        binary: string,
        args: string[],
        ports: number[],
    ): Promise<void> {
        const child = spawn(this.supervisor, ['--binary', binary, '--', ...args], {
            stdio: ['pipe', 'ignore', 'ignore'],
            windowsHide: true,
        });
        let resolve!: () => void;
        const record: Child = {
            child,
            exited: false,
            done: new Promise<void>((done) => {
                resolve = done;
            }),
        };
        const exited = () => {
            record.exited = true;
            resolve();
        };
        child.once('exit', exited);
        child.once('error', exited);
        this.children.set(name, record);
        const deadline = Date.now() + 12000;
        for (const port of ports)
            while (true) {
                if (record.exited || Date.now() > deadline)
                    throw new Error('AnyTLS core did not become ready.');
                if (await portAccepts(port)) break;
                await delay(50);
            }
    }

    private async terminate(name: string): Promise<void> {
        const record = this.children.get(name);
        if (!record) return;
        record.child.stdin?.end();
        record.child.kill('SIGTERM');
        let timer: NodeJS.Timeout | undefined;
        try {
            await Promise.race([
                record.done,
                new Promise<never>((_, reject) => {
                    timer = setTimeout(
                        () => reject(new Error('AnyTLS supervisor did not stop.')),
                        7000,
                    );
                }),
            ]);
        } catch {
            // Pdeathsig in the supervisor ensures that killing this exact child also kills its core.
            record.child.kill('SIGKILL');
            await Promise.race([record.done, delay(3000)]);
            if (!record.exited) throw new Error('AnyTLS supervisor is still alive.');
        } finally {
            clearTimeout(timer);
        }
        this.children.delete(name);
    }
}

async function assertUnusedPort(port: number): Promise<void> {
    const server = createServer();
    await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', resolve);
    });
    await new Promise<void>((resolve) => server.close(() => resolve()));
}

async function portAccepts(port: number): Promise<boolean> {
    return new Promise((resolve) => {
        const socket = connect(port, '127.0.0.1');
        const finish = (value: boolean) => {
            socket.destroy();
            resolve(value);
        };
        socket.setTimeout(300, () => finish(false));
        socket.once('connect', () => finish(true));
        socket.once('error', () => finish(false));
    });
}
