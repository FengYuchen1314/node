import { randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { connect } from 'node:net';
import { dirname, join } from 'node:path';
import { z } from 'zod';

import { Injectable } from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';
import { NodeEdgePlanSchema, TNodeEdgePlan } from '@libs/contracts/models';

import { renderCaddyfile, renderHaproxy } from './edge-config';

const SnapshotSchema = z.object({
    haproxy: z.string().max(4 << 20),
    caddy: z.record(z.string(), z.unknown()),
    plan: NodeEdgePlanSchema.nullable(),
});
export type EdgeSnapshot = z.infer<typeof SnapshotSchema>;

@Injectable()
export class EdgeConfigIO {
    private readonly directory: string;
    private readonly socket: string;
    private readonly admin: string;

    constructor(config: TypedConfigService) {
        this.directory = config.getOrThrow('EDGE_CONFIG_DIR');
        this.socket = config.getOrThrow('EDGE_HAPROXY_MASTER_SOCKET');
        this.admin = config.getOrThrow('EDGE_CADDY_ADMIN_URL');
    }

    async status(): Promise<{ haproxy: boolean; caddy: boolean }> {
        const [haproxy, caddy] = await Promise.all([
            this.command('show proc')
                .then((result) => /^\s*\d+\s+worker\b/m.test(result))
                .catch(() => false),
            this.request('/config/')
                .then(() => true)
                .catch(() => false),
        ]);
        return { haproxy, caddy };
    }

    async snapshot(): Promise<EdgeSnapshot> {
        return SnapshotSchema.parse({
            haproxy: await readFile(join(this.directory, 'haproxy.cfg'), 'utf8'),
            caddy: JSON.parse(await this.request('/config/')),
            plan: await this.readPlan(),
        });
    }

    async readPlan(): Promise<TNodeEdgePlan | null> {
        const value = await this.readOptional('edge-plan.json');
        return value === null ? null : NodeEdgePlanSchema.parse(JSON.parse(value));
    }

    async begin(snapshot: EdgeSnapshot): Promise<void> {
        await atomicWrite(join(this.directory, 'edge-transaction.json'), JSON.stringify(snapshot));
    }

    async apply(plan: TNodeEdgePlan): Promise<void> {
        // /load itself rolls back a rejected Caddy configuration. The outer journal
        // restores both services when HAProxy or the later commit fails.
        await this.request('/load', renderCaddyfile(plan), 'text/caddyfile');
        await atomicWrite(join(this.directory, 'haproxy.cfg'), renderHaproxy(plan));
        await this.reload();
        await atomicWrite(join(this.directory, 'edge-plan.json'), JSON.stringify(plan));
    }

    async commit(): Promise<void> {
        await unlink(join(this.directory, 'edge-transaction.json'));
    }

    async recover(): Promise<void> {
        const raw = await this.readOptional('edge-transaction.json');
        if (raw !== null) await this.restore(SnapshotSchema.parse(JSON.parse(raw)));
    }

    async restore(snapshot: EdgeSnapshot): Promise<void> {
        const errors: unknown[] = [];
        try {
            await atomicWrite(join(this.directory, 'haproxy.cfg'), snapshot.haproxy);
            await this.reload();
        } catch (error) {
            errors.push(error);
        }
        try {
            await this.request('/load', JSON.stringify(snapshot.caddy), 'application/json');
        } catch (error) {
            errors.push(error);
        }
        if (errors.length)
            throw new Error('Edge rollback was not confirmed; recovery journal retained.');
        if (snapshot.plan) {
            await atomicWrite(
                join(this.directory, 'edge-plan.json'),
                JSON.stringify(snapshot.plan),
            );
        } else {
            await unlink(join(this.directory, 'edge-plan.json')).catch((error) => {
                if (!missing(error)) throw error;
            });
        }
        await this.commit();
    }

    private async reload(): Promise<void> {
        if (!/^Success=1\s*$/m.test(await this.command('reload'))) {
            throw new Error('HAProxy rejected the configuration reload.');
        }
    }

    private async readOptional(name: string): Promise<string | null> {
        try {
            return await readFile(join(this.directory, name), 'utf8');
        } catch (error) {
            if (missing(error)) return null;
            throw error;
        }
    }

    private async request(path: string, body?: string, contentType?: string): Promise<string> {
        const response = await fetch(`${this.admin}${path}`, {
            method: body === undefined ? 'GET' : 'POST',
            // Node fetch sends Sec-Fetch-Mode: cors. Caddy consequently checks
            // Origin even without enforce_origin; keep its CSRF protection on.
            headers: {
                Origin: new URL(this.admin).origin,
                ...(contentType ? { 'Content-Type': contentType } : {}),
            },
            body,
            redirect: 'error',
            signal: AbortSignal.timeout(15_000),
        });
        if (!response.ok) throw new Error(`Caddy ${path} failed (${response.status}).`);
        return response.text();
    }

    private command(command: 'reload' | 'show proc'): Promise<string> {
        return new Promise((resolve, reject) => {
            const socket = connect(this.socket);
            let output = '';
            socket.setTimeout(15_000, () =>
                socket.destroy(new Error('HAProxy control timed out.')),
            );
            socket.once('connect', () => socket.end(`${command}\n`));
            socket.on('data', (chunk: Buffer) => {
                output += chunk.toString('utf8');
                if (output.length > 1 << 20)
                    socket.destroy(new Error('HAProxy control output is too large.'));
            });
            socket.once('end', () => resolve(output));
            socket.once('error', reject);
            socket.once('close', () => reject(new Error('HAProxy control closed before EOF.')));
        });
    }
}

async function atomicWrite(path: string, data: string): Promise<void> {
    const directory = dirname(path);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const temporary = join(directory, `.edge-${randomUUID()}.tmp`);
    try {
        const file = await open(temporary, 'wx', 0o600);
        try {
            await file.writeFile(data, 'utf8');
            await file.sync();
        } finally {
            await file.close();
        }
        await rename(temporary, path);
        if (process.platform !== 'win32') {
            const parent = await open(directory, 'r');
            try {
                await parent.sync();
            } finally {
                await parent.close();
            }
        }
    } finally {
        await unlink(temporary).catch(() => undefined);
    }
}

function missing(error: unknown): boolean {
    return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}
