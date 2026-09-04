import { randomUUID } from 'node:crypto';
import { mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { z } from 'zod';

import { Injectable } from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';
import { MieruIsolatedConfigSchema, MieruMetricsSchema } from '@libs/contracts/models';

const RuntimeStateSchema = z.object({
    version: z.literal(1),
    desired: MieruIsolatedConfigSchema.nullable(),
    retired: z.record(z.uuid(), MieruMetricsSchema),
    legacy: MieruMetricsSchema,
});
export type MieruRuntimeState = z.infer<typeof RuntimeStateSchema>;

@Injectable()
export class MieruRuntimeStore {
    private readonly path: string;

    constructor(config: TypedConfigService) {
        this.path = join(config.getOrThrow('MIERU_STATE_DIR'), 'runtime.json');
    }

    async load(): Promise<MieruRuntimeState> {
        try {
            const file = await open(this.path, 'r');
            try {
                const info = await file.stat();
                if (!info.isFile() || info.size > 64 << 20) {
                    throw new Error('Invalid Mieru runtime state file.');
                }
                return RuntimeStateSchema.parse(JSON.parse(await file.readFile('utf8')));
            } finally {
                await file.close();
            }
        } catch (error) {
            if (!hasCode(error, 'ENOENT')) throw error;
            return { version: 1, desired: null, retired: {}, legacy: {} };
        }
    }

    async save(state: MieruRuntimeState): Promise<void> {
        const payload = JSON.stringify(RuntimeStateSchema.parse(state));
        if (Buffer.byteLength(payload) > 64 << 20) {
            throw new Error('Mieru runtime state exceeds its maximum size.');
        }
        const directory = dirname(this.path);
        await mkdir(directory, { recursive: true, mode: 0o700 });
        const temporary = join(directory, `.runtime-${randomUUID()}.tmp`);
        const file = await open(temporary, 'wx', 0o600);
        try {
            await file.writeFile(payload, 'utf8');
            await file.sync();
        } finally {
            await file.close();
        }
        try {
            await rename(temporary, this.path);
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
}

export function hasCode(error: unknown, code: string): boolean {
    return error instanceof Error && 'code' in error && error.code === code;
}
