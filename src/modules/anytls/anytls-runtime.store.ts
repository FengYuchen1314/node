import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { z } from 'zod';

import { Injectable } from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';
import { AnyTlsConfigSchema } from '@libs/contracts/models';

import { AnyTlsCountersSchema } from './anytls-stats.client';

export const AnyTlsRuntimeStateSchema = z
    .object({
        version: z.literal(1),
        desired: AnyTlsConfigSchema.nullable(),
        totals: AnyTlsCountersSchema,
        seen: AnyTlsCountersSchema,
        billed: AnyTlsCountersSchema,
    })
    .strict();
export type AnyTlsRuntimeState = z.infer<typeof AnyTlsRuntimeStateSchema>;

@Injectable()
export class AnyTlsRuntimeStore {
    readonly directory: string;
    constructor(config: TypedConfigService) {
        this.directory = config.getOrThrow('ANYTLS_STATE_DIR');
    }

    async load(): Promise<AnyTlsRuntimeState> {
        try {
            const file = await open(
                join(this.directory, 'runtime.json'),
                constants.O_RDONLY | constants.O_NOFOLLOW,
            );
            try {
                const info = await file.stat();
                if (!info.isFile() || info.size > 64 * 1024 * 1024)
                    throw new Error('Invalid AnyTLS state file.');
                return AnyTlsRuntimeStateSchema.parse(JSON.parse(await file.readFile('utf8')));
            } finally {
                await file.close();
            }
        } catch (error) {
            if (!hasCode(error, 'ENOENT')) throw new Error('Cannot read AnyTLS runtime state.');
            return { version: 1, desired: null, totals: {}, seen: {}, billed: {} };
        }
    }

    async save(state: AnyTlsRuntimeState): Promise<void> {
        await privateJson(
            join(this.directory, 'runtime.json'),
            AnyTlsRuntimeStateSchema.parse(state),
        );
    }
}

export async function privateJson(path: string, value: unknown): Promise<void> {
    const payload = JSON.stringify(value);
    if (Buffer.byteLength(payload) > 64 * 1024 * 1024)
        throw new Error('AnyTLS state is too large.');
    const directory = dirname(path);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink())
        throw new Error('Unsafe AnyTLS state directory.');
    const temporary = join(directory, `.write-${randomUUID()}.tmp`);
    const file = await open(temporary, 'wx', 0o600);
    try {
        await file.writeFile(payload);
        await file.sync();
    } finally {
        await file.close();
    }
    try {
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

export function hasCode(error: unknown, code: string): boolean {
    return error instanceof Error && 'code' in error && error.code === code;
}
