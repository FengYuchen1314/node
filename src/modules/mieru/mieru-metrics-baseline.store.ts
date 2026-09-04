import { randomUUID } from 'node:crypto';
import { mkdir, open, rename, unlink } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { z } from 'zod';

import { Injectable, Logger } from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';

const BASELINE_SCHEMA_VERSION = 1 as const;
const MAX_BASELINE_FILE_BYTES = 64 << 20;
const MAX_MITA_COUNTER = 9_223_372_036_854_775_807n;
const MAX_USERS = 100_000;

export type MieruMetricsConsumer = 'combined' | 'users';

export interface MieruCumulativeUserCounters {
    downlink: bigint;
    uplink: bigint;
}

export interface MieruMetricsConsumerState {
    baselines: Map<string, MieruCumulativeUserCounters>;
    initialized: boolean;
}

export type MieruMetricsBaselineState = Record<MieruMetricsConsumer, MieruMetricsConsumerState>;

const DecimalCounterSchema = z
    .string()
    .regex(/^\d{1,19}$/)
    .refine((value) => BigInt(value) <= MAX_MITA_COUNTER);

const BaselineEntrySchema = z
    .object({
        username: z
            .string()
            .min(1)
            .max(64)
            .refine((value) => Buffer.byteLength(value, 'utf8') <= 64),
        uplink: DecimalCounterSchema,
        downlink: DecimalCounterSchema,
    })
    .strict();

const PersistedStateSchema = z
    .object({
        version: z.literal(BASELINE_SCHEMA_VERSION),
        consumers: z
            .object({
                users: z
                    .object({
                        initialized: z.boolean(),
                        baselines: z.array(BaselineEntrySchema).max(MAX_USERS),
                    })
                    .strict(),
                combined: z
                    .object({
                        initialized: z.boolean(),
                        baselines: z.array(BaselineEntrySchema).max(MAX_USERS),
                    })
                    .strict(),
            })
            .strict(),
    })
    .strict();

@Injectable()
export class MieruMetricsBaselineStore {
    private readonly logger = new Logger(MieruMetricsBaselineStore.name);
    private readonly path: string;

    constructor(configService: TypedConfigService) {
        this.path = configService.getOrThrow('MIERU_METRICS_BASELINE_PATH');
    }

    public async load(): Promise<MieruMetricsBaselineState | null> {
        let file;
        try {
            file = await open(this.path, 'r');
        } catch (error: unknown) {
            if (isFileMissing(error)) return null;
            throw error;
        }

        let raw: string;
        try {
            const info = await file.stat();
            if (!info.isFile() || info.size > MAX_BASELINE_FILE_BYTES) {
                this.logger.warn('Ignoring an invalid Mieru metrics baseline file.');
                return null;
            }
            raw = await file.readFile({ encoding: 'utf8' });
        } finally {
            await file.close();
        }

        try {
            const parsed = PersistedStateSchema.parse(JSON.parse(raw));
            return {
                users: restoreConsumer(parsed.consumers.users),
                combined: restoreConsumer(parsed.consumers.combined),
            };
        } catch {
            this.logger.warn(
                'Ignoring a corrupt Mieru metrics baseline; the next snapshot will establish a new zero baseline.',
            );
            return null;
        }
    }

    public async save(state: MieruMetricsBaselineState): Promise<void> {
        const payload = `${JSON.stringify({
            version: BASELINE_SCHEMA_VERSION,
            consumers: {
                users: serializeConsumer(state.users),
                combined: serializeConsumer(state.combined),
            },
        })}\n`;
        if (Buffer.byteLength(payload, 'utf8') > MAX_BASELINE_FILE_BYTES) {
            throw new Error('Mieru metrics baseline exceeds the maximum file size.');
        }

        const directory = dirname(this.path);
        await mkdir(directory, { recursive: true, mode: 0o700 });
        const temporaryPath = join(
            directory,
            `.${basename(this.path)}.${process.pid}.${randomUUID()}.tmp`,
        );
        let temporaryFile;
        let renamed = false;
        try {
            temporaryFile = await open(temporaryPath, 'wx', 0o600);
            await temporaryFile.writeFile(payload, { encoding: 'utf8' });
            await temporaryFile.sync();
            await temporaryFile.close();
            temporaryFile = undefined;
            await rename(temporaryPath, this.path);
            renamed = true;
            await syncDirectoryBestEffort(directory, this.logger);
        } finally {
            await temporaryFile?.close().catch(() => undefined);
            if (!renamed) await unlink(temporaryPath).catch(() => undefined);
        }
    }
}

function restoreConsumer(
    persisted: z.infer<typeof PersistedStateSchema>['consumers']['users'],
): MieruMetricsConsumerState {
    const baselines = new Map<string, MieruCumulativeUserCounters>();
    for (const entry of persisted.baselines) {
        if (baselines.has(entry.username)) {
            throw new Error('Mieru metrics baseline contains a duplicate user.');
        }
        baselines.set(entry.username, {
            uplink: BigInt(entry.uplink),
            downlink: BigInt(entry.downlink),
        });
    }
    return { initialized: persisted.initialized, baselines };
}

function serializeConsumer(state: MieruMetricsConsumerState) {
    return {
        initialized: state.initialized,
        baselines: [...state.baselines]
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([username, counters]) => ({
                username,
                uplink: counters.uplink.toString(),
                downlink: counters.downlink.toString(),
            })),
    };
}

async function syncDirectoryBestEffort(directory: string, logger: Logger): Promise<void> {
    if (process.platform === 'win32') return;
    let handle;
    try {
        handle = await open(directory, 'r');
        await handle.sync();
    } catch (error: unknown) {
        logger.warn(
            `Mieru metrics baseline was replaced, but its directory could not be synchronized: ${error instanceof Error ? error.message : 'unknown error'}`,
        );
    } finally {
        await handle?.close().catch(() => undefined);
    }
}

function isFileMissing(error: unknown): boolean {
    return (
        error instanceof Error &&
        'code' in error &&
        (error as NodeJS.ErrnoException).code === 'ENOENT'
    );
}
