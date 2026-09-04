import { execFile } from 'node:child_process';
import { mkdtemp, rmdir, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { z } from 'zod';

import { Injectable } from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';
import {
    MieruMetricsSchema,
    MieruOperationSchema,
    MieruStatusSchema,
    TMieruMetrics,
    TMieruOperation,
    TMieruServerConfig,
    TMieruStatus,
} from '@libs/contracts/models';

const execFileAsync = promisify(execFile);
const HELPER_TIMEOUT_MS = 40_000;
const HELPER_MAX_BUFFER_BYTES = 32 << 20;

const HelperErrorSchema = z.object({
    stage: z.string(),
    message: z.string(),
    rollbackAttempted: z.boolean(),
    rollbackSucceeded: z.boolean(),
});

const SyncResultSchema = z.object({
    status: MieruStatusSchema,
    operation: MieruOperationSchema,
    version: z.string(),
});

const StopResultSchema = z.object({
    status: MieruStatusSchema,
    operation: z.enum(['STOPPED', 'ALREADY_STOPPED']),
});

const StatusResultSchema = z.object({
    status: MieruStatusSchema,
    version: z.string(),
    metrics: MieruMetricsSchema,
});

export interface IMieruSyncResult {
    status: TMieruStatus;
    operation: TMieruOperation;
    version: string;
}

export interface IMieruStopResult {
    status: TMieruStatus;
    operation: 'ALREADY_STOPPED' | 'STOPPED';
}

export interface IMieruStatusResult {
    status: TMieruStatus;
    version: string;
    metrics: TMieruMetrics;
}

export class MieruControlError extends Error {
    constructor(
        message: string,
        public readonly stage: string,
        public readonly rollbackAttempted = false,
        public readonly rollbackSucceeded = false,
    ) {
        super(message);
        this.name = 'MieruControlError';
    }
}

export function parseMieruHelperOutput<T>(stdout: string, resultSchema: z.ZodType<T>): T {
    let decoded: unknown;
    try {
        decoded = JSON.parse(stdout);
    } catch {
        throw new MieruControlError('Mita control helper returned invalid JSON.', 'parse-output');
    }

    const envelope = z
        .discriminatedUnion('ok', [
            z.object({ ok: z.literal(true), result: resultSchema }),
            z.object({ ok: z.literal(false), error: HelperErrorSchema }),
        ])
        .safeParse(decoded);

    if (!envelope.success) {
        throw new MieruControlError(
            'Mita control helper returned an invalid response.',
            'parse-output',
        );
    }
    if (!envelope.data.ok) {
        throw new MieruControlError(
            sanitizeMessage(envelope.data.error.message),
            envelope.data.error.stage,
            envelope.data.error.rollbackAttempted,
            envelope.data.error.rollbackSucceeded,
        );
    }
    return envelope.data.result;
}

@Injectable()
export class MieruControlClient {
    private readonly helperPath: string;
    private readonly socketPath: string;
    private mutationQueue: Promise<void> = Promise.resolve();

    constructor(configService: TypedConfigService) {
        this.helperPath = configService.getOrThrow('MIERU_CONTROL_HELPER_PATH');
        this.socketPath = configService.getOrThrow('MITA_UDS_PATH');
    }

    public apply(config: TMieruServerConfig): Promise<IMieruSyncResult> {
        return this.withMutationLock(async () => {
            const directory = await mkdtemp(join(tmpdir(), 'rw-mita-control-'));
            const configPath = join(directory, 'server-config.json');
            let result: IMieruSyncResult | undefined;
            let operationError: unknown;
            try {
                await writeFile(configPath, JSON.stringify(config), {
                    encoding: 'utf8',
                    flag: 'wx',
                    mode: 0o600,
                });
                result = await this.execute(
                    ['apply', '--socket', this.socketPath, '--config', configPath],
                    SyncResultSchema,
                );
            } catch (error: unknown) {
                operationError = error;
            }

            const cleanupError = await removeTemporaryConfig(configPath, directory);
            if (cleanupError) throw cleanupError;
            if (operationError) throw operationError;
            if (!result) {
                throw new MieruControlError('Mita control helper returned no result.', 'execute');
            }
            return result;
        });
    }

    public stop(): Promise<IMieruStopResult> {
        return this.withMutationLock(() =>
            this.execute(['stop', '--socket', this.socketPath], StopResultSchema),
        );
    }

    public status(): Promise<IMieruStatusResult> {
        return this.withMutationLock(() =>
            this.execute(['status', '--socket', this.socketPath], StatusResultSchema),
        );
    }

    private async execute<T>(arguments_: string[], resultSchema: z.ZodType<T>): Promise<T> {
        try {
            const { stdout } = await execFileAsync(this.helperPath, arguments_, {
                encoding: 'utf8',
                maxBuffer: HELPER_MAX_BUFFER_BYTES,
                timeout: HELPER_TIMEOUT_MS,
                windowsHide: true,
            });
            return parseMieruHelperOutput(stdout, resultSchema);
        } catch (error: unknown) {
            if (error instanceof MieruControlError) {
                throw error;
            }

            const output = asExecOutput(error, 'stdout');
            if (output) {
                try {
                    return parseMieruHelperOutput(output, resultSchema);
                } catch (parsedError) {
                    if (
                        parsedError instanceof MieruControlError &&
                        parsedError.stage !== 'parse-output'
                    ) {
                        throw parsedError;
                    }
                }
            }

            const stderr = asExecOutput(error, 'stderr');
            const message =
                stderr || (error instanceof Error ? error.message : 'Mita control helper failed.');
            throw new MieruControlError(sanitizeMessage(message), 'execute');
        }
    }

    private async withMutationLock<T>(operation: () => Promise<T>): Promise<T> {
        const previous = this.mutationQueue;
        let release!: () => void;
        this.mutationQueue = new Promise<void>((resolve) => {
            release = resolve;
        });
        await previous;
        try {
            return await operation();
        } finally {
            release();
        }
    }
}

function asExecOutput(error: unknown, field: 'stderr' | 'stdout'): string {
    if (!error || typeof error !== 'object' || !(field in error)) return '';
    const output = (error as Record<string, unknown>)[field];
    if (typeof output === 'string') return output;
    if (Buffer.isBuffer(output)) return output.toString('utf8');
    return '';
}

function sanitizeMessage(message: string): string {
    return message
        .replaceAll(/\/tmp\/rw-mita-control-[^\s/]+\/server-config\.json/g, '<config>')
        .replaceAll(/\s+/g, ' ')
        .trim()
        .slice(0, 600);
}

async function removeTemporaryConfig(
    configPath: string,
    directory: string,
): Promise<MieruControlError | null> {
    let cleanupError: MieruControlError | null = null;
    try {
        await unlink(configPath);
    } catch (error: unknown) {
        if (!isFileMissing(error)) {
            cleanupError = new MieruControlError(
                'Failed to remove the temporary Mita configuration.',
                'cleanup-config',
            );
        }
    }
    await rmdir(directory).catch(() => undefined);
    return cleanupError;
}

function isFileMissing(error: unknown): boolean {
    return (
        error instanceof Error &&
        'code' in error &&
        (error as NodeJS.ErrnoException).code === 'ENOENT'
    );
}
