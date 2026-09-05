import { randomBytes, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { hasCode } from './anytls-runtime.store';

// Pinned Mihomo invokes -post-up after hub.Parse -> tunnel.OnRunning, not when the socket
// first opens. This fixed command contains no interpolated paths, config, or subscriber data.
// Quoted environment values are data even if the private state directory contains shell syntax.
const POST_UP =
    'set -C; umask 077; printf \'%s\' "$RW_ANYTLS_READY_TOKEN" > "$RW_ANYTLS_READY_FILE"';

export class MihomoStartupReadiness {
    readonly environment: Readonly<{
        RW_ANYTLS_READY_FILE: string;
        RW_ANYTLS_READY_TOKEN: string;
    }>;
    readonly args = ['-post-up', POST_UP, '-post-down', ''];

    constructor(directory: string) {
        this.environment = {
            RW_ANYTLS_READY_FILE: join(directory, `ready-${randomUUID()}`),
            RW_ANYTLS_READY_TOKEN: randomBytes(32).toString('hex'),
        };
    }

    async wait(isAlive: () => boolean, timeoutMs = 12000): Promise<void> {
        const deadline = performance.now() + timeoutMs;
        while (performance.now() < deadline && isAlive()) {
            if (await this.received()) {
                if (isAlive()) return;
                break;
            }
            await delay(Math.max(1, Math.min(25, deadline - performance.now())));
        }
        throw new Error('AnyTLS outer core did not confirm application readiness.');
    }

    async dispose(): Promise<void> {
        await unlink(this.environment.RW_ANYTLS_READY_FILE).catch((error) => {
            if (!hasCode(error, 'ENOENT')) throw new Error('AnyTLS readiness cleanup failed.');
        });
    }

    private async received(): Promise<boolean> {
        const path = this.environment.RW_ANYTLS_READY_FILE;
        const nonce = this.environment.RW_ANYTLS_READY_TOKEN;
        try {
            // Refuse pipes/devices/links before opening; O_NOFOLLOW/O_NONBLOCK also guard races.
            if (!(await lstat(path)).isFile()) throw new Error('Invalid readiness record.');
            const file = await open(
                path,
                constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
            );
            try {
                const info = await file.stat();
                if (
                    !info.isFile() ||
                    info.nlink !== 1 ||
                    info.size > nonce.length ||
                    (process.platform !== 'win32' &&
                        ((info.mode & 0o077) !== 0 || info.uid !== process.getuid!()))
                )
                    throw new Error('Invalid readiness record.');
                // A just-created file may not contain the complete printf yet. Never read unbounded
                // content or accept an old/foreign generation's nonce as readiness.
                if (info.size < nonce.length) return false;
                const bytes = Buffer.alloc(nonce.length + 1);
                const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
                if (bytesRead !== nonce.length || bytes.subarray(0, bytesRead).toString() !== nonce)
                    throw new Error('Invalid readiness record.');
                return true;
            } finally {
                await file.close();
            }
        } catch (error) {
            if (hasCode(error, 'ENOENT')) return false;
            // Paths, nonces and native diagnostics never enter API/log error output.
            throw new Error('AnyTLS outer core supplied an invalid readiness record.');
        }
    }
}
