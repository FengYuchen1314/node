import { ChildProcess, spawn } from 'node:child_process';
import { lstat, mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { connect } from 'node:net';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';

import { Injectable } from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';

import { hasCode } from './mieru-runtime.store';

interface DaemonChild {
    child: ChildProcess;
    exited: boolean;
    done: Promise<void>;
}

@Injectable()
export class MieruDaemonManager {
    private readonly children = new Map<string, DaemonChild>();
    private readonly binary: string;
    private readonly stateDirectory: string;
    private readonly socketDirectory: string;
    readonly legacySocket: string;

    constructor(config: TypedConfigService) {
        this.binary = config.getOrThrow('MIERU_DAEMON_PATH');
        this.stateDirectory = config.getOrThrow('MIERU_STATE_DIR');
        this.socketDirectory = config.getOrThrow('MIERU_SOCKET_DIR');
        this.legacySocket = config.getOrThrow('MITA_UDS_PATH');
    }

    socket(id: string): string {
        z.uuid().parse(id);
        const path = join(this.socketDirectory, `${id}.sock`);
        if (Buffer.byteLength(path) >= 104) throw new Error('Mieru socket path is too long.');
        return path;
    }

    ids(): string[] {
        return [...this.children.keys()];
    }

    dumpPath(id: string): string {
        z.uuid().parse(id);
        return join(this.stateDirectory, id, 'metrics.pb');
    }

    async prepare(id: string): Promise<void> {
        await this.removeStaleSocket(this.socket(id), join(this.socketDirectory, `${id}.pid`));
    }

    async hasLegacy(): Promise<boolean> {
        try {
            const info = await lstat(this.legacySocket);
            if (!info.isSocket()) throw new Error('Legacy Mieru control path is not a socket.');
            return true;
        } catch (error) {
            if (hasCode(error, 'ENOENT')) return false;
            throw error;
        }
    }

    async ensure(id: string): Promise<void> {
        const existing = this.children.get(id);
        if (existing && !existing.exited) return;
        if (existing) this.children.delete(id);
        const socket = this.socket(id);
        const directory = join(this.stateDirectory, id);
        await mkdir(directory, { recursive: true, mode: 0o700 });
        await mkdir(this.socketDirectory, { recursive: true, mode: 0o700 });
        const pidPath = join(this.socketDirectory, `${id}.pid`);
        await this.removeStaleSocket(socket, pidPath);
        const child = spawn(
            this.binary,
            ['--state-dir', directory, '--socket', socket, '--watch-parent'],
            {
                stdio: ['pipe', 'ignore', 'ignore'],
                windowsHide: true,
            },
        );
        let release!: () => void;
        const record: DaemonChild = {
            child,
            exited: false,
            done: new Promise<void>((resolve) => {
                release = resolve;
            }),
        };
        const exit = () => {
            record.exited = true;
            release();
        };
        child.once('exit', exit);
        child.once('error', exit);
        this.children.set(id, record);
        if (child.pid) await writeFile(pidPath, String(child.pid), { mode: 0o600 });
        const deadline = Date.now() + 10_000;
        while (!record.exited && Date.now() < deadline) {
            if (await socketAccepts(socket)) return;
            await delay(50);
        }
        await this.terminate(id);
        throw new Error(`Mieru instance ${id} did not open its management socket.`);
    }

    async terminate(id: string): Promise<void> {
        const record = this.children.get(id);
        if (!record) return;
        if (!record.exited) {
            record.child.stdin?.end();
            record.child.kill('SIGTERM');
            if (!(await exitsWithin(record, 12_000))) {
                record.child.kill('SIGKILL');
                if (!(await exitsWithin(record, 3_000))) {
                    throw new Error(`Mieru instance ${id} could not be stopped.`);
                }
            }
        }
        this.children.delete(id);
        try {
            const socket = this.socket(id);
            const info = await lstat(socket);
            if (!info.isSocket() || (await socketAccepts(socket))) {
                throw new Error('Refusing to remove a replaced Mieru management socket.');
            }
            // This exact child has exited, including after a forced kill.
            await unlink(socket);
        } catch (error) {
            if (!hasCode(error, 'ENOENT')) throw error;
        }
        await unlink(join(this.socketDirectory, `${id}.pid`)).catch((error) => {
            if (!hasCode(error, 'ENOENT')) throw error;
        });
    }

    private async removeStaleSocket(socket: string, pidPath: string): Promise<void> {
        // Never kill a PID read from disk. A still-live owner (including PID reuse)
        // blocks startup; only a confirmed dead owner permits stale-socket cleanup.
        let pid: number | null = null;
        try {
            const raw = await readFile(pidPath, 'utf8');
            if (!/^[1-9]\d{0,9}$/.test(raw)) throw new Error('Invalid Mieru owner PID.');
            pid = Number(raw);
        } catch (error) {
            if (!hasCode(error, 'ENOENT')) throw error;
        }
        if (pid !== null) {
            const deadline = Date.now() + 12_000;
            while (isProcessAlive(pid) && Date.now() < deadline) await delay(100);
            if (isProcessAlive(pid)) throw new Error('A previous Mieru daemon is still alive.');
        }
        try {
            const info = await lstat(socket);
            if (!info.isSocket() || pid === null || (await socketAccepts(socket))) {
                throw new Error('Refusing to replace an unowned or active Mieru socket.');
            }
            await unlink(socket);
        } catch (error) {
            if (!hasCode(error, 'ENOENT')) throw error;
        }
    }
}

function isProcessAlive(pid: number): boolean {
    try {
        process.kill(pid, 0);
        return true;
    } catch (error) {
        if (hasCode(error, 'ESRCH')) return false;
        throw error;
    }
}

async function exitsWithin(record: DaemonChild, timeout: number): Promise<boolean> {
    let timer: NodeJS.Timeout | undefined;
    try {
        return await Promise.race([
            record.done.then(() => true),
            new Promise<boolean>((resolve) => {
                timer = setTimeout(() => resolve(false), timeout);
            }),
        ]);
    } finally {
        clearTimeout(timer);
    }
}

async function socketAccepts(path: string): Promise<boolean> {
    return new Promise((resolve) => {
        const socket = connect(path);
        const finish = (result: boolean) => {
            socket.destroy();
            resolve(result);
        };
        socket.setTimeout(300, () => finish(false));
        socket.once('connect', () => finish(true));
        socket.once('error', () => finish(false));
    });
}
