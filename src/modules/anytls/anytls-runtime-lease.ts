import { ChildProcess, spawn } from 'node:child_process';

interface LeaseProcess {
    child: ChildProcess;
    done: Promise<void>;
    exited: boolean;
    ready: boolean;
    closing: boolean;
}

// A held native flock, not a PID from a previous container namespace. The fixed helper
// protocol is readiness on stdout and parent lifetime on stdin; no shell is involved.
export class AnyTlsRuntimeLease {
    private record: LeaseProcess | undefined;

    constructor(
        private readonly supervisor: string,
        private readonly path: string,
        private readonly lost: () => void,
    ) {}

    isHeld(): boolean {
        return !!this.record?.ready && !this.record.exited && !this.record.closing;
    }

    async acquire(): Promise<void> {
        if (this.isHeld()) return;
        if (this.record) await this.release();
        const child = spawn(this.supervisor, ['--lease', this.path], {
            stdio: ['pipe', 'pipe', 'ignore'],
            windowsHide: true,
        });
        const completed = Promise.withResolvers<void>();
        const ready = Promise.withResolvers<void>();
        const record: LeaseProcess = {
            child,
            done: completed.promise,
            exited: false,
            ready: false,
            closing: false,
        };
        this.record = record;
        const exited = () => {
            if (record.exited) return;
            record.exited = true;
            completed.resolve();
            ready.reject(new Error('AnyTLS runtime lease is unavailable.'));
            if (record.ready && !record.closing) this.lost();
        };
        child.once('exit', exited);
        child.once('error', exited);
        child.stdin!.on('error', () => undefined);
        let output = '';
        child.stdout!.on('data', (chunk: Buffer) => {
            output += chunk.toString('utf8');
            if (output === 'READY\n') ready.resolve();
            else if (output.length >= 6) ready.reject(new Error('Invalid AnyTLS lease readiness.'));
        });
        const timer = setTimeout(
            () => ready.reject(new Error('AnyTLS lease acquisition timed out.')),
            5000,
        );
        try {
            await ready.promise;
            if (record.exited) throw new Error('AnyTLS lease exited before admission.');
            record.ready = true;
        } catch (error) {
            await this.release();
            throw error;
        } finally {
            clearTimeout(timer);
        }
    }

    async release(): Promise<void> {
        const record = this.record;
        if (!record) return;
        record.closing = true;
        record.child.stdin?.end();
        const timer = setTimeout(() => record.child.kill('SIGKILL'), 3000);
        try {
            await record.done;
        } finally {
            clearTimeout(timer);
        }
        if (this.record === record) this.record = undefined;
    }
}
