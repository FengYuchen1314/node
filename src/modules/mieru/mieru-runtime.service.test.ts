import assert from 'node:assert/strict';
import { test } from 'node:test';

import { TypedConfigService } from '@common/config/app-config';
import { TMieruIsolatedConfig, TMieruMetrics, TMieruServerConfig } from '@libs/contracts/models';

import { MieruControlClient, MieruControlError } from './mieru-control.client';
import { MieruDaemonManager } from './mieru-daemon.manager';
import { MieruRuntimeService } from './mieru-runtime.service';
import { MieruRuntimeState, MieruRuntimeStore } from './mieru-runtime.store';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const config = (port: number, user = '1'): TMieruServerConfig => ({
    portBindings: [{ port, protocol: 'TCP' }],
    users: [{ name: user, password: `password-${user}` }],
    loggingLevel: 'INFO',
});
const desired = (instances: Array<[string, TMieruServerConfig]>): TMieruIsolatedConfig => ({
    kind: 'ISOLATED_LISTENERS',
    instances: instances.map(([id, value]) => ({ id, config: value })),
});

class FakeRuntimeIO {
    saved: MieruRuntimeState = { version: 1, desired: null, legacy: {}, retired: {} };
    live = new Set<string>();
    configs = new Map<string, TMieruServerConfig>();
    counters: Record<string, TMieruMetrics> = {};
    calls: string[] = [];
    failApply: string | null = null;
    failStop: string | null = null;
    failSave = false;
    legacy = false;
    readonly legacySocket = 'legacy';
    socket(id: string) {
        return id;
    }
    dumpPath(id: string) {
        return id;
    }
    ids() {
        return [...this.live];
    }
    async prepare(_id: string) {}
    async hasLegacy() {
        return this.legacy;
    }
    async readDump(id: string) {
        return this.counters[id] ?? null;
    }
    async ensure(id: string) {
        this.calls.push(`ensure:${id}`);
        this.live.add(id);
    }
    async terminate(id: string) {
        this.calls.push(`terminate:${id}`);
        this.live.delete(id);
        this.configs.delete(id);
    }
    async apply(value: TMieruServerConfig, id: string) {
        this.calls.push(`apply:${id}`);
        if (this.failApply === id) {
            this.failApply = null;
            throw new Error('apply failed');
        }
        this.configs.set(id, structuredClone(value));
        return { status: 'RUNNING', version: '3.36.0', operation: 'STARTED' };
    }
    async stop(id: string) {
        this.calls.push(`stop:${id}`);
        if (this.failStop === id) throw new Error('stop failed');
        this.configs.delete(id);
        return { status: 'IDLE', operation: 'STOPPED' };
    }
    async status(id: string) {
        return {
            status: this.configs.has(id) ? 'RUNNING' : 'IDLE',
            version: '3.36.0',
            metrics: this.counters[id] ?? {},
        };
    }
    async load() {
        return structuredClone(this.saved);
    }
    async save(state: MieruRuntimeState) {
        if (this.failSave) {
            this.failSave = false;
            throw new Error('save failed');
        }
        this.saved = structuredClone(state);
    }
}

function runtime(io = new FakeRuntimeIO()) {
    return new MieruRuntimeService(
        { getOrThrow: () => true } as unknown as TypedConfigService,
        io as unknown as MieruControlClient,
        io as unknown as MieruDaemonManager,
        io as unknown as MieruRuntimeStore,
    );
}

test('isolated Mieru reconciles users independently and stops revoked sessions before applying', async () => {
    const io = new FakeRuntimeIO();
    const service = runtime(io);
    await service.apply(
        desired([
            [A, config(24443)],
            [B, config(25443, '2')],
        ]),
    );
    assert.deepEqual(
        io.configs.get(A)?.users.map((user) => user.name),
        ['1'],
    );
    assert.deepEqual(
        io.configs.get(B)?.users.map((user) => user.name),
        ['2'],
    );
    io.calls = [];
    await service.apply(
        desired([
            [A, config(24443, '3')],
            [B, config(25443, '2')],
        ]),
    );
    assert.ok(io.calls.indexOf(`stop:${A}`) < io.calls.indexOf(`apply:${A}`));
    assert.equal(io.calls.includes(`stop:${B}`), false);
});

test('removed listeners stop and retain their final per-instance counters', async () => {
    const io = new FakeRuntimeIO();
    const service = runtime(io);
    await service.apply(
        desired([
            [A, config(24443)],
            [B, config(25443, '2')],
        ]),
    );
    io.counters[B] = { users: { '2': { UploadBytes: '91', DownloadBytes: '92' } } };
    await service.apply(desired([[A, config(24443)]]));
    assert.deepEqual(io.ids(), [A]);
    assert.deepEqual((await service.status()).instanceMetrics?.[B], io.counters[B]);
    assert.deepEqual(io.saved.retired[B], io.counters[B]);
});

test('partial apply failure rolls back every listener and persists the previous desired state', async () => {
    const io = new FakeRuntimeIO();
    const service = runtime(io);
    const before = desired([[A, config(24443)]]);
    await service.apply(before);
    io.failApply = B;
    await assert.rejects(
        service.apply(
            desired([
                [A, config(24443, '3')],
                [B, config(25443)],
            ]),
        ),
        (error: unknown) => {
            assert.ok(error instanceof MieruControlError);
            return error.rollbackSucceeded;
        },
    );
    assert.deepEqual(io.ids(), [A]);
    assert.deepEqual(io.configs.get(A), before.instances[0].config);
    assert.deepEqual(io.saved.desired, before);
});

test('an explicit failed stop still persists null, attempts every child and cannot auto-revive', async () => {
    const io = new FakeRuntimeIO();
    const service = runtime(io);
    await service.apply(
        desired([
            [A, config(24443)],
            [B, config(25443)],
        ]),
    );
    io.failStop = A;
    await assert.rejects(service.stop(), /could not be stopped/);
    assert.deepEqual(io.ids(), []);
    assert.equal(io.saved.desired, null);
    io.failStop = null;
    await runtime(io).onModuleInit();
    assert.deepEqual(io.ids(), []);
});

test('graceful restart restores only committed listeners; stop overrides restart state', async () => {
    const io = new FakeRuntimeIO();
    const first = runtime(io);
    await first.apply(desired([[A, config(24443)]]));
    await first.onModuleDestroy();
    assert.deepEqual(io.ids(), []);
    const second = runtime(io);
    await second.onModuleInit();
    assert.deepEqual(io.ids(), [A]);
    await second.stop();
    await runtime(io).onModuleInit();
    assert.deepEqual(io.ids(), []);
});

test('legacy single listener migrates after stopping the sidecar; legacy multi-listener is rejected', async () => {
    const io = new FakeRuntimeIO();
    io.legacy = true;
    const service = runtime(io);
    const legacy = config(24443);
    await service.apply(legacy);
    assert.equal(io.calls[0], 'stop:legacy');
    await assert.rejects(
        service.apply({
            ...legacy,
            portBindings: [...legacy.portBindings, { port: 25443, protocol: 'TCP' }],
        }),
        /cannot preserve/,
    );
});

test('pre-mutation persistence failure changes no live listeners', async () => {
    const io = new FakeRuntimeIO();
    const service = runtime(io);
    await service.apply(desired([[A, config(24443)]]));
    io.calls = [];
    io.failSave = true;
    await assert.rejects(service.apply(desired([[B, config(25443)]])), /save failed/);
    assert.deepEqual(io.calls, []);
    assert.deepEqual(io.ids(), [A]);
    io.failApply = B;
    await assert.rejects(service.apply(desired([[B, config(25443)]])));
    assert.deepEqual(io.configs.get(A), config(24443));
});
