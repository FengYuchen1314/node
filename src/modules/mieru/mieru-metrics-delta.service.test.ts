import assert from 'node:assert/strict';
import { test } from 'node:test';

import { TypedConfigService } from '@common/config/app-config';
import { TMieruMetrics } from '@libs/contracts/models';

import { IMieruStatusResult, MieruControlClient } from './mieru-control.client';
import {
    MieruMetricsBaselineState,
    MieruMetricsBaselineStore,
} from './mieru-metrics-baseline.store';
import { MieruMetricsDeltaService } from './mieru-metrics-delta.service';

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

test('Mieru consumers establish independent baselines and emit exact per-user deltas', async () => {
    const control = new FakeControl([
        metrics({ alice: [100n, 200n] }),
        metrics({ alice: [100n, 200n] }),
        metrics({ alice: [130n, 240n] }),
        metrics({ alice: [130n, 240n] }),
    ]);
    const service = createService(control);

    assert.deepEqual(await service.getUserDeltas('users', true), [
        { username: 'alice', uplink: 0, downlink: 0 },
    ]);
    assert.deepEqual(await service.getAggregateDelta(true), { uplink: 0, downlink: 0 });
    assert.deepEqual(await service.getUserDeltas('users', true), [
        { username: 'alice', uplink: 30, downlink: 40 },
    ]);
    assert.deepEqual(await service.getAggregateDelta(true), { uplink: 30, downlink: 40 });
});

test('Mieru reset=false observes without advancing its billing baseline', async () => {
    const control = new FakeControl([
        metrics({ alice: [10n, 20n] }),
        metrics({ alice: [15n, 26n] }),
        metrics({ alice: [18n, 29n] }),
        metrics({ alice: [20n, 30n] }),
    ]);
    const service = createService(control);

    await service.getUserDeltas('users', true);
    assert.deepEqual(await service.getUserDeltas('users', false), [
        { username: 'alice', uplink: 5, downlink: 6 },
    ]);
    assert.deepEqual(await service.getUserDeltas('users', true), [
        { username: 'alice', uplink: 8, downlink: 9 },
    ]);
    assert.deepEqual(await service.getUserDeltas('users', true), [
        { username: 'alice', uplink: 2, downlink: 1 },
    ]);
});

test('Mieru counter rollback emits the new cumulative value', async () => {
    const control = new FakeControl([
        metrics({ alice: [100n, 200n] }),
        metrics({ alice: [7n, 11n] }),
        metrics({ alice: [9n, 14n] }),
    ]);
    const service = createService(control);

    await service.getUserDeltas('users', true);
    assert.deepEqual(await service.getUserDeltas('users', true), [
        { username: 'alice', uplink: 7, downlink: 11 },
    ]);
    assert.deepEqual(await service.getUserDeltas('users', true), [
        { username: 'alice', uplink: 2, downlink: 3 },
    ]);
});

test('Mieru bills a user metric that appears after the initial baseline', async () => {
    const control = new FakeControl([metrics({}), metrics({ alice: [7n, 11n] })]);
    const service = createService(control);

    assert.deepEqual(await service.getUserDeltas('users', true), []);
    assert.deepEqual(await service.getUserDeltas('users', true), [
        { username: 'alice', uplink: 7, downlink: 11 },
    ]);
});

test('Mieru deltas are chunked without crossing JavaScript safe integer precision', async () => {
    const current = MAX_SAFE * 3n;
    const control = new FakeControl([
        metrics({ alice: [0n, 0n] }),
        metrics({ alice: [current, current] }),
        metrics({ alice: [current, current] }),
    ]);
    const service = createService(control);

    await service.getUserDeltas('users', true);
    const first = (await service.getUserDeltas('users', true))[0];
    const second = (await service.getUserDeltas('users', true))[0];
    assert.equal(Number.isSafeInteger(first.uplink), true);
    assert.equal(Number.isSafeInteger(first.downlink), true);
    assert.equal(BigInt(first.uplink) + BigInt(first.downlink), MAX_SAFE);
    assert.equal(BigInt(second.uplink) + BigInt(second.downlink), MAX_SAFE);
});

test('Mieru aggregate uses one safe budget across all users and only sums user counters', async () => {
    const current = MAX_SAFE * 2n;
    const control = new FakeControl([
        metrics({ alice: [0n, 0n], bob: [0n, 0n] }),
        metrics({ alice: [current, 3n], bob: [5n, current] }),
    ]);
    const service = createService(control);

    await service.getAggregateDelta(true);
    const aggregate = await service.getAggregateDelta(true);
    assert.equal(Number.isSafeInteger(aggregate.uplink), true);
    assert.equal(Number.isSafeInteger(aggregate.downlink), true);
    assert.equal(BigInt(aggregate.uplink) + BigInt(aggregate.downlink), MAX_SAFE);
});

test('Mieru rejects malformed user counters without advancing the baseline', async () => {
    const control = new FakeControl([
        metrics({ alice: [100n, 200n] }),
        {
            users: { alice: { UploadBytes: '-1', DownloadBytes: '210' } },
        },
        metrics({ alice: [120n, 220n] }),
    ]);
    const service = createService(control);

    await service.getUserDeltas('users', true);
    await assert.rejects(
        service.getUserDeltas('users', true),
        /not a non-negative decimal integer/,
    );
    assert.deepEqual(await service.getUserDeltas('users', true), [
        { username: 'alice', uplink: 20, downlink: 20 },
    ]);
});

test('Mieru metrics can be activated after a successful runtime start', async () => {
    const control = new FakeControl([metrics({})]);
    const service = createService(control, false);

    assert.equal(service.isEnabled(), false);
    service.enable();
    assert.equal(service.isEnabled(), true);
    assert.deepEqual(await service.getAggregateDelta(true), { uplink: 0, downlink: 0 });
});

test('Mieru restores both billing baselines after a Node process restart', async () => {
    const store = new FakeBaselineStore();
    const firstProcess = createService(
        new FakeControl([metrics({ alice: [100n, 200n] })]),
        true,
        store,
    );
    await firstProcess.getUserDeltas('users', true);

    const restartedProcess = createService(
        new FakeControl([metrics({ alice: [130n, 240n] })]),
        true,
        store,
    );
    assert.deepEqual(await restartedProcess.getUserDeltas('users', true), [
        { username: 'alice', uplink: 30, downlink: 40 },
    ]);
});

test('Mieru does not advance an in-memory baseline when persistence fails', async () => {
    const store = new FakeBaselineStore();
    const service = createService(
        new FakeControl([
            metrics({ alice: [100n, 200n] }),
            metrics({ alice: [130n, 240n] }),
            metrics({ alice: [130n, 240n] }),
        ]),
        true,
        store,
    );
    await service.getUserDeltas('users', true);
    store.failNextSave = true;
    await assert.rejects(service.getUserDeltas('users', true), /fake persistence failure/);
    assert.deepEqual(await service.getUserDeltas('users', true), [
        { username: 'alice', uplink: 30, downlink: 40 },
    ]);
});

function createService(
    control: FakeControl,
    enabled = true,
    store = new FakeBaselineStore(),
): MieruMetricsDeltaService {
    const config = {
        getOrThrow(key: string): unknown {
            assert.equal(key, 'MIERU_ENABLED');
            return enabled;
        },
    } as TypedConfigService;
    return new MieruMetricsDeltaService(
        config,
        control as unknown as MieruControlClient,
        store as unknown as MieruMetricsBaselineStore,
    );
}

function metrics(users: Record<string, [bigint, bigint]>): TMieruMetrics {
    return {
        users: Object.fromEntries(
            Object.entries(users).map(([username, [uplink, downlink]]) => [
                username,
                { UploadBytes: uplink.toString(), DownloadBytes: downlink.toString() },
            ]),
        ),
    };
}

class FakeControl {
    private index = 0;

    constructor(private readonly snapshots: TMieruMetrics[]) {}

    public async status(): Promise<IMieruStatusResult> {
        const snapshot = this.snapshots[this.index++];
        if (!snapshot) throw new Error('Fake Mita metrics exhausted.');
        return { status: 'RUNNING', version: '3.36.0', metrics: snapshot };
    }
}

class FakeBaselineStore {
    public failNextSave = false;
    private state: MieruMetricsBaselineState | null = null;

    public async load(): Promise<MieruMetricsBaselineState | null> {
        return this.state === null ? null : cloneState(this.state);
    }

    public async save(state: MieruMetricsBaselineState): Promise<void> {
        if (this.failNextSave) {
            this.failNextSave = false;
            throw new Error('fake persistence failure');
        }
        this.state = cloneState(state);
    }
}

function cloneState(state: MieruMetricsBaselineState): MieruMetricsBaselineState {
    return {
        users: { initialized: state.users.initialized, baselines: new Map(state.users.baselines) },
        combined: {
            initialized: state.combined.initialized,
            baselines: new Map(state.combined.baselines),
        },
    };
}
