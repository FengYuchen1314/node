import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { TypedConfigService } from '@common/config/app-config';

import {
    MieruMetricsBaselineState,
    MieruMetricsBaselineStore,
} from './mieru-metrics-baseline.store';

test('Mieru baseline store atomically round-trips its versioned state', async (context) => {
    const directory = await mkdtemp(join(tmpdir(), 'rw-mita-baseline-test-'));
    context.after(() => rm(directory, { recursive: true, force: true }));
    const path = join(directory, 'baselines.json');
    const store = createStore(path);
    const state = baselineState();

    await store.save(state);
    state.users.baselines.set('alice', { uplink: 789n, downlink: 987n });
    await store.save(state);
    const restored = await store.load();
    assert.ok(restored);
    assert.equal(restored.users.initialized, true);
    assert.deepEqual(restored.users.baselines.get('alice'), { uplink: 789n, downlink: 987n });
    assert.equal(restored.combined.initialized, false);
    assert.deepEqual(await readdir(directory), ['baselines.json']);
    if (process.platform !== 'win32') {
        assert.equal((await stat(path)).mode & 0o777, 0o600);
    }
});

test('Mieru baseline store discards corrupt state for a zero-baseline rebuild', async (context) => {
    const directory = await mkdtemp(join(tmpdir(), 'rw-mita-baseline-test-'));
    context.after(() => rm(directory, { recursive: true, force: true }));
    const path = join(directory, 'baselines.json');
    await writeFile(path, '{"version":999}', { encoding: 'utf8', mode: 0o600 });

    assert.equal(await createStore(path).load(), null);
});

function createStore(path: string): MieruMetricsBaselineStore {
    const config = {
        getOrThrow(key: string): unknown {
            assert.equal(key, 'MIERU_METRICS_BASELINE_PATH');
            return path;
        },
    } as TypedConfigService;
    return new MieruMetricsBaselineStore(config);
}

function baselineState(): MieruMetricsBaselineState {
    return {
        users: {
            initialized: true,
            baselines: new Map([['alice', { uplink: 123n, downlink: 456n }]]),
        },
        combined: { initialized: false, baselines: new Map() },
    };
}
