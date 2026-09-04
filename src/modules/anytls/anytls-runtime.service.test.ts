import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { TypedConfigService } from '@common/config/app-config';
import { AnyTlsConfigSchema, TAnyTlsConfig } from '@libs/contracts/models';

import { CamouflageRuntimePolicy } from '../camouflage-domain/camouflage-runtime-policy.service';
import { AnyTlsConfigRenderer, validateAnyTlsConfig } from './anytls-config';
import { AnyTlsRuntimeIO, PreparedAnyTls } from './anytls-runtime.io';
import { AnyTlsRuntimeService, AnyTlsUpdateError, difference } from './anytls-runtime.service';
import {
    AnyTlsRuntimeState,
    AnyTlsRuntimeStateSchema,
    AnyTlsRuntimeStore,
    privateJson,
} from './anytls-runtime.store';
import { AnyTlsCounters, AnyTlsStatsClient } from './anytls-stats.client';

const A = '11111111-1111-4111-8111-111111111111';
const desired = (port = 14001): TAnyTlsConfig => ({
    version: 1,
    listeners: [
        {
            id: A,
            tag: 'ANYTLS_A',
            wrapperPort: port,
            innerPort: 16001,
            camouflage: { serverName: 'example.com', address: '93.184.215.14', port: 443 },
            wrapperPassword: 'a'.repeat(48),
            shadowPassword: 'b'.repeat(48),
            tls: {
                serverName: 'inner.test',
                certificate: 'c'.repeat(64),
                privateKey: 'd'.repeat(64),
                caCertificate: 'e'.repeat(64),
            },
            users: [{ name: '1', password: 'f'.repeat(48) }],
        },
    ],
});

test('AnyTLS preparation rejects known Cloudflare camouflage before TLS parsing or process mutation', () => {
    const options = {
        statsPort: 15999,
        controlPort: 15998,
        controlSecret: 'fixture',
        nodePort: 2222,
    };
    for (const address of ['104.16.0.1', '2606:4700::1', '::ffff:104.16.0.1']) {
        const config = desired();
        config.listeners[0].camouflage.address = address;
        assert.throws(() => validateAnyTlsConfig(config, options), /Cloudflare CDN/);
    }
    for (const serverName of ['www.cloudflare.com', 'edge.cloudflare.net']) {
        const config = desired();
        config.listeners[0].camouflage.serverName = serverName;
        assert.throws(() => validateAnyTlsConfig(config, options), /Cloudflare CDN/);
    }
});
class FakeIO {
    saved: AnyTlsRuntimeState = { version: 1, desired: null, totals: {}, seen: {}, billed: {} };
    counters: AnyTlsCounters = {};
    running = false;
    owner = false;
    preparedCount = 0;
    discardedCount = 0;
    starts = 0;
    stops = 0;
    failStart = 0;
    failRetire = false;
    failWrite: ((state: AnyTlsRuntimeState) => boolean) | undefined;
    async acquire() {
        this.owner = true;
    }
    async release() {
        this.owner = false;
    }
    validate(config: unknown) {
        return AnyTlsConfigSchema.parse(config);
    }
    async prepare(config: TAnyTlsConfig) {
        this.preparedCount++;
        return { config } as PreparedAnyTls;
    }
    async start(_value: PreparedAnyTls) {
        if (this.failStart-- > 0) throw new Error('start failed');
        this.running = true;
        this.counters = {};
        this.starts++;
    }
    async discard(_value: PreparedAnyTls) {
        this.discardedCount++;
    }
    isRunning() {
        return this.running;
    }
    hasChildren() {
        return this.running;
    }
    async snapshot() {
        if (!this.running) throw new Error('not running');
        return structuredClone(this.counters);
    }
    async retire() {
        if (this.failRetire) throw new Error('cannot drain');
        this.running = false;
        this.stops++;
        return structuredClone(this.counters);
    }
    async abort() {
        this.running = false;
    }
    async load() {
        return structuredClone(this.saved);
    }
    async save(value: AnyTlsRuntimeState) {
        if (this.failWrite?.(value)) throw new Error('disk failure');
        this.saved = AnyTlsRuntimeStateSchema.parse(structuredClone(value));
    }
    add(name: string, up: number, down: number) {
        this.counters[name] = { uplink: String(up), downlink: String(down) };
    }
}
function service(io: FakeIO, enabled = true, check: () => Promise<void> = async () => {}) {
    return new AnyTlsRuntimeService(
        { getOrThrow: () => enabled } as unknown as TypedConfigService,
        io as unknown as AnyTlsRuntimeIO,
        io as unknown as AnyTlsRuntimeStore,
        { assertAnyTls: check } as unknown as CamouflageRuntimePolicy,
    );
}

test('AnyTLS schema rejects duplicate SNI, ports, credentials, config injection and dangerous usernames', () => {
    assert(AnyTlsConfigSchema.safeParse(desired()).success);
    for (const mutate of [
        (value: TAnyTlsConfig) => {
            value.listeners.push(structuredClone(value.listeners[0]));
        },
        (value: TAnyTlsConfig) => {
            value.listeners[0].innerPort = value.listeners[0].wrapperPort;
        },
        (value: TAnyTlsConfig) => {
            value.listeners[0].wrapperPort = 18080;
        },
        (value: TAnyTlsConfig) => {
            value.listeners[0].users[0].name = '__proto__';
        },
        (value: TAnyTlsConfig) => {
            value.listeners[0].users.push(structuredClone(value.listeners[0].users[0]));
        },
        (value: TAnyTlsConfig) => {
            value.listeners[0].tag = 'tag\nMATCH,DIRECT';
        },
        (value: TAnyTlsConfig) => {
            Object.assign(value.listeners[0], { 'allow-insecure': true });
        },
    ]) {
        const value = desired();
        mutate(value);
        assert(!AnyTlsConfigSchema.safeParse(value).success);
    }
});

test('AnyTLS is opt-in and rejects a start without touching state when disabled', async () => {
    const io = new FakeIO();
    const runtime = service(io, false);
    await runtime.onModuleInit();
    await assert.rejects(runtime.apply(desired()), /disabled/);
    assert.equal((await runtime.status()).available, false);
    assert.equal(io.owner, false);
});

test('unchanged reconciliation does not restart or keep writing private generation files', async () => {
    const io = new FakeIO();
    const runtime = service(io);
    await runtime.apply(desired());
    assert.equal((await runtime.apply(desired())).operation, 'UNCHANGED');
    assert.equal(io.starts, 1);
    assert.equal(io.preparedCount, 1);
    await runtime.onModuleDestroy();
});

test('live camouflage rejection preserves the prior runtime and also gates unchanged reconciliation', async () => {
    const io = new FakeIO();
    let denied = false;
    let checks = 0;
    const runtime = service(io, true, async () => {
        checks++;
        if (denied) throw new Error('Cloudflare CDN camouflage is forbidden.');
    });
    try {
        await runtime.apply(desired());
        const previous = structuredClone(io.saved);
        denied = true;
        for (const config of [desired(14002), desired()]) {
            await assert.rejects(runtime.apply(config), /Cloudflare CDN/);
            assert.deepEqual(io.saved, previous);
            assert.equal(io.preparedCount, 1);
            assert.equal(io.starts, 1);
            assert.equal(io.stops, 0);
            assert.equal(io.running, true);
        }
        assert.equal(checks, 3);
        // Operators must still be able to stop when DNS or the camouflage service is unavailable.
        await runtime.stop();
        assert.equal(checks, 3);
        assert.equal(io.running, false);
    } finally {
        await runtime.onModuleDestroy();
    }
});

test('rollback revalidates the old camouflage and cannot restart a now-forbidden endpoint', async () => {
    const io = new FakeIO();
    let checks = 0;
    const runtime = service(io, true, async () => {
        if (++checks === 3) throw new Error('Cloudflare CDN camouflage is forbidden.');
    });
    try {
        await runtime.apply(desired());
        io.failStart = 1;
        await assert.rejects(
            runtime.apply(desired(14002)),
            (error) => error instanceof AnyTlsUpdateError && !error.rollbackSucceeded,
        );
        assert.equal(checks, 3);
        assert.equal(io.preparedCount, 2);
        assert.equal(io.starts, 1);
        assert.equal(io.running, false);
        assert.equal(io.saved.desired, null);
    } finally {
        await runtime.onModuleDestroy();
    }
});

test('unsafe saved camouflage cannot start after reboot but management and explicit stop remain available', async () => {
    const io = new FakeIO();
    io.saved.desired = desired();
    const runtime = service(io, true, async () => {
        throw new Error('Cloudflare CDN camouflage is forbidden.');
    });
    try {
        await runtime.onModuleInit();
        assert.deepEqual(await runtime.status(), {
            available: true,
            isStarted: false,
            desiredListeners: 1,
            error: 'Saved AnyTLS configuration could not be restored safely.',
        });
        assert.equal(io.preparedCount, 0);
        assert.equal(io.starts, 0);
        await runtime.stop();
        assert.equal(io.saved.desired, null);
    } finally {
        await runtime.onModuleDestroy();
    }
});

test('cumulative users are not replayed by parallel consumers or after an Agent restart', async () => {
    const io = new FakeIO();
    const first = service(io);
    await first.apply(desired());
    io.add('1', 100, 200);
    const results = await Promise.all(Array.from({ length: 8 }, () => first.users(true)));
    assert.equal(
        results.reduce(
            (sum, users) => sum + users.reduce((total, user) => total + user.uplink, 0),
            0,
        ),
        100,
    );
    io.add('1', 130, 260);
    await first.onModuleDestroy();
    const next = service(io);
    await next.onModuleInit();
    assert.deepEqual(await next.users(true), [{ username: '1', uplink: 30, downlink: 60 }]);
    io.add('1', 7, 9);
    assert.deepEqual(await next.users(true), [{ username: '1', uplink: 7, downlink: 9 }]);
    await next.onModuleDestroy();
});

test('failed baseline persistence does not consume unbilled traffic', async () => {
    const io = new FakeIO();
    const runtime = service(io);
    await runtime.apply(desired());
    io.add('1', 42, 9);
    io.failWrite = (state) => !!state.billed['1'];
    await assert.rejects(runtime.users(true));
    io.failWrite = undefined;
    assert.deepEqual(await runtime.users(true), [{ username: '1', uplink: 42, downlink: 9 }]);
    assert.deepEqual(await runtime.users(true), []);
    await runtime.onModuleDestroy();
});

test('failed final-counter save is retained and retried before restarting a core generation', async () => {
    const io = new FakeIO();
    const runtime = service(io);
    await runtime.apply(desired());
    io.add('1', 91, 17);
    let failed = false;
    io.failWrite = (state) => {
        if (!failed && state.totals['1']) {
            failed = true;
            return true;
        }
        return false;
    };
    await assert.rejects(
        runtime.apply(desired(14002)),
        (error) => error instanceof AnyTlsUpdateError && error.rollbackSucceeded,
    );
    assert.equal(io.saved.desired?.listeners[0].wrapperPort, 14001);
    assert.deepEqual(await runtime.users(true), [{ username: '1', uplink: 91, downlink: 17 }]);
    await runtime.onModuleDestroy();
});

test('startup failure rolls back; failed rollback never claims runtime success', async () => {
    const io = new FakeIO();
    const runtime = service(io);
    await runtime.apply(desired());
    io.failStart = 1;
    await assert.rejects(
        runtime.apply(desired(14002)),
        (error) => error instanceof AnyTlsUpdateError && error.rollbackSucceeded,
    );
    assert.equal(io.running, true);
    io.failStart = 2;
    await assert.rejects(
        runtime.apply(desired(14003)),
        (error) => error instanceof AnyTlsUpdateError && !error.rollbackSucceeded,
    );
    assert.equal(io.saved.desired, null);
    assert.equal(io.running, false);
    await runtime.onModuleDestroy();
});

test('explicit stop is durable even if draining fails, and a restart cannot revive listeners', async () => {
    const io = new FakeIO();
    const runtime = service(io);
    await runtime.apply(desired());
    io.failRetire = true;
    await assert.rejects(runtime.stop(), /accounting/);
    assert.equal(io.saved.desired, null);
    assert.equal(io.running, false);
    await runtime.onModuleDestroy();
    const next = service(io);
    await next.onModuleInit();
    assert.equal((await next.status()).isStarted, false);
    await next.onModuleDestroy();
});

test('prototype-like usernames and very large lifetime totals do not corrupt accounting', () => {
    assert.deepEqual(
        {
            ...difference(
                { toString: { uplink: '9007199254740993', downlink: '1' } },
                { toString: { uplink: '9007199254740992', downlink: '0' } },
            ),
        },
        { toString: { uplink: '1', downlink: '1' } },
    );
    assert.throws(
        () =>
            difference(
                { '1': { uplink: '0', downlink: '1' } },
                { '1': { uplink: '2', downlink: '1' } },
            ),
        /reset/,
    );
});

test('duplicate shutdown hooks cannot overwrite a newer owner state', async () => {
    const io = new FakeIO();
    const first = service(io);
    await first.apply(desired());
    await first.onModuleDestroy();
    const next = service(io);
    await next.onModuleInit();
    await next.stop();
    await first.onModuleDestroy();
    assert.equal(io.saved.desired, null);
    await next.onModuleDestroy();
});

test('failed stop-intent persistence discards the unused preparation without stopping live traffic', async () => {
    const io = new FakeIO();
    const runtime = service(io);
    await runtime.apply(desired());
    const discarded = io.discardedCount;
    io.failWrite = (state) => state.desired === null;
    await assert.rejects(runtime.apply(desired(14002)), /disk failure/);
    assert.equal(io.running, true);
    assert.equal(io.starts, 1);
    assert.equal(io.stops, 0);
    assert.equal(io.discardedCount, discarded + 1);
    io.failWrite = undefined;
    await runtime.onModuleDestroy();
});

test('failed native preparation removes only its own generated configuration directory', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'rw-anytls-cleanup-'));
    const values = {
        ANYTLS_STATE_DIR: directory,
        ANYTLS_MIHOMO_PATH: join(directory, 'missing-core'),
        ANYTLS_SINGBOX_PATH: join(directory, 'missing-inner'),
        ANYTLS_SUPERVISOR_PATH: join(directory, 'missing-supervisor'),
        ANYTLS_STATS_PORT: 15999,
        ANYTLS_CONTROL_PORT: 15998,
        NODE_PORT: 2222,
    };
    const env = {
        getOrThrow: (key: keyof typeof values) => values[key],
    } as unknown as TypedConfigService;
    const renderer = {
        render: () => ({ config: desired(), outer: { secret: 'fixture' }, inner: {} }),
    } as unknown as AnyTlsConfigRenderer;
    const io = new AnyTlsRuntimeIO(env, renderer, new AnyTlsStatsClient());
    const untouched = join(directory, 'generation-11111111-1111-4111-8111-111111111111');
    try {
        await io.acquire();
        await privateJson(join(untouched, 'keep.json'), { userOwned: true });
        for (let attempt = 0; attempt < 3; attempt++)
            await assert.rejects(io.prepare(desired()), /Native AnyTLS/);
        // Even a generation-shaped path is not ours unless this process created it exclusively.
        await io.discard({ directory: untouched } as PreparedAnyTls);
        assert.deepEqual((await readdir(directory)).sort(), [
            'generation-11111111-1111-4111-8111-111111111111',
            'owner.pid',
        ]);
        assert.deepEqual(JSON.parse(await readFile(join(untouched, 'keep.json'), 'utf8')), {
            userOwned: true,
        });
    } finally {
        await io.release();
        await rm(directory, { recursive: true, force: true });
    }
});

test('shutdown releases a lease even when the state could not be loaded', async () => {
    const io = new FakeIO();
    io.load = async () => {
        throw new Error('invalid state');
    };
    const runtime = service(io);
    await assert.rejects(runtime.onModuleInit(), /invalid state/);
    assert.equal(io.owner, true);
    await runtime.onModuleDestroy();
    assert.equal(io.owner, false);
});
