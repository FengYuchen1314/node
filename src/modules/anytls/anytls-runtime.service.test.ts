import assert from 'node:assert/strict';
import { test } from 'node:test';

import { TypedConfigService } from '@common/config/app-config';
import { AnyTlsConfigSchema, TAnyTlsConfig } from '@libs/contracts/models';

import { AnyTlsRuntimeIO, PreparedAnyTls } from './anytls-runtime.io';
import { AnyTlsRuntimeService, AnyTlsUpdateError, difference } from './anytls-runtime.service';
import {
    AnyTlsRuntimeState,
    AnyTlsRuntimeStateSchema,
    AnyTlsRuntimeStore,
} from './anytls-runtime.store';
import { AnyTlsCounters } from './anytls-stats.client';

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
class FakeIO {
    saved: AnyTlsRuntimeState = { version: 1, desired: null, totals: {}, seen: {}, billed: {} };
    counters: AnyTlsCounters = {};
    running = false;
    owner = false;
    preparedCount = 0;
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
function service(io: FakeIO, enabled = true) {
    return new AnyTlsRuntimeService(
        { getOrThrow: () => enabled } as unknown as TypedConfigService,
        io as unknown as AnyTlsRuntimeIO,
        io as unknown as AnyTlsRuntimeStore,
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
