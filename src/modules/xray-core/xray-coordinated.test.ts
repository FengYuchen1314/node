import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { TypedConfigService } from '@common/config/app-config';
import { StartXrayCommand } from '@libs/contracts/commands';
import { TAnyTlsConfig, TNodeEdgePlan } from '@libs/contracts/models';

import { CoordinatedAnyTlsTransition } from '../anytls/anytls-runtime.service';
import { EdgeConfigIO, EdgeSnapshot, quiescentEdgeSnapshot } from '../edge/edge-config.io';
import { EdgeService } from '../edge/edge.service';
import { XrayController } from './xray.controller';

const request = (generation: string): StartXrayCommand.Request => ({
    internals: { forceRestart: false, hashes: { emptyConfig: generation, inbounds: [] } },
    xrayConfig: { inbounds: [], generation },
    anyTlsConfig: { version: 1, listeners: [] },
    edgePlan: {
        version: 1,
        publicHttpPort: 80,
        publicHttpsPort: 443,
        caddyHttpTarget: '127.0.0.1:18080',
        caddyHttpsTarget: '127.0.0.1:18443',
        routes: [],
        management: null,
        website: null,
    },
});

function fixture(coordinated = true) {
    const events: string[] = [];
    const state = {
        denied: false,
        failPublish: false,
        failXrayStart: false,
        failRollback: false,
        failXrayStop: false,
        failAnyTlsStop: false,
        ready: undefined as Promise<void> | undefined,
        entered: undefined as (() => void) | undefined,
        current: null as TNodeEdgePlan | null,
        journal: null as EdgeSnapshot | null,
    };
    const io = {
        recover: async () => {},
        snapshot: async () => ({ haproxy: '', caddy: {}, plan: state.current }),
        begin: async (snapshot: EdgeSnapshot) => {
            state.journal = snapshot;
        },
        commit: async () => {
            state.journal = null;
            events.push('commit');
        },
        readPlan: async () => state.current,
        apply: async (plan: TNodeEdgePlan) => {
            events.push('publish');
            if (state.failPublish) throw new Error('edge reload failed');
            state.current = plan;
        },
        restore: async (snapshot: EdgeSnapshot) => {
            events.push('restore-edge');
            state.current = snapshot.plan;
            state.journal = null;
        },
        withdraw: async (snapshot: EdgeSnapshot) => {
            events.push('withdraw');
            state.current = quiescentEdgeSnapshot(snapshot).plan;
            state.journal = null;
        },
    };
    const env = {
        getOrThrow: (key: string) =>
            ({
                EDGE_ENABLED: coordinated,
                ANYTLS_ENABLED: coordinated,
                NODE_PORT: 2222,
                ANYTLS_STATS_PORT: 15999,
                ANYTLS_CONTROL_PORT: 15998,
            })[key],
    };
    const edge = new EdgeService(
        env as unknown as TypedConfigService,
        io as unknown as EdgeConfigIO,
    );
    const controller = new XrayController(
        ...([
            {
                startXray: async (body: StartXrayCommand.Request) => {
                    const generation = String(body.xrayConfig.generation);
                    events.push(
                        `xray:${generation}${body.internals.forceRestart ? ':forced' : ''}`,
                    );
                    return {
                        isOk: true,
                        response: {
                            isStarted: !(
                                state.failXrayStart ||
                                (body.internals.forceRestart && state.failRollback)
                            ),
                            error: 'fixture failure',
                            version: 'test',
                            nodeInformation: { version: 'test' },
                            system: {},
                        },
                    };
                },
                stopXray: async () => {
                    events.push('stop-xray');
                    if (state.failXrayStop) throw new Error('stop failed');
                    return { isOk: true, response: { isStopped: true } };
                },
            },
            edge,
            {
                coordinated: () => coordinated,
                withCoordinatedUpdate: async <T>(
                    _config: TAnyTlsConfig,
                    run: (runtime: CoordinatedAnyTlsTransition) => Promise<T>,
                ) => {
                    events.push('lock-anytls');
                    try {
                        return await run({
                            quiesce: async () => {
                                events.push('quiesce-anytls');
                            },
                            apply: async () => {
                                events.push('start-anytls');
                                state.entered?.();
                                await state.ready;
                                events.push('ready-anytls');
                            },
                            rollback: async () => {
                                events.push('rollback-anytls');
                            },
                        });
                    } finally {
                        events.push('unlock-anytls');
                    }
                },
                withCoordinatedStop: async <T>(run: (stop: () => Promise<void>) => Promise<T>) =>
                    run(async () => {
                        events.push('stop-anytls');
                        if (state.failAnyTlsStop) throw new Error('accounting failure');
                    }),
            },
            {
                prepareXray: async () => {
                    events.push('preflight-xray');
                    if (state.denied) throw new Error('Cloudflare CDN');
                },
            },
        ] as unknown as ConstructorParameters<typeof XrayController>),
    );
    return { controller, events, state };
}

test('coordinated contract retains the explicit empty AnyTLS configuration', () => {
    assert.deepEqual(StartXrayCommand.RequestSchema.parse(request('a')).anyTlsConfig, {
        version: 1,
        listeners: [],
    });
    assert(
        !StartXrayCommand.RequestSchema.safeParse({
            ...request('a'),
            anyTlsConfig: { version: 1, listeners: [], insecure: true },
        }).success,
    );
});

test('controller rejects omission or unsupported joint mode before any mutation and preserves legacy start', async () => {
    for (const coordinated of [true, false]) {
        const { controller, events } = fixture(coordinated);
        const body = request('a');
        if (coordinated) delete body.anyTlsConfig;
        await assert.rejects(controller.startXray(body, '127.0.0.1'), /explicit anyTlsConfig/);
        assert.deepEqual(events, []);
        if (!coordinated) {
            delete body.anyTlsConfig;
            delete body.edgePlan;
            assert.equal((await controller.startXray(body, '127.0.0.1')).response.isStarted, true);
            assert.deepEqual(events, ['xray:a']);
        }
    }
});

test('joint Xray camouflage preflight cannot mutate the edge or either runtime', async () => {
    const { controller, events, state } = fixture();
    state.denied = true;
    await assert.rejects(controller.startXray(request('a'), '127.0.0.1'), /Cloudflare CDN/);
    assert.deepEqual(events, ['lock-anytls', 'preflight-xray', 'unlock-anytls']);
});

test('full controller waits for application readiness, retains the joint lock through publication, then runs a queued stop', async () => {
    const { controller, events, state } = fixture();
    const ready = Promise.withResolvers<void>();
    const entered = Promise.withResolvers<void>();
    state.ready = ready.promise;
    state.entered = entered.resolve;
    const start = controller.startXray(request('a'), '127.0.0.1');
    await entered.promise;
    assert(!events.includes('publish'));
    assert(!events.includes('unlock-anytls'));
    assert(events.indexOf('stop-xray') < events.indexOf('xray:a'));
    assert(events.indexOf('quiesce-anytls') < events.indexOf('xray:a'));
    const stop = controller.stopXray();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert(!events.includes('stop-anytls'));
    ready.resolve();
    assert.equal((await start).response.isStarted, true);
    assert.equal((await stop).response.isStopped, true);
    assert(events.indexOf('ready-anytls') < events.indexOf('publish'));
    assert(events.indexOf('commit') < events.indexOf('unlock-anytls'));
    assert(events.indexOf('unlock-anytls') < events.indexOf('stop-anytls'));
});

test('queued replacement rolls back to the preceding committed request, not an older generation', async () => {
    const { controller, events, state } = fixture();
    const ready = Promise.withResolvers<void>();
    const entered = Promise.withResolvers<void>();
    state.ready = ready.promise;
    state.entered = entered.resolve;
    const first = controller.startXray(request('a'), '127.0.0.1');
    await entered.promise;
    const second = controller.startXray(request('b'), '127.0.0.1');
    const failed = assert.rejects(second, /previous configuration restored/);
    ready.resolve();
    await first;
    state.failPublish = true;
    await failed;
    assert(events.includes('xray:a:forced'));
    assert(events.includes('rollback-anytls'));
    assert(events.lastIndexOf('quiesce-anytls') < events.indexOf('xray:a:forced'));
    assert(events.indexOf('rollback-anytls') < events.lastIndexOf('restore-edge'));
});

test('failed Xray rollback still attempts AnyTLS rollback and leaves edge admission withdrawn', async () => {
    const { controller, events, state } = fixture();
    await controller.startXray(request('a'), '127.0.0.1');
    state.failPublish = true;
    state.failRollback = true;
    await assert.rejects(controller.startXray(request('b'), '127.0.0.1'), /not confirmed/);
    assert(events.includes('rollback-anytls'));
    assert(events.lastIndexOf('withdraw') > events.indexOf('xray:a:forced'));
    assert.equal(events.at(-1), 'unlock-anytls');
});

test('joint stop attempts both cores even when either core fails', async () => {
    for (const failing of ['failXrayStop', 'failAnyTlsStop'] as const) {
        const { controller, events, state } = fixture();
        state[failing] = true;
        await assert.rejects(controller.stopXray(), /not confirmed/);
        assert(events.includes('stop-xray'));
        assert(events.includes('stop-anytls'));
    }
});
