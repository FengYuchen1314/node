import assert from 'node:assert/strict';
import { test } from 'node:test';

import { TypedConfigService } from '@common/config/app-config';
import { NodeEdgePlanSchema, TAnyTlsConfig, TNodeEdgePlan } from '@libs/contracts/models';

import {
    rejectLocalEdgeLoops,
    renderCaddyfile,
    renderHaproxy,
    validateEdgePlan,
} from './edge-config';
import { EdgeConfigIO, EdgeSnapshot } from './edge-config.io';
import { EdgeService } from './edge.service';

const plan: TNodeEdgePlan = {
    version: 1,
    publicHttpPort: 80,
    publicHttpsPort: 443,
    caddyHttpTarget: '127.0.0.1:18080',
    caddyHttpsTarget: '127.0.0.1:18443',
    routes: [
        {
            sni: 'cover.example.com',
            targetHost: '127.0.0.1',
            targetPort: 12443,
            sendProxyV2: true,
            inboundTag: 'VLESS',
        },
    ],
    management: { domains: ['panel.example.com'], upstream: 'http://127.0.0.1:3000/' },
    website: null,
};
const xray = {
    inbounds: [
        {
            tag: 'VLESS',
            protocol: 'vless',
            port: 12443,
            listen: '127.0.0.1',
            streamSettings: {
                security: 'reality',
                realitySettings: { serverNames: ['cover.example.com'] },
                sockopt: { acceptProxyProtocol: true },
            },
        },
    ],
};

// Binding-only fixture; these placeholders cannot pass native TLS validation or start a runtime.
const anyTls: TAnyTlsConfig = {
    version: 1,
    listeners: [
        {
            id: '11111111-1111-4111-8111-111111111111',
            tag: 'ANYTLS',
            wrapperPort: 14001,
            innerPort: 16001,
            camouflage: { serverName: 'anytls.example.com', address: '192.0.2.1', port: 443 },
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
};
const mixedPlan: TNodeEdgePlan = {
    ...plan,
    routes: [
        ...plan.routes,
        {
            sni: anyTls.listeners[0].camouflage.serverName,
            targetHost: '127.0.0.1',
            targetPort: anyTls.listeners[0].wrapperPort,
            sendProxyV2: false,
            inboundTag: anyTls.listeners[0].tag,
        },
    ],
};

test('edge binds exact SNI to PROXY-v2 loopback listeners and leaves web fallback', () => {
    const config = renderHaproxy(validateEdgePlan(plan, xray));
    assert.match(config, /req.ssl_sni -i cover\.example\.com/);
    assert.match(config, /127\.0\.0\.1:12443 send-proxy-v2/);
    assert.match(config, /default_backend xboard_caddy_https/);
    assert.match(config, /bind :443/);
});

test('mixed edge sends PROXY-v2 only to VLESS and never exposes the inner AnyTLS listener', () => {
    const config = renderHaproxy(validateEdgePlan(mixedPlan, xray, anyTls));
    assert.match(config, /127\.0\.0\.1:12443 send-proxy-v2 check/);
    assert.match(config, /127\.0\.0\.1:14001 check/);
    assert.doesNotMatch(config, /14001 send-proxy|16001/);
    assert.match(config, /req.ssl_sni -i anytls\.example\.com/);
    assert.match(config, /default_backend xboard_caddy_https/);
});

test('raw TLS routes fail closed without both explicit protected runtime configurations', () => {
    for (const candidate of [undefined, xray])
        assert.throws(() => validateEdgePlan(mixedPlan, candidate), /protected AnyTLS wrapper/);
    assert.throws(() => validateEdgePlan(mixedPlan, undefined, anyTls), /explicit Xray inbounds/);
    assert.throws(() => validateEdgePlan(mixedPlan, {}, anyTls), /explicit Xray inbounds/);
    const anyTlsOnly = { ...mixedPlan, routes: [mixedPlan.routes[1]] };
    assert.doesNotThrow(() => validateEdgePlan(anyTlsOnly, { inbounds: [] }, anyTls));
    // An unchanged VLESS route may not silently drop the required PROXY header.
    assert.throws(
        () =>
            validateEdgePlan(
                {
                    ...plan,
                    routes: [{ ...plan.routes[0], sendProxyV2: false }],
                },
                xray,
            ),
        /protected AnyTLS wrapper/,
    );
});

test('mixed edge rejects inner/management targets, wrong SNI, wrong tag and wrong header mode', () => {
    for (const patch of [
        { targetPort: 16001 },
        { targetPort: 2222 },
        { targetPort: 2019 },
        { sni: 'other.example.com' },
        { inboundTag: 'OTHER' },
        { sendProxyV2: true },
        { targetHost: '0.0.0.0' },
    ])
        assert.throws(() =>
            validateEdgePlan(
                {
                    ...mixedPlan,
                    routes: [mixedPlan.routes[0], { ...mixedPlan.routes[1], ...patch }],
                },
                xray,
                anyTls,
            ),
        );
    assert.throws(
        () => validateEdgePlan(plan, xray, anyTls),
        /requires its own protected edge route/,
    );
    assert.throws(
        () =>
            validateEdgePlan(
                {
                    ...mixedPlan,
                    website: { domains: ['anytls.example.com'], upstream: 'http://127.0.0.1:3001' },
                },
                xray,
                anyTls,
            ),
        /must not share SNI/,
    );
    assert.throws(
        () =>
            validateEdgePlan(
                {
                    ...mixedPlan,
                    routes: [...mixedPlan.routes, mixedPlan.routes[1]],
                },
                xray,
                anyTls,
            ),
        /Duplicate edge SNI/,
    );
});

test('mixed edge reserves both AnyTLS ports against numeric, comma-list and ranged Xray ports', () => {
    for (const port of [
        14001,
        16001,
        '14001',
        '16001',
        '11000,14001,20000',
        '16000-16002',
        '10000,13999-14002,65000',
        '1-65535',
    ]) {
        assert.throws(
            () =>
                validateEdgePlan(
                    mixedPlan,
                    {
                        inbounds: [
                            ...xray.inbounds,
                            { tag: 'OTHER', port, protocol: 'socks', listen: '::' },
                        ],
                    },
                    anyTls,
                ),
            /listener ports overlap/,
            String(port),
        );
    }
    for (const port of [
        undefined,
        null,
        {},
        '',
        'invalid',
        '14001-',
        '2-1',
        0,
        65536,
        '1,',
        1.5,
        -1,
        '1-9999999999999999999999999999999',
    ]) {
        assert.throws(
            () =>
                validateEdgePlan(
                    mixedPlan,
                    {
                        inbounds: [...xray.inbounds, { tag: 'OTHER', port }],
                    },
                    anyTls,
                ),
            /Cannot validate Xray ports/,
            String(port),
        );
    }
    assert.doesNotThrow(() =>
        validateEdgePlan(
            mixedPlan,
            {
                inbounds: [
                    ...xray.inbounds,
                    { tag: 'OTHER', port: '13000-14000, 14002-16000,16002-65535' },
                ],
            },
            anyTls,
        ),
    );
});

test('edge rejects ambiguous duplicate Xray tags and cross-runtime identities', () => {
    assert.throws(
        () => validateEdgePlan(plan, { inbounds: [...xray.inbounds, xray.inbounds[0]] }),
        /protected Xray listener/,
    );
    for (const tag of ['ANYTLS', 'VLESS'])
        assert.throws(
            () =>
                validateEdgePlan(
                    mixedPlan,
                    {
                        inbounds: [...xray.inbounds, { tag, port: 17001 }],
                    },
                    anyTls,
                ),
            /inbound tags must be unique/,
        );
    assert.throws(
        () => validateEdgePlan(mixedPlan, { inbounds: [null] }, anyTls),
        /Invalid Xray inbound/,
    );
});

test('website upstreams cannot bypass the AnyTLS wrapper by reaching local inner TLS', async () => {
    for (const host of ['localhost', '127.0.0.1', '127.0.0.2', '[::1]', '[::ffff:127.0.0.1]'])
        for (const port of [14001, 16001])
            await assert.rejects(
                rejectLocalEdgeLoops(
                    {
                        ...mixedPlan,
                        website: {
                            domains: ['site.example.com'],
                            upstream: `http://${host}:${port}`,
                        },
                    },
                    anyTls,
                ),
                /resolves back/,
            );
    await assert.doesNotReject(
        rejectLocalEdgeLoops(
            {
                ...mixedPlan,
                website: { domains: ['site.example.com'], upstream: 'http://192.0.2.100:16001' },
            },
            anyTls,
        ),
    );
});

test('Caddy renders private listeners, public HTTPS redirects and loop protection', () => {
    const config = renderCaddyfile(plan);
    assert.match(config, /default_bind 127\.0\.0\.1/);
    assert.match(config, /redir @managed https:\/\/\{host\}\{uri\} 308/);
    assert.match(config, /https:\/\/panel\.example\.com:18443/);
    assert.match(config, /reverse_proxy "http:\/\/127\.0\.0\.1:3000"/);
    assert.match(config, /respond @loop "Reverse proxy loop detected" 508/);
    assert.doesNotMatch(config, /tls_insecure_skip_verify/);
    const unconfigured = renderCaddyfile({ ...plan, management: null });
    assert.doesNotMatch(unconfigured, /https_port 18443/);
    assert.match(unconfigured, /http:\/\/127\.0\.0\.1:18443/);
});

test('edge rejects unbound routes, config injection, internal-port targets and local DNS loops', async () => {
    assert.throws(() => validateEdgePlan(plan, { inbounds: [] }), /does not match/);
    assert.throws(() =>
        NodeEdgePlanSchema.parse({ ...plan, routes: [{ ...plan.routes[0], sni: 'x\nbind :22' }] }),
    );
    assert.throws(
        () => validateEdgePlan({ ...plan, routes: [{ ...plan.routes[0], targetPort: 2019 }] }),
        /reserved/,
    );
    assert.throws(
        () =>
            validateEdgePlan({
                ...plan,
                website: {
                    domains: ['site.example.com'],
                    upstream: 'http://upstream.example.com/path',
                },
            }),
        /origin/,
    );
    await assert.rejects(
        rejectLocalEdgeLoops({
            ...plan,
            website: { domains: ['site.example.com'], upstream: 'http://localhost:443/' },
        }),
        /resolves back/,
    );
});

class FakeIO {
    events: string[] = [];
    failApply = false;
    failRestore = false;
    journal: EdgeSnapshot | null = null;
    current: TNodeEdgePlan | null = null;
    async recover() {
        this.events.push('recover');
    }
    async status() {
        return { haproxy: true, caddy: true };
    }
    async snapshot(): Promise<EdgeSnapshot> {
        return { haproxy: 'old', caddy: {}, plan: this.current };
    }
    async begin(snapshot: EdgeSnapshot) {
        this.journal = snapshot;
        this.events.push('begin');
    }
    async apply(next: TNodeEdgePlan) {
        this.events.push('apply');
        if (this.failApply) throw new Error('reload failed');
        this.current = next;
    }
    async commit() {
        this.events.push('commit');
        this.journal = null;
    }
    async restore(snapshot: EdgeSnapshot) {
        this.events.push('restore');
        if (this.failRestore) throw new Error('restore failed');
        this.current = snapshot.plan;
        this.journal = null;
    }
    async readPlan() {
        return this.current;
    }
}
const service = (io: FakeIO, enabled = true) =>
    new EdgeService(
        { getOrThrow: () => enabled } as unknown as TypedConfigService,
        io as unknown as EdgeConfigIO,
    );

test('the existing Agent start path rejects raw routes before any mutation until runtime coordination is connected', async () => {
    const io = new FakeIO();
    await assert.rejects(
        service(io).run(
            mixedPlan,
            xray,
            async () => assert.fail('must not start the core'),
            async () => assert.fail('must not need rollback'),
        ),
        /protected AnyTLS wrapper/,
    );
    assert.deepEqual(io.events, []);
    assert.equal(io.journal, null);
});

test('Caddy control requests supply a matching Origin without disabling CSRF checks', async (context) => {
    const fetchMock = context.mock.method(
        globalThis,
        'fetch',
        async (_url: string, init: RequestInit) => {
            assert.equal(new Headers(init.headers).get('Origin'), 'http://127.0.0.1:2019');
            assert.equal(init.redirect, 'error');
            return new Response('{}');
        },
    );
    const values: Record<string, string> = {
        EDGE_CONFIG_DIR: '.',
        EDGE_HAPROXY_MASTER_SOCKET: 'nonexistent-edge-test-socket',
        EDGE_CADDY_ADMIN_URL: 'http://127.0.0.1:2019',
    };
    const io = new EdgeConfigIO({
        getOrThrow: (key: string) => values[key],
    } as unknown as TypedConfigService);
    assert.equal((await io.status()).caddy, true);
    assert.equal(fetchMock.mock.callCount(), 1);
});

test('edge commits only after the core and both edge processes succeed', async () => {
    const io = new FakeIO();
    const edge = service(io);
    const result = await edge.run(
        plan,
        xray,
        async () => {
            io.events.push('core');
            return 42;
        },
        async () => {
            assert.fail('unexpected rollback');
        },
    );
    assert.equal(result, 42);
    assert.deepEqual(io.events, ['recover', 'begin', 'core', 'apply', 'commit']);
    assert.equal(io.journal, null);
});

test('a failed edge reload restores the previous core and edge configuration', async () => {
    const io = new FakeIO();
    io.failApply = true;
    await assert.rejects(
        service(io).run(
            plan,
            xray,
            async () => 42,
            async () => {
                io.events.push('core-rollback');
            },
        ),
        /previous configuration restored/,
    );
    assert.deepEqual(io.events.slice(-2), ['core-rollback', 'restore']);
    assert.equal(io.journal, null);
    io.failRestore = true;
    await assert.rejects(
        service(io).run(
            plan,
            xray,
            async () => 42,
            async () => {},
        ),
        /not confirmed/,
    );
    assert.notEqual(io.journal, null);
});

test('stopping a proxy preserves website routes and blocks new proxy sessions before stopping the core', async () => {
    const io = new FakeIO();
    io.current = plan;
    await service(io).stop(async () => {
        io.events.push('stop-core');
    });
    assert.deepEqual(io.current?.routes, []);
    assert.deepEqual(io.current?.management, plan.management);
    assert.deepEqual(io.events.slice(-3), ['apply', 'commit', 'stop-core']);
});

test('non-edge Agents preserve the old core path and reject unsupported edge plans', async () => {
    const io = new FakeIO();
    const edge = service(io, false);
    assert.equal(
        await edge.run(
            undefined,
            {},
            async () => false,
            async () => {},
        ),
        false,
    );
    assert.deepEqual(io.events, []);
    await assert.rejects(
        edge.run(
            plan,
            xray,
            async () => true,
            async () => {},
        ),
        /no managed/,
    );
});
