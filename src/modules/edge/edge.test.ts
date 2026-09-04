import assert from 'node:assert/strict';
import { test } from 'node:test';

import { TypedConfigService } from '@common/config/app-config';
import { NodeEdgePlanSchema, TNodeEdgePlan } from '@libs/contracts/models';

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

test('edge binds exact SNI to PROXY-v2 loopback listeners and leaves web fallback', () => {
    const config = renderHaproxy(validateEdgePlan(plan, xray));
    assert.match(config, /req.ssl_sni -i cover\.example\.com/);
    assert.match(config, /127\.0\.0\.1:12443 send-proxy-v2/);
    assert.match(config, /default_backend xboard_caddy_https/);
    assert.match(config, /bind :443/);
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
