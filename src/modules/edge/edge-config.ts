import { createHash } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { networkInterfaces } from 'node:os';

import {
    AnyTlsConfigSchema,
    NodeEdgePlanSchema,
    TAnyTlsConfig,
    TNodeEdgePlan,
} from '@libs/contracts/models';

import { canonicalizeEndpointAddress } from '../camouflage-domain/ip-address';

const EDGE_PORTS = new Set([80, 443, 2019, 18080, 18443]);

export function validateEdgePlan(
    input: unknown,
    xrayConfig?: Record<string, unknown>,
    anyTlsConfig?: TAnyTlsConfig,
    managementPorts: readonly number[] = [],
): TNodeEdgePlan {
    const plan = NodeEdgePlanSchema.parse(input);
    const anyTls = anyTlsConfig === undefined ? undefined : AnyTlsConfigSchema.parse(anyTlsConfig);
    if (anyTls) validateMixedListeners(xrayConfig, anyTls, managementPorts);
    const webDomains = [...(plan.management?.domains ?? []), ...(plan.website?.domains ?? [])];
    if (new Set(webDomains).size !== webDomains.length)
        throw new Error('Edge website domains overlap.');
    for (const route of plan.routes) {
        if (EDGE_PORTS.has(route.targetPort) || managementPorts.includes(route.targetPort))
            throw new Error('An edge route points to a reserved listener.');
        if (!route.sendProxyV2) {
            const listener = anyTls?.listeners.find((item) => item.tag === route.inboundTag);
            if (
                !listener ||
                listener.wrapperPort !== route.targetPort ||
                listener.camouflage.serverName !== route.sni
            ) {
                throw new Error('Edge route does not match its protected AnyTLS wrapper.');
            }
            continue;
        }
        if (xrayConfig) {
            const inbounds = xrayConfig.inbounds;
            if (!Array.isArray(inbounds)) throw new Error('Xray inbounds are missing.');
            const matches = inbounds.filter((item) => item?.tag === route.inboundTag);
            const inbound = matches[0];
            if (
                matches.length !== 1 ||
                inbound.listen !== '127.0.0.1' ||
                inbound.port !== route.targetPort ||
                inbound.protocol !== 'vless' ||
                inbound.streamSettings?.security !== 'reality' ||
                !inbound.streamSettings?.realitySettings?.serverNames?.includes(route.sni) ||
                inbound.streamSettings?.sockopt?.acceptProxyProtocol !== true
            ) {
                throw new Error('Edge route does not match its protected Xray listener.');
            }
        }
    }
    for (const listener of anyTls?.listeners ?? []) {
        if (!plan.routes.some((route) => !route.sendProxyV2 && route.inboundTag === listener.tag)) {
            throw new Error('Every managed AnyTLS listener requires its own protected edge route.');
        }
    }
    for (const site of [plan.management, plan.website]) {
        if (!site) continue;
        const upstream = new URL(site.upstream);
        if (upstream.pathname !== '/' || upstream.search)
            throw new Error('Use an upstream origin without a path or query.');
        const host = upstream.hostname.replace(/^\[|\]$/g, '');
        if (
            !isIP(host) &&
            !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(host)
        ) {
            throw new Error('Invalid edge upstream hostname.');
        }
        if (webDomains.includes(host))
            throw new Error('Edge website upstream forms a public-domain loop.');
    }
    return plan;
}

// This is binding validation, not certificate/CDN validation or permission to start either core.
// The coordinated runtime must still validate both native configurations before applying the plan.
function validateMixedListeners(
    xrayConfig: Record<string, unknown> | undefined,
    anyTls: TAnyTlsConfig,
    managementPorts: readonly number[],
): void {
    if (!Array.isArray(xrayConfig?.inbounds))
        throw new Error('Mixed edge validation requires explicit Xray inbounds.');
    const tags = new Set(anyTls.listeners.map((listener) => listener.tag));
    const ports = [
        ...managementPorts,
        ...EDGE_PORTS,
        ...anyTls.listeners.flatMap((listener) => [listener.wrapperPort, listener.innerPort]),
    ];
    for (const inbound of xrayConfig.inbounds) {
        if (!inbound || typeof inbound !== 'object')
            throw new Error('Invalid Xray inbound in mixed edge configuration.');
        if (typeof inbound.tag === 'string') {
            if (tags.has(inbound.tag))
                throw new Error('Xray and AnyTLS inbound tags must be unique on a server.');
            tags.add(inbound.tag);
        }
        // Do not assume only numeric ports: Xray also accepts comma lists and ranges.
        // Unknown/missing/dynamic ports cannot prove that a private listener is protected.
        const ranges = inboundPortRanges(inbound.port);
        if (ports.some((port) => ranges.some(([from, to]) => port >= from && port <= to)))
            throw new Error('Xray and AnyTLS listener ports overlap.');
    }
}

function inboundPortRanges(value: unknown): Array<[number, number]> {
    if (typeof value !== 'number' && typeof value !== 'string')
        throw new Error('Cannot validate Xray ports in mixed edge configuration.');
    return String(value)
        .split(',')
        .map((part) => {
            const match = /^(\d+)(?:-(\d+))?$/.exec(part.trim());
            const from = Number(match?.[1]);
            const to = Number(match?.[2] ?? match?.[1]);
            if (
                !match ||
                !Number.isSafeInteger(from) ||
                !Number.isSafeInteger(to) ||
                from < 1 ||
                to > 65535 ||
                from > to
            )
                throw new Error('Cannot validate Xray ports in mixed edge configuration.');
            return [from, to];
        });
}

export async function rejectLocalEdgeLoops(
    plan: TNodeEdgePlan,
    anyTlsConfig?: TAnyTlsConfig,
    managementPorts: readonly number[] = [],
): Promise<void> {
    const local = new Set(['127.0.0.1', '::1', '0.0.0.0', '::']);
    for (const entries of Object.values(networkInterfaces())) {
        for (const entry of entries ?? [])
            local.add(canonicalizeEndpointAddress(entry.address.split('%')[0]));
    }
    const anyTls = anyTlsConfig === undefined ? undefined : AnyTlsConfigSchema.parse(anyTlsConfig);
    const reserved = new Set([
        ...EDGE_PORTS,
        ...managementPorts,
        ...plan.routes.map((route) => route.targetPort),
        ...(anyTls?.listeners.flatMap((listener) => [listener.wrapperPort, listener.innerPort]) ??
            []),
    ]);
    for (const site of [plan.management, plan.website]) {
        if (!site) continue;
        const upstream = new URL(site.upstream);
        const port = Number(upstream.port || (upstream.protocol === 'https:' ? 443 : 80));
        if (!reserved.has(port)) continue;
        const host = upstream.hostname.replace(/^\[|\]$/g, '');
        const addresses = isIP(host) ? [{ address: host }] : await lookup(host, { all: true });
        if (
            addresses.some(({ address }) => {
                const endpoint = canonicalizeEndpointAddress(address);
                return local.has(endpoint) || endpoint.startsWith('127.');
            })
        ) {
            throw new Error('Edge upstream resolves back to a local edge or proxy listener.');
        }
    }
}

export function renderHaproxy(plan: TNodeEdgePlan): string {
    const routes = plan.routes.map((route, index) => ({ ...route, name: `proxy_${index}` }));
    return `global
    log stdout format raw local0
    master-worker
    user haproxy
    group haproxy

defaults
    log global
    mode tcp
    timeout connect 5s
    timeout client 5m
    timeout server 5m

frontend xboard_http
    bind :80
    default_backend xboard_caddy_http

frontend xboard_https
    bind :443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
${routes.map((route) => `    use_backend ${route.name} if { req.ssl_sni -i ${route.sni} }`).join('\n')}
    default_backend xboard_caddy_https

backend xboard_caddy_http
    server caddy_http 127.0.0.1:18080 check

backend xboard_caddy_https
    server caddy_https 127.0.0.1:18443 check

${routes.map((route) => `backend ${route.name}\n    server target 127.0.0.1:${route.targetPort}${route.sendProxyV2 ? ' send-proxy-v2' : ''} check\n`).join('\n')}`;
}

export function renderCaddyfile(plan: TNodeEdgePlan): string {
    const sites = [plan.management, plan.website].filter((site) => site !== null);
    const domains = sites.flatMap((site) => site.domains);
    const loopId = createHash('sha256').update(JSON.stringify(sites)).digest('hex').slice(0, 24);
    const redirect = domains.length
        ? `    @managed host ${domains.join(' ')}\n    redir @managed https://{host}{uri} 308\n`
        : '';
    return `{
    admin 127.0.0.1:2019
    http_port 18080
${sites.length ? '    https_port 18443' : ''}
    default_bind 127.0.0.1
    auto_https disable_redirects
    servers {
        protocols h1 h2
    }
}

http://:18080 {
    bind 127.0.0.1
${redirect}    respond "Not found" 404
}

${
    sites.length
        ? sites
              .map(
                  (site) => `${site.domains.map((domain) => `https://${domain}:18443`).join(', ')} {
    bind 127.0.0.1
    @loop header X-Xboard-Edge-Hop *${loopId}*
    respond @loop "Reverse proxy loop detected" 508
    reverse_proxy ${JSON.stringify(new URL(site.upstream).origin)} {
        header_up +X-Xboard-Edge-Hop ${loopId}
    }
}`,
              )
              .join('\n\n')
        : 'http://127.0.0.1:18443 {\n    bind 127.0.0.1\n    respond "Not configured" 404\n}'
}
`;
}
