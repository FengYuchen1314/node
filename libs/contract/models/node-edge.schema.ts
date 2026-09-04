import { z } from 'zod';

import { CamouflageDomainSchema } from './camouflage-domain.schema';

export const NODE_EDGE_PLAN_VERSION = 1 as const;
export const NODE_EDGE_STATUS_PATH = '/node/edge/status' as const;

const HttpUpstreamSchema = z
    .url()
    .transform((value) => new URL(value))
    .refine((value) => value.protocol === 'http:' || value.protocol === 'https:', {
        message: 'Edge upstream must use HTTP or HTTPS.',
    })
    .refine((value) => !value.username && !value.password && !value.hash, {
        message: 'Edge upstream must not contain credentials or a fragment.',
    })
    .transform((value) => value.toString());

export const NodeEdgeSiteSchema = z
    .object({
        domains: z.array(CamouflageDomainSchema).min(1).max(32),
        upstream: HttpUpstreamSchema,
    })
    .strict()
    .superRefine((site, context) => {
        const unique = new Set(site.domains);
        if (unique.size !== site.domains.length) {
            context.addIssue({
                code: 'custom',
                path: ['domains'],
                message: 'Edge site domains must be unique.',
            });
        }

        const upstreamHost = new URL(site.upstream).hostname.toLowerCase();
        if (unique.has(upstreamHost)) {
            context.addIssue({
                code: 'custom',
                path: ['upstream'],
                message: 'Edge upstream must not point back to its own public domain.',
            });
        }
    });

export const NodeEdgeSettingsSchema = z
    .object({
        management: NodeEdgeSiteSchema.nullable().default(null),
        website: NodeEdgeSiteSchema.nullable().default(null),
    })
    .strict()
    .superRefine((settings, context) => {
        const domains = [
            ...(settings.management?.domains ?? []),
            ...(settings.website?.domains ?? []),
        ];
        if (new Set(domains).size !== domains.length) {
            context.addIssue({
                code: 'custom',
                path: ['website', 'domains'],
                message: 'Management and website domains must not overlap.',
            });
        }

        const publicDomains = new Set(domains);
        for (const [role, site] of [
            ['management', settings.management],
            ['website', settings.website],
        ] as const) {
            if (site && publicDomains.has(new URL(site.upstream).hostname.toLowerCase())) {
                context.addIssue({
                    code: 'custom',
                    path: [role, 'upstream'],
                    message: 'Edge upstream must not point to any public domain on this node.',
                });
            }
        }
    });

export const NodeEdgeTcpRouteSchema = z
    .object({
        sni: CamouflageDomainSchema,
        targetHost: z.literal('127.0.0.1'),
        targetPort: z.int().min(1_024).max(65_535),
        sendProxyV2: z.literal(true),
        inboundTag: z.string().min(1).max(256),
    })
    .strict();

export const NodeEdgePlanSchema = z
    .object({
        version: z.literal(NODE_EDGE_PLAN_VERSION),
        publicHttpPort: z.literal(80),
        publicHttpsPort: z.literal(443),
        caddyHttpTarget: z.literal('127.0.0.1:18080'),
        caddyHttpsTarget: z.literal('127.0.0.1:18443'),
        routes: z.array(NodeEdgeTcpRouteSchema).max(256),
        management: NodeEdgeSiteSchema.nullable(),
        website: NodeEdgeSiteSchema.nullable(),
    })
    .strict()
    .superRefine((plan, context) => {
        const routeSnis = new Set<string>();
        const tagByPort = new Map<number, string>();
        const portByTag = new Map<string, number>();

        plan.routes.forEach((route, index) => {
            if (routeSnis.has(route.sni)) {
                context.addIssue({
                    code: 'custom',
                    path: ['routes', index, 'sni'],
                    message: `Duplicate edge SNI ${route.sni}.`,
                });
            }
            routeSnis.add(route.sni);
            const existingTag = tagByPort.get(route.targetPort);
            if (existingTag !== undefined && existingTag !== route.inboundTag) {
                context.addIssue({
                    code: 'custom',
                    path: ['routes', index, 'targetPort'],
                    message: 'Different inbound tags must not share an internal edge port.',
                });
            }
            tagByPort.set(route.targetPort, route.inboundTag);

            const existingPort = portByTag.get(route.inboundTag);
            if (existingPort !== undefined && existingPort !== route.targetPort) {
                context.addIssue({
                    code: 'custom',
                    path: ['routes', index, 'inboundTag'],
                    message: 'One inbound tag must use one internal edge port.',
                });
            }
            portByTag.set(route.inboundTag, route.targetPort);
        });

        const webDomains = [...(plan.management?.domains ?? []), ...(plan.website?.domains ?? [])];
        webDomains.forEach((domain) => {
            if (routeSnis.has(domain)) {
                context.addIssue({
                    code: 'custom',
                    path: ['routes'],
                    message: `Proxy and web routes must not share SNI ${domain}.`,
                });
            }
        });
    });

export const NodeEdgeStatusResponseSchema = z
    .object({
        response: z
            .object({
                available: z.boolean(),
                planVersion: z.literal(NODE_EDGE_PLAN_VERSION),
                haproxy: z.boolean(),
                caddy: z.boolean(),
            })
            .strict(),
    })
    .strict();

export type TNodeEdgeSettings = z.infer<typeof NodeEdgeSettingsSchema>;
export type TNodeEdgePlan = z.infer<typeof NodeEdgePlanSchema>;
export type TNodeEdgeStatusResponse = z.infer<typeof NodeEdgeStatusResponseSchema>['response'];
