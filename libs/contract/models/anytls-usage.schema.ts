import { z } from 'zod';

export const ANYTLS_USAGE_PATH = '/node/anytls/usage' as const;
export const AnyTlsUsageCounterSchema = z
    .object({
        uplink: z.string().regex(/^(0|[1-9]\d{0,39})$/),
        downlink: z.string().regex(/^(0|[1-9]\d{0,39})$/),
    })
    .strict();
export const AnyTlsUsageUserSchema = AnyTlsUsageCounterSchema.extend({
    username: z.string().regex(/^(?!__proto__$|constructor$|prototype$)[A-Za-z0-9_.@-]{1,64}$/),
}).strict();
export const AnyTlsUsageSnapshotSchema = z
    .object({
        available: z.literal(true),
        version: z.literal(1),
        epoch: z.uuid(),
        users: z.array(AnyTlsUsageUserSchema).max(100000),
    })
    .strict()
    .refine(
        (value) => new Set(value.users.map((user) => user.username)).size === value.users.length,
        {
            message: 'Cumulative AnyTLS usage must contain unique users.',
        },
    );
export const AnyTlsUsageResponseSchema = z.union([
    z.object({ available: z.literal(false) }).strict(),
    AnyTlsUsageSnapshotSchema,
]);
export type TAnyTlsUsageSnapshot = z.infer<typeof AnyTlsUsageSnapshotSchema>;
export type TAnyTlsUsageResponse = z.infer<typeof AnyTlsUsageResponseSchema>;
