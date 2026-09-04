import { z } from 'zod';

const utf8 = new TextEncoder();
const isAtMost64Bytes = (value: string) => utf8.encode(value).byteLength <= 64;

export const MieruStatusSchema = z.enum([
    'UNKNOWN',
    'IDLE',
    'STARTING',
    'RUNNING',
    'STOPPING',
    'STOPPED',
]);

export const MieruOperationSchema = z.enum(['UNCHANGED', 'STARTED', 'RELOADED', 'RESTARTED']);

export const MieruServerConfigSchema = z
    .object({
        portBindings: z
            .array(
                z
                    .object({
                        port: z.number().int().min(1).max(65_535),
                        protocol: z.enum(['TCP', 'UDP']),
                    })
                    .strict(),
            )
            .min(1)
            .max(128),
        users: z
            .array(
                z
                    .object({
                        name: z.string().min(1).refine(isAtMost64Bytes, {
                            message: 'Mieru user name must be at most 64 UTF-8 bytes.',
                        }),
                        password: z.string().min(1).refine(isAtMost64Bytes, {
                            message: 'Mieru password must be at most 64 UTF-8 bytes.',
                        }),
                    })
                    .strict(),
            )
            .max(100_000),
        advancedSettings: z
            .object({
                metricsLoggingInterval: z.string().min(1).max(32).optional(),
                userHintIsMandatory: z.boolean().optional(),
            })
            .strict()
            .optional(),
        loggingLevel: z.enum(['FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE']).default('INFO'),
        mtu: z.number().int().min(1280).max(1500).optional(),
    })
    .strict()
    .superRefine((config, context) => {
        const bindings = new Set<string>();
        config.portBindings.forEach((binding, index) => {
            const identity = `${binding.protocol}:${binding.port}`;
            if (bindings.has(identity)) {
                context.addIssue({
                    code: 'custom',
                    message: `Duplicate Mieru port binding ${identity}.`,
                    path: ['portBindings', index],
                });
            }
            bindings.add(identity);
        });

        const names = new Set<string>();
        config.users.forEach((user, index) => {
            if (names.has(user.name)) {
                context.addIssue({
                    code: 'custom',
                    message: `Duplicate Mieru user ${user.name}.`,
                    path: ['users', index, 'name'],
                });
            }
            names.add(user.name);
        });
    });

export const MieruMetricIntegerSchema = z.string().regex(/^-?\d+$/);
const MieruMetricValuesSchema = z.record(z.string(), MieruMetricIntegerSchema);

export const MieruMetricsSchema = z.record(
    z.string(),
    z.union([MieruMetricValuesSchema, z.record(z.string(), MieruMetricValuesSchema)]),
);

export const MieruRollbackSchema = z.object({
    attempted: z.boolean(),
    succeeded: z.boolean(),
});

export type TMieruServerConfig = z.infer<typeof MieruServerConfigSchema>;

export const MieruIsolatedConfigSchema = z
    .object({
        kind: z.literal('ISOLATED_LISTENERS'),
        instances: z
            .array(
                z
                    .object({
                        id: z.uuid(),
                        config: MieruServerConfigSchema.refine(
                            (config) => config.portBindings.length === 1,
                            {
                                message:
                                    'Each isolated Mieru instance must have exactly one listener.',
                            },
                        ),
                    })
                    .strict(),
            )
            .min(1)
            .max(128),
    })
    .strict()
    .superRefine((runtime, context) => {
        const ids = new Set<string>();
        const ports = new Set<string>();
        for (const [index, instance] of runtime.instances.entries()) {
            const binding = instance.config.portBindings[0];
            const port = `${binding.protocol}:${binding.port}`;
            if (ids.has(instance.id) || ports.has(port)) {
                context.addIssue({
                    code: 'custom',
                    message: 'Mieru instance IDs and listeners must be unique.',
                    path: ['instances', index],
                });
            }
            ids.add(instance.id);
            ports.add(port);
        }
    });
export type TMieruIsolatedConfig = z.infer<typeof MieruIsolatedConfigSchema>;
export type TMieruStatus = z.infer<typeof MieruStatusSchema>;
export type TMieruOperation = z.infer<typeof MieruOperationSchema>;
export type TMieruMetrics = z.infer<typeof MieruMetricsSchema>;
export type TMieruRollback = z.infer<typeof MieruRollbackSchema>;
