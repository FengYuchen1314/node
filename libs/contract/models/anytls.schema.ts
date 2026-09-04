import { z } from 'zod';

import { CamouflageDomainSchema } from './camouflage-domain.schema';

const Port = z.int().min(1024).max(65535);
const Secret = z
    .string()
    .min(32)
    .max(256)
    .regex(/^[A-Za-z0-9_-]+$/);
export const AnyTlsUserSchema = z
    .object({
        name: z
            .string()
            .min(1)
            .max(64)
            .regex(/^(?!__proto__$|constructor$|prototype$)[A-Za-z0-9_.@-]+$/),
        password: Secret,
    })
    .strict();

export const AnyTlsListenerSchema = z
    .object({
        id: z.uuid(),
        tag: z
            .string()
            .min(1)
            .max(128)
            .regex(/^[A-Za-z0-9_-]+$/),
        wrapperPort: Port,
        innerPort: Port,
        camouflage: z
            .object({
                serverName: CamouflageDomainSchema,
                // The panel pins a resolved handshake endpoint. SNI remains the selected hostname.
                address: z.union([z.ipv4(), z.ipv6()]),
                port: z.int().min(1).max(65535).default(443),
            })
            .strict(),
        wrapperPassword: Secret,
        shadowPassword: Secret,
        tls: z
            .object({
                serverName: CamouflageDomainSchema,
                certificate: z.string().min(64).max(65536),
                privateKey: z.string().min(64).max(16384),
                caCertificate: z.string().min(64).max(16384),
            })
            .strict(),
        users: z.array(AnyTlsUserSchema).max(100000),
    })
    .strict();

export const AnyTlsConfigSchema = z
    .object({
        version: z.literal(1),
        listeners: z.array(AnyTlsListenerSchema).max(256),
    })
    .strict()
    .superRefine((config, context) => {
        const identities = new Set<string>();
        const tags = new Set<string>();
        const snis = new Set<string>();
        const ports = new Set([80, 443, 2019, 18080, 18443]);
        config.listeners.forEach((listener, index) => {
            const reject = (message: string) =>
                context.addIssue({ code: 'custom', path: ['listeners', index], message });
            if (identities.has(listener.id) || tags.has(listener.tag))
                reject('AnyTLS listener identities and tags must be unique.');
            if (snis.has(listener.camouflage.serverName))
                reject('AnyTLS camouflage SNI must be unique on a server.');
            identities.add(listener.id);
            tags.add(listener.tag);
            snis.add(listener.camouflage.serverName);
            for (const port of [listener.wrapperPort, listener.innerPort]) {
                if (ports.has(port))
                    reject('AnyTLS internal ports must be unique and not reserved.');
                ports.add(port);
            }
            if (listener.wrapperPassword === listener.shadowPassword)
                reject('Use independent transport passwords.');
            const users = new Set<string>();
            const passwords = new Set<string>();
            for (const user of listener.users) {
                if (users.has(user.name) || passwords.has(user.password))
                    reject('AnyTLS users and credentials must be unique within a listener.');
                if (
                    user.password === listener.wrapperPassword ||
                    user.password === listener.shadowPassword
                )
                    reject(
                        'Subscriber credentials must be independent from transport credentials.',
                    );
                users.add(user.name);
                passwords.add(user.password);
            }
        });
    });

export type TAnyTlsConfig = z.infer<typeof AnyTlsConfigSchema>;
export type TAnyTlsListener = z.infer<typeof AnyTlsListenerSchema>;
