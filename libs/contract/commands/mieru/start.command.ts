import { z } from 'zod';

import { REST_API } from '../../api';
import {
    MieruOperationSchema,
    MieruRollbackSchema,
    MieruServerConfigSchema,
    MieruStatusSchema,
    NodeSystemSchema,
} from '../../models';

export namespace StartMieruCommand {
    export const url = REST_API.MIERU.START;
    export const RequestSchema = z.object({
        config: MieruServerConfigSchema,
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: z.object({
            isStarted: z.boolean(),
            version: z.string().nullable(),
            error: z.string().nullable(),
            nodeInformation: z.object({
                version: z.string().nullable(),
            }),
            system: NodeSystemSchema,
            state: MieruStatusSchema.nullable(),
            operation: MieruOperationSchema.nullable(),
            rollback: MieruRollbackSchema.nullable(),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
