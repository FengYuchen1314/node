import { z } from 'zod';

import { REST_API } from '../../api';
import { MieruStatusSchema } from '../../models';

export namespace StopMieruCommand {
    export const url = REST_API.MIERU.STOP;

    export const ResponseSchema = z.object({
        response: z.object({
            isStopped: z.boolean(),
            state: MieruStatusSchema.nullable(),
            operation: z.enum(['STOPPED', 'ALREADY_STOPPED']).nullable(),
            error: z.string().nullable(),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
