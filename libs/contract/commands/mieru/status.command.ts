import { z } from 'zod';

import { REST_API } from '../../api';
import { MieruMetricsSchema, MieruStatusSchema } from '../../models';

export namespace GetMieruStatusCommand {
    export const url = REST_API.MIERU.STATUS;

    export const ResponseSchema = z.object({
        response: z.object({
            isAvailable: z.boolean(),
            state: MieruStatusSchema.nullable(),
            version: z.string().nullable(),
            metrics: MieruMetricsSchema,
            error: z.string().nullable(),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
