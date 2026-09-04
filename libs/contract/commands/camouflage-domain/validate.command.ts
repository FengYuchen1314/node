import { z } from 'zod';

import { REST_API } from '../../api';
import {
    CamouflageDomainAgentValidationRequestSchema,
    CamouflageDomainAgentValidationResponseSchema,
} from '../../models';

export namespace ValidateCamouflageDomainCommand {
    export const url = REST_API.CAMOUFLAGE_DOMAIN.VALIDATE;
    export const RequestSchema = CamouflageDomainAgentValidationRequestSchema;
    export const ResponseSchema = CamouflageDomainAgentValidationResponseSchema;
    export type Request = z.infer<typeof RequestSchema>;
    export type Response = z.infer<typeof ResponseSchema>;
}
