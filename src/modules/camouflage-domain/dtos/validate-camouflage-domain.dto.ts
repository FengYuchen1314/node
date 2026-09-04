import { createZodDto } from 'nestjs-zod';

import { ValidateCamouflageDomainCommand } from '@libs/contracts/commands';

export class ValidateCamouflageDomainRequestDto extends createZodDto(
    ValidateCamouflageDomainCommand.RequestSchema,
) {}
export class ValidateCamouflageDomainResponseDto extends createZodDto(
    ValidateCamouflageDomainCommand.ResponseSchema,
) {}
