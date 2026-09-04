import { createZodDto } from 'nestjs-zod';

import { GetMieruStatusCommand } from '@libs/contracts/commands';

export class GetMieruStatusResponseDto extends createZodDto(GetMieruStatusCommand.ResponseSchema) {}
