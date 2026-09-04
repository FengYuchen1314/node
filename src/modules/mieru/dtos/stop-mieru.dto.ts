import { createZodDto } from 'nestjs-zod';

import { StopMieruCommand } from '@libs/contracts/commands';

export class StopMieruResponseDto extends createZodDto(StopMieruCommand.ResponseSchema) {}
