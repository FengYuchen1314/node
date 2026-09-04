import { createZodDto } from 'nestjs-zod';

import { StartMieruCommand } from '@libs/contracts/commands';

export class StartMieruRequestDto extends createZodDto(StartMieruCommand.RequestSchema) {}
export class StartMieruResponseDto extends createZodDto(StartMieruCommand.ResponseSchema) {}
