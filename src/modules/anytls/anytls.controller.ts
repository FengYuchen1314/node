import { createZodDto } from 'nestjs-zod';
import { z } from 'zod';

import { Body, Controller, Get, Post, UseFilters, UseGuards } from '@nestjs/common';

import { HttpExceptionFilter } from '@common/exception/http-exception.filter';
import { JwtDefaultGuard } from '@common/guards/jwt-guards';
import { AnyTlsConfigSchema } from '@libs/contracts/models';

import { AnyTlsRuntimeService } from './anytls-runtime.service';

class ApplyAnyTlsDto extends createZodDto(AnyTlsConfigSchema) {}
class AnyTlsStatsDto extends createZodDto(
    z.object({ reset: z.boolean().default(false) }).strict(),
) {}

// Panel-only, protected by the same JWT + transport authentication as existing Node routes.
// Activation is opt-in until mixed-Xray preparation/accounting and subscriptions are connected.
@UseFilters(HttpExceptionFilter)
@UseGuards(JwtDefaultGuard)
@Controller('anytls')
export class AnyTlsController {
    constructor(private readonly runtime: AnyTlsRuntimeService) {}
    @Post('start') async start(@Body() body: ApplyAnyTlsDto) {
        return { response: await this.runtime.apply(body) };
    }
    @Post('stop') async stop() {
        return { response: await this.runtime.stop() };
    }
    @Get('status') async status() {
        return { response: await this.runtime.status() };
    }
    @Get('capabilities') capabilities() {
        return { response: this.runtime.capabilities() };
    }
    @Post('stats') async stats(@Body() body: AnyTlsStatsDto) {
        return { response: { users: await this.runtime.users(body.reset) } };
    }
}
