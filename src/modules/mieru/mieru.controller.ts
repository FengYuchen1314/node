import { Body, Controller, Get, Post, UseFilters, UseGuards } from '@nestjs/common';

import { HttpExceptionFilter } from '@common/exception/http-exception.filter';
import { JwtDefaultGuard } from '@common/guards/jwt-guards';
import { MIERU_CONTROLLER, MIERU_ROUTES } from '@libs/contracts/api';
import {
    GetMieruStatusCommand,
    StartMieruCommand,
    StopMieruCommand,
} from '@libs/contracts/commands';

import {
    GetMieruStatusResponseDto,
    StartMieruRequestDto,
    StartMieruResponseDto,
    StopMieruResponseDto,
} from './dtos';
import { MieruService } from './mieru.service';

@UseFilters(HttpExceptionFilter)
@UseGuards(JwtDefaultGuard)
@Controller(MIERU_CONTROLLER)
export class MieruController {
    constructor(private readonly mieruService: MieruService) {}

    @Post(MIERU_ROUTES.START)
    public async start(@Body() body: StartMieruRequestDto): Promise<StartMieruResponseDto> {
        const response: StartMieruCommand.Response['response'] =
            await this.mieruService.start(body);
        return { response };
    }

    @Get(MIERU_ROUTES.STOP)
    public async stop(): Promise<StopMieruResponseDto> {
        const response: StopMieruCommand.Response['response'] = await this.mieruService.stop();
        return { response };
    }

    @Get(MIERU_ROUTES.STATUS)
    public async status(): Promise<GetMieruStatusResponseDto> {
        const response: GetMieruStatusCommand.Response['response'] =
            await this.mieruService.status();
        return { response };
    }
}
