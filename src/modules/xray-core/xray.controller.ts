import { Body, Controller, Get, Ip, Logger, Post, UseFilters, UseGuards } from '@nestjs/common';

import { HttpExceptionFilter } from '@common/exception/http-exception.filter';
import { JwtDefaultGuard } from '@common/guards/jwt-guards';
import { errorHandler } from '@common/helpers/error-handler.helper';
import { XRAY_CONTROLLER, XRAY_ROUTES } from '@libs/contracts/api';

import { EdgeService } from '../edge/edge.service';
import {
    GetNodeHealthCheckResponseDto,
    StartXrayRequestDto,
    StartXrayResponseDto,
    StopXrayResponseDto,
} from './dtos/';
import { XrayService } from './xray.service';

@UseFilters(HttpExceptionFilter)
@UseGuards(JwtDefaultGuard)
@Controller(XRAY_CONTROLLER)
export class XrayController {
    private readonly logger = new Logger(XrayController.name);
    private previousStart: StartXrayRequestDto | undefined;

    constructor(
        private readonly xrayService: XrayService,
        private readonly edge: EdgeService,
    ) {}

    @Post(XRAY_ROUTES.START)
    public async startXray(
        @Body() body: StartXrayRequestDto,
        @Ip() ip: string,
    ): Promise<StartXrayResponseDto> {
        return this.edge
            .run(
                body.edgePlan,
                body.xrayConfig,
                async () => {
                    const data = errorHandler(await this.xrayService.startXray(body, ip));
                    if (!data.isStarted && body.edgePlan)
                        throw new Error(data.error ?? 'Xray did not start.');
                    return { response: data };
                },
                async () => {
                    if (this.previousStart) {
                        const previous = structuredClone(this.previousStart);
                        previous.internals.forceRestart = true;
                        const result = errorHandler(await this.xrayService.startXray(previous, ip));
                        if (!result.isStarted) throw new Error('Xray rollback failed.');
                    } else {
                        const result = errorHandler(
                            await this.xrayService.stopXray({ withOnlineCheck: false }),
                        );
                        if (!result.isStopped)
                            throw new Error('Xray could not be stopped after rollback.');
                    }
                },
            )
            .then((result) => {
                if (result.response.isStarted) this.previousStart = structuredClone(body);
                return result;
            });
    }

    @Get(XRAY_ROUTES.STOP)
    public async stopXray(): Promise<StopXrayResponseDto> {
        this.logger.log('Remnawave requested to stop Xray.');

        const response = await this.edge.stop(() =>
            this.xrayService.stopXray({
                withOnlineCheck: false,
                withPluginCleanup: true,
            }),
        );
        const data = errorHandler(response);
        if (data.isStopped) this.previousStart = undefined;

        return {
            response: data,
        };
    }

    @Get(XRAY_ROUTES.NODE_HEALTH_CHECK)
    public async getNodeHealthCheck(): Promise<GetNodeHealthCheckResponseDto> {
        const response = await this.xrayService.getNodeHealthCheck();
        const data = errorHandler(response);

        return {
            response: data,
        };
    }
}
