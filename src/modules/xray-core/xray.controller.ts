import {
    BadRequestException,
    Body,
    Controller,
    Get,
    Ip,
    Logger,
    Post,
    UseFilters,
    UseGuards,
} from '@nestjs/common';

import { HttpExceptionFilter } from '@common/exception/http-exception.filter';
import { JwtDefaultGuard } from '@common/guards/jwt-guards';
import { errorHandler } from '@common/helpers/error-handler.helper';
import { XRAY_CONTROLLER, XRAY_ROUTES } from '@libs/contracts/api';

import {
    AnyTlsRuntimeService,
    CoordinatedAnyTlsTransition,
} from '../anytls/anytls-runtime.service';
import { CamouflageRuntimePolicy } from '../camouflage-domain/camouflage-runtime-policy.service';
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
    private queue: Promise<unknown> = Promise.resolve();

    constructor(
        private readonly xrayService: XrayService,
        private readonly edge: EdgeService,
        private readonly anyTls: AnyTlsRuntimeService,
        private readonly camouflage: CamouflageRuntimePolicy,
    ) {}

    @Post(XRAY_ROUTES.START)
    public async startXray(
        @Body() body: StartXrayRequestDto,
        @Ip() ip: string,
    ): Promise<StartXrayResponseDto> {
        const request = structuredClone(body);
        return this.lock(async () => {
            const coordinated = this.anyTls.coordinated();
            if (coordinated !== (request.anyTlsConfig !== undefined))
                throw new BadRequestException(
                    'Shared-443 AnyTLS requires an explicit anyTlsConfig (empty listeners to remove it); other Agents must omit it.',
                );
            const run = async (runtime?: CoordinatedAnyTlsTransition) => {
                // Reject live CDN/DNS/certificate policy failures before withdrawing the old
                // generation. XrayService rechecks again on actual activation and rollback.
                if (runtime) await this.camouflage.prepareXray(request.xrayConfig);
                let xrayAttempted = false;
                return this.edge.run(
                    request.edgePlan,
                    request.xrayConfig,
                    async () => {
                        xrayAttempted = true;
                        // Both old generations must release their ports before either replacement
                        // starts. This also permits a port to move between Xray and AnyTLS safely.
                        if (runtime) await this.quiesceCores(runtime);
                        const data = errorHandler(await this.xrayService.startXray(request, ip));
                        if (!data.isStarted && request.edgePlan)
                            throw new Error(data.error ?? 'Xray did not start.');
                        if (runtime) await runtime.apply();
                        return { response: data };
                    },
                    async () => {
                        if (runtime && xrayAttempted) {
                            try {
                                await this.quiesceCores(runtime);
                            } catch {
                                this.previousStart = undefined;
                                throw new Error(
                                    'Core retirement before rollback was not confirmed.',
                                );
                            }
                        }
                        const results = await Promise.allSettled([
                            xrayAttempted ? this.rollbackXray(ip) : Promise.resolve(),
                            runtime?.rollback() ?? Promise.resolve(),
                        ]);
                        if (results.some((result) => result.status === 'rejected')) {
                            this.previousStart = undefined;
                            throw new Error('Coordinated core rollback was not confirmed.');
                        }
                    },
                    request.anyTlsConfig,
                );
            };
            const result = coordinated
                ? await this.anyTls.withCoordinatedUpdate(request.anyTlsConfig, run)
                : await run();
            if (result.response.isStarted) this.previousStart = request;
            return result;
        });
    }

    private async quiesceCores(runtime: CoordinatedAnyTlsTransition): Promise<void> {
        const results = await Promise.allSettled([
            this.xrayService.stopXray({ withOnlineCheck: false }).then((response) => {
                if (!errorHandler(response).isStopped)
                    throw new Error('Xray stop was not confirmed.');
            }),
            runtime.quiesce(),
        ]);
        if (results.some((result) => result.status === 'rejected'))
            throw new Error('Core retirement was not confirmed.');
    }

    @Get(XRAY_ROUTES.STOP)
    public async stopXray(): Promise<StopXrayResponseDto> {
        this.logger.log('Remnawave requested to stop Xray.');

        return this.lock(async () => {
            const stop = (stopAnyTls?: () => Promise<void>) =>
                this.edge.stop(async () => {
                    // One failed core stop must not prevent an attempt to stop the other core.
                    const results = await Promise.allSettled([
                        this.xrayService
                            .stopXray({
                                withOnlineCheck: false,
                                withPluginCleanup: true,
                            })
                            .then(errorHandler),
                        stopAnyTls?.() ?? Promise.resolve(),
                    ]);
                    this.previousStart = undefined;
                    const xray = results[0];
                    if (xray.status === 'rejected' || results[1].status === 'rejected')
                        throw new Error('Core stop or final accounting was not confirmed.');
                    return { response: xray.value };
                });
            return this.anyTls.coordinated() ? this.anyTls.withCoordinatedStop(stop) : stop();
        });
    }

    private async rollbackXray(ip: string): Promise<void> {
        try {
            if (this.previousStart) {
                const previous = structuredClone(this.previousStart);
                previous.internals.forceRestart = true;
                const result = errorHandler(await this.xrayService.startXray(previous, ip));
                if (result.isStarted) return;
            } else {
                const result = errorHandler(
                    await this.xrayService.stopXray({ withOnlineCheck: false }),
                );
                if (result.isStopped) return;
            }
        } catch {
            /* Failed API results must still attempt to stop the unconfirmed core. */
        }
        // Do not retain an unconfirmed replacement when restoring the previous core failed.
        await this.xrayService.stopXray({ withOnlineCheck: false }).catch(() => undefined);
        throw new Error('Xray rollback failed.');
    }

    private lock<T>(operation: () => Promise<T>): Promise<T> {
        const result = this.queue.then(operation);
        this.queue = result.catch(() => undefined);
        return result;
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
