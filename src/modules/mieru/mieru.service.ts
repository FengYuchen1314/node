import { Injectable, Logger } from '@nestjs/common';
import { QueryBus } from '@nestjs/cqrs';

import { getSystemInfo, getSystemStats } from '@common/utils/get-system-stats';
import {
    GetMieruStatusCommand,
    StartMieruCommand,
    StopMieruCommand,
} from '@libs/contracts/commands';

import { GetInterfaceStatsQuery } from '../network-stats/queries/get-interface-stats/get-interface-stats.query';
import { MieruControlError } from './mieru-control.client';
import { MieruMetricsDeltaService } from './mieru-metrics-delta.service';
import { MieruRuntimeService } from './mieru-runtime.service';

@Injectable()
export class MieruService {
    private readonly logger = new Logger(MieruService.name);
    private readonly nodeVersion = __RWNODE_VERSION__ ?? '0.0.0';

    constructor(
        private readonly control: MieruRuntimeService,
        private readonly queryBus: QueryBus,
        private readonly metricsDelta: MieruMetricsDeltaService,
    ) {}

    public async start(
        body: StartMieruCommand.Request,
    ): Promise<StartMieruCommand.Response['response']> {
        const interfaceStats = await this.queryBus.execute(new GetInterfaceStatsQuery());
        const system = {
            info: getSystemInfo(),
            stats: getSystemStats(),
            interface: interfaceStats,
        };

        try {
            const result = await this.control.apply(body.config);
            this.metricsDelta.enable();
            return {
                isStarted: result.status === 'RUNNING',
                version: result.version,
                error: null,
                nodeInformation: { version: this.nodeVersion },
                system,
                state: result.status,
                operation: result.operation,
                rollback: null,
            };
        } catch (error: unknown) {
            const controlError = asControlError(error);
            this.logger.error(`Failed to synchronize Mita: ${controlError.message}`);
            return {
                isStarted: false,
                version: null,
                error: controlError.message,
                nodeInformation: { version: this.nodeVersion },
                system,
                state: null,
                operation: null,
                rollback: controlError.rollbackAttempted
                    ? {
                          attempted: true,
                          succeeded: controlError.rollbackSucceeded,
                      }
                    : null,
            };
        }
    }

    public async stop(): Promise<StopMieruCommand.Response['response']> {
        try {
            const result = await this.control.stop();
            return {
                isStopped: result.status !== 'RUNNING',
                state: result.status,
                operation: result.operation,
                error: null,
            };
        } catch (error: unknown) {
            const controlError = asControlError(error);
            this.logger.error(`Failed to stop Mita: ${controlError.message}`);
            return { isStopped: false, state: null, operation: null, error: controlError.message };
        }
    }

    public async status(): Promise<GetMieruStatusCommand.Response['response']> {
        try {
            const result = await this.control.status();
            return {
                isAvailable: true,
                state: result.status,
                version: result.version,
                metrics: result.metrics,
                error: null,
            };
        } catch (error: unknown) {
            const controlError = asControlError(error);
            this.logger.warn(`Failed to query Mita: ${controlError.message}`);
            return {
                isAvailable: false,
                state: null,
                version: null,
                metrics: {},
                error: controlError.message,
            };
        }
    }
}

function asControlError(error: unknown): MieruControlError {
    if (error instanceof MieruControlError) return error;
    return new MieruControlError(
        error instanceof Error ? error.message : 'Unknown Mita control error.',
        'unknown',
    );
}
