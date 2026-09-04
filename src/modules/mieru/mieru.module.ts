import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { MieruControlClient } from './mieru-control.client';
import { MieruDaemonManager } from './mieru-daemon.manager';
import { MieruMetricsBaselineStore } from './mieru-metrics-baseline.store';
import { MieruMetricsDeltaService } from './mieru-metrics-delta.service';
import { MieruRuntimeService } from './mieru-runtime.service';
import { MieruRuntimeStore } from './mieru-runtime.store';
import { MieruController } from './mieru.controller';
import { MieruService } from './mieru.service';

@Module({
    imports: [CqrsModule],
    providers: [
        MieruControlClient,
        MieruDaemonManager,
        MieruRuntimeStore,
        MieruRuntimeService,
        MieruMetricsBaselineStore,
        MieruMetricsDeltaService,
        MieruService,
    ],
    controllers: [MieruController],
    exports: [MieruMetricsDeltaService],
})
export class MieruModule {}
