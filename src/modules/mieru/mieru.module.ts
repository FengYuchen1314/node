import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { MieruControlClient } from './mieru-control.client';
import { MieruMetricsBaselineStore } from './mieru-metrics-baseline.store';
import { MieruMetricsDeltaService } from './mieru-metrics-delta.service';
import { MieruController } from './mieru.controller';
import { MieruService } from './mieru.service';

@Module({
    imports: [CqrsModule],
    providers: [
        MieruControlClient,
        MieruMetricsBaselineStore,
        MieruMetricsDeltaService,
        MieruService,
    ],
    controllers: [MieruController],
    exports: [MieruMetricsDeltaService],
})
export class MieruModule {}
