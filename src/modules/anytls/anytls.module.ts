import { Module } from '@nestjs/common';

import { AnyTlsConfigRenderer } from './anytls-config';
import { AnyTlsRuntimeIO } from './anytls-runtime.io';
import { AnyTlsRuntimeService } from './anytls-runtime.service';
import { AnyTlsRuntimeStore } from './anytls-runtime.store';
import { AnyTlsStatsClient } from './anytls-stats.client';
import { AnyTlsController } from './anytls.controller';

@Module({
    providers: [
        AnyTlsConfigRenderer,
        AnyTlsRuntimeIO,
        AnyTlsRuntimeStore,
        AnyTlsStatsClient,
        AnyTlsRuntimeService,
    ],
    controllers: [AnyTlsController],
    exports: [AnyTlsRuntimeService],
})
export class AnyTlsModule {}
