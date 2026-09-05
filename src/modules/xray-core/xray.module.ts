import { Logger, Module, OnModuleDestroy } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { AnyTlsModule } from '../anytls/anytls.module';
import { CamouflageDomainModule } from '../camouflage-domain/camouflage-domain.module';
import { EdgeModule } from '../edge/edge.module';
import { InternalModule } from '../internal/internal.module';
import { COMMANDS } from './commands';
import { CoreLoaderService } from './core-loader.service';
import { GeodataService } from './geodata.service';
import { XrayProcessService } from './xray-process.service';
import { XrayController } from './xray.controller';
import { XrayService } from './xray.service';

@Module({
    imports: [InternalModule, CqrsModule, EdgeModule, CamouflageDomainModule, AnyTlsModule],
    providers: [XrayService, XrayProcessService, GeodataService, CoreLoaderService, ...COMMANDS],
    controllers: [XrayController],
    exports: [XrayService],
})
export class XrayModule implements OnModuleDestroy {
    private readonly logger = new Logger(XrayModule.name);

    constructor(private readonly xrayService: XrayService) {}

    async onModuleDestroy() {
        this.logger.log('Destroying module.');

        try {
            await this.xrayService.killAllXrayProcesses();
        } catch {
            // s6 may have removed its control socket already during container shutdown.
            // Do not abort later module hooks: AnyTLS still needs to drain and release its lease.
            this.logger.warn('Xray shutdown could not use s6 control; continuing module cleanup.');
        }
    }
}
