import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { MieruModule } from '../mieru/mieru.module';
import { GeocheckService } from './geocheck.service';
import { StatsController } from './stats.controller';
import { StatsService } from './stats.service';
@Module({
    imports: [CqrsModule, MieruModule],
    providers: [StatsService, GeocheckService],
    controllers: [StatsController],
})
export class StatsModule {}
