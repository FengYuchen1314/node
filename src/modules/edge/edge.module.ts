import { Controller, Get, Module, UseFilters, UseGuards } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { HttpExceptionFilter } from '@common/exception/http-exception.filter';
import { JwtDefaultGuard } from '@common/guards/jwt-guards';

import { EdgeConfigIO } from './edge-config.io';
import { EdgeService } from './edge.service';

@UseFilters(HttpExceptionFilter)
@UseGuards(JwtDefaultGuard)
@Controller('edge')
class EdgeController {
    constructor(private readonly service: EdgeService) {}

    @Get('status')
    async status() {
        return { response: await this.service.status() };
    }
}

@Module({
    imports: [CqrsModule],
    providers: [EdgeConfigIO, EdgeService],
    controllers: [EdgeController],
    exports: [EdgeService],
})
export class EdgeModule {}
