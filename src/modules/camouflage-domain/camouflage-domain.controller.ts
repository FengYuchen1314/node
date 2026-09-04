import { Body, Controller, Post, UseFilters, UseGuards } from '@nestjs/common';

import { HttpExceptionFilter } from '@common/exception/http-exception.filter';
import { HttpExceptionWithErrorCodeType } from '@common/exception/http-exeception-with-error-code.type';
import { JwtDefaultGuard } from '@common/guards/jwt-guards';
import { CAMOUFLAGE_DOMAIN_CONTROLLER, CAMOUFLAGE_DOMAIN_ROUTES } from '@libs/contracts/api';

import { CamouflageDomainError } from './camouflage-domain.error';
import { CamouflageDomainService } from './camouflage-domain.service';
import { ValidateCamouflageDomainRequestDto, ValidateCamouflageDomainResponseDto } from './dtos';

@UseFilters(HttpExceptionFilter)
@UseGuards(JwtDefaultGuard)
@Controller(CAMOUFLAGE_DOMAIN_CONTROLLER)
export class CamouflageDomainController {
    constructor(private readonly service: CamouflageDomainService) {}

    @Post(CAMOUFLAGE_DOMAIN_ROUTES.VALIDATE)
    public async validate(
        @Body() body: ValidateCamouflageDomainRequestDto,
    ): Promise<ValidateCamouflageDomainResponseDto> {
        try {
            return { response: await this.service.validate(body) };
        } catch (error: unknown) {
            if (error instanceof CamouflageDomainError) {
                throw new HttpExceptionWithErrorCodeType(
                    error.message,
                    `CD_${error.code}`,
                    error.httpStatus,
                );
            }
            throw error;
        }
    }
}
