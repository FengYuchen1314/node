import { Module } from '@nestjs/common';

import { AsnLmdbModule } from '../asn-lmdb/asn-lmdb.module';
import { CamouflageDomainDnsService } from './camouflage-domain-dns.service';
import { CamouflageDomainNetworkService } from './camouflage-domain-network.service';
import { CamouflageDomainController } from './camouflage-domain.controller';
import { CamouflageDomainService } from './camouflage-domain.service';
import { CamouflageRuntimePolicy } from './camouflage-runtime-policy.service';

@Module({
    imports: [AsnLmdbModule],
    providers: [
        CamouflageDomainDnsService,
        CamouflageDomainNetworkService,
        CamouflageDomainService,
        CamouflageRuntimePolicy,
    ],
    controllers: [CamouflageDomainController],
    exports: [CamouflageRuntimePolicy],
})
export class CamouflageDomainModule {}
