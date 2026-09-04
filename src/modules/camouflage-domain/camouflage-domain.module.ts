import { Module } from '@nestjs/common';

import { AsnLmdbModule } from '../asn-lmdb/asn-lmdb.module';
import { CamouflageDomainDnsService } from './camouflage-domain-dns.service';
import { CamouflageDomainNetworkService } from './camouflage-domain-network.service';
import { CamouflageDomainController } from './camouflage-domain.controller';
import { CamouflageDomainService } from './camouflage-domain.service';

@Module({
    imports: [AsnLmdbModule],
    providers: [
        CamouflageDomainDnsService,
        CamouflageDomainNetworkService,
        CamouflageDomainService,
    ],
    controllers: [CamouflageDomainController],
})
export class CamouflageDomainModule {}
