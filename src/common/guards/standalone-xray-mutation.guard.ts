import { BadRequestException, CanActivate, Injectable } from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';

// Legacy incremental user/plugin APIs do not carry the complete mixed generation. In joint
// mode they could resurrect revoked users during rollback, or stop Xray behind an admitted edge.
// Keep these APIs unchanged for existing standalone Agents; joint panels must reconcile in full.
@Injectable()
export class StandaloneXrayMutationGuard implements CanActivate {
    constructor(private readonly env: TypedConfigService) {}

    canActivate(): boolean {
        if (this.env.getOrThrow('ANYTLS_ENABLED') && this.env.getOrThrow('EDGE_ENABLED'))
            throw new BadRequestException(
                'Use complete coordinated Xray/AnyTLS configuration instead of incremental Xray mutations.',
            );
        return true;
    }
}
