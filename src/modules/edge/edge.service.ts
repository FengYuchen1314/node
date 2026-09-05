import { Injectable, OnModuleInit } from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';
import {
    NODE_EDGE_PLAN_VERSION,
    TAnyTlsConfig,
    TNodeEdgePlan,
    TNodeEdgeStatusResponse,
} from '@libs/contracts/models';

import { rejectLocalEdgeLoops, validateEdgePlan } from './edge-config';
import { EdgeConfigIO } from './edge-config.io';

@Injectable()
export class EdgeService implements OnModuleInit {
    private readonly enabled: boolean;
    private readonly coordinated: boolean;
    private readonly managementPorts: number[];
    private unsafeRecovery = false;
    private queue: Promise<unknown> = Promise.resolve();

    constructor(
        config: TypedConfigService,
        private readonly io: EdgeConfigIO,
    ) {
        this.enabled = config.getOrThrow('EDGE_ENABLED');
        this.coordinated = this.enabled && config.getOrThrow('ANYTLS_ENABLED');
        this.managementPorts = this.coordinated
            ? [
                  config.getOrThrow('NODE_PORT'),
                  config.getOrThrow('ANYTLS_STATS_PORT'),
                  config.getOrThrow('ANYTLS_CONTROL_PORT'),
              ]
            : [];
    }

    async onModuleInit(): Promise<void> {
        if (this.enabled)
            await this.lock(async () => {
                await this.recover();
                if (this.coordinated && (await this.io.readPlan())?.routes.length)
                    await this.io.withdraw(await this.io.snapshot());
            });
    }

    async status(): Promise<TNodeEdgeStatusResponse> {
        if (!this.enabled)
            return {
                available: false,
                planVersion: NODE_EDGE_PLAN_VERSION,
                haproxy: false,
                caddy: false,
            };
        return this.lock(async () => {
            try {
                await this.recover();
            } catch {
                return {
                    available: false,
                    planVersion: NODE_EDGE_PLAN_VERSION,
                    haproxy: false,
                    caddy: false,
                };
            }
            const status = await this.io.status();
            return {
                ...status,
                available: status.haproxy && status.caddy,
                planVersion: NODE_EDGE_PLAN_VERSION,
            };
        });
    }

    run<T>(
        plan: TNodeEdgePlan | undefined,
        xrayConfig: Record<string, unknown>,
        start: () => Promise<T>,
        rollback: () => Promise<void>,
        anyTlsConfig?: TAnyTlsConfig,
    ): Promise<T> {
        return this.lock(async () => {
            if (!this.enabled) {
                if (plan) throw new Error('This Agent has no managed shared-443 edge.');
                return start();
            }
            if (!plan) throw new Error('A shared-443 Agent requires an explicit edge plan.');
            if (this.coordinated !== (anyTlsConfig !== undefined))
                throw new Error(
                    'A coordinated Agent requires an explicit AnyTLS configuration; other Agents must omit it.',
                );
            const validated = validateEdgePlan(
                plan,
                xrayConfig,
                anyTlsConfig,
                this.managementPorts,
            );
            await rejectLocalEdgeLoops(validated, anyTlsConfig, this.managementPorts);
            await this.recover();
            const snapshot = await this.io.snapshot();
            await this.io.begin(snapshot);
            let attempted = false;
            try {
                // No new proxy admission while either runtime is being replaced. Keep Caddy's
                // website/panel configuration until the entire new generation is ready.
                if (this.coordinated) {
                    await this.io.withdraw(snapshot);
                    await this.io.begin(snapshot);
                }
                attempted = true;
                const result = await start();
                await this.io.apply(validated);
                await this.io.commit();
                return result;
            } catch {
                let restored = true;
                try {
                    if (attempted) await rollback();
                } catch {
                    restored = false;
                }
                try {
                    if (restored) await this.io.restore(snapshot);
                    else {
                        this.unsafeRecovery = true;
                        await this.io.withdraw(snapshot);
                    }
                } catch {
                    restored = false;
                }
                throw new Error(
                    restored
                        ? 'Shared-443 update failed; previous configuration restored.'
                        : 'Shared-443 update failed and rollback was not confirmed.',
                );
            }
        });
    }

    stop<T>(stop: () => Promise<T>): Promise<T> {
        return this.lock(async () => {
            if (!this.enabled) return stop();
            await this.recover();
            const plan = await this.io.readPlan();
            if (plan) {
                const snapshot = await this.io.snapshot();
                await this.io.begin(snapshot);
                try {
                    // Keep website/panel routes, but stop accepting new proxy sessions.
                    await this.io.apply({ ...plan, routes: [] });
                    await this.io.commit();
                } catch (error) {
                    await this.io.restore(snapshot);
                    throw error;
                }
            }
            return stop();
        });
    }

    private async recover(): Promise<void> {
        await this.io.recover(this.coordinated || this.unsafeRecovery);
    }

    private lock<T>(operation: () => Promise<T>): Promise<T> {
        const result = this.queue.then(operation);
        this.queue = result.catch(() => undefined);
        return result;
    }
}
