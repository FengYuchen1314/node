import {
    BadRequestException,
    Logger,
    Injectable,
    OnModuleDestroy,
    OnModuleInit,
} from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';
import {
    AnyTlsConfigSchema,
    AnyTlsUsageResponseSchema,
    TAnyTlsConfig,
    TAnyTlsUsageResponse,
} from '@libs/contracts/models';

import { CamouflageRuntimePolicy } from '../camouflage-domain/camouflage-runtime-policy.service';
import { AnyTlsRuntimeIO } from './anytls-runtime.io';
import { AnyTlsRuntimeState, AnyTlsRuntimeStore } from './anytls-runtime.store';
import { AnyTlsCounters } from './anytls-stats.client';

export class AnyTlsUpdateError extends Error {
    constructor(readonly rollbackSucceeded: boolean) {
        super(
            rollbackSucceeded
                ? 'AnyTLS update failed; previous configuration restored.'
                : 'AnyTLS update failed and rollback was not confirmed.',
        );
    }
}

export interface CoordinatedAnyTlsTransition {
    quiesce: () => Promise<void>;
    apply: () => Promise<void>;
    rollback: () => Promise<void>;
}

@Injectable()
export class AnyTlsRuntimeService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger(AnyTlsRuntimeService.name);
    private queue: Promise<unknown> = Promise.resolve();
    private state: AnyTlsRuntimeState | undefined;
    private timer: NodeJS.Timeout | undefined;
    private checkpointPending = false;
    private stopped = false;
    private lastError: string | null = null;
    private pendingFinal: AnyTlsCounters | undefined;
    private shutdown: Promise<void> | undefined;
    private awaitingCoordinatedStart = false;

    constructor(
        private readonly env: TypedConfigService,
        private readonly io: AnyTlsRuntimeIO,
        private readonly store: AnyTlsRuntimeStore,
        private readonly camouflage: CamouflageRuntimePolicy,
    ) {}

    async onModuleInit(): Promise<void> {
        if (!this.enabled()) return;
        await this.lock(async () => {
            await this.io.acquire();
            const state = await this.load();
            if (state.desired?.listeners.length) {
                if (this.coordinated()) {
                    // Saved listeners alone do not prove that Xray and the edge have the same
                    // generation after a crash. The panel must reconcile the complete plan.
                    this.awaitingCoordinatedStart = true;
                    this.lastError = 'Awaiting coordinated Xray/AnyTLS/edge start from the panel.';
                    return;
                }
                try {
                    await this.applyUnlocked(state.desired);
                } catch {
                    // Keep the authenticated management API available so an invalid/expired saved
                    // endpoint can be replaced or stopped. Never start it just to restore availability.
                    this.lastError = 'Saved AnyTLS configuration could not be restored safely.';
                    this.logger.error(this.lastError);
                }
            }
        });
        this.timer = setInterval(() => {
            if (this.checkpointPending || this.stopped) return;
            this.checkpointPending = true;
            void this.lock(async () => {
                if (this.io.hasChildren()) await this.refresh();
            })
                .catch(() => {
                    this.lastError = 'AnyTLS runtime or accounting checkpoint is unhealthy.';
                    this.logger.error(this.lastError);
                })
                .finally(() => {
                    this.checkpointPending = false;
                });
        }, 5000);
        this.timer.unref();
    }

    async onModuleDestroy(): Promise<void> {
        if (this.shutdown) return this.shutdown;
        this.stopped = true;
        clearInterval(this.timer);
        this.shutdown = this.lock(async () => {
            try {
                if (!this.state) return;
                const desired = this.state.desired;
                await this.retire();
                await this.persist({ ...this.state, desired, seen: {} });
            } finally {
                await this.io.abort();
                await this.io.release();
            }
        });
        return this.shutdown;
    }

    apply(input: unknown): Promise<{
        isStarted: boolean;
        operation: 'STARTED' | 'RELOADED' | 'UNCHANGED' | 'STOPPED';
    }> {
        return this.lock(async () => {
            this.requireEnabled();
            this.requireStandalone();
            const config = AnyTlsConfigSchema.parse(input);
            if (!config.listeners.length) {
                await this.stopUnlocked();
                return { isStarted: false, operation: 'STOPPED' };
            }
            return this.applyUnlocked(config);
        });
    }

    stop(): Promise<{ isStopped: true }> {
        return this.lock(async () => {
            this.requireEnabled();
            this.requireStandalone();
            await this.stopUnlocked();
            return { isStopped: true };
        });
    }

    coordinated(): boolean {
        return this.enabled() && this.env.getOrThrow('EDGE_ENABLED');
    }

    capabilities() {
        return {
            available: this.enabled(),
            coordinatedStartVersion: this.coordinated() ? 1 : null,
        };
    }

    // Keep the accounting/standalone API lock through edge commit or rollback, not just
    // through process activation. Callbacks deliberately use the unlocked operations.
    withCoordinatedUpdate<T>(
        input: unknown,
        operation: (runtime: CoordinatedAnyTlsTransition) => Promise<T>,
    ): Promise<T> {
        return this.lock(async () => {
            this.requireEnabled();
            if (!this.coordinated()) throw new Error('Coordinated AnyTLS requires a managed edge.');
            const config = AnyTlsConfigSchema.parse(input);
            if (config.listeners.length) {
                try {
                    this.io.validate(config);
                } catch {
                    throw new BadRequestException(
                        'AnyTLS listener configuration failed validation.',
                    );
                }
                await this.camouflage.assertAnyTls(config);
            }
            const state = await this.load();
            // A saved but inactive generation is not a confirmed rollback target.
            const previous = this.io.isRunning() ? structuredClone(state.desired) : null;
            let attempted = false;
            return operation({
                quiesce: async () => {
                    attempted = true;
                    this.awaitingCoordinatedStart = false;
                    await this.stopUnlocked();
                },
                apply: async () => {
                    attempted = true;
                    this.awaitingCoordinatedStart = false;
                    if (config.listeners.length) await this.applyUnlocked(config);
                    else await this.stopUnlocked();
                },
                rollback: async () => {
                    if (!attempted) return;
                    try {
                        if (previous?.listeners.length) await this.applyUnlocked(previous);
                        else await this.stopUnlocked();
                    } catch {
                        // applyUnlocked's standalone rollback may have restored the NEW config.
                        // That must never survive a failed restoration of the joint generation.
                        await this.io.abort().catch(() => undefined);
                        await this.persist({ ...this.state!, desired: null, seen: {} }).catch(
                            () => undefined,
                        );
                        this.lastError = 'Coordinated AnyTLS rollback was not confirmed.';
                        throw new Error(this.lastError);
                    }
                },
            });
        });
    }

    withCoordinatedStop<T>(operation: (stop: () => Promise<void>) => Promise<T>): Promise<T> {
        return this.lock(async () => {
            this.requireEnabled();
            if (!this.coordinated()) throw new Error('Coordinated AnyTLS requires a managed edge.');
            return operation(async () => {
                this.awaitingCoordinatedStart = false;
                await this.stopUnlocked();
            });
        });
    }

    status(): Promise<{
        available: boolean;
        isStarted: boolean;
        desiredListeners: number;
        error: string | null;
    }> {
        return this.lock(async () => {
            if (!this.enabled())
                return { available: false, isStarted: false, desiredListeners: 0, error: null };
            const state = await this.load();
            return {
                available: true,
                isStarted: this.io.isRunning(),
                desiredListeners: state.desired?.listeners.length ?? 0,
                error:
                    this.lastError ??
                    (state.desired?.listeners.length && !this.io.isRunning()
                        ? 'AnyTLS processes are not running.'
                        : null),
            };
        });
    }

    users(reset: boolean): Promise<Array<{ username: string; uplink: number; downlink: number }>> {
        return this.lock(async () => {
            this.requireEnabled();
            const state = await this.load();
            if (reset && state.usageLedger)
                throw new BadRequestException(
                    'Cumulative AnyTLS accounting is active; destructive stats resets are disabled.',
                );
            await this.flushFinal();
            if (
                (!this.awaitingCoordinatedStart && state.desired?.listeners.length) ||
                this.io.hasChildren()
            )
                await this.refresh();
            const delta = difference(this.state!.totals, this.state!.billed);
            const users = Object.entries(delta).map(([username, value]) => ({
                username,
                uplink: safeNumber(value.uplink),
                downlink: safeNumber(value.downlink),
            }));
            // A failed durable write must not consume a caller's unbilled delta.
            if (reset && users.some((value) => value.uplink !== 0 || value.downlink !== 0))
                await this.persist({ ...this.state!, billed: structuredClone(this.state!.totals) });
            return users.filter((value) => value.uplink !== 0 || value.downlink !== 0);
        });
    }

    usage(): Promise<TAnyTlsUsageResponse> {
        return this.lock(async () => {
            if (!this.enabled()) return { available: false };
            this.requireEnabled();
            const state = await this.load();
            await this.flushFinal();
            if (
                (!this.awaitingCoordinatedStart && state.desired?.listeners.length) ||
                this.io.hasChildren()
            )
                await this.refresh();
            const current = this.state!;
            const ledger = current.usageLedger ?? {
                epoch: randomUUID(),
                baseline: structuredClone(current.billed),
            };
            const counters = difference(current.totals, ledger.baseline);
            const snapshot = AnyTlsUsageResponseSchema.parse({
                available: true,
                version: 1,
                epoch: ledger.epoch,
                users: Object.entries(counters)
                    .sort(([a], [b]) => a.localeCompare(b))
                    .map(([username, values]) => ({ username, ...values })),
            });
            // Never publish an epoch or counters before the durable write succeeds.
            // Polling/retrying does not clear totals or advance an acknowledgement.
            if (!current.usageLedger) await this.persist({ ...current, usageLedger: ledger });
            return snapshot;
        });
    }

    private async applyUnlocked(
        config: TAnyTlsConfig,
    ): Promise<{ isStarted: true; operation: 'STARTED' | 'RELOADED' | 'UNCHANGED' }> {
        await this.io.acquire();
        const state = await this.load();
        const previous = state.desired;
        // Validate certificate identity and both native configs before touching a live runtime.
        try {
            this.io.validate(config);
        } catch {
            throw new BadRequestException('AnyTLS listener configuration failed validation.');
        }
        await this.camouflage.assertAnyTls(config);
        if (this.io.isRunning() && JSON.stringify(previous) === JSON.stringify(config)) {
            this.lastError = null;
            return { isStarted: true, operation: 'UNCHANGED' };
        }
        const prepared = await this.io.prepare(config);
        try {
            await this.persist({ ...state, desired: null });
        } catch (error) {
            await this.io.discard(prepared);
            throw error;
        }
        try {
            await this.retire();
            await this.persist({ ...this.state!, seen: {} });
            await this.io.start(prepared);
            await this.persist({ ...this.state!, desired: config });
            this.lastError = null;
            return { isStarted: true, operation: previous ? 'RELOADED' : 'STARTED' };
        } catch {
            let restored = false;
            try {
                await this.retire();
                await this.persist({ ...this.state!, desired: null, seen: {} });
                if (previous?.listeners.length) {
                    await this.camouflage.assertAnyTls(previous);
                    const rollback = await this.io.prepare(previous);
                    try {
                        await this.io.start(rollback);
                    } finally {
                        await this.io.discard(rollback);
                    }
                }
                await this.persist({ ...this.state!, desired: previous });
                restored = true;
            } catch {
                await this.io.abort().catch(() => undefined);
                await this.persist({ ...this.state!, desired: null, seen: {} }).catch(
                    () => undefined,
                );
            }
            this.lastError = new AnyTlsUpdateError(restored).message;
            throw new AnyTlsUpdateError(restored);
        } finally {
            await this.io.discard(prepared);
        }
    }

    private async stopUnlocked(): Promise<void> {
        const state = await this.load();
        await this.io.acquire();
        // Persist explicit stop intent first. Neither partial failure nor restart may revive it.
        await this.persist({ ...state, desired: null });
        try {
            await this.retire();
            await this.persist({ ...this.state!, seen: {} });
            this.lastError = null;
        } catch {
            await this.io.abort();
            this.lastError = 'AnyTLS stopped, but final accounting was not confirmed.';
            throw new Error(this.lastError);
        }
    }

    private async refresh(): Promise<void> {
        await this.record(await this.io.snapshot());
    }
    private async retire(): Promise<void> {
        await this.flushFinal();
        if (this.io.hasChildren()) {
            this.pendingFinal = await this.io.retire();
            await this.flushFinal();
        }
    }
    private async flushFinal(): Promise<void> {
        if (!this.pendingFinal) return;
        await this.record(this.pendingFinal);
        this.pendingFinal = undefined;
    }
    private async record(snapshot: AnyTlsCounters): Promise<void> {
        const state = await this.load();
        const delta = difference(snapshot, state.seen);
        if (Object.values(delta).every((value) => value.uplink === '0' && value.downlink === '0'))
            return;
        const totals = structuredClone(state.totals);
        for (const [name, values] of Object.entries(delta)) {
            if (!Object.hasOwn(totals, name)) totals[name] = { uplink: '0', downlink: '0' };
            const total = totals[name];
            total.uplink = String(BigInt(total.uplink) + BigInt(values.uplink));
            total.downlink = String(BigInt(total.downlink) + BigInt(values.downlink));
        }
        await this.persist({ ...state, totals, seen: structuredClone(snapshot) });
    }
    private async load(): Promise<AnyTlsRuntimeState> {
        return (this.state ??= await this.store.load());
    }
    private async persist(state: AnyTlsRuntimeState): Promise<void> {
        await this.store.save(state);
        this.state = state;
    }
    private enabled(): boolean {
        return this.env.getOrThrow('ANYTLS_ENABLED');
    }
    private requireEnabled(): void {
        if (!this.enabled() || this.stopped) throw new Error('Managed AnyTLS runtime is disabled.');
    }
    private requireStandalone(): void {
        if (this.coordinated())
            throw new BadRequestException(
                'Use the coordinated Xray start/stop endpoint on a shared-443 Agent.',
            );
    }
    private lock<T>(operation: () => Promise<T>): Promise<T> {
        const result = this.queue.then(operation);
        this.queue = result.catch(() => undefined);
        return result;
    }
}

export function difference(current: AnyTlsCounters, before: AnyTlsCounters): AnyTlsCounters {
    const result: AnyTlsCounters = Object.create(null);
    for (const name of new Set([...Object.keys(current), ...Object.keys(before)])) {
        const next = Object.hasOwn(current, name) ? current[name] : { uplink: '0', downlink: '0' };
        const prior = Object.hasOwn(before, name) ? before[name] : { uplink: '0', downlink: '0' };
        const uplink = BigInt(next.uplink) - BigInt(prior.uplink);
        const downlink = BigInt(next.downlink) - BigInt(prior.downlink);
        if (uplink < 0 || downlink < 0)
            throw new Error('Unexpected AnyTLS counter reset inside one runtime generation.');
        result[name] = { uplink: String(uplink), downlink: String(downlink) };
    }
    return result;
}
function safeNumber(value: string): number {
    const integer = BigInt(value);
    if (integer > BigInt(Number.MAX_SAFE_INTEGER))
        throw new Error('AnyTLS delta exceeds the accounting API safe integer limit.');
    return Number(integer);
}
import { randomUUID } from 'node:crypto';
