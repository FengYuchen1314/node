import { createHash } from 'node:crypto';

import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';
import {
    MieruIsolatedConfigSchema,
    TMieruIsolatedConfig,
    TMieruServerConfig,
} from '@libs/contracts/models';

import {
    IMieruStatusResult,
    IMieruStopResult,
    IMieruSyncResult,
    MieruControlClient,
    MieruControlError,
} from './mieru-control.client';
import { MieruDaemonManager } from './mieru-daemon.manager';
import { MieruRuntimeState, MieruRuntimeStore } from './mieru-runtime.store';

@Injectable()
export class MieruRuntimeService implements OnModuleInit, OnModuleDestroy {
    private state: MieruRuntimeState | undefined;
    private queue: Promise<unknown> = Promise.resolve();
    private active = new Map<string, TMieruServerConfig>();
    private version = 'unknown';
    private legacyStopped = false;

    constructor(
        private readonly config: TypedConfigService,
        private readonly control: MieruControlClient,
        private readonly daemons: MieruDaemonManager,
        private readonly store: MieruRuntimeStore,
    ) {}

    async onModuleInit(): Promise<void> {
        if (this.config.getOrThrow('MIERU_ENABLED')) {
            await this.lock(async () => {
                const state = await this.load();
                if (state.desired) await this.applyUnlocked(state.desired);
            });
        }
    }

    async onModuleDestroy(): Promise<void> {
        await this.lock(async () => {
            if (!this.state) return;
            // Retain desired state on normal shutdown; an explicit stop persists null.
            await this.retireAll();
            await this.store.save(this.state);
        });
    }

    apply(config: TMieruIsolatedConfig | TMieruServerConfig): Promise<IMieruSyncResult> {
        return this.lock(() => this.applyUnlocked(normalizeConfig(config)));
    }

    stop(): Promise<IMieruStopResult> {
        return this.lock(async () => {
            const state = await this.load();
            // A failed or interrupted stop must never auto-revive listeners at restart.
            await this.store.save({ ...state, desired: null });
            state.desired = null;
            const errors: unknown[] = [];
            try {
                await this.stopLegacy();
            } catch (error) {
                errors.push(error);
            }
            try {
                await this.retireAll();
            } catch (error) {
                errors.push(error);
            }
            await this.store.save(state);
            if (errors.length)
                throw new Error(
                    'Some Mieru instances could not be stopped or their final counters could not be saved.',
                );
            return { status: 'IDLE', operation: 'STOPPED' };
        });
    }

    status(): Promise<IMieruStatusResult> {
        return this.lock(async () => {
            const state = await this.load();
            const instanceMetrics = { ...state.retired };
            for (const id of this.daemons.ids()) {
                const result = await this.control.status(this.daemons.socket(id));
                if (this.active.has(id) && result.status !== 'RUNNING') {
                    throw new Error(`Mieru instance ${id} is not running.`);
                }
                instanceMetrics[id] = result.metrics;
            }
            // Legacy and per-instance counters remain separate until AFTER delta calculation.
            const legacy =
                !this.legacyStopped && (await this.daemons.hasLegacy())
                    ? (await this.control.status(this.daemons.legacySocket)).metrics
                    : state.legacy;
            return {
                status: this.active.size ? 'RUNNING' : 'IDLE',
                version: this.version,
                metrics: legacy,
                instanceMetrics,
            };
        });
    }

    private async applyUnlocked(next: TMieruIsolatedConfig): Promise<IMieruSyncResult> {
        const state = await this.load();
        const previous = state.desired;
        await this.store.save({ ...state, desired: null });
        state.desired = null;
        try {
            await this.stopLegacy();
            await this.reconcile(next);
            state.desired = next;
            await this.store.save(state);
            return {
                status: 'RUNNING',
                version: this.version,
                operation: previous ? 'RELOADED' : 'STARTED',
            };
        } catch {
            let rolledBack = false;
            try {
                await this.retireAll();
                if (previous) await this.reconcile(previous);
                state.desired = previous;
                await this.store.save(state);
                rolledBack = true;
            } catch {
                state.desired = null;
                await this.retireAll().catch(() => undefined);
                await this.store.save(state).catch(() => undefined);
            }
            throw new MieruControlError(
                'Mieru listener reconciliation failed.',
                'reconcile-instances',
                true,
                rolledBack,
            );
        }
    }

    private async reconcile(next: TMieruIsolatedConfig): Promise<void> {
        const wanted = new Map(next.instances.map((instance) => [instance.id, instance.config]));
        for (const [id, old] of this.active) {
            const config = wanted.get(id);
            if (
                !config ||
                JSON.stringify(config.portBindings) !== JSON.stringify(old.portBindings)
            ) {
                await this.retire(id);
            }
        }
        for (const [id, config] of wanted) {
            if (!(id in this.state!.retired)) {
                // Journal the identity before spawning, even if reconciliation is interrupted.
                this.state!.retired[id] = {};
                await this.store.save(this.state!);
            }
            await this.daemons.ensure(id);
            // Upstream Reload only updates the credential registry, not already-authenticated
            // sessions. Stop changed listeners first so revoked credentials lose open tunnels.
            const previous = this.active.get(id);
            if (previous && JSON.stringify(previous) !== JSON.stringify(config)) {
                await this.control.stop(this.daemons.socket(id));
            }
            const result = await this.control.apply(config, this.daemons.socket(id));
            if (result.status !== 'RUNNING')
                throw new Error('Mieru did not confirm a running listener.');
            this.version = result.version;
            this.active.set(id, config);
        }
    }

    private async retire(id: string): Promise<void> {
        const errors: unknown[] = [];
        try {
            const result = await this.control.stop(this.daemons.socket(id));
            if (result.status === 'RUNNING') throw new Error('Mieru stop was not confirmed.');
            this.state!.retired[id] = (await this.control.status(this.daemons.socket(id))).metrics;
            await this.store.save(this.state!);
        } catch (error) {
            errors.push(error);
        }
        try {
            await this.daemons.terminate(id);
            this.active.delete(id);
        } catch (error) {
            errors.push(error);
        }
        if (errors.length) throw new Error(`Mieru instance ${id} stop/accounting failed.`);
    }

    private async retireAll(): Promise<void> {
        const errors: unknown[] = [];
        for (const id of this.daemons.ids()) {
            try {
                await this.retire(id);
            } catch (error) {
                errors.push(error);
            }
        }
        if (errors.length) throw new Error('One or more Mieru instance stops failed.');
    }

    private async stopLegacy(): Promise<void> {
        if (this.legacyStopped) return;
        if (await this.daemons.hasLegacy()) {
            const result = await this.control.stop(this.daemons.legacySocket);
            if (result.status === 'RUNNING') throw new Error('Legacy Mieru did not stop.');
            this.state!.legacy = (await this.control.status(this.daemons.legacySocket)).metrics;
            await this.store.save(this.state!);
        }
        this.legacyStopped = true;
    }

    private async load(): Promise<MieruRuntimeState> {
        if (!this.state) {
            const state = await this.store.load();
            for (const id of Object.keys(state.retired)) {
                await this.daemons.prepare(id);
                // Recover final counters written when the previous Agent/daemon exited,
                // including instances interrupted before desired state could be committed.
                const metrics = await this.control.readDump(this.daemons.dumpPath(id));
                if (metrics) state.retired[id] = metrics;
            }
            this.state = state;
        }
        return this.state;
    }

    private lock<T>(operation: () => Promise<T>): Promise<T> {
        const result = this.queue.then(operation);
        this.queue = result.catch(() => undefined);
        return result;
    }
}

function normalizeConfig(config: TMieruIsolatedConfig | TMieruServerConfig): TMieruIsolatedConfig {
    if ('kind' in config) return MieruIsolatedConfigSchema.parse(config);
    if (config.portBindings.length !== 1)
        throw new Error(
            'Legacy multi-listener configurations cannot preserve per-listener permissions.',
        );
    const hex = createHash('sha256').update(JSON.stringify(config.portBindings[0])).digest('hex');
    const id = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
    return MieruIsolatedConfigSchema.parse({
        kind: 'ISOLATED_LISTENERS',
        instances: [{ id, config }],
    });
}
