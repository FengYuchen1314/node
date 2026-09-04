import { Injectable } from '@nestjs/common';

import { TypedConfigService } from '@common/config/app-config';
import { TMieruMetrics } from '@libs/contracts/models';

import {
    MieruCumulativeUserCounters,
    MieruMetricsBaselineState,
    MieruMetricsBaselineStore,
} from './mieru-metrics-baseline.store';
import { MieruRuntimeService } from './mieru-runtime.service';

export const MIERU_AGGREGATE_OUTBOUND_TAG = '__mieru_user_aggregate__';

const MAX_SAFE_DELTA = BigInt(Number.MAX_SAFE_INTEGER);
const DECIMAL_COUNTER_PATTERN = /^\d+$/;

export interface MieruUserDelta {
    downlink: number;
    uplink: number;
    username: string;
}

export interface MieruAggregateDelta {
    downlink: number;
    uplink: number;
}

interface PendingDelta {
    baseline: MieruCumulativeUserCounters;
    current: MieruCumulativeUserCounters;
    downlink: bigint;
    uplink: bigint;
    username: string;
}

@Injectable()
export class MieruMetricsDeltaService {
    private enabled: boolean;
    private baselineState = createEmptyBaselineState();
    private baselineStateLoaded = false;
    private pollQueue: Promise<void> = Promise.resolve();
    private readonly usernames = new Map<string, string>();

    constructor(
        configService: TypedConfigService,
        private readonly control: MieruRuntimeService,
        private readonly baselineStore: MieruMetricsBaselineStore,
    ) {
        this.enabled = configService.getOrThrow('MIERU_ENABLED');
    }

    public enable(): void {
        this.enabled = true;
    }

    public isEnabled(): boolean {
        return this.enabled;
    }

    public getUserDeltas(consumer: 'users', reset: boolean): Promise<MieruUserDelta[]> {
        return this.withPollLock(async () => {
            await this.ensureBaselineStateLoaded();
            const current = await this.readCumulativeUsers();
            const working = cloneBaselineState(this.baselineState);
            const consumerState = working[consumer];
            const baselines = consumerState.baselines;
            const result = new Map<string, MieruUserDelta>();

            if (!consumerState.initialized) {
                consumerState.initialized = true;
                for (const [username, counters] of current) {
                    baselines.set(username, counters);
                    const logicalName = this.usernames.get(username)!;
                    result.set(logicalName, { username: logicalName, uplink: 0, downlink: 0 });
                }
                await this.commitBaselineState(working);
                return [...result.values()];
            }

            for (const [username, counters] of current) {
                const baseline = baselines.get(username) ?? { uplink: 0n, downlink: 0n };
                const logicalName = this.usernames.get(username)!;
                const total = result.get(logicalName) ?? {
                    username: logicalName,
                    uplink: 0,
                    downlink: 0,
                };
                const budget = MAX_SAFE_DELTA - BigInt(total.uplink) - BigInt(total.downlink);

                const available = calculateAvailable(baseline, counters);
                const emitted = allocatePair(available.uplink, available.downlink, budget);
                if (reset) {
                    baselines.set(username, advanceBaseline(baseline, counters, emitted));
                }
                total.uplink += Number(emitted.uplink);
                total.downlink += Number(emitted.downlink);
                result.set(logicalName, total);
            }

            await this.commitBaselineState(working);
            return [...result.values()];
        });
    }

    public getAggregateDelta(reset: boolean): Promise<MieruAggregateDelta> {
        return this.withPollLock(async () => {
            await this.ensureBaselineStateLoaded();
            const current = await this.readCumulativeUsers();
            const working = cloneBaselineState(this.baselineState);
            const consumerState = working.combined;
            const baselines = consumerState.baselines;
            const pending: PendingDelta[] = [];
            let totalUplink = 0n;
            let totalDownlink = 0n;

            if (!consumerState.initialized) {
                consumerState.initialized = true;
                for (const [username, counters] of current) {
                    baselines.set(username, counters);
                }
                await this.commitBaselineState(working);
                return { uplink: 0, downlink: 0 };
            }

            for (const [username, counters] of current) {
                const baseline = baselines.get(username) ?? { uplink: 0n, downlink: 0n };
                const available = calculateAvailable(baseline, counters);
                pending.push({ username, baseline, current: counters, ...available });
                totalUplink += available.uplink;
                totalDownlink += available.downlink;
            }

            const budget = allocatePair(totalUplink, totalDownlink, MAX_SAFE_DELTA);
            let remainingUplink = budget.uplink;
            let remainingDownlink = budget.downlink;

            for (const delta of pending) {
                const emitted = {
                    uplink: minBigInt(delta.uplink, remainingUplink),
                    downlink: minBigInt(delta.downlink, remainingDownlink),
                };
                remainingUplink -= emitted.uplink;
                remainingDownlink -= emitted.downlink;
                if (reset) {
                    baselines.set(
                        delta.username,
                        advanceBaseline(delta.baseline, delta.current, emitted),
                    );
                }
            }

            await this.commitBaselineState(working);
            return {
                uplink: Number(budget.uplink),
                downlink: Number(budget.downlink),
            };
        });
    }

    private async readCumulativeUsers(): Promise<Map<string, MieruCumulativeUserCounters>> {
        if (!this.enabled) {
            throw new Error('Mieru metrics are not enabled for this node.');
        }
        const response = await this.control.status();
        const current = parseCumulativeUsers(response.metrics);
        this.usernames.clear();
        for (const username of current.keys()) this.usernames.set(username, username);
        for (const [instance, metrics] of Object.entries(response.instanceMetrics ?? {}).sort()) {
            for (const [username, counters] of parseCumulativeUsers(metrics)) {
                const key = JSON.stringify([instance, username]);
                if (current.has(key)) throw new Error('Mieru metric identity collision.');
                current.set(key, counters);
                this.usernames.set(key, username);
            }
        }
        return current;
    }

    private async ensureBaselineStateLoaded(): Promise<void> {
        if (this.baselineStateLoaded) return;
        this.baselineState = (await this.baselineStore.load()) ?? createEmptyBaselineState();
        this.baselineStateLoaded = true;
    }

    private async commitBaselineState(state: MieruMetricsBaselineState): Promise<void> {
        if (baselineStatesEqual(this.baselineState, state)) return;
        await this.baselineStore.save(state);
        this.baselineState = state;
    }

    private async withPollLock<T>(operation: () => Promise<T>): Promise<T> {
        const previous = this.pollQueue;
        let release!: () => void;
        this.pollQueue = new Promise<void>((resolve) => {
            release = resolve;
        });
        await previous;
        try {
            return await operation();
        } finally {
            release();
        }
    }
}

function parseCumulativeUsers(metrics: TMieruMetrics): Map<string, MieruCumulativeUserCounters> {
    const result = new Map<string, MieruCumulativeUserCounters>();
    const users = metrics.users;
    if (users === undefined) return result;
    if (!isRecord(users)) {
        throw new Error('Mita user metrics are not an object.');
    }

    for (const [username, value] of Object.entries(users).sort(([left], [right]) =>
        left.localeCompare(right),
    )) {
        if (username.length === 0 || Buffer.byteLength(username, 'utf8') > 64) {
            throw new Error('Mita metrics contain an invalid user name.');
        }
        if (!isRecord(value)) {
            throw new Error(`Mita metrics for user ${JSON.stringify(username)} are invalid.`);
        }
        result.set(username, {
            uplink: parseCounter(value.UploadBytes, username, 'UploadBytes'),
            downlink: parseCounter(value.DownloadBytes, username, 'DownloadBytes'),
        });
    }
    return result;
}

function parseCounter(value: unknown, username: string, name: string): bigint {
    if (typeof value !== 'string' || !DECIMAL_COUNTER_PATTERN.test(value)) {
        throw new Error(
            `Mita ${name} counter for user ${JSON.stringify(username)} is not a non-negative decimal integer.`,
        );
    }
    return BigInt(value);
}

function calculateAvailable(
    baseline: MieruCumulativeUserCounters,
    current: MieruCumulativeUserCounters,
): MieruCumulativeUserCounters {
    return {
        uplink:
            current.uplink >= baseline.uplink ? current.uplink - baseline.uplink : current.uplink,
        downlink:
            current.downlink >= baseline.downlink
                ? current.downlink - baseline.downlink
                : current.downlink,
    };
}

function advanceBaseline(
    baseline: MieruCumulativeUserCounters,
    current: MieruCumulativeUserCounters,
    emitted: MieruCumulativeUserCounters,
): MieruCumulativeUserCounters {
    return {
        uplink:
            current.uplink >= baseline.uplink ? baseline.uplink + emitted.uplink : emitted.uplink,
        downlink:
            current.downlink >= baseline.downlink
                ? baseline.downlink + emitted.downlink
                : emitted.downlink,
    };
}

function allocatePair(
    uplink: bigint,
    downlink: bigint,
    budget: bigint,
): MieruCumulativeUserCounters {
    if (uplink + downlink <= budget) return { uplink, downlink };
    if (uplink === 0n) return { uplink: 0n, downlink: minBigInt(downlink, budget) };
    if (downlink === 0n) return { uplink: minBigInt(uplink, budget), downlink: 0n };

    let emittedUplink = minBigInt(uplink, budget / 2n);
    let emittedDownlink = minBigInt(downlink, budget - budget / 2n);
    let remaining = budget - emittedUplink - emittedDownlink;
    const moreUplink = minBigInt(uplink - emittedUplink, remaining);
    emittedUplink += moreUplink;
    remaining -= moreUplink;
    emittedDownlink += minBigInt(downlink - emittedDownlink, remaining);
    return { uplink: emittedUplink, downlink: emittedDownlink };
}

function minBigInt(left: bigint, right: bigint): bigint {
    return left < right ? left : right;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function createEmptyBaselineState(): MieruMetricsBaselineState {
    return {
        users: { initialized: false, baselines: new Map() },
        combined: { initialized: false, baselines: new Map() },
    };
}

function cloneBaselineState(state: MieruMetricsBaselineState): MieruMetricsBaselineState {
    return {
        users: { initialized: state.users.initialized, baselines: new Map(state.users.baselines) },
        combined: {
            initialized: state.combined.initialized,
            baselines: new Map(state.combined.baselines),
        },
    };
}

function baselineStatesEqual(
    left: MieruMetricsBaselineState,
    right: MieruMetricsBaselineState,
): boolean {
    return (
        consumerStatesEqual(left.users, right.users) &&
        consumerStatesEqual(left.combined, right.combined)
    );
}

function consumerStatesEqual(
    left: MieruMetricsBaselineState['users'],
    right: MieruMetricsBaselineState['users'],
): boolean {
    if (left.initialized !== right.initialized || left.baselines.size !== right.baselines.size) {
        return false;
    }
    for (const [username, counters] of left.baselines) {
        const other = right.baselines.get(username);
        if (!other || counters.uplink !== other.uplink || counters.downlink !== other.downlink) {
            return false;
        }
    }
    return true;
}
