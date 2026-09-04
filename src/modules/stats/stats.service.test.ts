import type { MieruMetricsDeltaService } from '../mieru/mieru-metrics-delta.service';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { QueryBus } from '@nestjs/cqrs';

import type { XtlsApi } from '@remnawave/xtls-sdk';

import { MIERU_AGGREGATE_OUTBOUND_TAG } from '../mieru/mieru-metrics-delta.service';
import { StatsService } from './stats.service';

test('stats billing routes use Mieru user deltas without querying Xray', async () => {
    const xtls = {
        stats: {
            getAllUsersStats(): never {
                throw new Error('Xray user stats must not be queried.');
            },
            getAllInboundsStats(): never {
                throw new Error('Xray inbound stats must not be queried.');
            },
            getAllOutboundsStats(): never {
                throw new Error('Xray outbound stats must not be queried.');
            },
        },
    } as unknown as XtlsApi;
    const mieru = {
        isEnabled: () => true,
        getUserDeltas: async () => [
            { username: '42', uplink: 11, downlink: 13 },
            { username: 'unused', uplink: 0, downlink: 0 },
        ],
        getAggregateDelta: async () => ({ uplink: 17, downlink: 19 }),
    } as unknown as MieruMetricsDeltaService;
    const service = createStatsService(xtls, mieru);

    const users = await service.getUsersStats(true);
    assert.equal(users.isOk, true);
    if (!users.isOk) return;
    assert.deepEqual(users.response.users, [{ username: '42', uplink: 11, downlink: 13 }]);

    const combined = await service.getCombinedStats(true);
    assert.equal(combined.isOk, true);
    if (!combined.isOk) return;
    assert.deepEqual(combined.response.inbounds, []);
    assert.deepEqual(combined.response.outbounds, [
        { outbound: MIERU_AGGREGATE_OUTBOUND_TAG, uplink: 17, downlink: 19 },
    ]);
});

test('stats billing routes preserve the existing Xray path when Mieru is disabled', async () => {
    let userReset: boolean | undefined;
    let inboundReset: boolean | undefined;
    let outboundReset: boolean | undefined;
    const xtls = {
        stats: {
            getAllUsersStats: async (reset: boolean) => {
                userReset = reset;
                return {
                    isOk: true,
                    data: { users: [{ username: '7', uplink: 23, downlink: 29 }] },
                };
            },
            getAllInboundsStats: async (reset: boolean) => {
                inboundReset = reset;
                return {
                    isOk: true,
                    data: { inbounds: [{ inbound: 'in', uplink: 31, downlink: 37 }] },
                };
            },
            getAllOutboundsStats: async (reset: boolean) => {
                outboundReset = reset;
                return {
                    isOk: true,
                    data: { outbounds: [{ outbound: 'out', uplink: 41, downlink: 43 }] },
                };
            },
        },
    } as unknown as XtlsApi;
    const mieru = { isEnabled: () => false } as MieruMetricsDeltaService;
    const service = createStatsService(xtls, mieru);

    const users = await service.getUsersStats(true);
    const combined = await service.getCombinedStats(false);
    assert.equal(users.isOk, true);
    assert.equal(combined.isOk, true);
    assert.equal(userReset, true);
    assert.equal(inboundReset, false);
    assert.equal(outboundReset, false);
});

function createStatsService(xtls: XtlsApi, mieru: MieruMetricsDeltaService): StatsService {
    return new StatsService(xtls, {} as QueryBus, mieru);
}
