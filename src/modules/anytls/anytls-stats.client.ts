import { createChannel, createClient, Channel } from 'nice-grpc';
import { z } from 'zod';

import { Injectable } from '@nestjs/common';

import { StatsServiceDefinition } from '@remnawave/xtls-sdk/build/src/xray-protos/app/stats/command/command';

export const AnyTlsCounterSchema = z
    .object({ uplink: z.string().regex(/^\d+$/), downlink: z.string().regex(/^\d+$/) })
    .strict();
export const AnyTlsCountersSchema = z.record(
    z.string().regex(/^(?!__proto__$|constructor$|prototype$)[A-Za-z0-9_.@-]{1,64}$/),
    AnyTlsCounterSchema,
);
export type AnyTlsCounters = z.infer<typeof AnyTlsCountersSchema>;

@Injectable()
export class AnyTlsStatsClient {
    async read(port: number): Promise<AnyTlsCounters> {
        const channel: Channel = createChannel(`127.0.0.1:${port}`, undefined, {
            'grpc.max_receive_message_length': 32 * 1024 * 1024,
        });
        try {
            // The wire messages are compatible; the upstream service name is not Xray's name.
            const client = createClient(
                {
                    ...StatsServiceDefinition,
                    fullName: 'v2ray.core.app.stats.command.StatsService',
                },
                channel,
            );
            const response = await client.queryStats(
                { reset: false, pattern: '' },
                { signal: AbortSignal.timeout(5000) },
            );
            const result: AnyTlsCounters = Object.create(null);
            for (const stat of response.stat) {
                const match = /^user>>>([A-Za-z0-9_.@-]{1,64})>>>traffic>>>(uplink|downlink)$/.exec(
                    stat.name,
                );
                if (
                    !match ||
                    ['__proto__', 'constructor', 'prototype'].includes(match[1]) ||
                    !Number.isSafeInteger(stat.value) ||
                    stat.value < 0
                )
                    throw new Error('Invalid AnyTLS user counter.');
                const user = (result[match[1]] ??= { uplink: '0', downlink: '0' });
                user[match[2] as 'uplink' | 'downlink'] = String(stat.value);
            }
            return result;
        } finally {
            channel.close();
        }
    }
}
