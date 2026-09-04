import assert from 'node:assert/strict';
import { test } from 'node:test';
import { z } from 'zod';

import {
    MieruMetricsSchema,
    MieruServerConfigSchema,
    MieruStatusSchema,
} from '@libs/contracts/models';

import { MieruControlError, parseMieruHelperOutput } from './mieru-control.client';

const StatusResultSchema = z.object({
    status: MieruStatusSchema,
    version: z.string(),
    metrics: MieruMetricsSchema,
});

test('Mieru metrics remain exact decimal strings beyond Number.MAX_SAFE_INTEGER', () => {
    const result = parseMieruHelperOutput(
        JSON.stringify({
            ok: true,
            result: {
                status: 'RUNNING',
                version: '3.36.0',
                metrics: {
                    users: {
                        alice: {
                            UploadBytes: '9223372036854775807',
                            DownloadBytes: '-9223372036854775808',
                        },
                    },
                },
            },
        }),
        StatusResultSchema,
    );

    const users = result.metrics.users as Record<string, Record<string, string>>;
    assert.equal(users.alice.UploadBytes, '9223372036854775807');
    assert.equal(users.alice.DownloadBytes, '-9223372036854775808');
});

test('Mieru helper output rejects unsafe numeric metrics', () => {
    assert.throws(
        () =>
            parseMieruHelperOutput(
                JSON.stringify({
                    ok: true,
                    result: {
                        status: 'RUNNING',
                        version: '3.36.0',
                        metrics: { users: { alice: { UploadBytes: 9_007_199_254_740_992 } } },
                    },
                }),
                StatusResultSchema,
            ),
        (error: unknown) => error instanceof MieruControlError && error.stage === 'parse-output',
    );
});

test('Mieru helper errors retain rollback outcome without leaking temporary paths', () => {
    assert.throws(
        () =>
            parseMieruHelperOutput(
                JSON.stringify({
                    ok: false,
                    error: {
                        stage: 'reload',
                        message:
                            'failed near /tmp/rw-mita-control-secret/server-config.json\nretry',
                        rollbackAttempted: true,
                        rollbackSucceeded: true,
                    },
                }),
                StatusResultSchema,
            ),
        (error: unknown) => {
            assert.ok(error instanceof MieruControlError);
            assert.equal(error.stage, 'reload');
            assert.equal(error.rollbackAttempted, true);
            assert.equal(error.rollbackSucceeded, true);
            assert.equal(error.message, 'failed near <config> retry');
            return true;
        },
    );
});

test('Mieru server config rejects duplicate identities and enforces upstream byte limits', () => {
    const duplicate = MieruServerConfigSchema.safeParse({
        portBindings: [
            { port: 443, protocol: 'TCP' },
            { port: 443, protocol: 'TCP' },
        ],
        users: [
            { name: 'alice', password: 'secret' },
            { name: 'alice', password: 'another-secret' },
        ],
    });
    assert.equal(duplicate.success, false);

    const tooLongUtf8 = MieruServerConfigSchema.safeParse({
        portBindings: [{ port: 443, protocol: 'TCP' }],
        users: [{ name: '用'.repeat(22), password: 'secret' }],
    });
    assert.equal(tooLongUtf8.success, false);

    const valid = MieruServerConfigSchema.parse({
        portBindings: [{ port: 443, protocol: 'TCP' }],
        users: [{ name: 'alice', password: 'secret' }],
    });
    assert.equal(valid.loggingLevel, 'INFO');

    const emptyUsers = MieruServerConfigSchema.parse({
        portBindings: [{ port: 443, protocol: 'TCP' }],
        users: [],
    });
    assert.deepEqual(emptyUsers.users, []);
});
