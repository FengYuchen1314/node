import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { TypedConfigService } from '@common/config/app-config';
import { TMieruIsolatedConfig } from '@libs/contracts/models';

import { MieruControlClient, MieruControlError } from './mieru-control.client';
import { MieruDaemonManager } from './mieru-daemon.manager';
import { MieruRuntimeService } from './mieru-runtime.service';
import { MieruRuntimeStore } from './mieru-runtime.store';

test(
    'Linux Agent manages actual Mieru processes through apply, rollback, removal and restart',
    {
        skip: process.platform !== 'linux' || process.env.RW_MITA_INTEGRATION !== '1',
        timeout: 90_000,
    },
    async (context) => {
        const directory = await mkdtemp(join(tmpdir(), 'rw-mi-agent-'));
        const values: Record<string, unknown> = {
            MIERU_ENABLED: true,
            MIERU_DAEMON_PATH: process.env.RW_MITA_TEST_DAEMON,
            MIERU_CONTROL_HELPER_PATH: process.env.RW_MITA_TEST_HELPER,
            MIERU_STATE_DIR: join(directory, 'state'),
            MIERU_SOCKET_DIR: join(directory, 'sock'),
            MITA_UDS_PATH: join(directory, 'legacy.sock'),
        };
        const config = {
            getOrThrow: (key: string) => {
                const value = values[key];
                assert.notEqual(value, undefined, `missing ${key}`);
                return value;
            },
        } as unknown as TypedConfigService;
        const store = new MieruRuntimeStore(config);
        const services: MieruRuntimeService[] = [];
        context.after(async () => {
            for (const service of services) await service.stop();
            await rm(directory, { recursive: true, force: true });
        });
        const create = () => {
            const control = new MieruControlClient(config);
            const manager = new MieruDaemonManager(config);
            const runtime = new MieruRuntimeService(config, control, manager, store);
            services.push(runtime);
            return { runtime, manager, control };
        };
        const A = '11111111-1111-4111-8111-111111111111';
        const B = '22222222-2222-4222-8222-222222222222';
        const C = '33333333-3333-4333-8333-333333333333';
        const a = await unusedPort();
        let b = await unusedPort();
        while (b === a) b = await unusedPort();
        const desired: TMieruIsolatedConfig = {
            kind: 'ISOLATED_LISTENERS',
            instances: [A, B].map((id, index) => ({
                id,
                config: {
                    portBindings: [{ port: index === 0 ? a : b, protocol: 'TCP' }],
                    users: [{ name: String(index + 1), password: 'password' }],
                    loggingLevel: 'ERROR',
                },
            })),
        };
        const first = create();
        assert.equal((await first.runtime.apply(desired)).status, 'RUNNING');
        assert.equal((await first.control.status(first.manager.socket(A))).status, 'RUNNING');
        assert.equal((await first.control.status(first.manager.socket(B))).status, 'RUNNING');

        const collision = createServer();
        await new Promise<void>((resolve) => collision.listen(0, '0.0.0.0', resolve));
        const occupied = (collision.address() as { port: number }).port;
        try {
            await assert.rejects(
                first.runtime.apply({
                    ...desired,
                    instances: [
                        ...desired.instances,
                        {
                            id: C,
                            config: {
                                ...desired.instances[0].config,
                                portBindings: [{ port: occupied, protocol: 'TCP' }],
                            },
                        },
                    ],
                }),
                (error: unknown) => error instanceof MieruControlError && error.rollbackSucceeded,
            );
        } finally {
            await new Promise<void>((resolve) => collision.close(() => resolve()));
        }
        assert.equal((await first.runtime.status()).status, 'RUNNING');
        assert.deepEqual(first.manager.ids().sort(), [A, B]);

        const reduced = {
            ...desired,
            instances: [
                {
                    ...desired.instances[0],
                    config: {
                        ...desired.instances[0].config,
                        users: [{ name: '3', password: 'replacement' }],
                    },
                },
            ],
        };
        await first.runtime.apply(reduced);
        assert.deepEqual(first.manager.ids(), [A]);
        await first.runtime.onModuleDestroy();
        const second = create();
        await second.runtime.onModuleInit();
        assert.equal((await second.runtime.status()).status, 'RUNNING');
        assert.deepEqual(second.manager.ids(), [A]);
        await second.runtime.stop();
        assert.deepEqual(second.manager.ids(), []);
        assert.equal((await store.load()).desired, null);
        const third = create();
        await third.runtime.onModuleInit();
        assert.equal((await third.runtime.status()).status, 'IDLE');
    },
);

async function unusedPort(): Promise<number> {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    return port;
}
