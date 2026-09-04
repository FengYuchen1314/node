import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { HashedSet } from '@remnawave/hashed-set';

import { InternalService } from './internal.service';

test('SOCKS users participate in the inbound hash', async () => {
    const service = new InternalService();
    const expectedHash = new HashedSet(['42\0first-password', '84\0second-password']).hash64String;
    const hashes = {
        emptyConfig: 'base-config-hash',
        inbounds: [{ tag: 'SOCKS_MANAGED', usersCount: 2, hash: expectedHash }],
    };

    await service.extractUsersFromConfig(hashes, {
        inbounds: [
            {
                tag: 'SOCKS_MANAGED',
                protocol: 'socks',
                settings: {
                    auth: 'password',
                    users: [
                        { user: '42', pass: 'first-password' },
                        { user: '84', pass: 'second-password' },
                    ],
                },
            },
        ],
    });

    assert.equal(service.isNeedRestartCore(hashes), false);
    assert.equal(
        service.isNeedRestartCore({
            ...hashes,
            inbounds: [
                {
                    tag: 'SOCKS_MANAGED',
                    usersCount: 1,
                    hash: new HashedSet(['42\0first-password']).hash64String,
                },
            ],
        }),
        true,
    );

    assert.equal(
        service.isNeedRestartCore({
            ...hashes,
            inbounds: [
                {
                    tag: 'SOCKS_MANAGED',
                    usersCount: 2,
                    hash: new HashedSet(['42\0changed-password', '84\0second-password'])
                        .hash64String,
                },
            ],
        }),
        true,
    );
});

test('current and legacy SOCKS user arrays use the same hash identity', async () => {
    const service = new InternalService();
    const expectedHash = new HashedSet(['same-user\0password']).hash64String;
    const hashes = {
        emptyConfig: 'base-config-hash',
        inbounds: [{ tag: 'MIXED_INPUT', usersCount: 1, hash: expectedHash }],
    };

    await service.extractUsersFromConfig(hashes, {
        inbounds: [
            {
                tag: 'MIXED_INPUT',
                protocol: 'socks',
                settings: {
                    users: [{ user: 'same-user', pass: 'password' }],
                    accounts: [{ user: 'same-user', pass: 'password' }],
                },
            },
        ],
    });

    assert.equal(service.isNeedRestartCore(hashes), false);
});

test('non-SOCKS users arrays are not treated as Xray-managed accounts', async () => {
    const service = new InternalService();
    const hashes = {
        emptyConfig: 'base-config-hash',
        inbounds: [{ tag: 'HTTP_INPUT', usersCount: 0, hash: new HashedSet().hash64String }],
    };

    await service.extractUsersFromConfig(hashes, {
        inbounds: [
            {
                tag: 'HTTP_INPUT',
                protocol: 'http',
                settings: {
                    users: [{ user: 'http-user', pass: 'http-password' }],
                },
            },
        ],
    });

    assert.equal(service.isNeedRestartCore(hashes), false);
});
