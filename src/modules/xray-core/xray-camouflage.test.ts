import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Logger } from '@nestjs/common';

import { StartXrayCommand } from '@libs/contracts/commands';

import { GetTorrentBlockerStateQuery } from '../_plugin/queries/get-torrent-blocker-state';
import { XrayService } from './xray.service';

Logger.overrideLogger(false);

const request = (): StartXrayCommand.Request => ({
    internals: { forceRestart: false, hashes: { emptyConfig: 'same', inbounds: [] } },
    xrayConfig: {
        inbounds: [{ tag: 'REALITY', streamSettings: { security: 'reality' } }],
    },
});

function fixture() {
    const calls: string[] = [];
    const state = { denied: false, address: '93.184.215.14', rendered: undefined as unknown };
    const args = [
        { stats: { getSysStats: async () => ({ isOk: true }) } },
        {
            stop: async () => calls.push('stop'),
            start: async () => calls.push('start'),
            getCoreVersion: async () => 'test',
            getStatus: async () => ({ up: true, pid: 123 }),
        },
        { prepare: async () => calls.push('geodata') },
        { prepare: async () => calls.push('core') },
        { sync: async () => (calls.push('integrations'), { error: null }) },
        {
            isNeedRestartCore: () => (calls.push('hash'), false),
            extractUsersFromConfig: async (_hashes: unknown, config: unknown) => {
                calls.push('users');
                state.rendered = config;
            },
        },
        { getOrThrow: (key: string) => (key === 'DISABLE_HASHED_SET_CHECK' ? false : '/fixture') },
        {
            execute: async (query: unknown) =>
                query instanceof GetTorrentBlockerStateQuery
                    ? { enabled: false, includeRuleTags: new Set(), rulePosition: 0 }
                    : null,
        },
        { execute: async () => calls.push('prestart') },
        {
            prepareXray: async (input: StartXrayCommand.Request['xrayConfig']) => {
                calls.push('camouflage');
                if (state.denied) throw new Error('Cloudflare CDN camouflage is forbidden.');
                return {
                    config: { ...structuredClone(input), verifiedTarget: state.address },
                    fingerprint: state.address,
                };
            },
        },
    ] as unknown as ConstructorParameters<typeof XrayService>;
    return { service: new XrayService(...args), calls, state };
}

test('every Xray start validates camouflage before integrations, user state or core mutation', async () => {
    const { service, calls, state } = fixture();
    state.denied = true;
    for (const forceRestart of [false, true]) {
        const body = request();
        body.internals.forceRestart = forceRestart;
        const result = await service.startXray(body, '127.0.0.1');
        assert(result.isOk);
        assert.equal(result.response.isStarted, false);
        assert.match(result.response.error!, /Cloudflare CDN/);
    }
    assert.deepEqual(calls, ['camouflage', 'camouflage']);
});

test('Xray unchanged hash is still revalidated and a changed verified IP forces a new config', async () => {
    const { service, calls, state } = fixture();
    const body = request();
    assert.equal((await service.startXray(body, '127.0.0.1')).isOk, true);
    assert.equal(calls.filter((call) => call === 'start').length, 1);
    assert.equal((state.rendered as { verifiedTarget: string }).verifiedTarget, state.address);
    assert.equal(body.xrayConfig.verifiedTarget, undefined);

    await service.startXray(body, '127.0.0.1');
    assert.equal(calls.filter((call) => call === 'camouflage').length, 2);
    assert.equal(calls.filter((call) => call === 'start').length, 1);
    assert.equal(calls.filter((call) => call === 'hash').length, 1);

    state.address = '93.184.215.15';
    await service.startXray(body, '127.0.0.1');
    assert.equal(calls.filter((call) => call === 'start').length, 2);
    assert.equal((state.rendered as { verifiedTarget: string }).verifiedTarget, state.address);
    assert.equal(calls.filter((call) => call === 'hash').length, 1);

    calls.length = 0;
    state.denied = true;
    const denied = await service.startXray(body, '127.0.0.1');
    assert(denied.isOk);
    assert.equal(denied.response.isStarted, false);
    assert.deepEqual(calls, ['camouflage']);
});
