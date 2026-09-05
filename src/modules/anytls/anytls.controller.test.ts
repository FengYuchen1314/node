import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { RequestMethod } from '@nestjs/common';
import { GUARDS_METADATA, METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';

import { JwtDefaultGuard } from '@common/guards/jwt-guards';
import { ROOT } from '@libs/contracts/api';

import { AnyTlsController } from './anytls.controller';

test('AnyTLS routes have exactly one global Node prefix and retain JWT protection', () => {
    const controllerPath = Reflect.getMetadata(PATH_METADATA, AnyTlsController);
    assert.deepEqual(Reflect.getMetadata(GUARDS_METADATA, AnyTlsController), [JwtDefaultGuard]);
    for (const [name, method] of [
        ['status', RequestMethod.GET],
        ['capabilities', RequestMethod.GET],
        ['start', RequestMethod.POST],
        ['stop', RequestMethod.POST],
        ['stats', RequestMethod.POST],
    ] as const) {
        const handler = AnyTlsController.prototype[name];
        const path = `${ROOT}/${controllerPath}/${Reflect.getMetadata(PATH_METADATA, handler)}`;
        assert.equal(path, `/node/anytls/${name}`);
        assert.equal(Reflect.getMetadata(METHOD_METADATA, handler), method);
    }
});
