import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
    canonicalizeEndpointAddress,
    canonicalizeIp,
    isAddressInCidrs,
    isPublicUnicastAddress,
} from './ip-address';

test('IP canonicalization is deterministic for IPv4 and IPv6', () => {
    assert.equal(canonicalizeIp('8.8.8.8'), '8.8.8.8');
    assert.equal(canonicalizeIp('2001:4860:0000:0000:0000:0000:0000:8888'), '2001:4860::8888');
});

test('endpoint equality normalizes mapped IPv4 without weakening address-family policy', () => {
    for (const address of ['::ffff:127.0.0.1', '::ffff:7f00:1', '0:0:0:0:0:ffff:7f00:1'])
        assert.equal(canonicalizeEndpointAddress(address), '127.0.0.1');
    assert.equal(canonicalizeEndpointAddress('::ffff:104.16.0.1'), '104.16.0.1');
    assert.equal(canonicalizeEndpointAddress('::ffff:192.0.2.10'), '192.0.2.10');
    assert.equal(canonicalizeEndpointAddress('2001:db8:0:0:0:0:0:1'), '2001:db8::1');
    assert.equal(canonicalizeEndpointAddress('0:0:0:0:0:0:0:1'), '::1');
    assert.equal(canonicalizeIp('::ffff:104.16.0.1'), '::ffff:6810:1');
    assert.equal(isPublicUnicastAddress('::ffff:8.8.8.8'), false);
});

test('private, loopback, link-local, multicast, documentation and reserved addresses are bogons', () => {
    for (const address of [
        '0.0.0.1',
        '10.1.2.3',
        '100.64.0.1',
        '127.0.0.1',
        '169.254.1.1',
        '172.16.0.1',
        '192.0.2.1',
        '192.168.1.1',
        '198.18.0.1',
        '198.51.100.1',
        '203.0.113.1',
        '224.0.0.1',
        '255.255.255.255',
        '::1',
        '::ffff:127.0.0.1',
        '64:ff9b::1',
        '2001:db8::1',
        '3fff::1',
        'fc00::1',
        'fe80::1',
        'ff02::1',
    ]) {
        assert.equal(isPublicUnicastAddress(address), false, address);
    }
    assert.equal(isPublicUnicastAddress('8.8.8.8'), true);
    assert.equal(isPublicUnicastAddress('2001:4860:4860::8888'), true);
});

test('CIDR matching supports both address families', () => {
    assert.equal(isAddressInCidrs('104.16.1.1', ['104.16.0.0/13']), true);
    assert.equal(isAddressInCidrs('104.32.1.1', ['104.16.0.0/13']), false);
    assert.equal(isAddressInCidrs('2606:4700::1111', ['2606:4700::/32']), true);
});
