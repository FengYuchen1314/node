import assert from 'node:assert/strict';
import { chmod, link, mkdir, mkdtemp, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, TestContext } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

import { MihomoStartupReadiness } from './mihomo-startup-readiness';

async function fixture(t: TestContext) {
    const directory = await mkdtemp(join(tmpdir(), 'rw-anytls-ready-'));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const readiness = new MihomoStartupReadiness(directory);
    return { directory, readiness, ...readiness.environment };
}

test('live processes without a post-up record cannot pass application readiness', async (t) => {
    const { readiness } = await fixture(t);
    await assert.rejects(
        readiness.wait(() => true, 40),
        /did not confirm application readiness/,
    );
    await readiness.dispose();
});

test('a complete current-generation record is required; empty files are not readiness', async (t) => {
    const {
        directory,
        readiness,
        RW_ANYTLS_READY_FILE: path,
        RW_ANYTLS_READY_TOKEN: nonce,
    } = await fixture(t);
    await writeFile(path, '', { mode: 0o600 });
    let resolved = false;
    const waiting = readiness
        .wait(() => true, 1000)
        .then(() => {
            resolved = true;
        });
    await delay(30);
    assert.equal(resolved, false);
    await writeFile(path, nonce, { mode: 0o600 });
    await waiting;
    assert.equal(resolved, true);
    await readiness.dispose();
    assert.deepEqual(await readdir(directory), []);
});

test('readiness never accepts a dead generation even with the exact nonce on disk', async (t) => {
    const {
        readiness,
        RW_ANYTLS_READY_FILE: path,
        RW_ANYTLS_READY_TOKEN: nonce,
    } = await fixture(t);
    await writeFile(path, nonce, { mode: 0o600 });
    await assert.rejects(
        readiness.wait(() => false, 100),
        /did not confirm application readiness/,
    );
    let checks = 0;
    await assert.rejects(
        readiness.wait(() => ++checks === 1, 100),
        /did not confirm application readiness/,
    );
});

test('every activation has a distinct record and nonce, including reuse of one prepared directory', async (t) => {
    const {
        directory,
        readiness,
        RW_ANYTLS_READY_FILE: path,
        RW_ANYTLS_READY_TOKEN: nonce,
    } = await fixture(t);
    const next = new MihomoStartupReadiness(directory);
    assert.notEqual(next.environment.RW_ANYTLS_READY_FILE, path);
    assert.notEqual(next.environment.RW_ANYTLS_READY_TOKEN, nonce);
    await writeFile(path, nonce, { mode: 0o600 });
    await assert.rejects(
        next.wait(() => true, 40),
        /did not confirm application readiness/,
    );
    await writeFile(next.environment.RW_ANYTLS_READY_FILE, nonce, { mode: 0o600 });
    await assert.rejects(
        next.wait(() => true, 100),
        /invalid readiness record/,
    );
    await readiness.wait(() => true, 100);
});

test('foreign/oversized records fail closed without leaking paths or challenge values', async (t) => {
    const {
        readiness,
        RW_ANYTLS_READY_FILE: path,
        RW_ANYTLS_READY_TOKEN: nonce,
    } = await fixture(t);
    for (const value of ['x'.repeat(64), nonce + '\n', nonce.repeat(1024)]) {
        await writeFile(path, value, { mode: 0o600 });
        await assert.rejects(
            readiness.wait(() => true, 100),
            (error: Error) => {
                assert.equal(
                    error.message,
                    'AnyTLS outer core supplied an invalid readiness record.',
                );
                assert(!error.message.includes(nonce) && !error.message.includes(path));
                return true;
            },
        );
    }
});

test('directories cannot masquerade as readiness records', async (t) => {
    const { readiness, RW_ANYTLS_READY_FILE: path } = await fixture(t);
    await mkdir(path);
    await assert.rejects(
        readiness.wait(() => true, 100),
        /invalid readiness record/,
    );
});

test(
    'POSIX readiness rejects symbolic/hard links and group/world-readable records',
    {
        skip: process.platform === 'win32',
    },
    async (t) => {
        const {
            directory,
            readiness,
            RW_ANYTLS_READY_FILE: path,
            RW_ANYTLS_READY_TOKEN: nonce,
        } = await fixture(t);
        const other = join(directory, 'other-record');
        await writeFile(other, nonce, { mode: 0o600 });
        await symlink(other, path);
        await assert.rejects(
            readiness.wait(() => true, 100),
            /invalid readiness record/,
        );
        await readiness.dispose();
        await link(other, path);
        await assert.rejects(
            readiness.wait(() => true, 100),
            /invalid readiness record/,
        );
        await readiness.dispose();
        await writeFile(path, nonce, { mode: 0o600 });
        await chmod(path, 0o644);
        await assert.rejects(
            readiness.wait(() => true, 100),
            /invalid readiness record/,
        );
    },
);

test('the hook is a fixed command; paths and nonces travel only as quoted environment data', () => {
    const one = new MihomoStartupReadiness('/private/state with spaces; $()');
    const two = new MihomoStartupReadiness('/other/path');
    assert.deepEqual(one.args, two.args);
    assert.equal(one.args[0], '-post-up');
    assert.match(one.args[1], /set -C; umask 077/);
    assert.match(one.args[1], /"\$RW_ANYTLS_READY_FILE"/);
    assert(!one.args[1].includes('state with spaces'));
    assert.deepEqual(one.args.slice(-2), ['-post-down', '']);
});
