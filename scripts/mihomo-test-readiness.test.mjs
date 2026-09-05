import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer, connect } from 'node:net';
import { test } from 'node:test';

import { createMihomoTestReadiness } from './mihomo-test-readiness.mjs';

// A tiny owned SOCKS frontend. It can acknowledge SOCKS before forwarding is ready, just as
// the pinned native client did in the independently reproduced startup race.
async function frontend(accept, wrongResponse = false) {
    const sockets = new Set();
    const server = createServer((socket) => {
        sockets.add(socket);
        socket.on('error', () => {});
        socket.on('close', () => sockets.delete(socket));
        let stage = 0;
        socket.on('data', function receive(data) {
            if (stage++ === 0) {
                assert.deepEqual([...data], [5, 1, 0]);
                socket.write(Buffer.from([5, 0]));
            } else {
                assert.equal(data.length, 10);
                socket.removeListener('data', receive);
                socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
                if (!accept()) return socket.end();
                if (wrongResponse) {
                    socket.once('data', () =>
                        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nwrong'),
                    );
                    return;
                }
                const target = connect(data.readUInt16BE(8), '127.0.0.1');
                sockets.add(target);
                target.on('error', () => socket.destroy());
                target.on('close', () => sockets.delete(target));
                socket.pipe(target).pipe(socket);
            }
        });
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    return {
        port: server.address().port,
        close: async () => {
            for (const socket of sockets) socket.destroy();
            await new Promise((resolve) => server.close(resolve));
        },
    };
}

test('an open SOCKS port and successful SOCKS reply do not satisfy application readiness', async () => {
    const readiness = await createMihomoTestReadiness();
    let attempts = 0;
    const socks = await frontend(() => ++attempts >= 3);
    try {
        await readiness.wait(socks.port, () => true, 2000);
        assert.equal(attempts, 3);
        assert(readiness.rule.includes(`(DST-PORT,${readiness.targetPort})`));
        assert(readiness.rule.endsWith(',DIRECT'));
    } finally {
        await socks.close();
        await readiness.close();
    }
});

test('readiness rejects a wrong application challenge and respects a bounded deadline', async () => {
    const readiness = await createMihomoTestReadiness();
    const socks = await frontend(() => true, true);
    try {
        const started = Date.now();
        await assert.rejects(
            readiness.wait(socks.port, () => true, 100),
            /application-ready/,
        );
        assert(Date.now() - started < 1000);
    } finally {
        await socks.close();
        await readiness.close();
    }
});

test('an exited client cannot pass readiness even if another listener occupies its port', async () => {
    const readiness = await createMihomoTestReadiness();
    let attempts = 0;
    const socks = await frontend(() => (++attempts, true));
    try {
        await assert.rejects(
            readiness.wait(socks.port, () => false),
            /application-ready/,
        );
        assert.equal(attempts, 0);
    } finally {
        await socks.close();
        await readiness.close();
    }
});
