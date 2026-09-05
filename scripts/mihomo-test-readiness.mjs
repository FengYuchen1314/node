// An application-readiness fixture, not a retry wrapper around proxy acceptance requests.
// Mihomo can open SOCKS before tunnel.OnRunning(). Probe a separate DIRECT-only loopback
// target until that frontend handles requests; never send this probe through an AnyTLS user.
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { connect } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

export async function createMihomoTestReadiness() {
    const nonce = randomBytes(24).toString('hex');
    const sockets = new Set();
    const server = createServer((request, response) => {
        request.resume();
        if (request.method !== 'GET' || request.url !== `/${nonce}`) {
            response.writeHead(404, { Connection: 'close' }).end();
            return;
        }
        response
            .writeHead(200, {
                'Content-Length': Buffer.byteLength(nonce),
                Connection: 'close',
            })
            .end(nonce);
    });
    server.on('connection', (socket) => {
        sockets.add(socket);
        socket.on('error', () => {});
        socket.on('close', () => sockets.delete(socket));
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const targetPort = server.address().port;
    return {
        targetPort,
        rule: `AND,((NETWORK,TCP),(IP-CIDR,127.0.0.1/32),(DST-PORT,${targetPort})),DIRECT`,
        async wait(socksPort, isAlive, timeoutMs = 10000) {
            const deadline = Date.now() + timeoutMs;
            while (Date.now() < deadline && isAlive()) {
                if (await probe(socksPort, targetPort, nonce, Math.min(250, deadline - Date.now())))
                    return;
                await delay(Math.max(0, Math.min(5, deadline - Date.now())));
            }
            throw new Error('Mihomo SOCKS frontend did not become application-ready.');
        },
        async close() {
            for (const socket of sockets) socket.destroy();
            await new Promise((resolve) => server.close(resolve));
        },
    };
}

async function probe(socksPort, targetPort, nonce, timeoutMs) {
    const socket = connect(socksPort, '127.0.0.1');
    let data = Buffer.alloc(0),
        closed = false,
        error,
        wake;
    socket.on('data', (chunk) => {
        data = Buffer.concat([data, chunk]);
        if (data.length > 4096) socket.destroy(new Error('Oversized readiness response'));
        wake?.();
    });
    socket.on('close', () => {
        closed = true;
        wake?.();
    });
    socket.on('error', (value) => {
        error = value;
        wake?.();
    });
    const timer = setTimeout(
        () => socket.destroy(new Error('Readiness deadline')),
        Math.max(1, timeoutMs),
    );
    const take = async (count) => {
        while (data.length < count) {
            if (error) throw error;
            if (closed) throw new Error('Readiness connection closed');
            await new Promise((resolve) => {
                wake = resolve;
            });
        }
        const result = data.subarray(0, count);
        data = data.subarray(count);
        return result;
    };
    try {
        await once(socket, 'connect');
        socket.write(Buffer.from([5, 1, 0]));
        const greeting = await take(2);
        if (greeting[0] !== 5 || greeting[1] !== 0) return false;
        const destination = Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, 0, 0]);
        destination.writeUInt16BE(targetPort, 8);
        socket.write(destination);
        const reply = await take(4);
        if (reply[0] !== 5 || reply[1] !== 0 || reply[2] !== 0) return false;
        if (reply[3] === 1) await take(6);
        else if (reply[3] === 4) await take(18);
        else if (reply[3] === 3) await take((await take(1))[0] + 2);
        else return false;
        socket.write(`GET /${nonce} HTTP/1.1\r\nHost: readiness.test\r\nConnection: close\r\n\r\n`);
        while (!closed && !error)
            await new Promise((resolve) => {
                wake = resolve;
            });
        if (error) return false;
        const response = data.toString('utf8');
        const separator = response.indexOf('\r\n\r\n');
        return (
            response.startsWith('HTTP/1.1 200 ') &&
            separator >= 0 &&
            response.slice(separator + 4) === nonce
        );
    } catch {
        return false;
    } finally {
        clearTimeout(timer);
        socket.destroy();
    }
}
