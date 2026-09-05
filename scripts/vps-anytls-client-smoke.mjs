// Real Mihomo TCP traffic through the full Agent's shared-443 route. No policy seam:
// public camouflage uses the system trust store; inner TLS independently pins its CA.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdir, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

import { createMihomoTestReadiness } from './mihomo-test-readiness.mjs';

export async function sendNativeAnyTlsTraffic(listener) {
    const allocator = createServer();
    allocator.listen(0, '127.0.0.1');
    await once(allocator, 'listening');
    const port = allocator.address().port;
    await new Promise((resolve) => allocator.close(resolve));
    const readiness = await createMihomoTestReadiness();
    let child;
    let exited;
    try {
        await mkdir('/test/native-client', { mode: 0o700 });
        await writeFile(
            '/test/native-client/client.json',
            JSON.stringify({
                mode: 'rule',
                'log-level': 'warning',
                'mixed-port': port,
                'bind-address': '127.0.0.1',
                'geo-auto-update': false,
                dns: { enable: false },
                proxies: [
                    {
                        name: 'wrapper',
                        type: 'anytls',
                        server: '127.0.0.1',
                        port: 443,
                        password: listener.wrapperPassword,
                        sni: listener.camouflage.serverName,
                        'shadow-tls-opts': { version: 3, password: listener.shadowPassword },
                        'skip-cert-verify': false,
                    },
                    {
                        name: 'encrypted',
                        type: 'anytls',
                        server: '127.0.0.1',
                        port: listener.innerPort,
                        password: listener.users[0].password,
                        sni: listener.tls.serverName,
                        fingerprint: new X509Certificate(
                            listener.tls.caCertificate,
                        ).fingerprint256.replaceAll(':', ''),
                        'dialer-proxy': 'wrapper',
                        'skip-cert-verify': false,
                    },
                ],
                rules: [readiness.rule, 'MATCH,encrypted'],
            }),
            { mode: 0o600 },
        );
        child = spawn(
            '/usr/local/bin/rw-anytls-outer',
            ['-d', '/test/native-client', '-f', '/test/native-client/client.json'],
            {
                stdio: 'ignore',
                env: { PATH: process.env.PATH },
            },
        );
        exited = new Promise((resolve) => {
            child.once('exit', resolve);
            child.once('error', resolve);
        });
        await readiness.wait(port, () => child.exitCode === null);
        await new Promise((resolve, reject) => {
            const req = request(
                {
                    hostname: '127.0.0.1',
                    port,
                    path: 'http://example.com/',
                    headers: { Host: 'example.com', Connection: 'close' },
                    timeout: 30000,
                },
                (res) => {
                    let body = '';
                    res.on('data', (chunk) => {
                        body += chunk;
                        if (body.length > 1024 * 1024)
                            req.destroy(new Error('Oversized fixture reply'));
                    });
                    res.once('error', reject);
                    res.once('end', () => {
                        try {
                            assert.equal(res.statusCode, 200, 'Encrypted HTTP target failed');
                            assert.match(body, /Example Domain/);
                            resolve();
                        } catch (error) {
                            reject(error);
                        }
                    });
                },
            );
            req.once('error', reject);
            req.once('timeout', () => req.destroy(new Error('Encrypted HTTP deadline')));
            req.end();
        });
    } finally {
        if (child && child.exitCode === null) {
            child.kill('SIGTERM');
            await Promise.race([exited, delay(3000)]);
            if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
            await exited;
        }
        await readiness.close();
    }
}
