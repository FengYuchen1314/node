// Test-only minimal client for sing-box's documented v2ray StatsService wire format.
// No production SDK is replaced; this keeps the portable security proof dependency-free.
import assert from 'node:assert/strict';
import { connect } from 'node:http2';

function fields(buffer) {
    let offset = 0;
    const result = [];
    function varint() {
        let value = 0n;
        for (let shift = 0n; shift < 70n; shift += 7n) {
            assert(offset < buffer.length, 'Truncated protobuf varint');
            const byte = buffer[offset++];
            value |= BigInt(byte & 127) << shift;
            if (!(byte & 128)) return value;
        }
        throw new Error('Invalid protobuf varint');
    }
    while (offset < buffer.length) {
        const tag = Number(varint());
        const wire = tag & 7;
        let value;
        if (wire === 0) value = varint();
        else if (wire === 2 || wire === 1 || wire === 5) {
            const length = wire === 2 ? Number(varint()) : wire === 1 ? 8 : 4;
            assert(
                Number.isSafeInteger(length) && length >= 0 && offset + length <= buffer.length,
                'Invalid protobuf field length',
            );
            value = buffer.subarray(offset, offset + length);
            offset += length;
        } else throw new Error('Unexpected protobuf wire type');
        result.push({ field: tag >>> 3, wire, value });
    }
    return result;
}

export async function queryUserCounters(port, reset = false) {
    const channel = connect(`http://127.0.0.1:${port}`);
    channel.on('error', () => {});
    const request = channel.request({
        ':method': 'POST',
        ':path': '/v2ray.core.app.stats.command.StatsService/QueryStats',
        'content-type': 'application/grpc',
        te: 'trailers',
    });
    const timer = setTimeout(() => request.destroy(new Error('Stats RPC deadline')), 3000);
    try {
        const response = await new Promise((resolve, reject) => {
            let data = Buffer.alloc(0);
            let status;
            let grpcStatus;
            request.on('response', (headers) => {
                status = headers[':status'];
                grpcStatus = headers['grpc-status'];
            });
            request.on('trailers', (headers) => {
                grpcStatus = headers['grpc-status'];
            });
            request.on('data', (chunk) => {
                data = Buffer.concat([data, chunk]);
                if (data.length > 1024 * 1024) request.destroy(new Error('Stats RPC too large'));
            });
            request.on('error', reject);
            request.on('end', () => resolve({ data, status, grpcStatus }));
            // Empty pattern means all configured counters; field 2 is QueryStatsRequest.reset.
            request.end(Buffer.from([0, 0, 0, 0, 2, 0x10, reset ? 1 : 0]));
        });
        assert.equal(response.status, 200);
        assert.equal(response.grpcStatus, '0');
        assert(response.data.length >= 5 && response.data[0] === 0, 'Invalid gRPC envelope');
        assert.equal(response.data.readUInt32BE(1), response.data.length - 5);
        const counters = {};
        for (const item of fields(response.data.subarray(5))) {
            if (item.field !== 1 || item.wire !== 2) continue;
            const stat = fields(item.value);
            const name = stat
                .find((field) => field.field === 1 && field.wire === 2)
                ?.value.toString('utf8');
            const value = stat.find((field) => field.field === 2 && field.wire === 0)?.value ?? 0n;
            assert(name?.startsWith('user>>>'), 'Only subscriber counters should be configured');
            assert(value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER));
            assert(!Object.hasOwn(counters, name), 'Duplicate user counter');
            counters[name] = Number(value);
        }
        return counters;
    } finally {
        clearTimeout(timer);
        request.close();
        channel.destroy();
    }
}
