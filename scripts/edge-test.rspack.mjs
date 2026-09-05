import path from 'node:path';

import base from '../rspack.config.mjs';

export default {
    ...base,
    entry: {
        'edge-policy.test': './src/modules/edge/edge.test.ts',
        'edge-native.test': './src/modules/edge/edge.linux.test.ts',
        'edge-ip.test': './src/modules/camouflage-domain/ip-address.test.ts',
        'edge-coordinated.test': './src/modules/xray-core/xray-coordinated.test.ts',
        'edge-anytls-lifecycle.test': './src/modules/anytls/anytls-runtime.service.test.ts',
    },
    output: {
        path: path.resolve(import.meta.dirname, '../test-dist'),
        clean: true,
        filename: '[name].cjs',
    },
    devtool: false,
    optimization: { ...base.optimization, minimize: false },
};
