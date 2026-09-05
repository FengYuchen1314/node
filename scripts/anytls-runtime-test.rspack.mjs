import path from 'node:path';

import base from '../rspack.config.mjs';

export default {
    ...base,
    entry: {
        'anytls-runtime.test': './src/modules/anytls/anytls-runtime.linux.test.ts',
        'anytls-usage-unit.test': './src/modules/anytls/anytls-runtime.service.test.ts',
        'anytls-startup-readiness.test': './src/modules/anytls/mihomo-startup-readiness.test.ts',
    },
    output: {
        path: path.resolve(import.meta.dirname, '../test-dist'),
        clean: true,
        filename: '[name].cjs',
    },
    devtool: false,
    optimization: { ...base.optimization, minimize: false },
};
