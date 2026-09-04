import path from 'node:path';

import base from '../rspack.config.mjs';

export default {
    ...base,
    entry: { 'anytls-runtime.test': './src/modules/anytls/anytls-runtime.linux.test.ts' },
    output: {
        path: path.resolve(import.meta.dirname, '../test-dist'),
        clean: true,
        filename: '[name].cjs',
    },
    devtool: false,
    optimization: { ...base.optimization, minimize: false },
};
