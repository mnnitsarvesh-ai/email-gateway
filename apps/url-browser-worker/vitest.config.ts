import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Unit tests of the browser worker and the egress proxy (no browser, no broker). The package
// script runs `vitest run --dir src`, so the include pattern is relative to src/.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: { include: ['**/*.test.ts'], exclude: ['integration/**', 'node_modules/**', 'dist/**'] },
});
