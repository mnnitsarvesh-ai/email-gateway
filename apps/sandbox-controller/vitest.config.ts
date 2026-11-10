import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Unit tests of the sandbox-controller (no broker, no MinIO, no Docker). The package script runs
// `vitest run --dir src`, so the include pattern is relative to src/.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: { include: ['**/*.test.ts'], exclude: ['integration/**', 'node_modules/**', 'dist/**'] },
});
