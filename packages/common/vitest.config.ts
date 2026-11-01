import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// SWC emits decorator metadata, which NestJS dependency injection needs at runtime.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: { include: ['src/**/*.test.ts'] },
});
