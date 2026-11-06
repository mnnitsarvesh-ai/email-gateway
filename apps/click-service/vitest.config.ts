import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Unit (`vitest run --dir src`) and e2e (`vitest run --dir test`, supertest against the Nest app)
// tests of the click-service.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: { include: ['**/*.test.ts'] },
});
