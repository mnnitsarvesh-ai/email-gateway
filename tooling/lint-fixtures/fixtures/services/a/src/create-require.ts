import { createRequire } from 'node:module';

export const b = createRequire(import.meta.url)('../../b/src/x.js');
