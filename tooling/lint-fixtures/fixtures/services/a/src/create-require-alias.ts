import { createRequire } from 'node:module';

const r = createRequire(import.meta.url);

export const q: unknown = r('../../b/src/x.js');
