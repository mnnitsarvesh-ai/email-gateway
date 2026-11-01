declare const require: (id: string) => { createRequire: (u: string) => (id: string) => unknown };

const { createRequire } = require('node:module');

export const r = createRequire(import.meta.url);
