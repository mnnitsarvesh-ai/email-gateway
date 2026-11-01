#!/usr/bin/env node
// Creates .env from .env.example with freshly generated local secrets.
// Refuses to overwrite an existing .env unless --force is given.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const target = join(root, '.env');
const force = process.argv.includes('--force');

if (existsSync(target) && !force) {
  console.error(
    '.env already exists; re-run with --force to regenerate (this rotates all secrets).',
  );
  process.exit(1);
}

const values = new Map();
const lines = readFileSync(join(root, '.env.example'), 'utf8')
  .split('\n')
  .map((line) => {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line);
    if (!match) return line;
    const [, key, raw] = match;
    // Hex secrets are URL-safe, so they can be embedded in connection strings unescaped.
    let value = raw === '__GENERATE__' ? randomBytes(24).toString('hex') : raw;
    value = value.replace(/\$\{([A-Z0-9_]+)\}/g, (_, ref) => {
      if (!values.has(ref)) throw new Error(`${key} references ${ref} before it is defined`);
      return values.get(ref);
    });
    values.set(key, value);
    return `${key}=${value}`;
  });

writeFileSync(target, lines.join('\n'), { mode: 0o600 });
console.log(`Wrote ${target} (mode 600).`);
