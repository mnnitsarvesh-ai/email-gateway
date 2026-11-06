#!/usr/bin/env node
// Generates data/confusables.json from the Unicode confusables table (UTS #39, Unicode 16.0.0),
// used by the lookalike skeleton (docs/plan/steps/11-url-protection.md U7).
//
//   node scripts/generate-confusables.mjs                  # downloads SOURCE_URL
//   node scripts/generate-confusables.mjs --source <file>  # uses a local copy of confusables.txt
//   node scripts/generate-confusables.mjs --check          # verifies data/confusables.json
//
// The source file's SHA-256 is pinned: a different file (a changed or corrupted download) is
// refused, so the committed table only changes through a deliberate edit of this script.
// The output records the source URL, version and SHA-256 and carries the Unicode license notice
// (the full text is data/LICENSE-UNICODE.txt).
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE_URL = 'https://www.unicode.org/Public/security/16.0.0/confusables.txt';
const UNICODE_VERSION = '16.0.0';
const SOURCE_SHA256 = '95bd0aad6dced5ebc63436f459c06ab21a8d107cd842fb57f5c3a1e91bca8611';
const LICENSE_NOTICE =
  'Derived from confusables.txt of the Unicode Security Mechanisms data (UTS #39), ' +
  'Copyright © 1991-2024 Unicode, Inc. Distributed under the Unicode License v3 ' +
  '(see data/LICENSE-UNICODE.txt and https://www.unicode.org/license.txt). ' +
  'Unicode and the Unicode Logo are registered trademarks of Unicode, Inc. in the U.S. and other countries.';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const target = join(root, 'data', 'confusables.json');

async function loadSource() {
  const index = process.argv.indexOf('--source');
  if (index > 0) {
    const file = process.argv[index + 1];
    if (!file) throw new Error('--source needs a file path');
    return readFileSync(file);
  }
  const response = await fetch(SOURCE_URL);
  if (!response.ok) throw new Error(`download failed: HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

const toString = (hexList) =>
  String.fromCodePoint(
    ...hexList
      .trim()
      .split(/\s+/)
      .map((hex) => Number.parseInt(hex, 16)),
  );

function build(source) {
  const sha256 = createHash('sha256').update(source).digest('hex');
  if (sha256 !== SOURCE_SHA256) {
    throw new Error(`confusables.txt SHA-256 ${sha256} does not match the pinned ${SOURCE_SHA256}`);
  }
  const text = source.toString('utf8').replace(/^﻿/, '');
  const dateLine = /^# Date: (.+)$/m.exec(text);
  const map = {};
  let entries = 0;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const fields = line.split(';').map((field) => field.trim());
    if (fields.length < 3) throw new Error(`malformed line: ${rawLine}`);
    const [from, to, type] = fields;
    // Since Unicode 6.3 the file has only MA (the union of all tables) entries.
    if (type !== 'MA') throw new Error(`unexpected table type ${type}`);
    const key = toString(from);
    if ([...key].length !== 1)
      throw new Error(`source of a mapping is not one code point: ${from}`);
    if (Object.prototype.hasOwnProperty.call(map, key)) throw new Error(`duplicate source ${from}`);
    map[key] = toString(to);
    entries += 1;
  }
  return {
    source: SOURCE_URL,
    unicodeVersion: UNICODE_VERSION,
    sourceSha256: sha256,
    sourceDate: dateLine ? dateLine[1].trim() : null,
    entries,
    license: LICENSE_NOTICE,
    map,
  };
}

const source = await loadSource();
const output = `${JSON.stringify(build(source), null, 2)}\n`;
if (process.argv.includes('--check')) {
  const current = readFileSync(target, 'utf8');
  if (current !== output) {
    console.error('data/confusables.json differs from the generated table');
    process.exit(1);
  }
  console.log('data/confusables.json is up to date');
} else {
  writeFileSync(target, output);
  console.log(`wrote ${target}`);
}
