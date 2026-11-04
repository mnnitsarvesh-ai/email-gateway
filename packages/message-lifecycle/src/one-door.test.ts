import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * One-door rule (step 3.3 §2.0 invariant 1, L5.9): `email_messages.status`, `status_changed_at`,
 * `version`, `lifecycle_round`, `status_reason` and the rows of `email_message_status_history`
 * are written only through this package. Scans `apps/<app>/src` and `packages/<pkg>/src`
 * (excluding this package and `packages/database/prisma`; `integration/` fixtures may set up
 * states directly, L8.6) for:
 *
 * - `emailMessageStatusHistory.create|createMany|update|updateMany|upsert(`;
 * - raw `UPDATE email_messages SET …` assigning a lifecycle column, raw `INSERT INTO` /
 *   `UPDATE` of `email_message_status_history`;
 * - `emailMessage.update|updateMany|upsert(` calls whose data names a lifecycle field.
 */

const ROOT = join(__dirname, '..', '..', '..');

/**
 * Files allowed to write the lifecycle directly. Empty since step 3.3 wave 3 (WP3 replaced the
 * step 2.3 recorder's writer with the transition service) and stays empty.
 */
const ALLOW_LIST: readonly string[] = [];

const LIFECYCLE_FIELDS =
  /\b(?:status|version|lifecycleRound|statusReason|statusChangedAt)\b\s*[:,}]/;
const LIFECYCLE_COLUMNS =
  /\b(?:status|status_changed_at|version|lifecycle_round|status_reason)\s*=/i;

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (entry === 'node_modules' || entry === 'dist' || entry === 'integration') continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...sourceFiles(path));
    else if (/\.(?:ts|tsx|mts|cts)$/.test(entry) && !entry.endsWith('.d.ts')) out.push(path);
  }
  return out;
}

function scannedFiles(): string[] {
  const files: string[] = [];
  for (const area of ['apps', 'packages']) {
    for (const name of readdirSync(join(ROOT, area))) {
      if (area === 'packages' && name === 'message-lifecycle') continue;
      files.push(...sourceFiles(join(ROOT, area, name, 'src')));
    }
  }
  return files.map((f) => relative(ROOT, f).split(sep).join('/'));
}

/** The text of the balanced `(…)` / `{…}` group that opens at `open` (best effort). */
function balanced(text: string, open: number): string {
  const opening = text[open];
  const closing = opening === '(' ? ')' : '}';
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    if (text[i] === opening) depth += 1;
    else if (text[i] === closing) {
      depth -= 1;
      if (depth === 0) return text.slice(open, i + 1);
    }
  }
  return text.slice(open);
}

/** Removes every `where: { … }` object (filters may name `status`; only writes matter). */
function withoutWhere(args: string): string {
  let out = args;
  for (let match = /\bwhere\s*:\s*\{/.exec(out); match; match = /\bwhere\s*:\s*\{/.exec(out)) {
    const start = match.index + match[0].length - 1;
    out = out.slice(0, match.index) + out.slice(start + balanced(out, start).length);
  }
  return out;
}

/** The violations in one source text (exported shape for the self-test below). */
export function violations(text: string): string[] {
  const found: string[] = [];
  if (
    /\bemailMessageStatusHistory\s*\.\s*(?:create|createMany|update|updateMany|upsert)\s*\(/.test(
      text,
    )
  ) {
    found.push('emailMessageStatusHistory write');
  }
  if (/\b(?:INSERT\s+INTO|UPDATE)\s+`?email_message_status_history`?/i.test(text)) {
    found.push('raw email_message_status_history write');
  }
  for (const m of text.matchAll(
    /UPDATE\s+`?email_messages`?\s+SET\s+([\s\S]*?)(?:\bWHERE\b|`|;|$)/gi,
  )) {
    if (LIFECYCLE_COLUMNS.test(m[1] ?? '')) found.push('raw UPDATE email_messages SET <lifecycle>');
  }
  for (const m of text.matchAll(/\bemailMessage\s*\.\s*(?:update|updateMany|upsert)\s*\(/g)) {
    const args = balanced(text, (m.index ?? 0) + m[0].length - 1);
    if (LIFECYCLE_FIELDS.test(withoutWhere(args)))
      found.push('emailMessage.update* of a lifecycle field');
  }
  return found;
}

describe('one door for the message lifecycle (L5.9)', () => {
  it('finds no direct lifecycle write outside @email-gateway/message-lifecycle', () => {
    const files = scannedFiles();
    expect(files.length).toBeGreaterThan(50);
    const offenders = files
      .filter((file) => !ALLOW_LIST.includes(file))
      .flatMap((file) =>
        violations(readFileSync(join(ROOT, file), 'utf8')).map((v) => `${file}: ${v}`),
      );
    expect(offenders).toEqual([]);
  });

  it('keeps the allow-list empty (and honest: every entry would still have to write)', () => {
    expect(ALLOW_LIST).toEqual([]);
    for (const file of ALLOW_LIST) {
      expect(violations(readFileSync(join(ROOT, file), 'utf8')), file).not.toEqual([]);
    }
  });

  it('detects the forbidden shapes and ignores filters and other columns', () => {
    expect(violations('await tx.emailMessageStatusHistory.create({ data })')).toHaveLength(1);
    expect(
      violations('tx.$executeRaw`UPDATE email_messages SET status = ${s} WHERE id = 1`'),
    ).toHaveLength(1);
    expect(
      violations('`UPDATE `email_messages` SET subject = ?, version = version + 1`'),
    ).toHaveLength(1);
    expect(violations('INSERT INTO email_message_status_history (id) VALUES (1)')).toHaveLength(1);
    expect(
      violations(
        'tx.emailMessage.updateMany({ where: { id }, data: { status: "x", version: 2 } })',
      ),
    ).toHaveLength(1);
    expect(
      violations('tx.emailMessage.updateMany({ where: { id, status: "x" }, data: { subject } })'),
    ).toEqual([]);
    expect(violations('UPDATE email_messages SET subject = ? WHERE status = ?')).toEqual([]);
    expect(violations('tx.emailMessage.create({ data: { ...init.messageFields } })')).toEqual([]);
  });
});
