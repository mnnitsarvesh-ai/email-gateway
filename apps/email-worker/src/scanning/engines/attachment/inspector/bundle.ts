import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * The YARA rules bundle (step 4.2 A9; layout and algorithm in apps/email-worker/yara/README.md,
 * reference implementation `yara/bundle.mjs`). Read-only file access: the worker computes the
 * bundle id at start, the inspector child computes it again from the files it compiles and
 * reports it in its handshake, and the pool refuses a child whose id differs.
 */

/** The bundled rules directory (`apps/email-worker/yara`), from `src/…` and from `dist/…`. */
export const BUNDLED_RULES_DIR = resolve(__dirname, '../../../../..', 'yara');

const RULE_FILE_PATTERN = /^[a-z][a-z0-9._-]{0,63}\.yar$/;
const BUNDLE_NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
const RULE_HEADER = /^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]{0,127})\b/gm;
const SEVERITIES = new Set(['high', 'medium', 'low']);

export interface BundleFile {
  name: string;
  bytes: Buffer;
}

export interface LoadedBundle {
  name: string;
  version: number;
  files: BundleFile[];
  /** Rule name → meta `severity` / `id` (from the rule declarations). */
  rules: Map<string, { severity: string; id: string }>;
}

export class BundleError extends Error {
  override readonly name = 'BundleError';
  constructor(readonly code: string) {
    super(`YARA bundle invalid (${code})`);
  }
}

const byName = (a: BundleFile, b: BundleFile): number =>
  a.name < b.name ? -1 : a.name > b.name ? 1 : 0;

/**
 * Bundle id (A9): `yara-<version>-<first 12 hex of SHA-256>` over the YARA-X version string,
 * then for each rule file in ascending name order: name, NUL, file bytes, NUL.
 */
export function bundleId(version: number, files: readonly BundleFile[], yaraX: string): string {
  const hash = createHash('sha256');
  hash.update(Buffer.from(yaraX, 'utf8'));
  for (const file of [...files].sort(byName)) {
    hash.update(Buffer.from(file.name, 'utf8'));
    hash.update(Buffer.from([0]));
    hash.update(file.bytes);
    hash.update(Buffer.from([0]));
  }
  return `yara-${String(version)}-${hash.digest('hex').slice(0, 12)}`;
}

/** Rule names with their `meta:` values (the convention of `bundle.mjs parseRules`). */
export function parseRuleMeta(
  source: string,
): Array<{ name: string; meta: Record<string, string> }> {
  const text = source
    .split('\n')
    .map((line) => (/^\s*\/\//.test(line) ? '' : line))
    .join('\n')
    .replace(/\/\*[\s\S]*?\*\//g, '');
  const headers = [...text.matchAll(RULE_HEADER)];
  return headers.map((match, index) => {
    const body = text.slice(match.index, headers[index + 1]?.index ?? text.length);
    const metaBlock = /\bmeta\s*:([\s\S]*?)(?:\bstrings\s*:|\bcondition\s*:)/.exec(body)?.[1] ?? '';
    const meta: Record<string, string> = {};
    for (const line of metaBlock.split('\n')) {
      const kv = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/.exec(line);
      if (!kv) continue;
      const raw = kv[2]!;
      meta[kv[1]!] = raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw;
    }
    return { name: match[1]!, meta };
  });
}

/**
 * Reads `bundle.json` and exactly the listed `rules/*.yar` files of `dir` (no compilation).
 * Throws `BundleError` on a malformed manifest, an unlisted or missing file, a rule without
 * `meta: severity` (high/medium/low) or `meta: id`, or a duplicate rule name.
 */
export function loadBundle(dir: string): LoadedBundle {
  let manifest: unknown;
  try {
    manifest = JSON.parse(readFileSync(join(dir, 'bundle.json'), 'utf8'));
  } catch {
    throw new BundleError('manifest_unreadable');
  }
  const m = manifest as { name?: unknown; version?: unknown; rules?: unknown };
  if (typeof m.name !== 'string' || !BUNDLE_NAME_PATTERN.test(m.name)) {
    throw new BundleError('manifest_name');
  }
  if (typeof m.version !== 'number' || !Number.isSafeInteger(m.version) || m.version < 1) {
    throw new BundleError('manifest_version');
  }
  if (!Array.isArray(m.rules) || m.rules.length === 0) throw new BundleError('manifest_rules');
  const listed = m.rules as unknown[];
  if (!listed.every((n): n is string => typeof n === 'string' && RULE_FILE_PATTERN.test(n))) {
    throw new BundleError('manifest_rule_name');
  }
  if (new Set(listed).size !== listed.length) throw new BundleError('manifest_duplicate');
  let present: string[];
  try {
    present = readdirSync(join(dir, 'rules')).filter((n) => n.endsWith('.yar'));
  } catch {
    throw new BundleError('rules_unreadable');
  }
  if (present.some((n) => !listed.includes(n))) throw new BundleError('rule_not_listed');
  if (listed.some((n) => !present.includes(n))) throw new BundleError('rule_missing');
  const files = listed.map((name) => ({ name, bytes: readFileSync(join(dir, 'rules', name)) }));
  const rules = new Map<string, { severity: string; id: string }>();
  for (const file of files) {
    for (const rule of parseRuleMeta(file.bytes.toString('utf8'))) {
      const severity = rule.meta.severity;
      const id = rule.meta.id;
      if (severity === undefined || !SEVERITIES.has(severity)) {
        throw new BundleError('rule_severity');
      }
      if (id === undefined || id.length === 0) throw new BundleError('rule_id');
      if (rules.has(rule.name)) throw new BundleError('rule_duplicate');
      rules.set(rule.name, { severity, id });
    }
  }
  if (rules.size === 0) throw new BundleError('no_rules');
  return { name: m.name, version: m.version, files, rules };
}

/** The compile source of a bundle: the files' text in ascending name order, joined with `\n`. */
export function bundleSource(bundle: LoadedBundle): string {
  return [...bundle.files]
    .sort(byName)
    .map((file) => file.bytes.toString('utf8'))
    .join('\n');
}

/** The `version` of the installed `@litko/yara-x` binding (A9: stands for the engine version). */
export function yaraXVersion(): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports -- package metadata only
  const pkg = require('@litko/yara-x/package.json') as { version: string };
  return pkg.version;
}

/** The bundle id of the rules directory (worker side, at start). */
export function bundleIdOf(dir: string): { bundleId: string; ruleCount: number; yaraX: string } {
  const bundle = loadBundle(dir);
  const yaraX = yaraXVersion();
  return {
    bundleId: bundleId(bundle.version, bundle.files, yaraX),
    ruleCount: bundle.rules.size,
    yaraX,
  };
}
