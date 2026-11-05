import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  BUNDLED_RULES_DIR,
  BundleError,
  bundleId,
  bundleIdOf,
  loadBundle,
  parseRuleMeta,
  yaraXVersion,
} from './bundle';
import { YaraXScanner } from './yara-scanner';

const APP = resolve(__dirname, '../../../../..');
const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function copyBundle(): string {
  const dir = mkdtempSync(join(tmpdir(), 'eg-bundle-test-'));
  dirs.push(dir);
  cpSync(BUNDLED_RULES_DIR, dir, { recursive: true });
  return dir;
}

describe('YARA rules bundle (step 4.2 A9)', () => {
  it('computes the same bundle id as yara/bundle.mjs --check', () => {
    const output = execFileSync(
      process.execPath,
      [join(APP, 'yara/bundle.mjs'), '--check', '--json'],
      { encoding: 'utf8' },
    );
    const reference = JSON.parse(output) as {
      bundleId: string;
      ruleCount: number;
      yaraXVersion: string;
    };
    const ours = bundleIdOf(BUNDLED_RULES_DIR);
    expect(ours.bundleId).toBe(reference.bundleId);
    expect(ours.ruleCount).toBe(reference.ruleCount);
    expect(ours.yaraX).toBe(reference.yaraXVersion);
    expect(ours.bundleId).toMatch(/^yara-1-[0-9a-f]{12}$/);
  });

  it('hashes the version string, then name NUL bytes NUL per file in ascending order', () => {
    const files = [
      { name: 'b.yar', bytes: Buffer.from('B') },
      { name: 'a.yar', bytes: Buffer.from('A') },
    ];
    const id = bundleId(3, files, '0.10.0');
    expect(id).toBe(bundleId(3, [...files].reverse(), '0.10.0'));
    expect(id).not.toBe(bundleId(3, files, '0.11.0'));
    expect(id).not.toBe(
      bundleId(3, [{ ...files[0]!, bytes: Buffer.from('B\r') }, files[1]!], '0.10.0'),
    );
    expect(id.startsWith('yara-3-')).toBe(true);
  });

  it('refuses a rule without severity or id, an unlisted file and a missing file', () => {
    const noSeverity = copyBundle();
    writeFileSync(
      join(noSeverity, 'rules', 'eg-test-markers.yar'),
      'rule X { meta: id = "x" condition: true }\n',
    );
    expect(() => loadBundle(noSeverity)).toThrow(BundleError);
    const unlisted = copyBundle();
    writeFileSync(
      join(unlisted, 'rules', 'extra.yar'),
      'rule E { meta: id = "e" severity = "low" condition: false }\n',
    );
    expect(() => loadBundle(unlisted)).toThrow(/rule_not_listed/);
    const missing = copyBundle();
    rmSync(join(missing, 'rules', 'eg-lnk-command.yar'));
    expect(() => loadBundle(missing)).toThrow(/rule_missing/);
    const bad = copyBundle();
    writeFileSync(join(bad, 'bundle.json'), '{"name":"eg-platform","version":0,"rules":[]}');
    expect(() => loadBundle(bad)).toThrow(/manifest_version/);
  });

  it('reads rule metadata with the bundle.mjs convention', () => {
    expect(
      parseRuleMeta(
        '// rule Commented {\nrule A {\n meta:\n  id = "a.1"\n  severity = "high"\n condition: true\n}\nprivate rule B { condition: false }',
      ),
    ).toEqual([
      { name: 'A', meta: { id: 'a.1', severity: 'high' } },
      { name: 'B', meta: {} },
    ]);
  });

  it('compiles the bundle in the scanner and reports rule names with severities', () => {
    const scanner = new YaraXScanner(BUNDLED_RULES_DIR, 10_000);
    expect(scanner.yaraXVersion).toBe(yaraXVersion());
    expect(scanner.bundleId).toBe(bundleIdOf(BUNDLED_RULES_DIR).bundleId);
    expect(scanner.scan(Buffer.from(['EG-YARA-TEST-', 'HIGH-5f0c2e7a'].join('')))).toEqual({
      matches: [{ rule: 'EG_Test_Marker_High', severity: 'high' }],
      timedOut: false,
    });
    expect(scanner.scan(Buffer.alloc(1024)).matches).toEqual([]);
  });
});
