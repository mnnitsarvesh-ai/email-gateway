import { compile } from '@litko/yara-x';
import type { YaraMatch, YaraSeverity } from '@email-gateway/security-contracts';
import { bundleId, bundleSource, loadBundle, yaraXVersion } from './bundle';

/** Result of one YARA scan of one buffer (rule names and severities only). */
export interface YaraScanResult {
  matches: Array<{ rule: string; severity: YaraSeverity }>;
  timedOut: boolean;
}

/** The subset of the YARA-X binding the inspector uses (a fake in unit tests). */
export interface YaraEngine {
  readonly bundleId: string;
  readonly ruleCount: number;
  readonly yaraXVersion: string;
  scan(bytes: Buffer): YaraScanResult;
}

const SEVERITIES: ReadonlySet<string> = new Set(['high', 'medium', 'low']);

/**
 * The compiled-rules object of `@litko/yara-x` 0.10.0 as the inspector uses it (its `YaraXImpl`
 * return type is not declared in the binding's typings).
 */
interface CompiledRules {
  setTimeout(timeoutMs: number): void;
  setMaxMatchesPerPattern(maxMatches: number): void;
  scan(data: Buffer): Array<{ ruleIdentifier: string; meta: object }>;
}
const compileRules = compile as unknown as (source: string) => CompiledRules;

/**
 * YARA-X over in-memory buffers (step 4.2 A4, A9), compiled once per inspector child from the
 * bundle in `dir` (the files in ascending name order joined with `\n`, as `bundle.mjs`). The
 * per-buffer timeout is `ATTACHMENT_YARA_TIMEOUT_MS` (YARA-X counts whole seconds: values are
 * rounded up, verified with the binding: a 50 ms timeout fires after ~1 s). Binding 0.10.0 has
 * no `setMaxScanSize` (design §12 WP2): the walker never passes a buffer above
 * `ATTACHMENT_MAX_ENTRY_BYTES`. A timeout is reported, never thrown; a rule without a valid
 * `meta: severity` cannot exist (the bundle loader refuses it).
 */
export class YaraXScanner implements YaraEngine {
  readonly bundleId: string;
  readonly ruleCount: number;
  readonly yaraXVersion: string;
  private readonly rules: CompiledRules;

  constructor(dir: string, timeoutMs: number) {
    const bundle = loadBundle(dir);
    this.yaraXVersion = yaraXVersion();
    this.bundleId = bundleId(bundle.version, bundle.files, this.yaraXVersion);
    this.ruleCount = bundle.rules.size;
    this.rules = compileRules(bundleSource(bundle));
    this.rules.setTimeout(Math.max(1, Math.ceil(timeoutMs)));
    // Rule names are all the inspector reports; matched data is never read.
    this.rules.setMaxMatchesPerPattern(1);
  }

  scan(bytes: Buffer): YaraScanResult {
    try {
      const found = this.rules.scan(bytes);
      const matches: YaraScanResult['matches'] = [];
      for (const match of found) {
        const severity = (match.meta as Record<string, unknown>).severity;
        matches.push({
          rule: match.ruleIdentifier,
          severity:
            typeof severity === 'string' && SEVERITIES.has(severity)
              ? (severity as YaraSeverity)
              : 'high',
        });
      }
      return { matches, timedOut: false };
    } catch (error) {
      if (/timed out/i.test(String((error as Error | null)?.message ?? ''))) {
        return { matches: [], timedOut: true };
      }
      throw error;
    }
  }
}

/** Deduplicated, bounded YARA matches with their scope (A4: ≤ 32). */
export function addMatches(
  target: YaraMatch[],
  scope: string,
  result: YaraScanResult,
  max: number,
): void {
  for (const match of result.matches) {
    if (target.length >= max) return;
    if (target.some((m) => m.rule === match.rule && m.scope === scope)) continue;
    target.push({ rule: match.rule, severity: match.severity, scope });
  }
}
