import type { YaraMatch, YaraSeverity } from '@email-gateway/security-contracts';

/**
 * The YARA engine seen by the walker (step 4.2 A4), without the native binding: `inspect.ts`
 * depends only on this module, so the DLP extractor child (step 4.5 D4) reaches the shared
 * walker without loading YARA-X (it passes `NOOP_YARA_ENGINE`). The real engine is
 * `YaraXScanner` (yara-scanner.ts).
 */

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

/** A YARA engine that matches nothing (the DLP extractor's walk, step 4.5 D4). */
export const NOOP_YARA_ENGINE: YaraEngine = Object.freeze({
  bundleId: 'none',
  ruleCount: 0,
  yaraXVersion: 'none',
  scan: (): YaraScanResult => ({ matches: [], timedOut: false }),
});

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
