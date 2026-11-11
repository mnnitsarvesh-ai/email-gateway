import type { EngineOutcome } from '@email-gateway/security-contracts';
import { buildScoringInput, type RoundRows, type ScoringInput } from './input';

/**
 * Test support: a complete, clean inbound round as raw rows, and small mutators. Codes and
 * outcomes only (no addresses, domains or content), like the real rows.
 */

export type Final = RoundRows['finals'][number];

const COMPLETED = new Date('2026-11-10T10:00:00.000Z');

export function final(
  engine: string,
  outcome: EngineOutcome,
  reasonCodes: string[],
  extra: Partial<Final> = {},
): Final {
  return {
    engine,
    outcome,
    errorCode: outcome === 'timeout' || outcome === 'error' ? 'engine.timeout' : null,
    reasonCodes,
    score: engine === 'rspamd' ? '1.5' : null,
    engineVersion: `${engine}/1`,
    settingsVersion: `${engine}-map/1;p=000000000000;t=none`,
    attempt: 1,
    completedAt: COMPLETED,
    ...extra,
  };
}

export function cleanRows(): RoundRows {
  return {
    scan: {
      requiredEngines: ['rspamd', 'attachment', 'url', 'bec', 'dlp'],
      scanKind: 'initial',
      lifecycleRound: 1,
      status: 'completed',
    },
    message: { direction: 'inbound', attachmentCount: 1, recipientCount: 1 },
    finals: [
      final('rspamd', 'clean', ['clean.below_threshold']),
      final('attachment', 'clean', ['clean.no_findings']),
      final('url', 'clean', ['clean.no_findings']),
      final('bec', 'clean', ['clean.below_threshold']),
      final('dlp', 'clean', ['dlp.no_findings']),
    ],
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', arc: 'none' },
    bec: { deterministicVerdict: 'clean', verdict: 'clean', rules: [] },
    dlp: { action: 'allow', verdict: 'clean', coverage: 'complete', categories: [] },
  };
}

/** Replaces the final of `engine` (adds it when absent). */
export function setFinal(rows: RoundRows, f: Final): RoundRows {
  return { ...rows, finals: [...rows.finals.filter((x) => x.engine !== f.engine), f] };
}

export function removeFinal(rows: RoundRows, engine: string): RoundRows {
  return { ...rows, finals: rows.finals.filter((x) => x.engine !== engine) };
}

export const rule = (code: string, suppressed: 'trust' | 'feedback' | null = null) => ({
  id: 'X',
  code,
  category: 'identity',
  severity: 'medium',
  weight: 10,
  suppressed,
  evidence: [],
});

/** A bec final plus its row with the given active rule codes. */
export function withBec(
  rows: RoundRows,
  deterministicVerdict: string,
  ruleCodes: string[],
  options: { verdict?: string; finalCodes?: string[]; suppressed?: string[] } = {},
): RoundRows {
  const outcome = (options.verdict ?? deterministicVerdict) as EngineOutcome;
  const finalCodes =
    options.finalCodes ?? (ruleCodes.length ? ruleCodes : ['clean.below_threshold']);
  return {
    ...setFinal(rows, final('bec', outcome, [...finalCodes])),
    bec: {
      deterministicVerdict,
      verdict: options.verdict ?? deterministicVerdict,
      rules: [
        ...ruleCodes.map((c) => rule(c)),
        ...(options.suppressed ?? []).map((c) => rule(c, 'trust')),
      ],
    },
  };
}

export function withCodes(
  rows: RoundRows,
  engine: string,
  outcome: EngineOutcome,
  codes: string[],
): RoundRows {
  return setFinal(rows, final(engine, outcome, codes));
}

export function build(rows: RoundRows, revision: 0 | 1 = 0): ScoringInput {
  return buildScoringInput(rows, revision);
}
