import {
  ATTACHMENT_REASON_CODES,
  AUTH_OUTCOMES,
  BEC_REASON_CODES,
  DLP_ACTIONS,
  DLP_REASON_CODES,
  DLP_SEVERITIES,
  DMARC_POLICIES,
  ENGINE_OUTCOMES,
  RSPAMD_REASON_CODES,
  SANDBOX_REASON_CODES,
  URL_REASON_CODES,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { Prng } from '../scripts/prng';
import {
  actionRank,
  buildScoringInput,
  canonicalJson,
  levelRank,
  platformProfile,
  RISK_GROUP_DEFINITIONS,
  RISK_SIGNALS,
  type ResolvedProfile,
  resolveProfile,
  riskResultSchema,
  scoreRisk,
  validateOverrides,
} from './index';
import type { RoundRows } from './input';
import { cleanRows, final } from './rows.test-support';

const CODE_LISTS: Record<string, readonly string[]> = {
  rspamd: RSPAMD_REASON_CODES,
  attachment: ATTACHMENT_REASON_CODES,
  url: URL_REASON_CODES,
  bec: BEC_REASON_CODES,
  dlp: DLP_REASON_CODES,
};
const ENGINES = ['rspamd', 'attachment', 'url', 'bec', 'dlp'] as const;
const PLATFORM = platformProfile('rsk-default/1');
const PUBLIC_ID = '0190a6f2-7b3c-7def-8abc-0123456789ab';

function randomRows(rng: Prng): { rows: RoundRows; revision: 0 | 1 } {
  const required = rng.sample(ENGINES, rng.int(1, 5));
  const finals: RoundRows['finals'][number][] = [];
  for (const engine of ENGINES) {
    if (rng.chance(required.includes(engine) ? 0.08 : 0.7)) continue; // missing / not in round
    const outcome = rng.pick(ENGINE_OUTCOMES);
    const codes = rng.sample(CODE_LISTS[engine]!, rng.int(0, 6));
    if (rng.chance(0.03)) codes.push(`${engine}.future_rule`);
    finals.push(final(engine, outcome, codes, { attempt: rng.int(1, 5) }));
  }
  const revision: 0 | 1 = rng.chance(0.25) ? 1 : 0;
  if (revision === 1 || rng.chance(0.2)) {
    const outcome =
      revision === 1
        ? rng.pick(['clean', 'suspicious', 'malicious', 'unknown', 'timeout', 'error'] as const)
        : rng.pick(['clean', 'skipped'] as const);
    finals.push(final('sandbox', outcome, rng.sample(SANDBOX_REASON_CODES, rng.int(0, 4))));
  }
  const auth = (): RoundRows['auth'] => ({
    spf: rng.chance(0.1) ? null : rng.pick(AUTH_OUTCOMES),
    dkim: rng.pick(AUTH_OUTCOMES),
    dmarc: rng.chance(0.5) ? 'pass' : rng.pick(AUTH_OUTCOMES),
    dmarcPolicy: rng.chance(0.2) ? null : rng.pick(DMARC_POLICIES),
    arc: rng.chance(0.3) ? null : rng.pick(AUTH_OUTCOMES),
  });
  const becVerdicts = ['clean', 'suspicious', 'malicious', 'unknown'] as const;
  return {
    revision,
    rows: {
      scan: {
        requiredEngines: required,
        scanKind: rng.pick(['initial', 'rescan'] as const),
        lifecycleRound: rng.int(1, 5),
        status: rng.pick(['completed', 'completed', 'failed', 'timed_out'] as const),
      },
      message: {
        direction: rng.pick(['inbound', 'inbound', 'outbound', 'internal'] as const),
        attachmentCount: rng.int(0, 5),
        recipientCount: rng.int(1, 50),
      },
      finals,
      auth: rng.chance(0.85) ? auth() : null,
      bec: rng.chance(0.8)
        ? {
            deterministicVerdict: rng.pick(becVerdicts),
            verdict: rng.pick(becVerdicts),
            rules: rng
              .sample(
                [...BEC_REASON_CODES, 'bec.trusted_sender', 'bec.trusted_sender'],
                rng.int(0, 8),
              )
              .map((code) => ({
                code,
                suppressed: rng.chance(0.15) ? rng.pick(['trust', 'feedback'] as const) : null,
              })),
          }
        : null,
      dlp: rng.chance(0.8)
        ? {
            action: rng.pick(DLP_ACTIONS),
            verdict: rng.pick(['clean', 'suspicious', 'unknown'] as const),
            coverage: rng.pick(['complete', 'partial'] as const),
            categories: Array.from({ length: rng.int(0, 3) }, () => ({
              maxSeverity: rng.pick(DLP_SEVERITIES),
            })),
          }
        : null,
    },
  };
}

function randomProfile(rng: Prng): ResolvedProfile {
  if (rng.chance(0.4)) return PLATFORM;
  const low = rng.int(50, 250);
  const medium = rng.int(Math.max(200, low + 50), 450);
  const high = rng.int(Math.max(400, medium + 50), 700);
  const critical = rng.int(Math.max(650, high + 50), 950);
  const overrides = {
    thresholds: { low, medium, high, critical },
    groupMultipliersPermille: {
      spam: rng.int(500, 2000),
      bec_intent: rng.int(500, 2000),
      lookalike: rng.int(500, 2000),
    },
    hardBlocks: {
      'hb.known_phishing': { enabled: rng.chance(0.5) },
      'hb.dmarc_reject': {
        enabled: rng.chance(0.5),
        action: rng.pick(['block', 'quarantine'] as const),
      },
      'hb.bec_malicious': { enabled: rng.chance(0.5) },
    },
    failures: {
      engineFailureWeight: rng.int(200, 600),
      groupCap: rng.int(300, 1000),
      unknownWeight: rng.int(30, 200),
    },
    trust: {
      mode: rng.pick(['off', 'reduce_content'] as const),
      contentFactorPermille: rng.int(250, 1000),
    },
    ai: { tagOnAiOnlyRaise: rng.chance(0.5) },
  };
  expect(validateOverrides(overrides)).toEqual([]);
  return resolveProfile('rsk-default/1', {
    publicId: PUBLIC_ID,
    versionNo: rng.int(1, 99),
    baseProfile: 'rsk-default/1',
    overrides,
  });
}

const trustGroups = new Set(RISK_SIGNALS.filter((s) => s.trustReducible).map((s) => s.group));

describe('determinism and invariants (seeded property test, 10 000 inputs)', () => {
  it('never throws, is reproducible and keeps every invariant', () => {
    const rng = new Prng(0x5eed_0051);
    let hardBlocked = 0;
    let failed = 0;
    for (let i = 0; i < 10_000; i += 1) {
      const { rows, revision } = randomRows(rng);
      const input = buildScoringInput(rows, revision);
      const profile = randomProfile(rng);
      const result = scoreRisk(input, profile);
      expect(riskResultSchema.safeParse(result).success).toBe(true);
      // determinism
      const again = scoreRisk(structuredClone(input), profile);
      expect(canonicalJson(again)).toBe(canonicalJson(result));
      // score range
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(1000);
      // never clean with a failure, unknown, missing row or a failed round
      const anyFailure =
        result.failures.length > 0 ||
        input.round.outcome === 'scan_failed' ||
        input.engines.some(
          (e) =>
            e.required &&
            (e.status === 'failed' || e.status === 'missing' || e.outcome === 'unknown'),
        ) ||
        input.engines.some((e) => e.reasonCodes.some((c) => c.startsWith('risk.input.')));
      if (anyFailure) {
        failed += 1;
        expect(result.verdict).not.toBe('clean');
      }
      if (
        result.failures.some((f) => f.status !== 'unknown') ||
        input.round.outcome === 'scan_failed'
      ) {
        expect(actionRank(result.recommendedAction)).toBeGreaterThanOrEqual(
          actionRank(profile.profile.failures.action),
        );
        expect(levelRank(result.level)).toBeGreaterThanOrEqual(
          levelRank(profile.profile.failures.minLevel),
        );
      }
      // hard block ⇒ critical
      if (result.hardBlocks.length > 0) {
        hardBlocked += 1;
        expect(result.level).toBe('critical');
        expect(result.score).toBeGreaterThanOrEqual(profile.profile.thresholds.critical);
        for (const h of result.hardBlocks) {
          expect(actionRank(result.recommendedAction)).toBeGreaterThanOrEqual(actionRank(h.action));
        }
      }
      // action at least the level's action and the DLP binding
      expect(actionRank(result.recommendedAction)).toBeGreaterThanOrEqual(
        actionRank(profile.profile.actions[result.level]),
      );
      if (input.dlp?.action === 'block') expect(result.recommendedAction).toBe('block');
      // trust never lowers a non-trust-reducible group
      if (result.trust.status === 'applied') {
        const untrusted = scoreRisk(input, {
          ...profile,
          profile: { ...profile.profile, trust: { ...profile.profile.trust, mode: 'off' } },
        });
        for (const g of result.groups) {
          const u = untrusted.groups.find((x) => x.group === g.group)!;
          if (!trustGroups.has(g.group) || g.trustFactorPermille === null)
            expect(g.total).toBe(u.total);
          else expect(g.total).toBeLessThanOrEqual(u.total);
          expect(RISK_GROUP_DEFINITIONS[g.group]).toBeDefined();
        }
      }
      // explanation bounded and content-free
      expect(result.explanation.text.length).toBeLessThanOrEqual(2048);
      expect(result.explanation.text).not.toMatch(/@|:\/\//);
    }
    // the generator exercised the interesting paths
    expect(hardBlocked).toBeGreaterThan(500);
    expect(failed).toBeGreaterThan(1000);
  });

  it('same input → identical output and hashes', () => {
    const input = buildScoringInput(cleanRows(), 0);
    const a = scoreRisk(input, PLATFORM);
    const b = scoreRisk(input, PLATFORM);
    expect(b).toEqual(a);
    expect(canonicalJson(b)).toBe(canonicalJson(a));
  });

  it('key-order and array-order permutations of the raw rows give the same inputSha256', () => {
    const rng = new Prng(42);
    const reverseKeys = <T>(value: T): T => {
      if (Array.isArray(value)) return value.map(reverseKeys) as T;
      if (value instanceof Date || value === null || typeof value !== 'object') return value;
      return Object.fromEntries(
        Object.entries(value)
          .reverse()
          .map(([k, v]) => [k, reverseKeys(v)]),
      ) as T;
    };
    for (let i = 0; i < 500; i += 1) {
      const { rows, revision } = randomRows(rng);
      const permuted: RoundRows = reverseKeys({
        ...rows,
        scan: { ...rows.scan, requiredEngines: rng.shuffle(rows.scan.requiredEngines as string[]) },
        finals: rng
          .shuffle(rows.finals)
          .map((f) => ({ ...f, reasonCodes: rng.shuffle(f.reasonCodes as string[]) })),
        bec: rows.bec ? { ...rows.bec, rules: rng.shuffle(rows.bec.rules as unknown[]) } : null,
        dlp: rows.dlp
          ? { ...rows.dlp, categories: rng.shuffle(rows.dlp.categories as unknown[]) }
          : null,
      });
      const a = scoreRisk(buildScoringInput(rows, revision), PLATFORM);
      const b = scoreRisk(buildScoringInput(permuted, revision), PLATFORM);
      expect(b.inputSha256).toBe(a.inputSha256);
      expect(b).toEqual(a);
    }
  });
});
