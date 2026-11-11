import {
  authOutcomeSchema,
  BEC_VERDICTS,
  DLP_ACTIONS,
  DLP_COVERAGES,
  DLP_SEVERITIES,
  dmarcPolicySchema,
  engineNameSchema,
  engineOutcomeSchema,
  reasonCodesSchema,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import { RISK_HARD_BLOCK_IDS } from './hard-blocks';
import { ENGINE_INPUT_STATUSES, SANDBOX_INPUT_OUTCOMES } from './input';
import { RISK_SIGNAL_GROUPS, RISK_SIGNAL_IDS } from './signals';
import {
  RISK_INPUT_VERSION,
  RISK_SCORER_VERSION,
  RISK_SIGNAL_MAP_VERSION,
  riskActionSchema,
  riskLevelSchema,
  riskVerdictSchema,
} from './vocabulary';

/**
 * `RiskResult` (step 5.1 R11): what `scoreRisk` returns and what a `message_risk_scores` row
 * stores, with the fixed row ↔ result mapping (`riskResultToRowJson` / `rowJsonToRiskView`) the
 * email-worker writes and the api reads. Codes, signal ids, integers and versions only.
 */

export const MAX_HARD_BLOCKS = RISK_HARD_BLOCK_IDS.length;
export const MAX_CONTRIBUTIONS = 64;
export const MAX_CONTRIBUTION_CODES = 8;
export const MAX_UNMAPPED_CODES = 8;
export const MAX_EXPLANATION_LINES = 20;
export const MAX_EXPLANATION_TEXT = 2048;

export const EXPLANATION_LINE_CODES = [
  'summary',
  'hard_block',
  'engine_failure',
  'engine_unknown',
  'input_missing',
  'top_signal',
  'unmapped_codes',
  'arc_trusted',
  'trust_applied',
  'trust_denied',
  'floor',
  'ai_raise_only',
  'sandbox',
  'profile',
  'scoring_error',
] as const;
export type ExplanationLineCode = (typeof EXPLANATION_LINE_CODES)[number];

/** Parameter values: integers or bounded vocabulary tokens (never message content). */
const paramValueSchema = z.union([
  z.number().int().min(0).max(1_000_000),
  z
    .string()
    .max(96)
    .regex(/^[A-Za-z0-9_/+#:,-]*$/),
]);

export const explanationLineSchema = z.strictObject({
  code: z.enum(EXPLANATION_LINE_CODES),
  params: z.record(z.string().regex(/^[a-zA-Z]{1,32}$/), paramValueSchema),
});
export type ExplanationLine = z.infer<typeof explanationLineSchema>;

const assertionSchema = z
  .string()
  .max(96)
  .regex(/^[a-z]+:[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/);

export const TRUST_STATUSES = [
  'applied',
  'not_trusted',
  'denied_unauthenticated',
  'denied_auth_failure',
  'off',
] as const;
export type TrustStatus = (typeof TRUST_STATUSES)[number];

export const FAILURE_STATUSES = ['timeout', 'error', 'missing', 'row_missing', 'unknown'] as const;
export const FLOOR_SOURCES = [
  'engine_malicious',
  'bec_suspicious',
  'engine_failure',
  'engine_unknown',
  'hard_block',
] as const;

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);
const groupSchema = z.enum(RISK_SIGNAL_GROUPS);
const points = z.number().int().min(0).max(1_000_000);

export const riskResultSchema = z.strictObject({
  status: z.enum(['scored', 'error']),
  score: z.number().int().min(0).max(1000),
  level: riskLevelSchema,
  verdict: riskVerdictSchema,
  recommendedAction: riskActionSchema,
  hardBlocks: z
    .array(
      z.strictObject({
        id: z.enum(RISK_HARD_BLOCK_IDS),
        verdict: riskVerdictSchema,
        action: riskActionSchema,
      }),
    )
    .max(MAX_HARD_BLOCKS),
  reasonCodes: reasonCodesSchema,
  contributions: z
    .array(
      z.strictObject({
        signal: z.enum(RISK_SIGNAL_IDS as [string, ...string[]]),
        group: groupSchema,
        weight: points,
        codes: z.array(assertionSchema).max(MAX_CONTRIBUTION_CODES),
        applied: points,
      }),
    )
    .max(MAX_CONTRIBUTIONS),
  groups: z
    .array(
      z.strictObject({
        group: groupSchema,
        rule: z.enum(['max', 'capped_sum']),
        raw: points,
        multiplierPermille: points,
        trustFactorPermille: points.nullable(),
        cap: points.nullable(),
        total: points,
      }),
    )
    .max(RISK_SIGNAL_GROUPS.length),
  engines: z
    .array(
      z.strictObject({
        engine: engineNameSchema,
        required: z.boolean(),
        status: z.enum(ENGINE_INPUT_STATUSES),
        outcome: engineOutcomeSchema.nullable(),
        errorCode: z.string().max(64).nullable(),
        engineVersion: z.string().max(128).nullable(),
        settingsVersion: z.string().max(128).nullable(),
        attempts: z.number().int().min(0).max(1000),
      }),
    )
    .max(8),
  failures: z
    .array(
      z.strictObject({
        engine: engineNameSchema,
        status: z.enum(FAILURE_STATUSES),
        weight: points,
      }),
    )
    .max(16),
  floors: z.array(z.strictObject({ source: z.enum(FLOOR_SOURCES), level: riskLevelSchema })).max(8),
  trust: z.strictObject({
    status: z.enum(TRUST_STATUSES),
    factorPermille: points,
    reducedGroups: z.array(groupSchema).max(RISK_SIGNAL_GROUPS.length),
    pointsRemoved: points,
  }),
  evidence: z.strictObject({
    auth: z
      .strictObject({
        spf: authOutcomeSchema.nullable(),
        dkim: authOutcomeSchema.nullable(),
        dmarc: authOutcomeSchema.nullable(),
        dmarcPolicy: dmarcPolicySchema.nullable(),
        arc: authOutcomeSchema.nullable(),
      })
      .nullable(),
    dlp: z
      .strictObject({
        action: z.enum(DLP_ACTIONS),
        coverage: z.enum(DLP_COVERAGES),
        maxSeverity: z.enum(DLP_SEVERITIES).nullable(),
      })
      .nullable(),
    bec: z
      .strictObject({
        deterministicVerdict: z.enum(BEC_VERDICTS),
        verdict: z.enum(BEC_VERDICTS),
      })
      .nullable(),
    sandbox: z.strictObject({ outcome: z.enum(SANDBOX_INPUT_OUTCOMES) }).nullable(),
    unmappedCodes: z.array(assertionSchema).max(MAX_UNMAPPED_CODES),
    aiRaiseOnly: z.boolean(),
  }),
  explanation: z.strictObject({
    lines: z.array(explanationLineSchema).max(MAX_EXPLANATION_LINES),
    text: z.string().max(MAX_EXPLANATION_TEXT),
  }),
  versions: z.strictObject({
    scorer: z.literal(RISK_SCORER_VERSION),
    signalMap: z.literal(RISK_SIGNAL_MAP_VERSION),
    input: z.literal(RISK_INPUT_VERSION),
    profile: z.strictObject({
      source: z.enum(['platform', 'tenant']),
      id: z.string().min(1).max(96),
      versionNo: z.number().int().min(1).nullable(),
      sha256: sha256Schema,
    }),
  }),
  inputSha256: sha256Schema,
});
export type RiskResult = z.infer<typeof riskResultSchema>;

/** A stored score for the api (R11): the result plus revision and creation time (ISO). */
export const riskScoreViewSchema = riskResultSchema.extend({
  revision: z.union([z.literal(0), z.literal(1)]),
  createdAt: z.iso.datetime({ offset: false }),
});
export type RiskScoreView = z.infer<typeof riskScoreViewSchema>;
/** Alias of `riskScoreViewSchema` under the name R1 lists. */
export const riskResultViewSchema = riskScoreViewSchema;

/** The JSON and scalar columns of `message_risk_scores` that come from the result (R11). */
export interface RiskScoreRowJson {
  status: RiskResult['status'];
  score: number;
  level: RiskResult['level'];
  verdict: RiskResult['verdict'];
  recommendedAction: RiskResult['recommendedAction'];
  hardBlocks: RiskResult['hardBlocks'];
  reasonCodes: RiskResult['reasonCodes'];
  contributions: RiskResult['contributions'];
  groups: RiskResult['groups'];
  engines: RiskResult['engines'];
  failures: RiskResult['failures'];
  floors: RiskResult['floors'];
  trust: RiskResult['trust'];
  evidence: RiskResult['evidence'];
  explanation: RiskResult['explanation']['lines'];
  explanationText: string;
  scorerVersion: string;
  signalMapVersion: string;
  inputVersion: string;
  profileSource: 'platform' | 'tenant';
  profileIdText: string;
  profileSha256: string;
  inputSha256: string;
}

/** Result → the row columns it owns (R11 mapping; ids, revision, timing come from the round). */
export function riskResultToRowJson(result: RiskResult): RiskScoreRowJson {
  const r = riskResultSchema.parse(result);
  return {
    status: r.status,
    score: r.score,
    level: r.level,
    verdict: r.verdict,
    recommendedAction: r.recommendedAction,
    hardBlocks: r.hardBlocks,
    reasonCodes: r.reasonCodes,
    contributions: r.contributions,
    groups: r.groups,
    engines: r.engines,
    failures: r.failures,
    floors: r.floors,
    trust: r.trust,
    evidence: r.evidence,
    explanation: r.explanation.lines,
    explanationText: r.explanation.text,
    scorerVersion: r.versions.scorer,
    signalMapVersion: r.versions.signalMap,
    inputVersion: r.versions.input,
    profileSource: r.versions.profile.source,
    profileIdText: r.versions.profile.id,
    profileSha256: r.versions.profile.sha256,
    inputSha256: r.inputSha256,
  };
}

/** A stored row as read (JSON columns as plain values) → the api view (validated). */
export type RiskScoreRowRead = { [K in keyof RiskScoreRowJson]: unknown } & {
  revision: number;
  createdAt: Date | string;
};

const VERSION_NO = /#(\d{1,9})$/;

export function rowJsonToRiskView(row: RiskScoreRowRead): RiskScoreView {
  const idText = typeof row.profileIdText === 'string' ? row.profileIdText : '';
  const match = VERSION_NO.exec(idText);
  const createdAt = row.createdAt instanceof Date ? row.createdAt.toISOString() : row.createdAt;
  return riskScoreViewSchema.parse({
    status: row.status,
    score: row.score,
    level: row.level,
    verdict: row.verdict,
    recommendedAction: row.recommendedAction,
    hardBlocks: row.hardBlocks,
    reasonCodes: row.reasonCodes,
    contributions: row.contributions,
    groups: row.groups,
    engines: row.engines,
    failures: row.failures,
    floors: row.floors,
    trust: row.trust,
    evidence: row.evidence,
    explanation: { lines: row.explanation, text: row.explanationText },
    versions: {
      scorer: row.scorerVersion,
      signalMap: row.signalMapVersion,
      input: row.inputVersion,
      profile: {
        source: row.profileSource,
        id: row.profileIdText,
        versionNo: row.profileSource === 'tenant' && match ? Number(match[1]) : null,
        sha256: row.profileSha256,
      },
    },
    inputSha256: row.inputSha256,
    revision: row.revision,
    createdAt,
  });
}
