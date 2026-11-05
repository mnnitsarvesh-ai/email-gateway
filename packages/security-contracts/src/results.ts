import { z } from 'zod';
import { engineNameSchema } from './engines';
import { definiteVerdictSchema, reasonCodesSchema } from './verdicts';

/**
 * Normalized engine results (docs/plan/steps/09-rspamd.md S9). Results hold scores, codes,
 * symbol names, bounded symbol options and authentication outcomes, never message content
 * (§2.0 invariant 2). Symbol options can contain addresses and URLs: they are stored only in
 * `scan_engine_results.evidence` and are never logged, evented or used as metric labels.
 */

/** RFC 8601 result names of SPF, DKIM, DMARC and ARC (Prisma `AuthOutcome`). */
export const AUTH_OUTCOMES = [
  'pass',
  'fail',
  'softfail',
  'neutral',
  'none',
  'temperror',
  'permerror',
] as const;
export type AuthOutcome = (typeof AUTH_OUTCOMES)[number];
export const authOutcomeSchema = z.enum(AUTH_OUTCOMES);

/** Published DMARC policies (Prisma `DmarcPolicy`). */
export const DMARC_POLICIES = ['none', 'quarantine', 'reject'] as const;
export type DmarcPolicy = (typeof DMARC_POLICIES)[number];
export const dmarcPolicySchema = z.enum(DMARC_POLICIES);

export const MAX_DKIM_SIGNATURES = 10;
export const MAX_SIGNALS = 200;
export const MAX_SIGNAL_OPTIONS = 5;
export const MAX_SIGNAL_OPTION_LENGTH = 200;

/** Normalized lower-case ASCII domain (A-labels), at most 253 characters. */
const domainSchema = z
  .string()
  .min(1)
  .max(253)
  .regex(/^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$/, 'Expected a lower-case ASCII domain');

/** True when `value` has no C0 control character and no DEL. */
const noControl = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
};

export const authResultsSchema = z.strictObject({
  spf: z.strictObject({
    result: authOutcomeSchema.nullable(),
    domain: domainSchema.nullable(),
  }),
  dkim: z.strictObject({
    result: authOutcomeSchema.nullable(),
    signatures: z
      .array(
        z.strictObject({
          domain: domainSchema,
          result: authOutcomeSchema,
          selector: z.string().min(1).max(253).refine(noControl).nullable(),
        }),
      )
      .max(MAX_DKIM_SIGNATURES),
  }),
  dmarc: z.strictObject({
    result: authOutcomeSchema.nullable(),
    policy: dmarcPolicySchema.nullable(),
    domain: domainSchema.nullable(),
  }),
  arc: z.strictObject({
    result: authOutcomeSchema.nullable(),
  }),
});
export type AuthResults = z.infer<typeof authResultsSchema>;

/** One engine signal (Rspamd: a symbol) with its score and bounded options. */
export const engineSignalSchema = z.strictObject({
  name: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[\x21-\x7e]+$/, 'Expected a printable ASCII signal name'),
  score: z.number().finite(),
  options: z
    .array(z.string().max(MAX_SIGNAL_OPTION_LENGTH).refine(noControl, 'Control character'))
    .max(MAX_SIGNAL_OPTIONS),
});
export type EngineSignal = z.infer<typeof engineSignalSchema>;

/**
 * The definite result of one engine for one round (S9). Failures (`timeout`, `error`) are not
 * results: the adapter reports them as an attempt failure, so a result can never carry them.
 */
export const normalizedEngineResultSchema = z.strictObject({
  engine: engineNameSchema,
  /** `'unknown'` when the engine version cannot be determined. */
  engineVersion: z.string().min(1).max(64).refine(noControl),
  outcome: definiteVerdictSchema,
  score: z.number().finite().nullable(),
  requiredScore: z.number().finite().nullable(),
  action: z.string().min(1).max(32).refine(noControl).nullable(),
  reasonCodes: reasonCodesSchema,
  signals: z.array(engineSignalSchema).max(MAX_SIGNALS),
  auth: authResultsSchema.optional(),
  durationMs: z.number().int().nonnegative(),
  settingsVersion: z.string().min(1).max(96),
  mappingVersion: z.string().min(1).max(32),
});
export type NormalizedEngineResult = z.infer<typeof normalizedEngineResultSchema>;
