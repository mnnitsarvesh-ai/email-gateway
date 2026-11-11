import {
  type AuthOutcome,
  authOutcomeSchema,
  BEC_AI_CODES,
  BEC_VERDICTS,
  DLP_ACTIONS,
  DLP_COVERAGES,
  DLP_SEVERITIES,
  DLP_VERDICTS,
  type DlpSeverity,
  type DmarcPolicy,
  dmarcPolicySchema,
  ENGINE_NAMES,
  type EngineName,
  type EngineOutcome,
  engineNameSchema,
  engineOutcomeSchema,
  MAX_REASON_CODES,
  reasonCodeSchema,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import { MESSAGE_DIRECTIONS, RISK_ROW_MISSING_CODES } from './signals';
import { RISK_INPUT_VERSION } from './vocabulary';

/**
 * The scoring input `risk-input/1` (step 5.1 R2) and its pure assembly from the round's stored
 * rows (R12). The canonical JSON of the input is hashed into `input_sha256`, so the email-worker
 * (writer, at completion) and the api dry-run (replica) produce identical inputs from the same
 * rows. Outcomes, codes, counts and versions only: never addresses, domains or content.
 */

/**
 * At most 32 engine codes, plus one synthetic `risk.input.<engine>_row_missing` (R2; wp2 note).
 */
export const MAX_INPUT_REASON_CODES = MAX_REASON_CODES + 1;

const sortedUnique = (values: readonly string[]): boolean => {
  for (let i = 1; i < values.length; i += 1) if (!(values[i - 1]! < values[i]!)) return false;
  return true;
};

const codeListSchema = (max: number) =>
  z.array(reasonCodeSchema).max(max).refine(sortedUnique, 'Expected sorted, unique reason codes');

const versionTextSchema = z.string().min(1).max(128);
const isoSchema = z.iso.datetime({ offset: false, precision: 3 });

export const ENGINE_INPUT_STATUSES = ['definite', 'failed', 'skipped', 'missing'] as const;
export type EngineInputStatus = (typeof ENGINE_INPUT_STATUSES)[number];

export const engineInputSchema = z.strictObject({
  engine: engineNameSchema,
  required: z.boolean(),
  status: z.enum(ENGINE_INPUT_STATUSES),
  outcome: engineOutcomeSchema.nullable(),
  errorCode: z.string().min(1).max(64).nullable(),
  reasonCodes: codeListSchema(MAX_INPUT_REASON_CODES),
  /** The engine's own score as decimal text (informational; the scorer never reads it). */
  score: z
    .string()
    .regex(/^-?\d{1,9}(\.\d{1,9})?$/)
    .nullable(),
  engineVersion: versionTextSchema.nullable(),
  settingsVersion: versionTextSchema.nullable(),
  attempts: z.number().int().min(0).max(1000),
  completedAt: isoSchema.nullable(),
});
export type EngineInput = z.infer<typeof engineInputSchema>;

export const TRUSTED_SENDER_STATES = ['authenticated', 'unauthenticated', 'none'] as const;
export const SANDBOX_INPUT_OUTCOMES = [
  'clean',
  'suspicious',
  'malicious',
  'unknown',
  'timeout',
  'error',
] as const;

export const scoringInputSchema = z
  .strictObject({
    version: z.literal(RISK_INPUT_VERSION),
    revision: z.union([z.literal(0), z.literal(1)]),
    round: z.strictObject({
      scanKind: z.enum(['initial', 'rescan']),
      lifecycleRound: z.number().int().min(0).max(65_535),
      outcome: z.enum(['scanned', 'scan_failed']),
      requiredEngines: z.array(engineNameSchema).max(ENGINE_NAMES.length).refine(sortedUnique, {
        message: 'Expected sorted, unique engine names',
      }),
    }),
    envelope: z.strictObject({
      direction: z.enum(MESSAGE_DIRECTIONS),
      attachmentCount: z.number().int().min(0).max(1_000_000),
      recipientCount: z.number().int().min(0).max(1_000_000),
    }),
    engines: z.array(engineInputSchema).max(ENGINE_NAMES.length),
    auth: z
      .strictObject({
        spf: authOutcomeSchema.nullable(),
        dkim: authOutcomeSchema.nullable(),
        dmarc: authOutcomeSchema.nullable(),
        dmarcPolicy: dmarcPolicySchema.nullable(),
        arc: authOutcomeSchema.nullable(),
      })
      .nullable(),
    bec: z
      .strictObject({
        deterministicVerdict: z.enum(BEC_VERDICTS),
        verdict: z.enum(BEC_VERDICTS),
        activeRuleCodes: codeListSchema(MAX_REASON_CODES),
        trustedSender: z.enum(TRUSTED_SENDER_STATES),
        aiRaised: z.boolean(),
      })
      .nullable(),
    dlp: z
      .strictObject({
        action: z.enum(DLP_ACTIONS),
        verdict: z.enum(DLP_VERDICTS),
        coverage: z.enum(DLP_COVERAGES),
        maxSeverity: z.enum(DLP_SEVERITIES).nullable(),
      })
      .nullable(),
    sandbox: z
      .strictObject({
        outcome: z.enum(SANDBOX_INPUT_OUTCOMES),
        reasonCodes: codeListSchema(MAX_REASON_CODES),
      })
      .nullable(),
  })
  .superRefine((input, ctx) => {
    const names = input.engines.map((e) => e.engine);
    if (!sortedUnique(names)) {
      ctx.addIssue({
        code: 'custom',
        path: ['engines'],
        message: 'Expected sorted, unique engines',
      });
    }
    if (names.includes('sandbox')) {
      ctx.addIssue({
        code: 'custom',
        path: ['engines'],
        message: 'The asynchronous sandbox is never a round engine',
      });
    }
    for (const [i, e] of input.engines.entries()) {
      if (e.required !== input.round.requiredEngines.includes(e.engine)) {
        ctx.addIssue({ code: 'custom', path: ['engines', i, 'required'], message: 'Mismatch' });
      }
      const consistent =
        (e.status === 'missing' && e.outcome === null) ||
        (e.status === 'failed' && (e.outcome === 'timeout' || e.outcome === 'error')) ||
        (e.status === 'skipped' && e.outcome === 'skipped') ||
        (e.status === 'definite' &&
          e.outcome !== null &&
          !['timeout', 'error', 'skipped'].includes(e.outcome));
      if (!consistent) {
        ctx.addIssue({ code: 'custom', path: ['engines', i, 'status'], message: 'Status/outcome' });
      }
    }
    for (const required of input.round.requiredEngines) {
      if (required === 'sandbox' || !names.includes(required)) {
        ctx.addIssue({
          code: 'custom',
          path: ['round', 'requiredEngines'],
          message: `Required engine ${required} has no entry`,
        });
      }
    }
    if ((input.revision === 1) !== (input.sandbox !== null)) {
      ctx.addIssue({
        code: 'custom',
        path: ['sandbox'],
        message: 'The sandbox input is present exactly in revision 1',
      });
    }
  });
export type ScoringInput = z.infer<typeof scoringInputSchema>;

/** The round's stored rows as plain objects (R12; exported, the shape is fixed). */
export interface RoundRows {
  scan: {
    requiredEngines: unknown /* JSON array of engine names */;
    scanKind: 'initial' | 'rescan';
    lifecycleRound: number;
    status: 'completed' | 'failed' | 'timed_out';
  }; // completed → scanned, else scan_failed
  message: {
    direction: 'inbound' | 'outbound' | 'internal';
    attachmentCount: number;
    recipientCount: number;
  };
  finals: ReadonlyArray<{
    engine: string;
    outcome: EngineOutcome;
    errorCode: string | null;
    reasonCodes: unknown;
    score: string | null /* Decimal.toString() */;
    engineVersion: string | null;
    settingsVersion: string | null;
    attempt: number;
    completedAt: Date;
  }>; // every is_final row of the round, sandbox included
  auth: {
    spf: AuthOutcome | null;
    dkim: AuthOutcome | null;
    dmarc: AuthOutcome | null;
    dmarcPolicy: DmarcPolicy | null;
    arc: AuthOutcome | null;
  } | null; // the rspamd email_auth_results row
  bec: { deterministicVerdict: string; verdict: string; rules: unknown /* JSON */ } | null;
  dlp: { action: string; verdict: string; coverage: string; categories: unknown /* JSON */ } | null;
}

/** Malformed round rows (R12): the caller writes the error row (R13), never a partial input. */
export class RiskInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RiskInputError';
  }
}

const fail = (message: string): never => {
  throw new RiskInputError(message);
};

const engineListSchema = z.array(engineNameSchema).max(ENGINE_NAMES.length);
const rawCodesSchema = z.array(reasonCodeSchema).max(MAX_REASON_CODES);
const becRulesSchema = z
  .array(
    z.looseObject({
      code: reasonCodeSchema,
      suppressed: z.enum(['trust', 'feedback']).nullable(),
    }),
  )
  .max(64);
const dlpCategoriesSchema = z.array(z.looseObject({ maxSeverity: z.enum(DLP_SEVERITIES) })).max(32);

const sortStrings = (values: Iterable<string>): string[] =>
  [...new Set(values)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

function parseOrFail<T>(schema: z.ZodType<T>, value: unknown, what: string): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const where = first && first.path.length > 0 ? ` at ${first.path.map(String).join('.')}` : '';
    fail(`Malformed ${what}${where}: ${first?.message ?? 'invalid'}`);
  }
  return (parsed as { data: T }).data;
}

/**
 * Assembles `risk-input/1` from the round's rows (R2, R12). Validates everything it reads and
 * throws `RiskInputError` on malformed data (unknown engines, duplicate finals, malformed JSON,
 * out-of-range values, a revision-1 call without a non-skipped sandbox final); never returns a
 * partial input. Deterministic: lists are sorted, so permutations of the raw rows give the same
 * input and `inputSha256`.
 */
export function buildScoringInput(rows: RoundRows, revision: 0 | 1): ScoringInput {
  if (revision !== 0 && revision !== 1) fail('Revision must be 0 or 1');
  const required = sortStrings(
    parseOrFail(engineListSchema, rows.scan.requiredEngines, 'requiredEngines'),
  ) as EngineName[];
  if (required.length !== (rows.scan.requiredEngines as unknown[]).length) {
    fail('Duplicate required engine');
  }
  if (required.includes('sandbox')) fail('The asynchronous sandbox cannot be required');
  const outcome =
    rows.scan.status === 'completed'
      ? 'scanned'
      : rows.scan.status === 'failed' || rows.scan.status === 'timed_out'
        ? 'scan_failed'
        : fail('Unknown scan status');

  const finals = new Map<EngineName, RoundRows['finals'][number]>();
  for (const final of rows.finals) {
    const engine = parseOrFail(engineNameSchema, final.engine, 'final engine');
    if (finals.has(engine)) fail(`Two finals for engine ${engine}`);
    finals.set(engine, final);
  }

  const engines: EngineInput[] = [];
  let becFinalCodes: string[] = [];
  const names = sortStrings(
    [...finals.keys(), ...required].filter((e) => e !== 'sandbox'),
  ) as EngineName[];
  for (const engine of names) {
    const final = finals.get(engine);
    if (!final) {
      engines.push({
        engine,
        required: true,
        status: 'missing',
        outcome: null,
        errorCode: null,
        reasonCodes: [],
        score: null,
        engineVersion: null,
        settingsVersion: null,
        attempts: 0,
        completedAt: null,
      });
      continue;
    }
    const finalOutcome = parseOrFail(engineOutcomeSchema, final.outcome, `${engine} outcome`);
    const codes = sortStrings(
      parseOrFail(rawCodesSchema, final.reasonCodes, `${engine} reason codes`),
    );
    if (engine === 'bec') becFinalCodes = codes;
    const status =
      finalOutcome === 'timeout' || finalOutcome === 'error'
        ? 'failed'
        : finalOutcome === 'skipped'
          ? 'skipped'
          : 'definite';
    if (!(final.completedAt instanceof Date) || Number.isNaN(final.completedAt.getTime())) {
      fail(`${engine} completedAt is not a valid date`);
    }
    engines.push({
      engine,
      required: required.includes(engine),
      status,
      outcome: finalOutcome,
      errorCode: final.errorCode,
      reasonCodes: codes,
      score: final.score,
      engineVersion: final.engineVersion,
      settingsVersion: final.settingsVersion,
      attempts: final.attempt,
      completedAt: final.completedAt.toISOString(),
    });
  }

  const entry = (engine: EngineName) => engines.find((e) => e.engine === engine);
  const addCode = (engine: EngineName, code: string) => {
    const e = entry(engine);
    if (e) e.reasonCodes = sortStrings([...e.reasonCodes, code]);
  };

  // Authentication: outcomes only.
  const rspamd = entry('rspamd');
  const auth = rows.auth
    ? {
        spf: rows.auth.spf,
        dkim: rows.auth.dkim,
        dmarc: rows.auth.dmarc,
        dmarcPolicy: rows.auth.dmarcPolicy,
        arc: rows.auth.arc,
      }
    : null;
  if (!auth && rspamd && rspamd.status === 'definite' && rspamd.outcome !== 'unknown') {
    addCode('rspamd', RISK_ROW_MISSING_CODES.rspamd);
  }

  // BEC: deterministic rule codes (suppressed rules excluded), trusted sender from codes.
  const becEntry = entry('bec');
  let bec: ScoringInput['bec'] = null;
  if (rows.bec) {
    const rules = parseOrFail(becRulesSchema, rows.bec.rules, 'bec rules');
    const activeRuleCodes = sortStrings(
      rules.filter((r) => r.suppressed === null).map((r) => r.code),
    );
    const deterministicVerdict = parseOrFail(
      z.enum(BEC_VERDICTS),
      rows.bec.deterministicVerdict,
      'bec deterministic verdict',
    );
    const verdict = parseOrFail(z.enum(BEC_VERDICTS), rows.bec.verdict, 'bec verdict');
    const allCodes = new Set([...activeRuleCodes, ...becFinalCodes]);
    const trustedSender = allCodes.has('bec.trusted_sender')
      ? 'authenticated'
      : allCodes.has('bec.trusted_sender_unauthenticated')
        ? 'unauthenticated'
        : 'none';
    const aiCodePresent = becFinalCodes.some((c) =>
      (BEC_AI_CODES as readonly string[]).includes(c),
    );
    bec = {
      deterministicVerdict,
      verdict,
      activeRuleCodes,
      trustedSender,
      aiRaised: verdict !== deterministicVerdict && aiCodePresent,
    };
  } else if (becEntry && becEntry.status === 'definite') {
    addCode('bec', RISK_ROW_MISSING_CODES.bec);
  }

  // DLP: action, verdict, coverage and the maximum category severity.
  const dlpEntry = entry('dlp');
  let dlp: ScoringInput['dlp'] = null;
  if (rows.dlp) {
    const categories = parseOrFail(dlpCategoriesSchema, rows.dlp.categories, 'dlp categories');
    let maxSeverity: DlpSeverity | null = null;
    for (const c of categories) {
      if (
        maxSeverity === null ||
        DLP_SEVERITIES.indexOf(c.maxSeverity) > DLP_SEVERITIES.indexOf(maxSeverity)
      ) {
        maxSeverity = c.maxSeverity;
      }
    }
    dlp = {
      action: parseOrFail(z.enum(DLP_ACTIONS), rows.dlp.action, 'dlp action'),
      verdict: parseOrFail(z.enum(DLP_VERDICTS), rows.dlp.verdict, 'dlp verdict'),
      coverage: parseOrFail(z.enum(DLP_COVERAGES), rows.dlp.coverage, 'dlp coverage'),
      maxSeverity,
    };
  } else if (dlpEntry && dlpEntry.status === 'definite') {
    addCode('dlp', RISK_ROW_MISSING_CODES.dlp);
  }

  // Sandbox: revision 1 only, and then required non-skipped.
  let sandbox: ScoringInput['sandbox'] = null;
  if (revision === 1) {
    const final = finals.get('sandbox');
    if (!final) fail('Revision 1 needs a sandbox final');
    const sandboxOutcome = parseOrFail(
      z.enum(['clean', 'suspicious', 'malicious', 'unknown', 'timeout', 'error', 'skipped']),
      final!.outcome,
      'sandbox outcome',
    );
    if (sandboxOutcome === 'skipped') fail('Revision 1 needs a non-skipped sandbox final');
    sandbox = {
      outcome: sandboxOutcome as Exclude<typeof sandboxOutcome, 'skipped'>,
      reasonCodes: sortStrings(parseOrFail(rawCodesSchema, final!.reasonCodes, 'sandbox codes')),
    };
  }

  const input = {
    version: RISK_INPUT_VERSION,
    revision,
    round: {
      scanKind: rows.scan.scanKind,
      lifecycleRound: rows.scan.lifecycleRound,
      outcome,
      requiredEngines: required,
    },
    envelope: {
      direction: rows.message.direction,
      attachmentCount: rows.message.attachmentCount,
      recipientCount: rows.message.recipientCount,
    },
    engines,
    auth,
    bec,
    dlp,
    sandbox,
  };
  return parseOrFail(scoringInputSchema, input, 'scoring input');
}
