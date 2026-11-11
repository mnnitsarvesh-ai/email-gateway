import {
  RISK_ACTIONS,
  RISK_HARD_BLOCK_IDS,
  RISK_LEVELS,
  RISK_VERDICTS,
  SANDBOX_INPUT_OUTCOMES,
} from '@email-gateway/risk-scoring';
import {
  ATTACHMENT_VERDICTS,
  AUTH_OUTCOMES,
  BEC_AI_CODES,
  BEC_VERDICTS,
  DLP_ACTIONS,
  DLP_CATEGORIES,
  DLP_COVERAGES,
  DLP_SEVERITIES,
  DLP_VERDICTS,
  DMARC_POLICIES,
  ENGINE_NAMES,
  ENGINE_OUTCOMES,
  FILE_TYPE_FAMILIES,
  MAX_REASON_CODES,
  normalizeContentType,
  REWRITE_SKIP_REASONS,
  reasonCodeSchema,
  SCAN_VERDICTS,
  URL_HOST_KINDS,
  URL_VERDICTS,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import { normalizeAddress, normalizeDomain, parseIp, formatIp } from './matchers';
import {
  POLICY_INPUT_VERSION,
  POLICY_LIMITS,
  POLICY_MESSAGE_DIRECTIONS,
  POLICY_TRIGGERS,
} from './vocabulary';

/**
 * The evaluation input `policy-input/1` (step 5.2 P7) and its pure assembly from the stored
 * rows of one round (P8). The policy-engine (writer rows) and the api dry-run (replica rows)
 * call the same `buildPolicyInput`, so a dry-run of a stored round reproduces `inputSha256`.
 * Message content never enters the input except the sanitized attachment filename (for `glob`
 * and `regex` conditions), which is never stored, logged or echoed by the evaluator.
 */

// ---------------------------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------------------------

const sortedUnique = (values: readonly string[]): boolean => {
  for (let i = 1; i < values.length; i += 1) if (!(values[i - 1]! < values[i]!)) return false;
  return true;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const directoryIdSchema = z.string().regex(UUID);
const idListSchema = z.array(directoryIdSchema).max(1000).refine(sortedUnique, 'sorted ids');
const codeList = (max: number) =>
  z.array(reasonCodeSchema).max(max).refine(sortedUnique, 'Expected sorted, unique codes');
const enumList = <T extends readonly [string, ...string[]]>(values: T) =>
  z.array(z.enum(values)).max(values.length).refine(sortedUnique, 'Expected sorted, unique values');
const count = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const isoSchema = z.iso.datetime({ offset: false, precision: 3 });

/** Bounds of collected code lists (risk unions and codes of two revisions). */
export const MAX_INPUT_CODES = 64;
export const MAX_BEC_RULE_CODES = 64;

export const addrSchema = z.strictObject({
  address: z.string().min(1).max(320),
  domain: z.string().min(1).max(253).nullable(),
  localPart: z.string().max(320),
});
export type Addr = z.infer<typeof addrSchema>;

/** `failures[].status` of a 5.1 risk row (risk-scoring `FAILURE_STATUSES`). */
export const RISK_FAILURE_STATUSES = [
  'error',
  'missing',
  'row_missing',
  'timeout',
  'unknown',
] as const;

export const riskFactsSchema = z.strictObject({
  status: z.enum(['scored', 'error']),
  score: z.number().int().min(0).max(1000),
  level: z.enum(RISK_LEVELS),
  verdict: z.enum(RISK_VERDICTS),
  recommendedAction: z.enum(RISK_ACTIONS),
  hardBlocks: z
    .array(z.strictObject({ id: z.enum(RISK_HARD_BLOCK_IDS), action: z.enum(RISK_ACTIONS) }))
    .max(RISK_HARD_BLOCK_IDS.length)
    .refine((h) => sortedUnique(h.map((x) => x.id)), 'Expected sorted hard blocks'),
  reasonCodes: codeList(MAX_REASON_CODES),
  /** Statuses of the stored `failures[]` (sorted, unique; P9.5 floor reasons). */
  failureStatuses: z
    .array(z.enum(RISK_FAILURE_STATUSES))
    .max(RISK_FAILURE_STATUSES.length)
    .refine(sortedUnique, 'Expected sorted, unique statuses'),
  levelOnly: z.boolean(),
  aiRaiseOnly: z.boolean(),
  /** Sandbox outcome of revision 1 (`evidence.sandbox.outcome`); null otherwise. */
  sandboxOutcome: z.enum(SANDBOX_INPUT_OUTCOMES).nullable(),
});
export type RiskFacts = z.infer<typeof riskFactsSchema>;

export const SCAN_ENGINE_OUTCOMES = [...ENGINE_OUTCOMES, 'missing'] as const;
export const ENGINE_FINAL_STATES = ['definite', 'skipped', 'failed', 'absent'] as const;
export type EngineFinalState = (typeof ENGINE_FINAL_STATES)[number];
export const TRUSTED_CODES = ['authenticated', 'unauthenticated', 'none'] as const;

export const policyInputSchema = z.strictObject({
  version: z.literal(POLICY_INPUT_VERSION),
  trigger: z.enum(POLICY_TRIGGERS),
  evaluationTime: isoSchema,
  direction: z.enum(POLICY_MESSAGE_DIRECTIONS),
  round: z.strictObject({
    lifecycleRound: z.number().int().min(0).max(65_535),
    scanId: z
      .string()
      .regex(/^[0-9]{1,20}$/)
      .nullable(),
    scanKind: z.enum(['initial', 'rescan']).nullable(),
  }),
  message: z.strictObject({ sizeBytes: count, recipientCount: count, attachmentCount: count }),
  sender: z.strictObject({
    envelope: addrSchema.nullable(),
    headerFrom: addrSchema.nullable(),
    authenticated: addrSchema.nullable(),
    trusted: z.boolean().nullable(),
    departments: idListSchema,
    users: idListSchema,
  }),
  recipients: z
    .array(
      z.strictObject({
        rcptSeq: z.number().int().min(0).max(65_535),
        address: z.string().min(1).max(320),
        domain: z.string().min(1).max(253).nullable(),
        localPart: z.string().max(320),
        departments: idListSchema,
        users: idListSchema,
      }),
    )
    .max(POLICY_LIMITS.recipients),
  recipientsTruncated: z.boolean(),
  client: z.strictObject({
    ip: z.string().max(64).nullable(),
    hostname: z.string().max(253).nullable(),
  }),
  auth: z
    .strictObject({
      spf: z.enum(AUTH_OUTCOMES).nullable(),
      dkim: z.enum(AUTH_OUTCOMES).nullable(),
      dmarc: z.enum(AUTH_OUTCOMES).nullable(),
      dmarcPolicy: z.enum(DMARC_POLICIES).nullable(),
      arc: z.enum(AUTH_OUTCOMES).nullable(),
    })
    .nullable(),
  attachments: z.strictObject({
    count,
    totalBytes: count,
    truncated: z.boolean(),
    items: z
      .array(
        z.strictObject({
          partIndex: z.number().int().min(0).max(65_535),
          extension: z.string().min(1).max(32).nullable(),
          filename: z.string().min(1).max(1024).nullable(),
          declaredType: z.string().min(1).max(255).nullable(),
          detectedType: z.string().min(1).max(255).nullable(),
          typeFamily: z.enum(FILE_TYPE_FAMILIES).nullable(),
          sizeBytes: count,
          sha256: z.string().regex(/^[0-9a-f]{64}$/),
          verdict: z.enum(ATTACHMENT_VERDICTS).nullable(),
          reasonCodes: codeList(MAX_REASON_CODES).nullable(),
          isArchive: z.boolean(),
          encrypted: z.boolean(),
          typeMismatch: z.boolean().nullable(),
        }),
      )
      .max(POLICY_LIMITS.attachments),
  }),
  urls: z.strictObject({
    count,
    truncated: z.boolean(),
    rewriteStatus: z.enum(['rewritten', 'skipped', 'none']),
    rewriteSkipReason: z.enum(REWRITE_SKIP_REASONS).nullable(),
    items: z
      .array(
        z.strictObject({
          urlSeq: z.number().int().min(0).max(65_535),
          host: z.string().min(1).max(253),
          domain: z.string().min(1).max(253).nullable(),
          scheme: z.enum(['http', 'https']),
          hostKind: z.enum(URL_HOST_KINDS),
          verdict: z.enum(URL_VERDICTS).nullable(),
          reasonCodes: codeList(MAX_REASON_CODES).nullable(),
        }),
      )
      .max(POLICY_LIMITS.urls),
  }),
  scan: z.strictObject({
    outcome: z.enum(['scanned', 'scan_failed', 'not_scanned']),
    verdict: z.enum(SCAN_VERDICTS).nullable(),
    reasonCodes: codeList(MAX_REASON_CODES),
    engines: z
      .array(
        z.strictObject({
          engine: z.enum(ENGINE_NAMES),
          required: z.boolean(),
          outcome: z.enum(SCAN_ENGINE_OUTCOMES),
        }),
      )
      .max(ENGINE_NAMES.length)
      .refine((e) => sortedUnique(e.map((x) => x.engine)), 'Expected sorted engines'),
  }),
  risk: z.strictObject({ rev0: riskFactsSchema.nullable(), rev1: riskFactsSchema.nullable() }),
  dlp: z
    .strictObject({
      action: z.enum(DLP_ACTIONS),
      verdict: z.enum(DLP_VERDICTS),
      coverage: z.enum(DLP_COVERAGES),
      categories: enumList(DLP_CATEGORIES),
      maxSeverity: z.enum(DLP_SEVERITIES).nullable(),
      detectorCodes: codeList(MAX_REASON_CODES),
    })
    .nullable(),
  dlpFinal: z.enum(ENGINE_FINAL_STATES),
  bec: z
    .strictObject({
      deterministicVerdict: z.enum(BEC_VERDICTS),
      verdict: z.enum(BEC_VERDICTS),
      aiRaised: z.boolean(),
      ruleCodes: codeList(MAX_BEC_RULE_CODES),
      trustedCode: z.enum(TRUSTED_CODES),
    })
    .nullable(),
  becFinal: z.enum(ENGINE_FINAL_STATES),
});
export type PolicyInput = z.infer<typeof policyInputSchema>;

// ---------------------------------------------------------------------------------------------
// Rows (P8)
// ---------------------------------------------------------------------------------------------

/** The stored rows of one round as plain objects (P8; exported, the shape is fixed). */
export interface PolicyRoundRows {
  trigger: 'scanned' | 'scan_failed' | 'parse_failed';
  message: {
    direction: 'inbound' | 'outbound' | 'internal';
    envelopeFrom: string;
    headerFrom: string | null;
    clientIp: string | null;
    clientName: string | null;
    sizeBytes: number;
    recipientCount: number;
    attachmentCount: number;
    lifecycleRound: number;
  };
  recipients: ReadonlyArray<{ rcptSeq: number; address: string }>;
  scan: {
    scanId: bigint | string;
    lifecycleRound: number;
    scanKind: 'initial' | 'rescan';
    status: 'completed' | 'failed' | 'timed_out';
    scanVerdict: string | null;
    reasonCodes: unknown;
    requiredEngines: unknown;
    completedAt: Date;
  } | null; // null for parse_failed
  parseFailedAt: Date | null; // email_message_parses completion time (parse_failed only)
  finals: ReadonlyArray<{ engine: string; outcome: string; reasonCodes: unknown }>;
  auth: {
    spf: string | null;
    dkim: string | null;
    dmarc: string | null;
    dmarcPolicy: string | null;
    arc: string | null;
  } | null;
  bec: { deterministicVerdict: string; verdict: string; rules: unknown } | null;
  dlp: { action: string; verdict: string; coverage: string; categories: unknown } | null;
  risk: ReadonlyArray<{
    revision: number;
    status: string;
    score: number;
    level: string;
    verdict: string;
    recommendedAction: string;
    hardBlocks: unknown;
    reasonCodes: unknown;
    failures: unknown;
    engines: unknown;
    evidence: unknown;
  }>;
  attachments: ReadonlyArray<{
    partIndex: number;
    filename: string | null;
    declaredContentType: string | null;
    detectedContentType: string | null;
    sizeBytes: number;
    sha256: string;
    archiveInfo: unknown;
  }>;
  attachmentResults: ReadonlyArray<{
    partIndex: number;
    detectedType: string;
    typeFamily: string;
    typeMismatch: boolean;
    verdict: string;
    reasonCodes: unknown;
    archive: unknown;
  }>;
  urls: ReadonlyArray<{
    urlSeq: number;
    host: string;
    registrableDomain: string | null;
    scheme: string;
    hostKind: string;
    truncated: boolean;
  }>;
  urlResults: ReadonlyArray<{
    urlSeq: number;
    verdict: string;
    reasonCodes: unknown;
    rewritten: boolean;
  }>;
  urlRewrite: { status: string; skipReason: string | null } | null;
  directory: {
    departmentsByAddress: Readonly<Record<string, readonly string[]>>;
    usersByAddress: Readonly<Record<string, readonly string[]>>;
  };
}

/** Malformed rows (P8): a defect, never a partial input (the engine dead-letters the event). */
export class PolicyInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyInputError';
  }
}

const fail = (message: string): never => {
  throw new PolicyInputError(message);
};

function parseOrFail<T>(schema: z.ZodType<T>, value: unknown, what: string): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const where = first && first.path.length > 0 ? ` at ${first.path.map(String).join('.')}` : '';
    return fail(`Malformed ${what}${where}: ${first?.message ?? 'invalid'}`);
  }
  return parsed.data;
}

export const sortStrings = (values: Iterable<string>): string[] =>
  [...new Set(values)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

const rawCodesSchema = z.array(reasonCodeSchema).max(MAX_REASON_CODES);
const intSchema = (max = Number.MAX_SAFE_INTEGER) => z.number().int().min(0).max(max);
const becRulesSchema = z
  .array(
    z.looseObject({
      code: reasonCodeSchema,
      suppressed: z.enum(['trust', 'feedback']).nullable(),
    }),
  )
  .max(64);
const dlpCategoriesSchema = z
  .array(
    z.looseObject({
      category: z.enum(DLP_CATEGORIES),
      maxSeverity: z.enum(DLP_SEVERITIES),
    }),
  )
  .max(32);
const riskHardBlocksSchema = z
  .array(z.looseObject({ id: z.enum(RISK_HARD_BLOCK_IDS), action: z.enum(RISK_ACTIONS) }))
  .max(RISK_HARD_BLOCK_IDS.length);
const riskFailuresSchema = z
  .array(z.looseObject({ engine: z.string(), status: z.enum(RISK_FAILURE_STATUSES) }))
  .max(16);
const riskEnginesSchema = z
  .array(
    z.looseObject({
      engine: z.enum(ENGINE_NAMES),
      status: z.enum(['definite', 'failed', 'skipped', 'missing']),
      outcome: z.enum(ENGINE_OUTCOMES).nullable(),
    }),
  )
  .max(8);
const riskEvidenceSchema = z.looseObject({
  aiRaiseOnly: z.boolean(),
  sandbox: z
    .looseObject({ outcome: z.enum(SANDBOX_INPUT_OUTCOMES) })
    .nullable()
    .optional(),
});
const archiveInfoSchema = z
  .looseObject({ encryptedEntries: z.number().int().min(0).nullable().optional() })
  .nullable();
const resultArchiveSchema = z.looseObject({ encrypted: z.boolean().optional() }).nullable();
const directoryMapSchema = z.record(z.string().max(320), z.array(directoryIdSchema).max(1000));

/** Codes of an authentication failure (P3 `sender.authenticated`, `sender.trusted`). */
export const AUTH_FAILURE_CODES: readonly string[] = Object.freeze([
  'auth.dmarc_reject',
  'auth.dmarc_quarantine',
]);
export const isAuthFailureCode = (code: string): boolean =>
  AUTH_FAILURE_CODES.includes(code) || /^auth\.[a-z0-9_]*_fail$/.test(code);

/** Address text → `Addr` (lower-cased, NFC, punycode domain) or null when not an address. */
export function toAddr(text: string | null | undefined): Addr | null {
  if (typeof text !== 'string' || text.length === 0 || text.length > 320) return null;
  const n = normalizeAddress(text);
  if (n.domain === null || n.localPart.length === 0) return null;
  return { address: n.address, domain: n.domain, localPart: n.localPart };
}

/** The extension of a sanitized filename: lower case, without the dot, ≤ 32 characters. */
export function extensionOf(filename: string | null): string | null {
  if (filename === null) return null;
  const text = filename.normalize('NFC').toLowerCase();
  const dot = text.lastIndexOf('.');
  if (dot === -1 || dot === text.length - 1) return null;
  const ext = text.slice(dot + 1);
  if (ext.length > 32 || /[\s/\\]/.test(ext)) return null;
  return ext;
}

/** `levelOnly` of a stored risk row (P7). */
export function riskRowLevelOnly(row: {
  status: string;
  hardBlocks: readonly unknown[];
  failures: readonly unknown[];
  engines: ReadonlyArray<{ status: string; outcome: string | null }>;
  reasonCodes: readonly string[];
}): boolean {
  return (
    row.status === 'scored' &&
    row.hardBlocks.length === 0 &&
    row.failures.length === 0 &&
    row.engines.every(
      (e) => (e.status === 'definite' || e.status === 'skipped') && e.outcome !== 'unknown',
    ) &&
    !row.reasonCodes.some((c) => c.startsWith('risk.input.') || c === 'risk.scoring_error')
  );
}

function riskFactsOf(row: PolicyRoundRows['risk'][number]): RiskFacts {
  const what = `risk revision ${row.revision}`;
  const hardBlocks = parseOrFail(riskHardBlocksSchema, row.hardBlocks, `${what} hard blocks`);
  const reasonCodes = parseOrFail(rawCodesSchema, row.reasonCodes, `${what} reason codes`);
  const failures = parseOrFail(riskFailuresSchema, row.failures, `${what} failures`);
  const engines = parseOrFail(riskEnginesSchema, row.engines, `${what} engines`);
  const evidence = parseOrFail(riskEvidenceSchema, row.evidence, `${what} evidence`);
  const status = parseOrFail(z.enum(['scored', 'error']), row.status, `${what} status`);
  const facts = {
    status,
    score: parseOrFail(z.number().int().min(0).max(1000), row.score, `${what} score`),
    level: parseOrFail(z.enum(RISK_LEVELS), row.level, `${what} level`),
    verdict: parseOrFail(z.enum(RISK_VERDICTS), row.verdict, `${what} verdict`),
    recommendedAction: parseOrFail(z.enum(RISK_ACTIONS), row.recommendedAction, `${what} action`),
    hardBlocks: [...new Map(hardBlocks.map((h) => [h.id, { id: h.id, action: h.action }]))]
      .map(([, h]) => h)
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    reasonCodes: sortStrings(reasonCodes),
    failureStatuses: sortStrings(failures.map((f) => f.status)),
    levelOnly: riskRowLevelOnly({ status, hardBlocks, failures, engines, reasonCodes }),
    aiRaiseOnly: evidence.aiRaiseOnly || reasonCodes.includes('risk.ai.raise_only'),
    sandboxOutcome: row.revision === 1 ? (evidence.sandbox?.outcome ?? null) : null,
  };
  return parseOrFail(riskFactsSchema, facts, what);
}

function finalState(outcome: string | undefined): PolicyInput['dlpFinal'] {
  if (outcome === undefined) return 'absent';
  if (outcome === 'skipped') return 'skipped';
  if (outcome === 'timeout' || outcome === 'error') return 'failed';
  return 'definite';
}

function directoryIds(
  map: Readonly<Record<string, readonly string[]>>,
  address: string | null,
): string[] {
  if (address === null || !Object.prototype.hasOwnProperty.call(map, address)) return [];
  return sortStrings(map[address]!);
}

/**
 * Assembles `policy-input/1` from the round's rows (P8). Validates everything it reads and throws
 * `PolicyInputError` on malformed data (never a partial input). Deterministic: lists are sorted
 * and capped (lowest `rcptSeq`/`partIndex`/`urlSeq` first, truncation flags set), so permutations
 * of the raw rows give the same input and `inputSha256`.
 */
export function buildPolicyInput(rows: PolicyRoundRows): PolicyInput {
  const trigger = parseOrFail(z.enum(POLICY_TRIGGERS), rows.trigger, 'trigger');
  const m = rows.message;
  const direction = parseOrFail(z.enum(POLICY_MESSAGE_DIRECTIONS), m.direction, 'direction');
  const ints: Array<[string, unknown, number?]> = [
    ['message.sizeBytes', m.sizeBytes],
    ['message.recipientCount', m.recipientCount],
    ['message.attachmentCount', m.attachmentCount],
    ['message.lifecycleRound', m.lifecycleRound, 65_535],
  ];
  for (const [name, v, max] of ints) parseOrFail(intSchema(max), v, name);

  // Scan / parse failure and the evaluation time.
  let evaluationTime: string;
  let round: PolicyInput['round'];
  let scan: PolicyInput['scan'];
  const finals = new Map<string, { outcome: string; codes: string[] }>();
  for (const f of rows.finals) {
    const engine = parseOrFail(z.enum(ENGINE_NAMES), f.engine, 'final engine');
    if (finals.has(engine)) fail(`Two finals for engine ${engine}`);
    finals.set(engine, {
      outcome: parseOrFail(z.enum(ENGINE_OUTCOMES), f.outcome, `${engine} outcome`),
      codes: sortStrings(parseOrFail(rawCodesSchema, f.reasonCodes, `${engine} reason codes`)),
    });
  }
  if (trigger === 'parse_failed') {
    if (rows.scan !== null) fail('A parse failure has no scan round');
    const at = rows.parseFailedAt;
    if (!(at instanceof Date) || Number.isNaN(at.getTime())) fail('parseFailedAt is not a date');
    evaluationTime = at!.toISOString();
    round = { lifecycleRound: m.lifecycleRound, scanId: null, scanKind: null };
    scan = { outcome: 'not_scanned', verdict: null, reasonCodes: [], engines: [] };
  } else {
    const s = rows.scan ?? fail(`Trigger ${trigger} needs its scan round`);
    const expected = s.status === 'completed' ? 'scanned' : 'scan_failed';
    if (!['completed', 'failed', 'timed_out'].includes(s.status)) fail('Unknown scan status');
    if (expected !== trigger) fail(`Scan status ${s.status} does not match trigger ${trigger}`);
    if (!(s.completedAt instanceof Date) || Number.isNaN(s.completedAt.getTime())) {
      fail('scan completedAt is not a date');
    }
    const scanId = typeof s.scanId === 'bigint' ? s.scanId.toString() : String(s.scanId);
    if (!/^[0-9]{1,20}$/.test(scanId)) fail('scanId is not a decimal id');
    parseOrFail(intSchema(65_535), s.lifecycleRound, 'scan lifecycleRound');
    const scanKind = parseOrFail(z.enum(['initial', 'rescan']), s.scanKind, 'scanKind');
    const required = parseOrFail(
      z.array(z.enum(ENGINE_NAMES)).max(ENGINE_NAMES.length),
      s.requiredEngines,
      'requiredEngines',
    );
    if (new Set(required).size !== required.length) fail('Duplicate required engine');
    const names = sortStrings([...required, ...finals.keys()]).filter((e) => e !== 'sandbox');
    evaluationTime = s.completedAt.toISOString();
    round = { lifecycleRound: s.lifecycleRound, scanId, scanKind };
    scan = {
      outcome: trigger,
      verdict:
        s.scanVerdict === null
          ? null
          : parseOrFail(z.enum(SCAN_VERDICTS), s.scanVerdict, 'verdict'),
      reasonCodes: sortStrings(parseOrFail(rawCodesSchema, s.reasonCodes, 'scan reason codes')),
      engines: names.map((engine) => ({
        engine: engine as (typeof ENGINE_NAMES)[number],
        required: (required as string[]).includes(engine),
        outcome: (finals.get(engine)?.outcome ??
          'missing') as (typeof SCAN_ENGINE_OUTCOMES)[number],
      })),
    };
  }

  // Authentication (outcomes only) and the failure codes of the rspamd final.
  let auth: PolicyInput['auth'] = null;
  if (rows.auth) {
    const outcome = (v: string | null, what: string) =>
      v === null ? null : parseOrFail(z.enum(AUTH_OUTCOMES), v, what);
    auth = {
      spf: outcome(rows.auth.spf, 'spf'),
      dkim: outcome(rows.auth.dkim, 'dkim'),
      dmarc: outcome(rows.auth.dmarc, 'dmarc'),
      dmarcPolicy:
        rows.auth.dmarcPolicy === null
          ? null
          : parseOrFail(z.enum(DMARC_POLICIES), rows.auth.dmarcPolicy, 'dmarcPolicy'),
      arc: outcome(rows.auth.arc, 'arc'),
    };
  }
  const authFailure = (finals.get('rspamd')?.codes ?? []).some(isAuthFailureCode);

  // BEC.
  let bec: PolicyInput['bec'] = null;
  if (rows.bec) {
    const rules = parseOrFail(becRulesSchema, rows.bec.rules, 'bec rules');
    const ruleCodes = sortStrings(rules.filter((r) => r.suppressed === null).map((r) => r.code));
    const finalCodes = finals.get('bec')?.codes ?? [];
    const all = new Set([...ruleCodes, ...finalCodes]);
    const deterministicVerdict = parseOrFail(
      z.enum(BEC_VERDICTS),
      rows.bec.deterministicVerdict,
      'bec deterministic verdict',
    );
    const verdict = parseOrFail(z.enum(BEC_VERDICTS), rows.bec.verdict, 'bec verdict');
    bec = {
      deterministicVerdict,
      verdict,
      aiRaised:
        verdict !== deterministicVerdict &&
        finalCodes.some((c) => (BEC_AI_CODES as readonly string[]).includes(c)),
      ruleCodes,
      trustedCode: all.has('bec.trusted_sender')
        ? 'authenticated'
        : all.has('bec.trusted_sender_unauthenticated')
          ? 'unauthenticated'
          : 'none',
    };
  }

  // DLP.
  let dlp: PolicyInput['dlp'] = null;
  if (rows.dlp) {
    const categories = parseOrFail(dlpCategoriesSchema, rows.dlp.categories, 'dlp categories');
    let maxSeverity: (typeof DLP_SEVERITIES)[number] | null = null;
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
      categories: sortStrings(
        categories.map((c) => c.category),
      ) as (typeof DLP_CATEGORIES)[number][],
      maxSeverity,
      detectorCodes: finals.get('dlp')?.codes ?? [],
    };
  }

  // Risk revisions.
  const risk: PolicyInput['risk'] = { rev0: null, rev1: null };
  for (const row of rows.risk) {
    if (row.revision !== 0 && row.revision !== 1) fail('Risk revision must be 0 or 1');
    const key = row.revision === 0 ? 'rev0' : 'rev1';
    if (risk[key] !== null) fail(`Two risk rows for revision ${row.revision}`);
    risk[key] = riskFactsOf(row);
  }

  // Directory.
  const departmentsByAddress = parseOrFail(
    directoryMapSchema,
    rows.directory.departmentsByAddress,
    'directory departments',
  );
  const usersByAddress = parseOrFail(directoryMapSchema, rows.directory.usersByAddress, 'users');

  // Sender.
  if (typeof m.envelopeFrom !== 'string') fail('envelopeFrom must be a string');
  const envelope = toAddr(m.envelopeFrom);
  const headerFrom = toAddr(m.headerFrom);
  let authenticated: Addr | null = null;
  let trusted: boolean | null = false;
  if (direction === 'inbound') {
    authenticated = auth !== null && auth.dmarc === 'pass' && !authFailure ? headerFrom : null;
    trusted =
      bec === null || auth === null
        ? null
        : bec.trustedCode === 'authenticated' && auth.dmarc === 'pass' && !authFailure;
  } else {
    authenticated = envelope;
  }
  const senderAddress = direction === 'inbound' ? null : (authenticated?.address ?? null);

  // Recipients (sorted by rcptSeq, capped).
  const seqs = new Set<number>();
  const recipients = [...rows.recipients]
    .map((r) => {
      parseOrFail(intSchema(65_535), r.rcptSeq, 'rcptSeq');
      if (seqs.has(r.rcptSeq)) fail('Duplicate rcptSeq');
      seqs.add(r.rcptSeq);
      if (typeof r.address !== 'string' || r.address.length < 1 || r.address.length > 320) {
        fail('Malformed recipient address');
      }
      const n = normalizeAddress(r.address);
      return {
        rcptSeq: r.rcptSeq,
        address: n.address,
        domain: n.domain,
        localPart: n.localPart,
        departments: directoryIds(departmentsByAddress, n.address),
        users: directoryIds(usersByAddress, n.address),
      };
    })
    .sort((a, b) => a.rcptSeq - b.rcptSeq);

  // Attachments.
  const results = new Map<number, PolicyRoundRows['attachmentResults'][number]>();
  for (const r of rows.attachmentResults) {
    parseOrFail(intSchema(65_535), r.partIndex, 'attachment result partIndex');
    if (results.has(r.partIndex)) fail('Two attachment results for one part');
    results.set(r.partIndex, r);
  }
  const parts = new Set<number>();
  let totalBytes = 0;
  const attachmentItems = [...rows.attachments]
    .map((a) => {
      parseOrFail(intSchema(65_535), a.partIndex, 'attachment partIndex');
      if (parts.has(a.partIndex)) fail('Duplicate attachment partIndex');
      parts.add(a.partIndex);
      parseOrFail(intSchema(), a.sizeBytes, 'attachment sizeBytes');
      totalBytes += a.sizeBytes;
      const sha256 = parseOrFail(z.string().regex(/^[0-9a-fA-F]{64}$/), a.sha256, 'sha256');
      const archiveInfo = parseOrFail(archiveInfoSchema, a.archiveInfo ?? null, 'archiveInfo');
      const r = results.get(a.partIndex);
      const reasonCodes = r
        ? sortStrings(parseOrFail(rawCodesSchema, r.reasonCodes, 'codes'))
        : null;
      const resultArchive = r
        ? parseOrFail(resultArchiveSchema, r.archive ?? null, 'archive')
        : null;
      const filename =
        a.filename === null || a.filename.length === 0 ? null : a.filename.normalize('NFC');
      if (filename !== null && filename.length > 1024) fail('Attachment filename too long');
      const declared = a.declaredContentType ? normalizeContentType(a.declaredContentType) : '';
      return {
        partIndex: a.partIndex,
        extension: extensionOf(filename),
        filename,
        declaredType: declared.length > 0 ? declared.slice(0, 255) : null,
        detectedType: r ? parseOrFail(z.string().min(1).max(32), r.detectedType, 'type') : null,
        typeFamily: r ? parseOrFail(z.enum(FILE_TYPE_FAMILIES), r.typeFamily, 'type family') : null,
        sizeBytes: a.sizeBytes,
        sha256: sha256.toLowerCase(),
        verdict: r ? parseOrFail(z.enum(ATTACHMENT_VERDICTS), r.verdict, 'verdict') : null,
        reasonCodes,
        isArchive: archiveInfo !== null,
        encrypted:
          (archiveInfo?.encryptedEntries ?? 0) > 0 ||
          (reasonCodes ?? []).includes('archive.encrypted') ||
          resultArchive?.encrypted === true,
        typeMismatch: r ? parseOrFail(z.boolean(), r.typeMismatch, 'typeMismatch') : null,
      };
    })
    .sort((a, b) => a.partIndex - b.partIndex);
  for (const partIndex of results.keys()) {
    if (!parts.has(partIndex)) fail('Attachment result without its attachment');
  }

  // URLs.
  const urlResults = new Map<number, PolicyRoundRows['urlResults'][number]>();
  for (const r of rows.urlResults) {
    parseOrFail(intSchema(65_535), r.urlSeq, 'url result urlSeq');
    if (urlResults.has(r.urlSeq)) fail('Two url results for one URL');
    urlResults.set(r.urlSeq, r);
  }
  const urlSeqs = new Set<number>();
  const urlItems = [...rows.urls]
    .map((u) => {
      parseOrFail(intSchema(65_535), u.urlSeq, 'urlSeq');
      if (urlSeqs.has(u.urlSeq)) fail('Duplicate urlSeq');
      urlSeqs.add(u.urlSeq);
      const hostKind = parseOrFail(z.enum(URL_HOST_KINDS), u.hostKind, 'hostKind');
      let host: string;
      if (hostKind === 'domain') {
        host = normalizeDomain(u.host) ?? fail('Malformed url host');
      } else {
        const ip = parseIp(u.host.replace(/^\[|\]$/g, ''));
        host = ip ? formatIp(ip) : fail('Malformed url IP host');
      }
      const r = urlResults.get(u.urlSeq);
      return {
        urlSeq: u.urlSeq,
        host,
        domain:
          u.registrableDomain === null
            ? null
            : (normalizeDomain(u.registrableDomain) ?? fail('Malformed registrable domain')),
        scheme: parseOrFail(z.enum(['http', 'https']), u.scheme, 'scheme'),
        hostKind,
        verdict: r ? parseOrFail(z.enum(URL_VERDICTS), r.verdict, 'url verdict') : null,
        reasonCodes: r ? sortStrings(parseOrFail(rawCodesSchema, r.reasonCodes, 'codes')) : null,
      };
    })
    .sort((a, b) => a.urlSeq - b.urlSeq);
  for (const seq of urlResults.keys()) if (!urlSeqs.has(seq)) fail('URL result without its URL');
  let rewriteStatus: PolicyInput['urls']['rewriteStatus'] = 'none';
  let rewriteSkipReason: PolicyInput['urls']['rewriteSkipReason'] = null;
  if (rows.urlRewrite) {
    rewriteStatus = parseOrFail(
      z.enum(['rewritten', 'skipped']),
      rows.urlRewrite.status,
      'rewrite',
    );
    rewriteSkipReason =
      rows.urlRewrite.skipReason === null
        ? null
        : parseOrFail(z.enum(REWRITE_SKIP_REASONS), rows.urlRewrite.skipReason, 'skip reason');
  }

  // Client.
  let clientIp: string | null = null;
  if (m.clientIp !== null) {
    const ip = parseIp(m.clientIp);
    clientIp = ip ? formatIp(ip) : null;
  }
  const clientHostname =
    m.clientName === null || m.clientName.toLowerCase() === 'unknown'
      ? null
      : normalizeDomain(m.clientName);

  const input = {
    version: POLICY_INPUT_VERSION,
    trigger,
    evaluationTime,
    direction,
    round,
    message: {
      sizeBytes: m.sizeBytes,
      recipientCount: m.recipientCount,
      attachmentCount: m.attachmentCount,
    },
    sender: {
      envelope,
      headerFrom,
      authenticated,
      trusted,
      departments: directoryIds(departmentsByAddress, senderAddress),
      users: directoryIds(usersByAddress, senderAddress),
    },
    recipients: recipients.slice(0, POLICY_LIMITS.recipients),
    recipientsTruncated: recipients.length > POLICY_LIMITS.recipients,
    client: { ip: clientIp, hostname: clientHostname },
    auth,
    attachments: {
      count: attachmentItems.length,
      totalBytes,
      truncated: attachmentItems.length > POLICY_LIMITS.attachments,
      items: attachmentItems.slice(0, POLICY_LIMITS.attachments),
    },
    urls: {
      count: urlItems.length,
      truncated: urlItems.length > POLICY_LIMITS.urls,
      rewriteStatus,
      rewriteSkipReason,
      items: urlItems.slice(0, POLICY_LIMITS.urls),
    },
    scan,
    risk,
    dlp,
    dlpFinal: finalState(finals.get('dlp')?.outcome),
    bec,
    becFinal: finalState(finals.get('bec')?.outcome),
  };
  return parseOrFail(policyInputSchema, input, 'policy input');
}
