import { AUTH_OUTCOMES, DMARC_POLICIES, SCAN_VERDICTS } from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * Shapes of `GET /messages/{messageId}/scans` (step 4.1 S16, docs/plan/steps/09-rspamd.md):
 * one entry per scan round (`email_scans`), newest round first, with the engine results
 * (`scan_engine_results`: the final row as the result, every row as an attempt), the
 * authentication results (`email_auth_results`) and the engine's symbols (`evidence.signals`).
 * Scores, codes, symbol names, bounded symbol options and authentication outcomes only: never
 * message content.
 */

/** Rounds per page (S16: at most 20). */
export const MAX_SCAN_PAGE_LIMIT = 20;
export const DEFAULT_SCAN_PAGE_LIMIT = 10;

export const MessageScansQuerySchema = z.strictObject({
  limit: z.coerce.number().int().min(1).max(MAX_SCAN_PAGE_LIMIT).default(DEFAULT_SCAN_PAGE_LIMIT),
  cursor: z.string().min(1).max(64).optional(),
});
export type MessageScansQuery = z.output<typeof MessageScansQuerySchema>;

const IsoDate = z.iso.datetime();

export const ScanVerdictSchema = z.enum(SCAN_VERDICTS);
/** `scan_engine_results.outcome`: the seven verdicts plus `skipped`. */
export const EngineOutcomeSchema = z.enum([...SCAN_VERDICTS, 'skipped']);
export const AuthOutcomeSchema = z.enum(AUTH_OUTCOMES);

export const ScanSymbolSchema = z.object({
  name: z.string(),
  score: z.number(),
  options: z
    .array(z.string())
    .describe('At most 5 options of at most 200 characters (may contain addresses or URLs)'),
});
export type ScanSymbol = z.output<typeof ScanSymbolSchema>;

export const ScanAttemptSchema = z.object({
  attempt: z.number().int().min(1),
  outcome: EngineOutcomeSchema,
  errorCode: z
    .string()
    .nullable()
    .describe('Failure code of a timeout/error attempt (e.g. eml_unavailable)'),
  durationMs: z.number().int().min(0),
  at: IsoDate.describe('When the attempt completed'),
});
export type ScanAttempt = z.output<typeof ScanAttemptSchema>;

export const ScanEngineResultSchema = z.object({
  engine: z.string(),
  final: z
    .boolean()
    .describe('Whether the engine has its final result; false while attempts are retried'),
  engineVersion: z.string().nullable(),
  outcome: EngineOutcomeSchema.nullable().describe('Final outcome; null before the final result'),
  score: z.number().nullable(),
  requiredScore: z.number().nullable(),
  action: z.string().nullable().describe('Engine action (Rspamd: `no action`, `reject`, …)'),
  reasonCodes: z.array(z.string()),
  symbols: z.array(ScanSymbolSchema).describe('Rspamd symbols, by |score| descending'),
  attempts: z.array(ScanAttemptSchema).describe('Every attempt of the engine in the round'),
  durationMs: z.number().int().min(0).nullable(),
  settingsVersion: z.string().nullable(),
  completedAt: IsoDate.nullable(),
});
export type ScanEngineResultView = z.output<typeof ScanEngineResultSchema>;

export const DkimSignatureSchema = z.object({
  domain: z.string(),
  result: AuthOutcomeSchema,
  selector: z.string().nullable(),
});

export const ScanAuthSchema = z.object({
  spf: AuthOutcomeSchema.nullable(),
  spfDomain: z.string().nullable(),
  dkim: AuthOutcomeSchema.nullable(),
  dkimSignatures: z.array(DkimSignatureSchema),
  dmarc: AuthOutcomeSchema.nullable(),
  dmarcPolicy: z.enum(DMARC_POLICIES).nullable(),
  dmarcDomain: z.string().nullable(),
  arc: AuthOutcomeSchema.nullable(),
});
export type ScanAuthView = z.output<typeof ScanAuthSchema>;

export const ScanRoundSchema = z.object({
  round: z.number().int().min(0).describe('Lifecycle round the scan belongs to (0 = initial)'),
  scanKind: z.enum(['initial', 'rescan', 'release_revalidation', 'retro']),
  status: z.enum(['pending', 'running', 'completed', 'failed', 'timed_out']),
  verdict: ScanVerdictSchema.nullable().describe('Aggregate verdict; null while running'),
  reasonCodes: z.array(z.string()),
  requiredEngines: z.array(z.string()),
  startedAt: IsoDate.nullable(),
  completedAt: IsoDate.nullable(),
  deadlineAt: IsoDate.nullable(),
  auth: ScanAuthSchema.nullable().describe('SPF/DKIM/DMARC/ARC; null before the engine reported'),
  engines: z.array(ScanEngineResultSchema),
});
export type ScanRoundView = z.output<typeof ScanRoundSchema>;

export const MessageScansPageSchema = z.object({
  messageId: z.uuid(),
  data: z.array(ScanRoundSchema).describe('Newest round first'),
  nextCursor: z.string().nullable(),
});
export type MessageScansPage = z.output<typeof MessageScansPageSchema>;
