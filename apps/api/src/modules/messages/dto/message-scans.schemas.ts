import {
  attachmentResultSchema,
  AUTH_OUTCOMES,
  BEC_MAX_AI_ASSESSMENTS,
  BEC_MAX_AI_SHADOW_ASSESSMENTS,
  BEC_MAX_EVIDENCE_ITEMS,
  BEC_MAX_FEEDBACK_REFS,
  BEC_MAX_RULES,
  becAiAssessmentViewSchema,
  becAiShadowAssessmentViewSchema,
  becFeedbackRefSchema,
  becInputsSchema,
  becRuleEntrySchema,
  becRuleEvidenceSchema,
  becVerdictSchema,
  CLICK_DECISIONS,
  dlpResultViewSchema,
  DMARC_POLICIES,
  REWRITE_SKIP_REASONS,
  SCAN_VERDICTS,
  urlResultSchema,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * Shapes of `GET /messages/{messageId}/scans` (step 4.1 S16, docs/plan/steps/09-rspamd.md):
 * one entry per scan round (`email_scans`), newest round first, with the engine results
 * (`scan_engine_results`: the final row as the result, every row as an attempt), the
 * authentication results (`email_auth_results`) and the engine's symbols (`evidence.signals`).
 * Scores, codes, symbol names, bounded symbol options and authentication outcomes only: never
 * message content. Step 4.2 A16: the `attachment` engine entry also lists its per-attachment
 * results (`attachment_scan_results`; hashes, sizes, type ids, signature and rule names, counts
 * and codes, never file content or archive entry names). Step 4.3 U16: the `url` engine entry also
 * lists its per-URL results (`message_urls` + `url_scan_results`, the latest dynamic inspection,
 * a click summary from `url_click_events`) and the round's rewrite (`url_rewrites`); normalized
 * URLs, hosts, codes and counts, never page content, anchor text or titles. Step 4.4 B15: the
 * `bec` engine entry carries its explainable verdict (`bec_scan_results`: versions, scores,
 * thresholds, input states, fired rules with structured evidence, AI assessments, feedback
 * references); never body text, span text, excerpts, response hashes, AI durations or history
 * hashes. Step 4.5 D20: the `dlp` engine entry carries its masked result (versions, verdict,
 * action, coverage detail, category aggregates, findings with masked samples, the policy match
 * with public ids, the evidence state) for callers holding `dlp:read`, else `dlp: null`; never
 * raw values, context text, offsets, dictionary terms, pattern text or durations.
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
  durationMs: z
    .number()
    .int()
    .min(0)
    .nullable()
    .describe(
      'Attempt duration; null for the `attachment` and `url` engines (it would reveal cache hits)',
    ),
  at: IsoDate.describe(
    'When the attempt completed (whole seconds for the `attachment` and `url` engines)',
  ),
});
export type ScanAttempt = z.output<typeof ScanAttemptSchema>;

/** Status of a sandbox submission (step 4.2 A11; the sandbox itself arrives in step 4.6). */
export const SandboxSubmissionStatusSchema = z.enum([
  'pending',
  'submitted',
  'completed',
  'failed',
  'expired',
]);

/**
 * The per-attachment fields shown to a tenant: the normalized result without `cache` and
 * `durationMs`. The content cache is shared by every organization and keyed by the file hash
 * only (A10), so its hit/miss outcome, and the per-file timing that reveals it, would tell a
 * tenant whether some other organization received a byte-identical file within the cache TTL.
 * Both stay in `attachment_scan_results` and in the operator metrics.
 */
const {
  cache: _cacheResult,
  durationMs: _attachmentDuration,
  ...tenantAttachmentShape
} = attachmentResultSchema.shape;

/**
 * One attachment's result in a round (step 4.2 A16): the normalized `attachmentResultSchema` of
 * `@email-gateway/security-contracts` (without the cross-tenant cache outcome and timing, see
 * above) plus the display metadata of the part and its sandbox submission. `filename` is the
 * sanitized display name of `email_attachments` (step 3.1 M9).
 */
export const AttachmentScanViewSchema = z.object({
  ...tenantAttachmentShape,
  filename: z
    .string()
    .nullable()
    .describe('Sanitized display filename of the part (attacker-controlled text, escaped)'),
  declaredContentType: z.string().nullable().describe('Content type the message declared'),
  sandbox: z
    .object({
      submissionId: z.string().describe('sandbox_submissions id (decimal)'),
      status: SandboxSubmissionStatusSchema,
    })
    .nullable()
    .describe('Sandbox submission of a suspicious/unknown attachment; null when not submitted'),
});
export type AttachmentScanView = z.output<typeof AttachmentScanViewSchema>;

/**
 * The per-URL fields shown to a tenant (step 4.3 U16): the normalized `urlResultSchema` shape of
 * `@email-gateway/security-contracts`. The stored rows also hold the reputation cache outcome,
 * the fetch-cache outcome and per-URL durations; the reputation, chain and dynamic caches are
 * shared by every organization (U6), so these would tell a tenant whether another organization
 * received the same URL recently. They are never returned (operators keep them in the rows and
 * the metrics). Platform threat-feed hits are shown (platform facts, not another tenant's data).
 * `registrableDomain` is null also for a host that is itself a public suffix (WP3 deviation 12).
 */
const {
  reputation: _reputation,
  lookalike: _lookalike,
  fetch: _fetch,
  ...tenantUrlShape
} = urlResultSchema.shape;

export const UrlClickDecisionSchema = z.enum(CLICK_DECISIONS);

export const UrlScanViewSchema = z.object({
  ...tenantUrlShape,
  reputation: z
    .array(
      z.object({
        provider: z.string().describe('`local_feed` (platform feed), `dnsbl`, `rdap`, …'),
        kind: z.enum(['url', 'domain', 'ip']),
        status: z.enum(['listed', 'clear', 'error']),
        category: z.enum(['phishing', 'malware', 'spam', 'scam', 'c2', 'other']).nullable(),
      }),
    )
    .describe('Reputation answers (≤ 12; listed first); never the cache outcome'),
  lookalike: z
    .array(
      z.object({
        rule: z.enum(['L1', 'L2', 'L3', 'L4', 'L5', 'L6']),
        targetKind: z.enum(['brand', 'tenant', 'extra']).nullable(),
        targetDomain: z.string().nullable(),
        score: z.number(),
      }),
    )
    .describe('Lookalike findings (≤ 5); L4 mixed script and L6 IDN without a target'),
  fetch: z
    .object({
      status: z.enum(['completed', 'error', 'blocked']),
      error: z.string().nullable().describe('Fetch error code when status is error'),
      hops: z.number().int().min(0).describe('Redirects followed'),
      chain: z
        .array(
          z.object({
            host: z.string(),
            status: z.number().int().nullable(),
            kind: z.enum(['initial', 'http', 'meta']),
            blocked: z.string().nullable().describe('SSRF guard reason when the hop was refused'),
          }),
        )
        .describe('Hosts of the redirect chain only (≤ 10; no paths or queries)'),
      finalUrl: z.string().nullable(),
      finalStatus: z.number().int().nullable(),
    })
    .nullable()
    .describe('Scan-time fetch (redirect chain); null when the URL was not fetched'),
  clicks: z
    .object({
      total: z.number().int().min(0),
      lastDecision: UrlClickDecisionSchema.nullable(),
      lastAt: IsoDate.nullable().describe('Whole seconds'),
    })
    .describe('Clicks on the rewritten link (all rounds of the message: one token per URL)'),
});
export type UrlScanView = z.output<typeof UrlScanViewSchema>;

export const UrlRewriteViewSchema = z.object({
  status: z.enum(['rewritten', 'skipped']),
  skipReason: z
    .enum(REWRITE_SKIP_REASONS)
    .nullable()
    .describe('Why the round was not rewritten (e.g. signed_smime, no_urls)'),
  linksRewritten: z.number().int().min(0),
  partsRewritten: z.number().int().min(0),
  dkimSigned: z
    .boolean()
    .describe('The message carried a DKIM signature that no longer verifies downstream'),
  expiresAt: IsoDate.nullable().describe('When the click tokens expire (whole seconds)'),
});
export type UrlRewriteView = z.output<typeof UrlRewriteViewSchema>;

const BecScore = z.number().int().min(0).max(100);

/** One fired rule (B15) with its evidence entries (≤ 5; B6 allows several per rule). */
export const BecRuleViewSchema = z.object({
  id: becRuleEntrySchema.shape.id,
  code: becRuleEntrySchema.shape.code,
  category: becRuleEntrySchema.shape.category,
  severity: becRuleEntrySchema.shape.severity,
  weight: becRuleEntrySchema.shape.weight.describe('bec-map/1 weight (0 effect when suppressed)'),
  suppressed: becRuleEntrySchema.shape.suppressed.describe(
    '`trust` (authenticated trusted sender) or `feedback` (a suppression rule); null = counted',
  ),
  evidence: z
    .array(becRuleEvidenceSchema)
    .max(BEC_MAX_EVIDENCE_ITEMS)
    .describe(
      'Structured evidence: header, parsed address/display name/domain, profile (public id), ' +
        'lookalike, authentication, lexicon ids and span offsets (never text), URL seqs, ' +
        'history buckets, trusted sender / suppression ids',
    ),
});

/** The `bec` section of the `bec` engine entry (step 4.4 B15). */
export const BecScanViewSchema = z.object({
  rulesVersion: z.string(),
  engineVersion: z.string(),
  settingsVersion: z.string(),
  lexiconVersion: z.string(),
  verdict: becVerdictSchema.describe('Final verdict (after the AI layer)'),
  deterministicVerdict: becVerdictSchema.describe('Verdict of the deterministic rules'),
  score: BecScore,
  deterministicScore: BecScore,
  thresholds: z
    .object({ suspicious: BecScore.nullable(), malicious: BecScore.nullable() })
    .describe('The thresholds applied; null when the engine did not record them'),
  inputs: becInputsSchema.nullable().describe('auth, url, text and history input states'),
  rules: z.array(BecRuleViewSchema).max(BEC_MAX_RULES),
  ai: z
    .array(becAiAssessmentViewSchema)
    .max(BEC_MAX_AI_ASSESSMENTS)
    .describe('Applied assessments'),
  aiShadow: z
    .array(becAiShadowAssessmentViewSchema)
    .max(BEC_MAX_AI_SHADOW_ASSESSMENTS)
    .describe('Shadow assessments (never change the verdict)'),
  feedback: z.array(becFeedbackRefSchema).max(BEC_MAX_FEEDBACK_REFS).describe('Newest first'),
});
export type BecScanView = z.output<typeof BecScanViewSchema>;

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
  attachments: z
    .array(AttachmentScanViewSchema)
    .optional()
    .describe(
      'Engine `attachment` only (step 4.2 A16): one result per scanned attachment of the ' +
        'round, by part index; empty before the final result and for `skipped`',
    ),
  urls: z
    .array(UrlScanViewSchema)
    .optional()
    .describe(
      'Engine `url` only (step 4.3 U16): one result per URL of the round (≤ 200, by urlSeq); ' +
        'empty before the final result and for `skipped`',
    ),
  rewrite: UrlRewriteViewSchema.nullable()
    .optional()
    .describe("Engine `url` only: the round's link rewriting; null before the final result"),
  bec: BecScanViewSchema.nullable()
    .optional()
    .describe(
      'Engine `bec` only (step 4.4 B15): the explainable verdict; null before the final ' +
        'result and for failures',
    ),
  dlp: dlpResultViewSchema
    .nullable()
    .optional()
    .describe(
      'Engine `dlp` only (step 4.5 D20): the masked DLP result; null before the final result, ' +
        'for failures, and for callers without `dlp:read`',
    ),
  durationMs: z
    .number()
    .int()
    .min(0)
    .nullable()
    .describe(
      'Engine duration of the final result; always null for the `attachment`, `url`, `bec` ' +
        'and `dlp` engines (cross-tenant cache hits; the AI layer’s and extraction timing)',
    ),
  settingsVersion: z.string().nullable(),
  completedAt: IsoDate.nullable().describe(
    'Final result time (whole seconds for the `attachment`, `url`, `bec` and `dlp` engines)',
  ),
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
  scanId: z
    .string()
    .describe('Decimal id of the round (`{scanId}` of the BEC feedback route, step 4.4)'),
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
