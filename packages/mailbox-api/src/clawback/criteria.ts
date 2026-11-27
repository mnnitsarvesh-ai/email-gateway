/**
 * Clawback documents (step API-3, design note 37 C4.1, §5): the strict search criteria
 * `api-clawback-criteria/1` (indexed keys only, combined with OR) with their window rules and
 * canonical hash, and the strict signal document `api-clawback-signal/1`. Pure; both the api and
 * the mailbox-worker validate with these schemas before storing.
 *
 * The documents hold hashes, normalized keys, sender addresses and time windows only (C-I6).
 */
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { canonicalJson } from '../remediation/policy';
import { MESSAGE_VERDICTS } from '../remediation/vocabulary';
import { CLAWBACK_SIGNAL_KINDS, CLAWBACK_SIGNAL_LEVELS } from './vocabulary';

export const CLAWBACK_CRITERIA_SCHEMA_VERSION = 1;
export const CLAWBACK_SIGNAL_SCHEMA_VERSION = 1;

/** Key and window limits of `api-clawback-criteria/1` (C4.1). */
export const CLAWBACK_CRITERIA_LIMITS = Object.freeze({
  messageIdHashes: 10,
  attachmentSha256: 20,
  urlSha256: 20,
  urlDomains: 5,
  senders: 5,
  senderDomains: 5,
  subjectKeyMaxCodePoints: 128,
  /** `from` never before now − 186 days (the copies retention). */
  retentionDays: 186,
  /** A sender + subject search spans at most 7 days unless it comes from a campaign seed. */
  senderSubjectMaxWindowDays: 7,
});

/** The zod issue code (message and `params.code`) of the reserved `refs.campaignRef`. */
export const UNSUPPORTED_UNTIL_ATP4 = 'unsupported_until_atp4';

const DAY_MS = 86_400_000;
const HEX64 = /^[0-9a-f]{64}$/;
/** Lower-case LDH domain with at least one dot (IDNs as A-labels). */
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;
const ADDRESS_LOCAL = /^[^\s@<>()[\]\\,;:"]{1,64}$/;

const hex64 = z.string().regex(HEX64, { message: 'not_hex64' });
const domain = z.string().regex(DOMAIN, { message: 'not_domain' });
/** A lower-case addr-spec `local@domain` (≤ 320). */
const address = z
  .string()
  .max(320)
  .refine(
    (value) => {
      const at = value.lastIndexOf('@');
      if (at <= 0) return false;
      const local = value.slice(0, at);
      return (
        value === value.toLowerCase() &&
        ADDRESS_LOCAL.test(local) &&
        DOMAIN.test(value.slice(at + 1))
      );
    },
    { message: 'not_lower_case_address' },
  );

const codePoints = (value: string): number => Array.from(value).length;

function uniqueArray<T extends z.ZodType<string>>(item: T, max: number) {
  return z
    .array(item)
    .min(1)
    .max(max)
    .refine((values) => new Set(values).size === values.length, { message: 'duplicate_values' });
}

const isoDateTime = z.iso.datetime({ offset: true });

const keysSchema = z.strictObject({
  messageIdHashes: uniqueArray(hex64, CLAWBACK_CRITERIA_LIMITS.messageIdHashes).optional(),
  attachmentSha256: uniqueArray(hex64, CLAWBACK_CRITERIA_LIMITS.attachmentSha256).optional(),
  urlSha256: uniqueArray(hex64, CLAWBACK_CRITERIA_LIMITS.urlSha256).optional(),
  /** Threat-intelligence clawbacks only (the api never builds these keys from admin input). */
  urlDomains: uniqueArray(domain, CLAWBACK_CRITERIA_LIMITS.urlDomains).optional(),
  senders: uniqueArray(address, CLAWBACK_CRITERIA_LIMITS.senders).optional(),
  senderDomains: uniqueArray(domain, CLAWBACK_CRITERIA_LIMITS.senderDomains).optional(),
  senderSubject: z
    .strictObject({
      sender: address,
      subjectKey: z
        .string()
        .refine(
          (v) =>
            codePoints(v) >= 1 && codePoints(v) <= CLAWBACK_CRITERIA_LIMITS.subjectKeyMaxCodePoints,
          { message: 'subject_key_length' },
        ),
    })
    .optional(),
});

/**
 * `api-clawback-criteria/1` (C4.1), structural rules only: strict, at least one key, `to` not
 * before `from`, directions unique, `includeReportMailboxes` always false. The time rules that
 * depend on the clock and configuration are checked by `parseClawbackCriteria`.
 */
export const clawbackCriteriaSchema = z
  .strictObject({
    v: z.literal(CLAWBACK_CRITERIA_SCHEMA_VERSION),
    window: z.strictObject({ from: isoDateTime, to: isoDateTime }),
    keys: keysSchema,
    directions: z
      .array(z.enum(['inbound', 'internal']))
      .min(1)
      .max(2)
      .refine((v) => new Set(v).size === v.length, { message: 'duplicate_values' }),
    includeReportMailboxes: z.literal(false),
  })
  .superRefine((criteria, ctx) => {
    const present = Object.values(criteria.keys).filter((v) => v !== undefined);
    if (present.length === 0) {
      ctx.addIssue({
        code: 'custom',
        message: 'no_keys',
        path: ['keys'],
        params: { code: 'no_keys' },
      });
    }
    if (Date.parse(criteria.window.to) < Date.parse(criteria.window.from)) {
      ctx.addIssue({
        code: 'custom',
        message: 'window_inverted',
        path: ['window', 'to'],
        params: { code: 'window_inverted' },
      });
    }
  });

export type ClawbackCriteria = z.infer<typeof clawbackCriteriaSchema>;
export type ClawbackCriteriaKeys = ClawbackCriteria['keys'];

export interface ClawbackCriteriaOptions {
  now: Date;
  /** `API_MODE_CLAWBACK_MAX_WINDOW_DAYS` (31). */
  maxWindowDays: number;
  /** The sender + subject key comes from a campaign seed (C2.4): the 7-day limit is lifted. */
  fromCampaignSeed?: boolean;
}

/** Codes of the clock- and configuration-dependent window rules. */
export const CLAWBACK_WINDOW_ISSUES = [
  'window_too_long',
  'window_before_retention',
  'sender_subject_window_too_long',
] as const;

/** The window rules of C4.1 for an already structurally valid document. */
export function clawbackWindowIssues(
  criteria: ClawbackCriteria,
  options: ClawbackCriteriaOptions,
): (typeof CLAWBACK_WINDOW_ISSUES)[number][] {
  const issues: (typeof CLAWBACK_WINDOW_ISSUES)[number][] = [];
  const from = Date.parse(criteria.window.from);
  const to = Date.parse(criteria.window.to);
  if (to - from > options.maxWindowDays * DAY_MS) issues.push('window_too_long');
  if (from < options.now.getTime() - CLAWBACK_CRITERIA_LIMITS.retentionDays * DAY_MS) {
    issues.push('window_before_retention');
  }
  if (
    criteria.keys.senderSubject !== undefined &&
    options.fromCampaignSeed !== true &&
    to - from > CLAWBACK_CRITERIA_LIMITS.senderSubjectMaxWindowDays * DAY_MS
  ) {
    issues.push('sender_subject_window_too_long');
  }
  return issues;
}

/** A validation issue without the offending value (C-I6: no hash, address or key in errors). */
export interface ClawbackCriteriaIssue {
  message: string;
  path: PropertyKey[];
}

export type ClawbackCriteriaParseResult =
  | { ok: true; criteria: ClawbackCriteria }
  | { ok: false; codes: string[]; issues: ClawbackCriteriaIssue[] };

/**
 * Validates an unknown value as `api-clawback-criteria/1` with every C4.1 rule. `codes` are the
 * distinct issue messages; issues carry message and path only (no input value is echoed).
 */
export function parseClawbackCriteria(
  value: unknown,
  options: ClawbackCriteriaOptions,
): ClawbackCriteriaParseResult {
  const parsed = clawbackCriteriaSchema.safeParse(value);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => ({ message: i.message, path: [...i.path] }));
    return { ok: false, codes: [...new Set(issues.map((i) => i.message))], issues };
  }
  const window = clawbackWindowIssues(parsed.data, options);
  if (window.length > 0) {
    return {
      ok: false,
      codes: window,
      issues: window.map((message) => ({ message, path: ['window'] })),
    };
  }
  return { ok: true, criteria: parsed.data };
}

const sorted = <T extends string>(values: readonly T[] | undefined): T[] | undefined =>
  values === undefined ? undefined : [...values].sort();

/** The criteria with set-like arrays sorted (equal searches give equal documents). */
export function normalizeClawbackCriteria(criteria: ClawbackCriteria): ClawbackCriteria {
  const k = criteria.keys;
  return {
    v: criteria.v,
    window: { from: criteria.window.from, to: criteria.window.to },
    keys: {
      messageIdHashes: sorted(k.messageIdHashes),
      attachmentSha256: sorted(k.attachmentSha256),
      urlSha256: sorted(k.urlSha256),
      urlDomains: sorted(k.urlDomains),
      senders: sorted(k.senders),
      senderDomains: sorted(k.senderDomains),
      senderSubject: k.senderSubject && { ...k.senderSubject },
    },
    directions: sorted(criteria.directions) as ClawbackCriteria['directions'],
    includeReportMailboxes: false,
  };
}

/** `criteria_sha256`: hex SHA-256 of the canonical JSON of the normalized criteria. */
export function canonicalCriteriaSha256(criteria: ClawbackCriteria): string {
  return createHash('sha256')
    .update(canonicalJson(normalizeClawbackCriteria(criteria)), 'utf8')
    .digest('hex');
}

// ---------------------------------------------------------------------------------------------
// api-clawback-signal/1 (§5)
// ---------------------------------------------------------------------------------------------

/** Hard-block ids as the event contract allows them (§5). */
export const HARD_BLOCK_ID = /^[a-z0-9_.:-]{1,64}$/;
/** At most this many hard-block ids in signal facts (§5). */
export const SIGNAL_MAX_HARD_BLOCKS = 9;

const ID_REF = /^[0-9]{1,20}$/;
const PUBLIC_REF = /^[0-9A-Za-z-]{1,64}$/;

/** `facts` of a signal: what the policy decides on (C3.1). */
export const clawbackSignalFactsSchema = z.strictObject({
  verdict: z.enum(MESSAGE_VERDICTS),
  level: z.enum(CLAWBACK_SIGNAL_LEVELS),
  hardBlocks: z
    .array(z.string().regex(HARD_BLOCK_ID, { message: 'not_hard_block_id' }))
    .max(SIGNAL_MAX_HARD_BLOCKS),
  score: z.number().int().min(0).max(1000).optional(),
});
export type ClawbackSignalFacts = z.infer<typeof clawbackSignalFactsSchema>;

/** `api-clawback-signal/1` (§5); `refs.campaignRef` is reserved for ATP-4 and refused. */
export const clawbackSignalSchema = z.strictObject({
  v: z.literal(CLAWBACK_SIGNAL_SCHEMA_VERSION),
  kind: z.enum(CLAWBACK_SIGNAL_KINDS),
  refs: z.strictObject({
    /** Registry message id (decimal string). */
    messageId: z.string().regex(ID_REF).optional(),
    receivedAt: isoDateTime.optional(),
    scanId: z.string().regex(PUBLIC_REF).optional(),
    revision: z.number().int().min(0).max(255).optional(),
    indicatorId: z.string().regex(ID_REF).optional(),
    signatureId: z.string().regex(ID_REF).optional(),
    /** `api_user_reports.public_id`. */
    reportId: z.string().regex(PUBLIC_REF).optional(),
    seedCopyId: z.string().regex(ID_REF).optional(),
    /** Reserved for ATP-4 campaign entities (C2.4): refused with `unsupported_until_atp4`. */
    campaignRef: z
      .custom<never>(() => false, {
        message: UNSUPPORTED_UNTIL_ATP4,
        params: { code: UNSUPPORTED_UNTIL_ATP4 },
      })
      .optional(),
  }),
  facts: clawbackSignalFactsSchema.nullable(),
  signalAt: isoDateTime,
});
export type ClawbackSignal = z.infer<typeof clawbackSignalSchema>;
