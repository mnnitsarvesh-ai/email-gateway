import { RISK_ACTIONS, RISK_LEVELS, RISK_VERDICTS } from '@email-gateway/risk-scoring';
import { RISK_HARD_BLOCK_IDS, SANDBOX_INPUT_OUTCOMES } from '@email-gateway/risk-scoring';
import {
  ATTACHMENT_VERDICTS,
  AUTH_OUTCOMES,
  BEC_VERDICTS,
  DLP_ACTIONS,
  DLP_CATEGORIES,
  DLP_COVERAGES,
  DLP_SEVERITIES,
  DLP_VERDICTS,
  DMARC_POLICIES,
  ENGINE_NAMES,
  FILE_TYPE_FAMILIES,
  SCAN_VERDICTS,
  URL_HOST_KINDS,
  URL_VERDICTS,
} from '@email-gateway/security-contracts';
import { POLICY_MESSAGE_DIRECTIONS, type PolicyMessageDirection } from './vocabulary';

/**
 * The closed field and operator catalog of `policy-dsl/1` (step 5.2 P3). Data, not code: the
 * validator, the compiler, the evaluator, the api catalog route and the DSL reference
 * (docs/architecture/policy-dsl.md, checked by a unit test) all read this table.
 */

export const POLICY_OPERATORS = [
  'equals',
  'in',
  'not_in',
  'domain_in',
  'glob',
  'regex',
  'in_cidr',
  'eq',
  'gt',
  'gte',
  'lt',
  'lte',
  'between',
  'contains_any',
  'contains_all',
  'exists',
  'is',
  'within',
] as const;
export type PolicyOperator = (typeof POLICY_OPERATORS)[number];

export const isPolicyOperator = (op: unknown): op is PolicyOperator =>
  typeof op === 'string' && (POLICY_OPERATORS as readonly string[]).includes(op);

/** Operators that negate (refused in exceptions, P6). */
export const NEGATED_OPERATORS: readonly PolicyOperator[] = Object.freeze(['not_in']);

export const POLICY_FIELD_TYPES = [
  'string',
  'address',
  'domain',
  'enum',
  'int',
  'bool',
  'ip',
  'codes',
  'id',
  'time',
] as const;
export type PolicyFieldType = (typeof POLICY_FIELD_TYPES)[number];

/** Where a field's fact lives: the message, or each element of a list (quantified). */
export const POLICY_FIELD_SCOPES = ['message', 'recipients', 'attachments', 'urls'] as const;
export type PolicyFieldScope = (typeof POLICY_FIELD_SCOPES)[number];

/** How sender identity reaches a field (P6). */
export const SENDER_IDENTITIES = ['raw', 'authenticated'] as const;
export type SenderIdentity = (typeof SENDER_IDENTITIES)[number];

export interface PolicyFieldDefinition {
  readonly type: PolicyFieldType;
  readonly ops: readonly PolicyOperator[];
  readonly scope: PolicyFieldScope;
  /** True for list-scoped fields (`quantifier` allowed; `all` required in exceptions). */
  readonly quantified: boolean;
  /** True for the sender identity fields exceptions and relaxing rules may use (P6). */
  readonly authenticatedIdentity: boolean;
  /** `raw` = spoofable sender identity (refused in exceptions and relaxing rules, P6). */
  readonly senderIdentity: SenderIdentity | null;
  /** True for AI-derived facts (no hold disposition, no exception, P9.8). */
  readonly aiDerived: boolean;
  /** Directions in which the fact can be known (else it evaluates to unknown or false). */
  readonly directions: readonly PolicyMessageDirection[];
  /** Closed value vocabulary of `enum` fields and of code sets with a fixed vocabulary. */
  readonly values: readonly string[] | null;
  /** True when `values` is ordered (weakest first) and gte/lte compare ranks. */
  readonly ordered: boolean;
  /** Inclusive integer bounds of `int` fields. */
  readonly min: number | null;
  readonly max: number | null;
  /** One-line description for the catalog and the DSL reference. */
  readonly description: string;
}

const ALL_DIRECTIONS = POLICY_MESSAGE_DIRECTIONS;
const STRING_OPS: readonly PolicyOperator[] = ['equals', 'in', 'not_in', 'glob', 'regex'];
const RAW_ADDRESS_OPS: readonly PolicyOperator[] = [...STRING_OPS, 'exists'];
const RAW_DOMAIN_OPS: readonly PolicyOperator[] = [
  'equals',
  'in',
  'not_in',
  'domain_in',
  'glob',
  'regex',
  'exists',
];
const NUMERIC_OPS: readonly PolicyOperator[] = ['eq', 'gt', 'gte', 'lt', 'lte', 'between'];
const ENUM_OPS: readonly PolicyOperator[] = ['equals', 'in'];
const ENUM_LIST_OPS: readonly PolicyOperator[] = ['equals', 'in', 'not_in'];
const ORDERED_OPS: readonly PolicyOperator[] = ['equals', 'in', 'gte', 'lte'];
const CODE_OPS: readonly PolicyOperator[] = ['contains_any', 'contains_all'];
const INT_MAX = Number.MAX_SAFE_INTEGER;

interface Spec {
  type: PolicyFieldType;
  ops: readonly PolicyOperator[];
  scope?: PolicyFieldScope;
  authenticatedIdentity?: boolean;
  senderIdentity?: SenderIdentity;
  aiDerived?: boolean;
  directions?: readonly PolicyMessageDirection[];
  values?: readonly string[];
  ordered?: boolean;
  min?: number;
  max?: number;
  description: string;
}

function field(spec: Spec): PolicyFieldDefinition {
  const scope = spec.scope ?? 'message';
  return Object.freeze({
    type: spec.type,
    ops: Object.freeze([...spec.ops]),
    scope,
    quantified: scope !== 'message',
    authenticatedIdentity: spec.authenticatedIdentity ?? false,
    senderIdentity: spec.senderIdentity ?? null,
    aiDerived: spec.aiDerived ?? false,
    directions: Object.freeze([...(spec.directions ?? ALL_DIRECTIONS)]),
    values: spec.values ? Object.freeze([...spec.values]) : null,
    ordered: spec.ordered ?? false,
    min: spec.type === 'int' ? (spec.min ?? 0) : null,
    max: spec.type === 'int' ? (spec.max ?? INT_MAX) : null,
    description: spec.description,
  });
}

const raw = { senderIdentity: 'raw' as const };
const authd = { authenticatedIdentity: true, senderIdentity: 'authenticated' as const };

/** The catalog (P3). Field names are stable; a removed or changed field is a new DSL version. */
export const POLICY_FIELDS = Object.freeze({
  direction: field({
    type: 'enum',
    ops: ENUM_OPS,
    values: POLICY_MESSAGE_DIRECTIONS,
    description: 'Message direction (prefer the rule `directions`).',
  }),
  'sender.envelope.address': field({
    type: 'address',
    ops: RAW_ADDRESS_OPS,
    ...raw,
    description: 'MAIL FROM address; raw, unauthenticated.',
  }),
  'sender.envelope.domain': field({
    type: 'domain',
    ops: RAW_DOMAIN_OPS,
    ...raw,
    description: 'MAIL FROM domain; raw, unauthenticated.',
  }),
  'sender.envelope.local_part': field({
    type: 'string',
    ops: RAW_ADDRESS_OPS,
    ...raw,
    description: 'MAIL FROM local part; raw, unauthenticated.',
  }),
  'sender.header_from.address': field({
    type: 'address',
    ops: RAW_ADDRESS_OPS,
    ...raw,
    description: 'Header From address; raw, unauthenticated.',
  }),
  'sender.header_from.domain': field({
    type: 'domain',
    ops: RAW_DOMAIN_OPS,
    ...raw,
    description: 'Header From domain; raw, unauthenticated.',
  }),
  'sender.authenticated.address': field({
    type: 'address',
    ops: ['equals', 'in', 'glob', 'exists'],
    ...authd,
    description:
      'Inbound: header From when DMARC passes and no authentication failure; outbound/internal: the organization-authenticated envelope sender; else unknown.',
  }),
  'sender.authenticated.domain': field({
    type: 'domain',
    ops: ['equals', 'in', 'domain_in', 'glob', 'exists'],
    ...authd,
    description: 'Domain of `sender.authenticated.address`.',
  }),
  'sender.trusted': field({
    type: 'bool',
    ops: ['is'],
    ...authd,
    directions: ['inbound'],
    description:
      'Inbound only: BEC trusted sender authenticated as From, DMARC pass, no authentication failure; false otherwise; unknown without bec or auth facts.',
  }),
  'sender.department': field({
    type: 'id',
    ops: ['in', 'not_in'],
    ...authd,
    directions: ['outbound', 'internal'],
    description: 'Departments of the authenticated sender (outbound/internal only).',
  }),
  'sender.user': field({
    type: 'id',
    ops: ['in', 'not_in'],
    ...authd,
    directions: ['outbound', 'internal'],
    description: 'Users matching the authenticated sender (outbound/internal only).',
  }),
  'recipient.address': field({
    type: 'address',
    ops: STRING_OPS,
    scope: 'recipients',
    description: 'Envelope recipient (trusted).',
  }),
  'recipient.domain': field({
    type: 'domain',
    ops: ['equals', 'in', 'not_in', 'domain_in', 'glob', 'regex'],
    scope: 'recipients',
    description: 'Envelope recipient domain.',
  }),
  'recipient.local_part': field({
    type: 'string',
    ops: STRING_OPS,
    scope: 'recipients',
    description: 'Envelope recipient local part.',
  }),
  'recipient.department': field({
    type: 'id',
    ops: ['in', 'not_in'],
    scope: 'recipients',
    description: 'Departments of the envelope recipient.',
  }),
  'recipient.user': field({
    type: 'id',
    ops: ['in', 'not_in'],
    scope: 'recipients',
    description: 'Users matching the envelope recipient.',
  }),
  'recipients.count': field({
    type: 'int',
    ops: NUMERIC_OPS,
    description: 'Number of envelope recipients.',
  }),
  'client.ip': field({
    type: 'ip',
    ops: ['equals', 'in_cidr'],
    description: 'Connecting client IP (XFORWARD ADDR); unknown when absent.',
  }),
  'client.hostname': field({
    type: 'domain',
    ops: ['equals', 'domain_in', 'glob'],
    description: 'Verified client host name (XFORWARD NAME); unknown when absent.',
  }),
  'auth.spf': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: AUTH_OUTCOMES,
    description: 'SPF result.',
  }),
  'auth.dkim': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: AUTH_OUTCOMES,
    description: 'DKIM result.',
  }),
  'auth.dmarc': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: AUTH_OUTCOMES,
    description: 'DMARC result.',
  }),
  'auth.arc': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: AUTH_OUTCOMES,
    description: 'ARC result.',
  }),
  'auth.dmarc_policy': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: DMARC_POLICIES,
    description: 'Published DMARC policy.',
  }),
  'message.size_bytes': field({ type: 'int', ops: NUMERIC_OPS, description: 'Message size.' }),
  'attachments.count': field({
    type: 'int',
    ops: NUMERIC_OPS,
    description: 'Number of attachments.',
  }),
  'attachments.total_bytes': field({
    type: 'int',
    ops: NUMERIC_OPS,
    description: 'Total decoded attachment bytes.',
  }),
  'attachments.truncated': field({
    type: 'bool',
    ops: ['is'],
    description: 'True when attachment facts were capped.',
  }),
  'attachment.extension': field({
    type: 'string',
    ops: ['equals', 'in', 'not_in'],
    scope: 'attachments',
    description: 'Lower-case extension of the sanitized filename, without the dot.',
  }),
  'attachment.filename': field({
    type: 'string',
    ops: ['glob', 'regex'],
    scope: 'attachments',
    description: 'Sanitized filename (never stored or echoed).',
  }),
  'attachment.declared_type': field({
    type: 'string',
    ops: ['equals', 'in', 'not_in', 'glob'],
    scope: 'attachments',
    description: 'Declared MIME type.',
  }),
  'attachment.detected_type': field({
    type: 'string',
    ops: ['equals', 'in', 'not_in', 'glob'],
    scope: 'attachments',
    description: 'Detected type (FILE_TYPES id) of the round.',
  }),
  'attachment.type_family': field({
    type: 'enum',
    ops: ENUM_LIST_OPS,
    scope: 'attachments',
    values: FILE_TYPE_FAMILIES,
    description: 'Detected type family of the round.',
  }),
  'attachment.size_bytes': field({
    type: 'int',
    ops: NUMERIC_OPS,
    scope: 'attachments',
    description: 'Decoded attachment size.',
  }),
  'attachment.sha256': field({
    type: 'string',
    ops: ['equals', 'in'],
    scope: 'attachments',
    description: 'Lower-case hex SHA-256 of the decoded bytes.',
  }),
  'attachment.verdict': field({
    type: 'enum',
    ops: ENUM_OPS,
    scope: 'attachments',
    values: ATTACHMENT_VERDICTS,
    description: 'Attachment verdict of the round; unknown without a result.',
  }),
  'attachment.reason_codes': field({
    type: 'codes',
    ops: CODE_OPS,
    scope: 'attachments',
    description: 'Attachment reason codes of the round.',
  }),
  'attachment.is_archive': field({
    type: 'bool',
    ops: ['is'],
    scope: 'attachments',
    description: 'True for archives.',
  }),
  'attachment.encrypted': field({
    type: 'bool',
    ops: ['is'],
    scope: 'attachments',
    description: 'True for encrypted archives.',
  }),
  'attachment.type_mismatch': field({
    type: 'bool',
    ops: ['is'],
    scope: 'attachments',
    description: 'Declared and detected types disagree; unknown without a result.',
  }),
  'urls.count': field({ type: 'int', ops: NUMERIC_OPS, description: 'Number of URLs.' }),
  'urls.truncated': field({
    type: 'bool',
    ops: ['is'],
    description: 'True when URL facts were capped.',
  }),
  'urls.rewrite_status': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: ['rewritten', 'skipped', 'none'],
    description: 'URL rewriting of the round (`none` = no rewrite record).',
  }),
  'url.host': field({
    type: 'domain',
    ops: ['equals', 'in', 'not_in', 'domain_in', 'glob'],
    scope: 'urls',
    description: 'URL host (ASCII).',
  }),
  'url.domain': field({
    type: 'domain',
    ops: ['equals', 'in', 'not_in', 'domain_in', 'glob'],
    scope: 'urls',
    description: 'Registrable domain of the URL host; unknown for IP hosts.',
  }),
  'url.scheme': field({
    type: 'enum',
    ops: ENUM_OPS,
    scope: 'urls',
    values: ['http', 'https'],
    description: 'URL scheme.',
  }),
  'url.host_kind': field({
    type: 'enum',
    ops: ENUM_OPS,
    scope: 'urls',
    values: URL_HOST_KINDS,
    description: 'Host kind.',
  }),
  'url.verdict': field({
    type: 'enum',
    ops: ENUM_OPS,
    scope: 'urls',
    values: URL_VERDICTS,
    description: 'URL verdict of the round; unknown without a result.',
  }),
  'url.reason_codes': field({
    type: 'codes',
    ops: CODE_OPS,
    scope: 'urls',
    description: 'URL reason codes of the round.',
  }),
  'risk.present': field({
    type: 'bool',
    ops: ['is'],
    description: 'A revision-0 risk row exists.',
  }),
  'risk.score': field({
    type: 'int',
    ops: NUMERIC_OPS,
    max: 1000,
    description: 'Risk score (maximum over revisions).',
  }),
  'risk.level': field({
    type: 'enum',
    ops: ORDERED_OPS,
    values: RISK_LEVELS,
    ordered: true,
    description: 'Risk level (maximum over revisions).',
  }),
  'risk.verdict': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: RISK_VERDICTS,
    description: 'Verdict of the decisive revision.',
  }),
  'risk.recommended_action': field({
    type: 'enum',
    ops: ORDERED_OPS,
    values: RISK_ACTIONS,
    ordered: true,
    description: 'Recommended action (maximum over revisions).',
  }),
  'risk.hard_blocks': field({
    type: 'codes',
    ops: ['contains_any', 'contains_all', 'exists'],
    values: RISK_HARD_BLOCK_IDS,
    description: 'Fired hard-block ids (union over revisions).',
  }),
  'risk.reason_codes': field({
    type: 'codes',
    ops: CODE_OPS,
    description: 'Risk reason codes (union over revisions).',
  }),
  'risk.status': field({
    type: 'enum',
    ops: ['equals'],
    values: ['scored', 'error'],
    description: 'Risk status (worst over revisions).',
  }),
  'risk.sandbox_outcome': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: SANDBOX_INPUT_OUTCOMES,
    description: 'Sandbox outcome of revision 1; unknown without it.',
  }),
  'dlp.present': field({ type: 'bool', ops: ['is'], description: 'A DLP result row exists.' }),
  'dlp.action': field({
    type: 'enum',
    ops: ORDERED_OPS,
    values: DLP_ACTIONS,
    ordered: true,
    description: 'Effective DLP action.',
  }),
  'dlp.verdict': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: DLP_VERDICTS,
    description: 'DLP verdict.',
  }),
  'dlp.coverage': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: DLP_COVERAGES,
    description: 'DLP coverage.',
  }),
  'dlp.max_severity': field({
    type: 'enum',
    ops: ORDERED_OPS,
    values: DLP_SEVERITIES,
    ordered: true,
    description: 'Highest finding severity; unknown without findings.',
  }),
  'dlp.categories': field({
    type: 'codes',
    ops: CODE_OPS,
    values: DLP_CATEGORIES,
    description: 'Matched DLP categories.',
  }),
  'dlp.detector_codes': field({
    type: 'codes',
    ops: CODE_OPS,
    description: 'Reason codes of the DLP final.',
  }),
  'bec.deterministic_verdict': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: BEC_VERDICTS,
    description: 'Deterministic BEC verdict.',
  }),
  'bec.rule_codes': field({
    type: 'codes',
    ops: CODE_OPS,
    description: 'Active (unsuppressed) deterministic BEC rule codes.',
  }),
  'bec.verdict': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: BEC_VERDICTS,
    aiDerived: true,
    description: 'BEC verdict including the AI layer (AI-derived).',
  }),
  'bec.ai_raised': field({
    type: 'bool',
    ops: ['is'],
    aiDerived: true,
    description: 'The AI layer raised the BEC verdict (AI-derived).',
  }),
  'scan.outcome': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: ['scanned', 'scan_failed', 'not_scanned'],
    description: 'Round outcome (`not_scanned` = parse failure).',
  }),
  'scan.verdict': field({
    type: 'enum',
    ops: ENUM_OPS,
    values: SCAN_VERDICTS,
    description: 'Round verdict.',
  }),
  'scan.reason_codes': field({
    type: 'codes',
    ops: CODE_OPS,
    description: 'Round reason codes.',
  }),
  'scan.failed_engines': field({
    type: 'codes',
    ops: ['contains_any', 'exists'],
    values: ENGINE_NAMES,
    description: 'Engines that timed out, failed or are missing.',
  }),
  'scan.unknown_engines': field({
    type: 'codes',
    ops: ['contains_any', 'exists'],
    values: ENGINE_NAMES,
    description: 'Engines with an `unknown` outcome.',
  }),
  'time.window': field({
    type: 'time',
    ops: ['within'],
    description: 'Weekly local-time window in an IANA time zone.',
  }),
  'time.date_range': field({
    type: 'time',
    ops: ['within'],
    description: 'Inclusive local date range in an IANA time zone.',
  }),
} satisfies Record<string, PolicyFieldDefinition>);

export type PolicyFieldName = keyof typeof POLICY_FIELDS;
export const POLICY_FIELD_NAMES = Object.freeze(Object.keys(POLICY_FIELDS)) as readonly [
  PolicyFieldName,
  ...PolicyFieldName[],
];

export const isPolicyField = (name: unknown): name is PolicyFieldName =>
  typeof name === 'string' && Object.prototype.hasOwnProperty.call(POLICY_FIELDS, name);

export const policyField = (name: PolicyFieldName): PolicyFieldDefinition => POLICY_FIELDS[name];

/** Fields whose ids reference the tenant directory (P5). */
export const DIRECTORY_FIELDS = Object.freeze({
  'sender.department': 'department',
  'recipient.department': 'department',
  'sender.user': 'user',
  'recipient.user': 'user',
} as const);
