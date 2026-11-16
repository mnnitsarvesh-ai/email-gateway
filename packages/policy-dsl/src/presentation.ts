import { RISK_REASON_CODES } from '@email-gateway/risk-scoring';
import {
  ATTACHMENT_REASON_CODES,
  BEC_RULE_IDS,
  BEC_RULES,
  DLP_DETECTOR_CODES,
  DLP_REASON_CODES,
  BEC_REASON_CODES,
  RSPAMD_REASON_CODES,
  URL_REASON_CODES,
} from '@email-gateway/security-contracts';
import {
  NEGATED_OPERATORS,
  POLICY_FIELDS,
  type PolicyFieldDefinition,
  type PolicyFieldName,
  type PolicyFieldScope,
  type PolicyOperator,
} from './fields';
import { isValidTimeZone } from './time';
import {
  ALERT_SEVERITIES,
  DISPOSITION_OF_ACTION,
  isDispositionAction,
  POLICY_HOLD_DISPOSITIONS,
  POLICY_LIMITS,
  URL_REWRITE_FALLBACKS,
  WARN_LEVELS,
  type PolicyActionType,
  type PolicyDisposition,
} from './vocabulary';

/**
 * Presentation metadata of `policy-dsl/1` (step 7.3 §4.1, docs/plan/steps/22-policy-builder.md;
 * ADR-0063 decision 1): human labels, groups, units and code suggestions of the fields, the value
 * shape and wording of every operator, the parameter definitions of every action, the quantifier
 * phrases, scope nouns and placement rules. Data next to the catalogue it describes, so a visual
 * builder renders every field, operator and action without hard-coding any of them. The api merges
 * it into `GET /policies/catalog`; the validator, the compiler and the evaluator never read it.
 * `presentation.test.ts` proves completeness and agreement with `validatePolicyDefinition`.
 */

// ---------------------------------------------------------------------------------------------
// Field groups, units and contexts
// ---------------------------------------------------------------------------------------------

export const POLICY_FIELD_GROUP_IDS = [
  'message',
  'sender',
  'recipient',
  'connection',
  'authentication',
  'attachments',
  'urls',
  'risk',
  'dlp',
  'bec',
  'scan',
  'time',
] as const;
export type PolicyFieldGroupId = (typeof POLICY_FIELD_GROUP_IDS)[number];

export interface PolicyFieldGroup {
  readonly id: PolicyFieldGroupId;
  readonly label: string;
}

/** The field groups in display order. */
export const POLICY_FIELD_GROUPS: readonly PolicyFieldGroup[] = Object.freeze(
  (
    [
      ['message', 'Message'],
      ['sender', 'Sender'],
      ['recipient', 'Recipients'],
      ['connection', 'Connection'],
      ['authentication', 'Authentication'],
      ['attachments', 'Attachments'],
      ['urls', 'Links'],
      ['risk', 'Risk'],
      ['dlp', 'Data loss prevention'],
      ['bec', 'Business email compromise'],
      ['scan', 'Scan results'],
      ['time', 'Time'],
    ] as const
  ).map(([id, label]) => Object.freeze({ id, label })),
);

/** Units of `int` fields (a builder converts bytes to KiB/MiB for display only). */
export const POLICY_FIELD_UNITS = ['bytes', 'count', 'score'] as const;
export type PolicyFieldUnit = (typeof POLICY_FIELD_UNITS)[number];

export interface PolicyFieldPresentation {
  /** Plain-English label (unique, 1..64 characters, never the code name). */
  readonly label: string;
  readonly group: PolicyFieldGroupId;
  /** Unit of an `int` field; null for every other type. */
  readonly unit: PolicyFieldUnit | null;
  /**
   * Known codes for autocomplete of an open `codes` field (one without a closed `values` list);
   * never a closed list: any code of the reason-code shape is accepted. Null otherwise.
   */
  readonly suggestions: readonly string[] | null;
}

/**
 * Where a field may be used (P6, P9.8): every field in a `when`; in exceptions (rule `unless`
 * and policy `exceptions`) only authenticated, non-AI fields; in the `when` of ALLOW and override
 * rules only fields that are not raw sender identity; in rules that hold mail (REQUIRE_APPROVAL,
 * QUARANTINE, REJECT) no AI-derived field.
 */
export interface PolicyFieldContexts {
  readonly when: true;
  readonly exception: boolean;
  readonly relaxingWhen: boolean;
  readonly holdRule: boolean;
}

export function fieldContexts(
  def: Pick<PolicyFieldDefinition, 'senderIdentity' | 'aiDerived'>,
): PolicyFieldContexts {
  return Object.freeze({
    when: true as const,
    exception: def.senderIdentity !== 'raw' && !def.aiDerived,
    relaxingWhen: def.senderIdentity !== 'raw',
    holdRule: !def.aiDerived,
  });
}

// ---------------------------------------------------------------------------------------------
// Code suggestions (open `codes` fields)
// ---------------------------------------------------------------------------------------------

const sortedUnique = (...lists: ReadonlyArray<readonly string[]>): readonly string[] =>
  Object.freeze([...new Set(lists.flat())].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));

/**
 * The suggestion lists. Every one is an exported vocabulary of the engine that writes the fact:
 *
 * - `attachment.reason_codes`: `ATTACHMENT_REASON_CODES`; `url.reason_codes`: `URL_REASON_CODES`;
 *   `dlp.detector_codes`: `DLP_DETECTOR_CODES` (security-contracts);
 * - `bec.rule_codes`: the codes of the BEC rule table `BEC_RULES` (P1 … S1): the deterministic
 *   codes of `BEC_REASON_CODES` without the AI codes, the input-unavailable codes and the two
 *   engine-level codes `bec.not_inbound` and `clean.below_threshold`, which a `bec_rules` row
 *   never carries (`becRuleEntrySchema` binds every row's code to its rule id);
 * - `scan.reason_codes`: the union of the reason-code lists of the synchronous engines whose
 *   finals the round aggregates (Rspamd, attachment, URL, BEC, DLP; the asynchronous sandbox
 *   never contributes to the round's codes);
 * - `risk.reason_codes`: `RISK_REASON_CODES` of `@email-gateway/risk-scoring` (every `risk.*`
 *   code the scorer emits).
 *
 * Engine failure codes of a round (`engine.timeout`, …) are not exported lists and stay typeable
 * (suggestions are never a closed list).
 */
const SUGGESTIONS: Readonly<Partial<Record<PolicyFieldName, readonly string[]>>> = Object.freeze({
  'attachment.reason_codes': sortedUnique(ATTACHMENT_REASON_CODES),
  'url.reason_codes': sortedUnique(URL_REASON_CODES),
  'dlp.detector_codes': sortedUnique(DLP_DETECTOR_CODES),
  'bec.rule_codes': sortedUnique(BEC_RULE_IDS.map((id) => BEC_RULES[id].code)),
  'scan.reason_codes': sortedUnique(
    RSPAMD_REASON_CODES,
    ATTACHMENT_REASON_CODES,
    URL_REASON_CODES,
    BEC_REASON_CODES,
    DLP_REASON_CODES,
  ),
  'risk.reason_codes': sortedUnique(RISK_REASON_CODES),
});

// ---------------------------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------------------------

/** Group of a field by its name (P3 prefixes). */
function groupOf(name: PolicyFieldName): PolicyFieldGroupId {
  if (name === 'direction' || name.startsWith('message.')) return 'message';
  if (name.startsWith('sender.')) return 'sender';
  if (name.startsWith('recipient.') || name === 'recipients.count') return 'recipient';
  if (name.startsWith('client.')) return 'connection';
  if (name.startsWith('auth.')) return 'authentication';
  if (name.startsWith('attachments.') || name.startsWith('attachment.')) return 'attachments';
  if (name.startsWith('urls.') || name.startsWith('url.')) return 'urls';
  if (name.startsWith('risk.')) return 'risk';
  if (name.startsWith('dlp.')) return 'dlp';
  if (name.startsWith('bec.')) return 'bec';
  if (name.startsWith('scan.')) return 'scan';
  if (name.startsWith('time.')) return 'time';
  throw new Error(`policy field without a presentation group: ${name}`);
}

const UNITS: Readonly<Partial<Record<PolicyFieldName, PolicyFieldUnit>>> = Object.freeze({
  'message.size_bytes': 'bytes',
  'attachments.total_bytes': 'bytes',
  'attachment.size_bytes': 'bytes',
  'recipients.count': 'count',
  'attachments.count': 'count',
  'urls.count': 'count',
  'risk.score': 'score',
});

/** Plain-English labels (raw sender identity says so; AI-derived facts say so). */
const LABELS: Readonly<Record<PolicyFieldName, string>> = Object.freeze({
  direction: 'Email direction',
  'sender.envelope.address': 'Envelope sender address (unauthenticated)',
  'sender.envelope.domain': 'Envelope sender domain (unauthenticated)',
  'sender.envelope.local_part': 'Envelope sender local part (unauthenticated)',
  'sender.header_from.address': 'From header address (unauthenticated)',
  'sender.header_from.domain': 'From header domain (unauthenticated)',
  'sender.authenticated.address': 'Authenticated sender address',
  'sender.authenticated.domain': 'Authenticated sender domain',
  'sender.trusted': 'Trusted sender',
  'sender.department': 'Sender department',
  'sender.user': 'Sender user',
  'recipient.address': 'Recipient address',
  'recipient.domain': 'Recipient domain',
  'recipient.local_part': 'Recipient local part',
  'recipient.department': 'Recipient department',
  'recipient.user': 'Recipient user',
  'recipients.count': 'Number of recipients',
  'client.ip': 'Connecting client IP address',
  'client.hostname': 'Connecting client host name',
  'auth.spf': 'SPF result',
  'auth.dkim': 'DKIM result',
  'auth.dmarc': 'DMARC result',
  'auth.arc': 'ARC result',
  'auth.dmarc_policy': 'Published DMARC policy',
  'message.size_bytes': 'Message size',
  'attachments.count': 'Number of attachments',
  'attachments.total_bytes': 'Total attachment size',
  'attachments.truncated': 'Attachment list truncated',
  'attachment.extension': 'Attachment file extension',
  'attachment.filename': 'Attachment file name',
  'attachment.declared_type': 'Attachment declared content type',
  'attachment.detected_type': 'Attachment detected file type',
  'attachment.type_family': 'Attachment file type family',
  'attachment.size_bytes': 'Attachment size',
  'attachment.sha256': 'Attachment SHA-256 hash',
  'attachment.verdict': 'Attachment verdict',
  'attachment.reason_codes': 'Attachment reason codes',
  'attachment.is_archive': 'Attachment is an archive',
  'attachment.encrypted': 'Attachment is an encrypted archive',
  'attachment.type_mismatch': 'Attachment type mismatch',
  'urls.count': 'Number of links',
  'urls.truncated': 'Link list truncated',
  'urls.rewrite_status': 'Link rewriting status',
  'url.host': 'Link host',
  'url.domain': 'Link registrable domain',
  'url.scheme': 'Link scheme',
  'url.host_kind': 'Link host kind',
  'url.verdict': 'Link verdict',
  'url.reason_codes': 'Link reason codes',
  'risk.present': 'Risk score available',
  'risk.score': 'Risk score',
  'risk.level': 'Risk level',
  'risk.verdict': 'Risk verdict',
  'risk.recommended_action': 'Recommended action',
  'risk.hard_blocks': 'Hard blocks fired',
  'risk.reason_codes': 'Risk reason codes',
  'risk.status': 'Risk scoring status',
  'risk.sandbox_outcome': 'Sandbox outcome',
  'dlp.present': 'DLP result available',
  'dlp.action': 'DLP action',
  'dlp.verdict': 'DLP verdict',
  'dlp.coverage': 'DLP coverage',
  'dlp.max_severity': 'Highest DLP finding severity',
  'dlp.categories': 'DLP data categories',
  'dlp.detector_codes': 'DLP detector codes',
  'bec.deterministic_verdict': 'BEC verdict (rules only)',
  'bec.rule_codes': 'BEC rule codes',
  'bec.verdict': 'BEC verdict including AI (AI-derived)',
  'bec.ai_raised': 'Raised by the BEC AI layer (AI-derived)',
  'scan.outcome': 'Scan outcome',
  'scan.verdict': 'Scan verdict',
  'scan.reason_codes': 'Scan reason codes',
  'scan.failed_engines': 'Failed scan engines',
  'scan.unknown_engines': 'Scan engines with unknown results',
  'time.window': 'Weekly time window',
  'time.date_range': 'Date range',
});

function presentationOf(name: PolicyFieldName): PolicyFieldPresentation {
  const def = POLICY_FIELDS[name];
  const open = def.type === 'codes' && def.values === null;
  return Object.freeze({
    label: LABELS[name],
    group: groupOf(name),
    unit: def.type === 'int' ? (UNITS[name] ?? null) : null,
    suggestions: open ? (SUGGESTIONS[name] ?? null) : null,
  });
}

/** Label, group, unit and suggestions of every field of `POLICY_FIELDS`. */
export const POLICY_FIELD_PRESENTATION: Readonly<Record<PolicyFieldName, PolicyFieldPresentation>> =
  Object.freeze(
    Object.fromEntries(
      (Object.keys(POLICY_FIELDS) as PolicyFieldName[]).map((name) => [name, presentationOf(name)]),
    ) as Record<PolicyFieldName, PolicyFieldPresentation>,
  );

// ---------------------------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------------------------

/**
 * Value shapes: `scalar` (one value of the field type), `list` (1..`maxItems` items of
 * `itemKind`), `range` (`[low, high]` integers), `none` (no value), `boolean` (`true`/`false`),
 * `time` (`{ timeZone, days, from, to }` for `time.window`, `{ timeZone, from, to }` for
 * `time.date_range`).
 */
export const POLICY_VALUE_SHAPES = ['scalar', 'list', 'range', 'none', 'boolean', 'time'] as const;
export type PolicyValueShape = (typeof POLICY_VALUE_SHAPES)[number];

/**
 * Item kinds: `field` (a value of the field's type and vocabulary), `domain` (a domain matched
 * with its subdomains), `glob` (`*`/`?` pattern), `regex` (an RE2 pattern string or
 * `{ pattern, flags: '' | 'i' }`), `cidr` (`address/prefix`), `code` (a reason code; the field's
 * vocabulary when it has one).
 */
export const POLICY_ITEM_KINDS = ['field', 'domain', 'glob', 'regex', 'cidr', 'code'] as const;
export type PolicyItemKind = (typeof POLICY_ITEM_KINDS)[number];

export interface PolicyOperatorPresentation {
  readonly label: string;
  /** Lower-case verb phrase of the readable summary (`<field> <phrase> <values>`). */
  readonly phrase: string;
  readonly valueShape: PolicyValueShape;
  readonly itemKind: PolicyItemKind | null;
  readonly maxItems: number | null;
  readonly maxItemLength: number | null;
  readonly negated: boolean;
  /** Exceptions are positive (P6): every operator but the negated one. */
  readonly allowedInException: boolean;
  readonly description: string;
}

type OperatorSpec = Omit<PolicyOperatorPresentation, 'negated' | 'allowedInException'>;

const OPERATOR_SPECS: Readonly<Record<PolicyOperator, OperatorSpec>> = {
  equals: {
    label: 'is',
    phrase: 'is',
    valueShape: 'scalar',
    itemKind: 'field',
    maxItems: null,
    maxItemLength: null,
    description: 'The fact equals the value (addresses and domains compared normalized).',
  },
  in: {
    label: 'is one of',
    phrase: 'is one of',
    valueShape: 'list',
    itemKind: 'field',
    maxItems: POLICY_LIMITS.listValues,
    maxItemLength: POLICY_LIMITS.stringValue,
    description: 'The fact equals one of the listed values.',
  },
  not_in: {
    label: 'is not one of',
    phrase: 'is not one of',
    valueShape: 'list',
    itemKind: 'field',
    maxItems: POLICY_LIMITS.listValues,
    maxItemLength: POLICY_LIMITS.stringValue,
    description:
      'The fact is known and equals none of the listed values (unknown facts never match). Not allowed in exceptions.',
  },
  domain_in: {
    label: 'is in domain',
    phrase: 'is in or under the domains',
    valueShape: 'list',
    itemKind: 'domain',
    maxItems: POLICY_LIMITS.listValues,
    maxItemLength: POLICY_LIMITS.stringValue,
    description: 'The domain equals a listed domain or is one of its subdomains.',
  },
  glob: {
    label: 'matches pattern',
    phrase: 'matches the patterns',
    valueShape: 'list',
    itemKind: 'glob',
    maxItems: POLICY_LIMITS.globs,
    maxItemLength: POLICY_LIMITS.globLength,
    description:
      'The fact matches one of the glob patterns (`*` any characters, `?` one character).',
  },
  regex: {
    label: 'matches regular expression',
    phrase: 'matches the regular expressions',
    valueShape: 'list',
    itemKind: 'regex',
    maxItems: POLICY_LIMITS.regexes,
    maxItemLength: POLICY_LIMITS.regexLength,
    description:
      'The fact matches one of the RE2 regular expressions (a pattern, or { pattern, flags: "i" } for case-insensitive); validated by the server.',
  },
  in_cidr: {
    label: 'is in network',
    phrase: 'is in the networks',
    valueShape: 'list',
    itemKind: 'cidr',
    maxItems: POLICY_LIMITS.cidrs,
    maxItemLength: null,
    description: 'The IP address is inside one of the networks (canonical address/prefix CIDRs).',
  },
  eq: {
    label: '=',
    phrase: 'equals',
    valueShape: 'scalar',
    itemKind: 'field',
    maxItems: null,
    maxItemLength: null,
    description: 'The number equals the value.',
  },
  gt: {
    label: '>',
    phrase: 'is greater than',
    valueShape: 'scalar',
    itemKind: 'field',
    maxItems: null,
    maxItemLength: null,
    description: 'The number is greater than the value.',
  },
  gte: {
    label: '≥',
    phrase: 'is at least',
    valueShape: 'scalar',
    itemKind: 'field',
    maxItems: null,
    maxItemLength: null,
    description:
      'The number is at least the value; for ordered vocabularies the rank is at least the value’s rank.',
  },
  lt: {
    label: '<',
    phrase: 'is less than',
    valueShape: 'scalar',
    itemKind: 'field',
    maxItems: null,
    maxItemLength: null,
    description: 'The number is less than the value.',
  },
  lte: {
    label: '≤',
    phrase: 'is at most',
    valueShape: 'scalar',
    itemKind: 'field',
    maxItems: null,
    maxItemLength: null,
    description:
      'The number is at most the value; for ordered vocabularies the rank is at most the value’s rank.',
  },
  between: {
    label: 'between',
    phrase: 'is between',
    valueShape: 'range',
    itemKind: 'field',
    maxItems: null,
    maxItemLength: null,
    description: 'The number is between low and high, both included ([low, high], low ≤ high).',
  },
  contains_any: {
    label: 'contains any of',
    phrase: 'contain any of',
    valueShape: 'list',
    itemKind: 'code',
    maxItems: POLICY_LIMITS.codes,
    maxItemLength: null,
    description: 'The set of codes contains at least one of the listed codes.',
  },
  contains_all: {
    label: 'contains all of',
    phrase: 'contain all of',
    valueShape: 'list',
    itemKind: 'code',
    maxItems: POLICY_LIMITS.codes,
    maxItemLength: null,
    description: 'The set of codes contains every listed code.',
  },
  exists: {
    label: 'is present',
    phrase: 'is present',
    valueShape: 'none',
    itemKind: null,
    maxItems: null,
    maxItemLength: null,
    description: 'The fact is known (for code sets: the set is not empty). Takes no value.',
  },
  is: {
    label: 'is',
    phrase: 'is',
    valueShape: 'boolean',
    itemKind: null,
    maxItems: null,
    maxItemLength: null,
    description: 'The yes/no fact is true or false.',
  },
  within: {
    label: 'is within',
    phrase: 'is within',
    valueShape: 'time',
    itemKind: null,
    maxItems: null,
    maxItemLength: null,
    description:
      'The evaluation time is inside the weekly window (time.window: days, from–to local time) or the inclusive date range (time.date_range) in an IANA time zone.',
  },
};

/** Label, phrase, value shape and limits of every operator. */
export const POLICY_OPERATOR_PRESENTATION: Readonly<
  Record<PolicyOperator, PolicyOperatorPresentation>
> = Object.freeze(
  Object.fromEntries(
    (Object.entries(OPERATOR_SPECS) as Array<[PolicyOperator, OperatorSpec]>).map(([op, spec]) => {
      const negated = NEGATED_OPERATORS.includes(op);
      return [op, Object.freeze({ ...spec, negated, allowedInException: !negated })];
    }),
  ) as Record<PolicyOperator, PolicyOperatorPresentation>,
);

// ---------------------------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------------------------

export const POLICY_ACTION_KINDS = ['disposition', 'non_terminal'] as const;
export type PolicyActionKind = (typeof POLICY_ACTION_KINDS)[number];

export const POLICY_ACTION_PARAM_TYPES = ['enum', 'string', 'boolean'] as const;
export type PolicyActionParamType = (typeof POLICY_ACTION_PARAM_TYPES)[number];

export interface PolicyActionParam {
  readonly name: string;
  readonly label: string;
  readonly type: PolicyActionParamType;
  readonly required: boolean;
  /** Allowed values of an `enum` parameter. */
  readonly values: readonly string[] | null;
  /** The value the evaluator uses when the parameter is absent (null = none or a setting). */
  readonly default: string | boolean | null;
  readonly minLength: number | null;
  readonly maxLength: number | null;
  /** A JavaScript/RE2-compatible pattern a valid string matches (the server still validates). */
  readonly pattern: string | null;
  readonly description: string;
}

export interface PolicyActionPresentation {
  readonly label: string;
  /** Lower-case verb phrase of the readable summary. */
  readonly phrase: string;
  readonly kind: PolicyActionKind;
  readonly disposition: PolicyDisposition | null;
  readonly params: readonly PolicyActionParam[];
  readonly description: string;
}

const param = (
  spec: Pick<PolicyActionParam, 'name' | 'label' | 'type' | 'description'> &
    Partial<Omit<PolicyActionParam, 'name' | 'label' | 'type' | 'description'>>,
): PolicyActionParam =>
  Object.freeze({
    name: spec.name,
    label: spec.label,
    type: spec.type,
    required: spec.required ?? false,
    values: spec.values ? Object.freeze([...spec.values]) : null,
    default: spec.default ?? null,
    minLength: spec.minLength ?? null,
    maxLength: spec.maxLength ?? null,
    pattern: spec.pattern ?? null,
    description: spec.description,
  });

/** `^[a-z0-9][a-z0-9._-]{0,31}$` with the class hyphen escaped (valid with the `u`/`v` flags). */
const TAG_LABEL_PATTERN = '^[a-z0-9][a-z0-9._\\-]{0,31}$';
/** Printable ASCII without `:` (header-safe subject prefix). */
const SUBJECT_PREFIX_PATTERN = '^[\\x20-\\x39\\x3B-\\x7E]{1,32}$';
/** Printable ASCII (header-safe warning text). */
const HEADER_TEXT_PATTERN = '^[\\x20-\\x7E]{1,128}$';

const subjectPrefix = (what: string): PolicyActionParam =>
  param({
    name: 'subjectPrefix',
    label: 'Subject prefix',
    type: 'string',
    minLength: 1,
    maxLength: 32,
    pattern: SUBJECT_PREFIX_PATTERN,
    description: `Text put before the subject of the delivered copy ${what} (printable ASCII, 1–32 characters, no colon).`,
  });

const ACTION_SPECS: Readonly<
  Record<PolicyActionType, Omit<PolicyActionPresentation, 'kind' | 'disposition'>>
> = {
  ALLOW: {
    label: 'Allow',
    phrase: 'allow',
    params: [],
    description:
      'Deliver the message. Enforced, but never below the platform strictness floor (hard blocks, failures and missing data still hold the message); in an override rule it may relax the platform recommendation only when the organization allows overrides.',
  },
  REQUIRE_APPROVAL: {
    label: 'Require approval',
    phrase: 'require approval',
    params: [],
    description:
      'Hold the message until an administrator approves it. Enforced: a quarantine entry awaiting approval (step 5.3).',
  },
  QUARANTINE: {
    label: 'Quarantine',
    phrase: 'quarantine',
    params: [],
    description: 'Hold the message in quarantine. Enforced: a quarantine entry (step 5.3).',
  },
  REJECT: {
    label: 'Reject',
    phrase: 'reject',
    params: [
      param({
        name: 'notifySender',
        label: 'Notify the sender',
        type: 'boolean',
        description:
          'Send the sender a non-delivery notice when an outbound or internal message is rejected (never for inbound mail); absent = the organization setting notices.senderNonDelivery. The notice is requested and mailed by the notification-worker.',
      }),
    ],
    description:
      'Do not deliver the message. Enforced: the message (or, with per-recipient evaluation, the recipient) is not delivered.',
  },
  TAG: {
    label: 'Tag',
    phrase: 'tag',
    params: [
      param({
        name: 'label',
        label: 'Tag label',
        type: 'string',
        required: true,
        minLength: 1,
        maxLength: 32,
        pattern: TAG_LABEL_PATTERN,
        description:
          'The tag written to the X-EG-Policy-Tag header (lower-case letters, digits, dot, underscore and hyphen; starts with a letter or digit; 1–32 characters).',
      }),
      subjectPrefix('of a tagged message'),
      param({
        name: 'addHeader',
        label: 'Add the tag header',
        type: 'boolean',
        default: true,
        description: 'Write the X-EG-Policy-Tag header (default true).',
      }),
    ],
    description:
      'Mark the delivered copy with the X-EG-Policy-Tag header and an optional subject prefix. Enforced in the delivered copy when the message is delivered and a policy copy can be made; recorded otherwise.',
  },
  WARN: {
    label: 'Warn recipients',
    phrase: 'warn recipients',
    params: [
      param({
        name: 'level',
        label: 'Warning level',
        type: 'enum',
        required: true,
        values: WARN_LEVELS,
        description: 'Severity of the warning, weakest first: caution, warning, danger.',
      }),
      param({
        name: 'text',
        label: 'Warning text',
        type: 'string',
        minLength: 1,
        maxLength: 128,
        pattern: HEADER_TEXT_PATTERN,
        description:
          'Text of the body banner (absent = the platform template of the level), also added after the level in the X-EG-Policy-Warning header (printable ASCII, 1–128 characters).',
      }),
      subjectPrefix('of a warned message'),
    ],
    description:
      'Warn the recipients with the X-EG-Policy-Warning header, an optional subject prefix and a body banner in the delivered copy. Applied after the scan when the message allows it; signed, encrypted or oversized messages record a skipped outcome instead.',
  },
  URL_REWRITE: {
    label: 'Require URL rewriting',
    phrase: 'require URL rewriting',
    params: [
      param({
        name: 'ifNotRewritten',
        label: 'If the links were not rewritten',
        type: 'enum',
        values: URL_REWRITE_FALLBACKS,
        default: 'deliver',
        description:
          'What happens when the links of the round could not be rewritten: deliver anyway (default) or quarantine.',
      }),
    ],
    description:
      'Deliver the copy with protected (rewritten) links. Applied after the scan when the message allows it; when the links cannot be rewritten the fallback applies.',
  },
  ARCHIVE: {
    label: 'Archive',
    phrase: 'archive',
    params: [],
    description: 'Request an archive copy of the message. Requested only: archiving is step 8.1.',
  },
  ALERT: {
    label: 'Alert administrators',
    phrase: 'alert administrators',
    params: [
      param({
        name: 'severity',
        label: 'Severity',
        type: 'enum',
        required: true,
        values: ALERT_SEVERITIES,
        description: 'Severity of the alert, weakest first: info, warning, critical.',
      }),
    ],
    description:
      'Request an alert to the organization’s administrators. Requested: the notification-worker mails it to the holders of policy:publish while the organization’s policy alerts are enabled (alerts.enabled); recorded otherwise.',
  },
};

/** Label, phrase, kind and parameter definitions of every action. */
export const POLICY_ACTION_PRESENTATION: Readonly<
  Record<PolicyActionType, PolicyActionPresentation>
> = Object.freeze(
  Object.fromEntries(
    (
      Object.entries(ACTION_SPECS) as Array<
        [PolicyActionType, Omit<PolicyActionPresentation, 'kind' | 'disposition'>]
      >
    ).map(([type, spec]) => {
      const disposition = isDispositionAction(type) ? DISPOSITION_OF_ACTION[type] : null;
      return [
        type,
        Object.freeze({
          ...spec,
          params: Object.freeze([...spec.params]),
          kind: disposition === null ? 'non_terminal' : 'disposition',
          disposition,
        }),
      ];
    }),
  ) as Record<PolicyActionType, PolicyActionPresentation>,
);

// ---------------------------------------------------------------------------------------------
// Quantifiers, scope nouns, placement rules, time zones
// ---------------------------------------------------------------------------------------------

export interface PolicyQuantifierPresentation {
  readonly id: 'any' | 'all';
  readonly label: string;
  readonly phrase: string;
}

/** `any` (at least one list element) and `all` (every element; required in exceptions). */
export const POLICY_QUANTIFIER_PRESENTATION: readonly PolicyQuantifierPresentation[] =
  Object.freeze([
    Object.freeze({ id: 'any', label: 'any', phrase: 'Any' }),
    Object.freeze({ id: 'all', label: 'every', phrase: 'Every' }),
  ]);

/** The noun of one element of a list-scoped field (`Every recipient: …`). */
export const POLICY_SCOPE_NOUNS: Readonly<Record<Exclude<PolicyFieldScope, 'message'>, string>> =
  Object.freeze({ recipients: 'recipient', attachments: 'attachment', urls: 'link' });

export interface PolicyContextRules {
  /** Quantifier the evaluator applies to a list-scoped condition without one. */
  readonly defaultQuantifier: 'any' | 'all';
  /** The only quantifier exceptions accept on list-scoped conditions (P6). */
  readonly exceptionQuantifier: 'any' | 'all';
  /** Exceptions accept neither `not` nor negated operators (P6). */
  readonly exceptionNegation: boolean;
  /**
   * Dispositions whose rules relax: their `when` sees no raw sender identity (P6). A rule with
   * `override: true` relaxes whatever its disposition.
   */
  readonly relaxingDispositions: readonly PolicyDisposition[];
  /** Dispositions that hold mail (their rules read no AI-derived field, P9.8). */
  readonly holdDispositions: readonly PolicyDisposition[];
}

export const POLICY_CONTEXT_RULES: PolicyContextRules = Object.freeze({
  defaultQuantifier: 'any',
  exceptionQuantifier: 'all',
  exceptionNegation: false,
  relaxingDispositions: Object.freeze(['allow'] as PolicyDisposition[]),
  holdDispositions: Object.freeze([...POLICY_HOLD_DISPOSITIONS]),
});

/**
 * The IANA time zones of this runtime for `time.window` and `time.date_range`: sorted, unique
 * `Intl.supportedValuesOf('timeZone')` plus `UTC`, each accepted by `isValidTimeZone` (the list
 * depends on the Node ICU build; aliases the runtime resolves are accepted too).
 */
export function policyTimeZones(): string[] {
  return [...new Set([...Intl.supportedValuesOf('timeZone'), 'UTC'])]
    .filter((zone) => isValidTimeZone(zone))
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
