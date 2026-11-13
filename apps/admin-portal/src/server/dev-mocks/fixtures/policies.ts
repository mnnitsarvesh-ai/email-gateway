import 'server-only';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { fixtureAnchor, stableUuid } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandler,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { fixtures as attachmentFixtures } from './attachments';
import { FIXTURE_MESSAGES, fixtureGuard, guarded } from './messages';
import { fixtures as settingsFixtures } from './settings';
import { fixtures as urlProtectionFixtures } from './url-protection';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the policy pages (WP5, read-only in 7.1): email policies with versions and DSL
 * definitions, the execution history (derived from the message fixtures' evaluations), policy
 * settings, the risk profile and its versions, the DSL catalogue, DLP and BEC lists. Scan settings
 * are owned by the Settings fixtures (WP3); a read-only list is provided here only when no other
 * fixture file defines it. Everything is synthetic.
 */

type Policy = SuccessBody<'PolicyManagementController_get_v1'>;
type PolicyRow = ListItem<'PolicyManagementController_list_v1'>;
type Version = SuccessBody<'PolicyManagementController_getVersion_v1'>;
type Execution = ListItem<'PolicyToolsController_history_v1'>;

const anchor = fixtureAnchor();
const DAY = 86_400_000;
const iso = (offsetDays: number) => new Date(anchor - offsetDays * DAY).toISOString();
const sha = (seed: string) =>
  Array.from({ length: 2 }, (_, i) => stableUuid(`${seed}:${i}`).replace(/-/g, ''))
    .join('')
    .slice(0, 64);
const ADMIN = stableUuid('user:organization_admin');

interface PolicySeed {
  readonly key: string;
  readonly name: string;
  readonly description: string | null;
  readonly status: Policy['status'];
  readonly direction: Policy['direction'];
  readonly priority: number;
  readonly versions: number;
  readonly active: number | null;
  readonly definition: Record<string, unknown>;
}

const SEEDS: readonly PolicySeed[] = [
  {
    key: 'inbound-threats',
    name: 'Inbound threats',
    description: 'Quarantine high-risk inbound mail; approval for BEC suspicions.',
    status: 'active',
    direction: 'inbound',
    priority: 10,
    versions: 3,
    active: 3,
    definition: {
      dslVersion: 'policy-dsl/1',
      direction: 'inbound',
      priority: 10,
      rules: [
        {
          id: 'block-high-risk',
          priority: 10,
          description: 'High and critical risk is quarantined',
          when: { field: 'risk.level', op: 'in', value: ['high', 'critical'] },
          actions: [{ type: 'QUARANTINE' }],
        },
        {
          id: 'bec-review',
          priority: 20,
          when: { field: 'verdict.final', op: 'equals', value: 'bec' },
          actions: [{ type: 'REQUIRE_APPROVAL' }, { type: 'ALERT', severity: 'warning' }],
        },
      ],
    },
  },
  {
    key: 'exec-impersonation',
    name: 'Executive impersonation warning',
    description: 'Warn when mail claims to come from executives but fails DMARC.',
    status: 'active',
    direction: 'inbound',
    priority: 30,
    versions: 2,
    active: 2,
    definition: {
      dslVersion: 'policy-dsl/1',
      direction: 'inbound',
      priority: 30,
      rules: [
        {
          id: 'exec-impersonation',
          priority: 10,
          when: {
            all: [
              { field: 'sender.header_from.address', op: 'in', value: ['ceo@alpha.example.test'] },
              { field: 'auth.dmarc', op: 'in', value: ['fail', 'none'] },
            ],
          },
          actions: [
            { type: 'WARN', level: 'danger', text: 'Possible executive impersonation <script>' },
          ],
        },
      ],
    },
  },
  {
    key: 'outbound-cards',
    name: 'Outbound card numbers need approval',
    description: null,
    status: 'active',
    direction: 'outbound',
    priority: 40,
    versions: 1,
    active: 1,
    definition: {
      dslVersion: 'policy-dsl/1',
      direction: 'outbound',
      priority: 40,
      rules: [
        {
          id: 'cards-external',
          priority: 10,
          when: { field: 'dlp.categories', op: 'contains_any', value: ['payment_card'] },
          actions: [{ type: 'REQUIRE_APPROVAL' }],
        },
      ],
    },
  },
  {
    key: 'partner-allow',
    name: 'Partner newsletters',
    description: 'Allow authenticated partner mail over level-only recommendations.',
    status: 'disabled',
    direction: 'inbound',
    priority: 50,
    versions: 2,
    active: 2,
    definition: {
      dslVersion: 'policy-dsl/1',
      direction: 'inbound',
      priority: 50,
      rules: [
        {
          id: 'partner-allow',
          priority: 10,
          when: {
            field: 'sender.authenticated.domain',
            op: 'domain_in',
            value: ['partner.example.test'],
          },
          actions: [{ type: 'ALLOW' }],
          override: true,
        },
      ],
    },
  },
  {
    key: 'internal-archive',
    name: 'Archive internal finance mail',
    description: 'Draft for the archive rollout (step 8.1).',
    status: 'draft',
    direction: 'internal',
    priority: 60,
    versions: 1,
    active: null,
    definition: { dslVersion: 'policy-dsl/1', direction: 'internal', priority: 60, rules: [] },
  },
  {
    key: 'any-attachments',
    name: 'Risky attachments everywhere',
    description: 'Tag executables in any direction.',
    status: 'active',
    direction: 'any',
    priority: 70,
    versions: 4,
    active: 4,
    definition: {
      dslVersion: 'policy-dsl/1',
      direction: 'any',
      priority: 70,
      rules: [
        {
          id: 'tag-executables',
          priority: 10,
          when: {
            field: 'attachments.type_family',
            op: 'in',
            value: ['executable', 'script'],
            quantifier: 'any',
          },
          actions: [{ type: 'TAG', value: 'risky-attachment' }],
        },
      ],
    },
  },
];

function policyOf(seed: PolicySeed, index: number): Policy {
  const id = stableUuid(`policy:${seed.key}`);
  return {
    id,
    name: seed.name,
    description: seed.description,
    status: seed.status,
    direction: seed.direction,
    priority: seed.priority,
    activeVersionNo: seed.active,
    latestVersionNo: seed.versions,
    rowVersion: seed.versions + 1,
    createdByUserId: ADMIN,
    updatedByUserId: ADMIN,
    createdAt: iso(120 - index * 3),
    updatedAt: iso(10 - index),
    activeVersion: seed.active
      ? {
          versionNo: seed.active,
          definitionSha256: sha(`${seed.key}:${seed.active}`),
          ruleCount: (seed.definition.rules as unknown[]).length,
          hasOverrideRules: seed.key === 'partner-allow',
          publishedAt: iso(12 - index),
        }
      : null,
    counts: {
      drafts: seed.active === null ? 1 : 0,
      published: seed.active === null ? 0 : 1,
      superseded: Math.max(0, seed.versions - 1),
      limit: 50,
    },
  };
}

function versionOf(seed: PolicySeed, versionNo: number): Version {
  const policyId = stableUuid(`policy:${seed.key}`);
  const status: Version['status'] =
    seed.active === null ? 'draft' : versionNo === seed.active ? 'published' : 'superseded';
  const rules = seed.definition.rules as unknown[];
  return {
    policyId,
    versionNo,
    status,
    active: versionNo === seed.active,
    dslVersion: 'policy-dsl/1',
    definitionSha256: sha(`${seed.key}:${versionNo}`),
    ruleCount: rules.length,
    hasOverrideRules: seed.key === 'partner-allow',
    references: null,
    changeNote: versionNo === 1 ? 'Initial version' : `Tuned thresholds (v${versionNo})`,
    rowVersion: 1,
    createdByUserId: ADMIN,
    updatedByUserId: ADMIN,
    publishedByUserId: status === 'draft' ? null : ADMIN,
    publishedAt: status === 'draft' ? null : iso(40 - versionNo * 5),
    createdAt: iso(45 - versionNo * 5),
    updatedAt: iso(41 - versionNo * 5),
    definition: {
      ...seed.definition,
      priority: (seed.definition.priority as number) + versionNo - 1,
    },
    validation:
      seed.key === 'exec-impersonation' && versionNo === 1
        ? {
            valid: false,
            violations: [
              { path: 'rules[0].when', code: 'field_unknown', message: 'The field was renamed' },
            ],
          }
        : { valid: true, violations: [] },
  };
}

const POLICIES = SEEDS.map(policyOf);
const BY_ID = new Map(
  SEEDS.map((seed, i) => [stableUuid(`policy:${seed.key}`), { seed, policy: POLICIES[i] }]),
);

function rowOf(policy: Policy): PolicyRow {
  const { activeVersion, counts, ...row } = policy;
  void activeVersion;
  void counts;
  return row;
}

function v0Page<T>(
  items: readonly T[],
  query: URLSearchParams,
): { data: T[]; nextCursor: string | null } {
  const limit = Math.min(100, Math.max(1, Number(query.get('limit') ?? '25') || 25));
  const cursor = query.get('cursor');
  const offset = cursor ? Number(Buffer.from(cursor, 'base64url').toString('utf8')) || 0 : 0;
  return {
    data: items.slice(offset, offset + limit),
    nextCursor:
      offset + limit < items.length
        ? Buffer.from(String(offset + limit)).toString('base64url')
        : null,
  };
}

const EXECUTIONS: Execution[] = FIXTURE_MESSAGES.flatMap((m) =>
  m.evaluations.map((e): Execution => ({
    messageId: m.detail.id,
    receivedAt: m.detail.receivedAt,
    lifecycleRound: e.lifecycleRound,
    scanId: e.round.scanId,
    trigger: e.trigger,
    direction: e.direction,
    disposition: e.disposition,
    finalAction: e.finalAction,
    decisive: {
      source: e.decisive.source,
      policyId: e.decisive.policyPublicId ? stableUuid('policy:inbound-threats') : null,
      versionNo: e.decisive.versionNo,
      ruleId: e.decisive.ruleId,
    },
    actions: e.actions.map((a, i) => ({ type: a.type, status: e.actionStatuses[i] ?? 'recorded' })),
    matchedRuleCount: e.matchedRules.length,
    overrideApplied: e.override !== null,
    generation: e.versions.generation,
    inputSha256: e.inputSha256,
    durationUs: e.durationUs,
    evaluatedAt: e.evaluatedAt,
  })),
).sort((a, b) => b.evaluatedAt.localeCompare(a.evaluatedAt));

function executions(request: FixtureRequest): FixtureResponse {
  const q = request.query;
  const from = Date.parse(q.get('from') ?? '');
  const to = Date.parse(q.get('to') ?? '');
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
    return apiError(400, 'validation_failed', ['from: required', 'to: required']);
  }
  if (to - from > 31 * DAY)
    return apiError(400, 'validation_failed', ['to: the range is at most 31 days']);
  const eq = (name: string, value: string | null) => !q.get(name) || q.get(name) === value;
  const rows = EXECUTIONS.filter((row) => {
    const t = Date.parse(row.evaluatedAt);
    return (
      t >= from &&
      t < to &&
      eq('direction', row.direction) &&
      eq('disposition', row.disposition) &&
      eq('source', row.decisive.source) &&
      eq('trigger', row.trigger) &&
      eq('policyId', row.decisive.policyId) &&
      eq('ruleId', row.decisive.ruleId) &&
      eq('overrideApplied', String(row.overrideApplied))
    );
  });
  return ok('PolicyToolsController_history_v1', v0Page(rows, q));
}

type Field = SuccessBody<'PolicyToolsController_catalog_v1'>['fields'][number];
const ALL_DIRECTIONS: Field['directions'] = ['inbound', 'outbound', 'internal'];
function field(
  name: string,
  type: Field['type'],
  scope: Field['scope'],
  ops: Field['ops'],
  description: string,
  extra: Partial<Field> = {},
): Field {
  return {
    name,
    type,
    scope,
    ops,
    quantified: scope !== 'message',
    authenticatedIdentity: false,
    senderIdentity: null,
    aiDerived: false,
    directions: ALL_DIRECTIONS,
    values: null,
    ordered: false,
    min: null,
    max: null,
    description,
    ...extra,
  };
}

const CATALOG: SuccessBody<'PolicyToolsController_catalog_v1'> = {
  versions: { dsl: 'policy-dsl/1', input: 'policy-input/1', evaluator: 'policy-eval/2' },
  platformDefault: {
    id: 'platform-default/1',
    description: 'Follow the risk recommendation within the strictness floor.',
  },
  fields: [
    field('direction', 'enum', 'message', ['equals', 'in', 'not_in'], 'Direction of the message.', {
      values: ['inbound', 'outbound', 'internal'],
    }),
    field(
      'sender.envelope.address',
      'address',
      'message',
      ['equals', 'in', 'not_in', 'glob', 'regex'],
      'Envelope sender (MAIL FROM), raw.',
      { senderIdentity: 'raw' },
    ),
    field(
      'sender.envelope.domain',
      'domain',
      'message',
      ['equals', 'in', 'not_in', 'domain_in'],
      'Domain of the envelope sender, raw.',
      { senderIdentity: 'raw' },
    ),
    field(
      'sender.header_from.address',
      'address',
      'message',
      ['equals', 'in', 'not_in', 'glob', 'regex'],
      'Header From address, raw (spoofable).',
      { senderIdentity: 'raw' },
    ),
    field(
      'sender.authenticated.domain',
      'domain',
      'message',
      ['equals', 'in', 'domain_in'],
      'Sender domain proven by DMARC alignment.',
      { senderIdentity: 'authenticated', authenticatedIdentity: true },
    ),
    field(
      'sender.trusted',
      'bool',
      'message',
      ['is'],
      'Sender is on the tenant trusted-sender list.',
    ),
    field(
      'recipient.address',
      'address',
      'recipients',
      ['equals', 'in', 'not_in', 'glob'],
      'Each recipient address.',
    ),
    field(
      'recipient.department',
      'id',
      'recipients',
      ['in', 'not_in'],
      'Departments of each recipient (tenant directory).',
    ),
    field('auth.spf', 'enum', 'message', ['equals', 'in', 'not_in'], 'SPF result.', {
      values: ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'],
    }),
    field('auth.dmarc', 'enum', 'message', ['equals', 'in', 'not_in'], 'DMARC result.', {
      values: ['pass', 'fail', 'none', 'temperror', 'permerror'],
    }),
    field('client.ip', 'ip', 'message', ['in_cidr'], 'IP address of the connecting client.', {
      directions: ['inbound'],
    }),
    field(
      'risk.score',
      'int',
      'message',
      ['eq', 'gt', 'gte', 'lt', 'lte', 'between'],
      'Risk score of the round (0–1000).',
      { min: 0, max: 1000 },
    ),
    field('risk.level', 'enum', 'message', ['equals', 'in', 'not_in'], 'Risk level of the round.', {
      values: ['none', 'low', 'medium', 'high', 'critical'],
      ordered: true,
    }),
    field(
      'verdict.final',
      'enum',
      'message',
      ['equals', 'in', 'not_in'],
      'Aggregate verdict of the scan.',
      {
        values: [
          'clean',
          'spam',
          'bulk',
          'phishing',
          'malware',
          'bec',
          'dlp_violation',
          'suspicious',
          'unknown',
        ],
      },
    ),
    field(
      'reason_codes',
      'codes',
      'message',
      ['contains_any', 'contains_all'],
      'Reason codes of every engine.',
    ),
    field(
      'attachments.count',
      'int',
      'message',
      ['eq', 'gt', 'gte', 'lt', 'lte'],
      'Number of attachments.',
      { min: 0, max: 1000 },
    ),
    field(
      'attachments.type_family',
      'enum',
      'attachments',
      ['in', 'not_in'],
      'Detected type family of each attachment.',
      {
        values: [
          'document',
          'archive',
          'executable',
          'script',
          'disk_image',
          'image',
          'markup',
          'text',
          'other',
        ],
      },
    ),
    field(
      'attachments.filename',
      'string',
      'attachments',
      ['glob', 'regex'],
      'Sanitized filename of each attachment (sender-chosen).',
    ),
    field('urls.verdict', 'enum', 'urls', ['in', 'not_in'], 'Verdict of each URL.', {
      values: ['clean', 'suspicious', 'malicious', 'unknown'],
    }),
    field('urls.host', 'domain', 'urls', ['domain_in', 'glob'], 'Host of each URL.'),
    field(
      'dlp.categories',
      'codes',
      'message',
      ['contains_any', 'contains_all'],
      'DLP categories found.',
    ),
    field('bec.ai_label', 'enum', 'message', ['in'], 'Label of the AI layer (raise-only).', {
      aiDerived: true,
      values: ['benign', 'impersonation', 'payment_fraud'],
    }),
    field('received_at', 'time', 'message', ['within'], 'Receipt time in the tenant time zone.'),
  ],
  operators: [
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
  ],
  actions: [
    'ALLOW',
    'REJECT',
    'QUARANTINE',
    'TAG',
    'WARN',
    'REQUIRE_APPROVAL',
    'URL_REWRITE',
    'ARCHIVE',
    'ALERT',
  ],
  nonTerminalActions: ['TAG', 'WARN', 'URL_REWRITE', 'ARCHIVE', 'ALERT'],
  dispositions: ['allow', 'require_approval', 'quarantine', 'reject'],
  limits: {
    maxPolicies: 50,
    maxVersionsPerPolicy: 50,
    maxActiveRules: 500,
    maxRulesPerPolicy: 100,
    maxConditionDepth: 8,
  },
  settingsDefaults: {
    allowRecommendationOverrides: false,
    recipientSplit: true,
    notices: { senderNonDelivery: true },
    alerts: { enabled: true },
    tagging: { platformTagHeader: true, platformTagOutbound: false },
  },
  enforcement:
    'Dispositions are enforced; ARCHIVE and ALERT are requested; WARN and URL_REWRITE apply to the delivered copy when possible.',
};

const RISK_PROFILE: SuccessBody<'RiskProfilesController_profile_v1'> = {
  id: stableUuid('risk-profile'),
  profileVersion: 3,
  platformProfile: 'rsk-default/1',
  active: {
    source: 'tenant',
    versionId: stableUuid('risk-version:2'),
    versionNo: 2,
    profileId: `rsk-default/1+t:${stableUuid('risk-version:2')}#2`,
    sha256: sha('risk:2'),
    fallback: null,
    violations: [],
  },
  effectiveProfile: {
    base: 'rsk-default/1',
    thresholds: { low: 150, medium: 300, high: 600, critical: 800 },
    actions: {
      none: 'deliver',
      low: 'deliver',
      medium: 'tag',
      high: 'quarantine',
      critical: 'block',
    },
    groupMultipliersPermille: {
      auth_dmarc: 1000,
      auth_other: 1000,
      spam: 1000,
      reputation_ip: 1000,
      reputation_domain: 1000,
      url_threat: 1200,
      lookalike: 1000,
      credential: 1000,
      url_structure: 1000,
      phishing_content: 1000,
      attachment_malware: 1000,
      attachment_risky: 1000,
      bec_impersonation: 1100,
      bec_identity: 1000,
      bec_intent: 1000,
      bec_history: 1000,
      dlp: 1000,
      coverage: 1000,
      engine_failure: 1000,
      engine_unknown: 1000,
      sandbox: 1000,
    },
    hardBlocks: {
      'hb.malware_attachment': { enabled: true, action: 'block' },
      'hb.malware_url': { enabled: true, action: 'block' },
      'hb.malware_sandbox': { enabled: true, action: 'quarantine' },
      'hb.dlp_block': { enabled: true, action: 'block' },
      'hb.known_phishing': { enabled: true, action: 'quarantine' },
      'hb.tenant_domain_spoof': { enabled: true, action: 'quarantine' },
      'hb.url_tenant_blocked': { enabled: true, action: 'quarantine' },
      'hb.bec_malicious': { enabled: true, action: 'require_approval' },
      'hb.dmarc_reject': { enabled: false, action: 'quarantine' },
    },
    failures: {
      engineFailureWeight: 200,
      groupCap: 400,
      unknownWeight: 100,
      minLevel: 'medium',
      unknownMinLevel: 'low',
      action: 'quarantine',
      unknownAction: 'tag',
    },
    floors: { engineMalicious: 'high', becSuspicious: 'medium' },
    trust: { mode: 'reduce_content', contentFactorPermille: 500 },
    ai: { tagOnAiOnlyRaise: true },
  },
  counts: { drafts: 1, published: 2, limit: 20 },
  updatedByUserId: ADMIN,
  updatedAt: iso(9),
};

const RISK_VERSIONS: ListItem<'RiskProfilesController_listVersions_v1'>[] = [3, 2, 1].map((n) => ({
  id: stableUuid(`risk-version:${n}`),
  versionNo: n,
  status: n === 3 ? 'draft' : 'published',
  baseProfile: 'rsk-default/1',
  overridesSha256: sha(`risk-overrides:${n}`),
  profileSha256: n === 3 ? null : sha(`risk:${n}`),
  changeNote:
    n === 3
      ? 'Raise URL threat weight further'
      : n === 2
        ? 'URL threat weight 1.2'
        : 'Initial tenant profile',
  rowVersion: 1,
  active: n === 2,
  createdByUserId: ADMIN,
  updatedByUserId: ADMIN,
  publishedByUserId: n === 3 ? null : ADMIN,
  publishedAt: n === 3 ? null : iso(30 - n * 10),
  createdAt: iso(35 - n * 10),
  updatedAt: iso(31 - n * 10),
}));

const POLICY_SETTINGS: SuccessBody<'PolicySettingsController_get_v1'> = {
  settings: { allowRecommendationOverrides: true },
  effective: {
    allowRecommendationOverrides: true,
    recipientSplit: true,
    notices: { senderNonDelivery: true },
    alerts: { enabled: true },
    tagging: { platformTagHeader: true, platformTagOutbound: false },
  },
  violations: [],
  generation: '42',
  rowVersion: 3,
  settingsSha256: sha('policy-settings'),
  updatedByUserId: ADMIN,
  updatedAt: iso(14),
};

const dlpBase = (key: string, i: number) => ({
  id: stableUuid(`dlp:${key}:${i}`),
  version: 1,
  createdByUserId: ADMIN,
  updatedByUserId: ADMIN,
  createdAt: iso(60 - i),
  updatedAt: iso(20 - i),
});

const DLP_POLICIES: ListItem<'DlpPoliciesController_list_v1'>[] = [
  {
    ...dlpBase('policy', 1),
    name: 'Payment cards outbound',
    description: 'Block card numbers leaving the company',
    enabled: true,
    mode: 'enforce',
    priority: 10,
    directions: ['outbound'],
    ruleCount: 2,
  },
  {
    ...dlpBase('policy', 2),
    name: 'Source code monitoring',
    description: null,
    enabled: true,
    mode: 'monitor',
    priority: 20,
    directions: ['outbound', 'internal'],
    ruleCount: 1,
  },
  {
    ...dlpBase('policy', 3),
    name: 'Legacy PII rule',
    description: 'Kept for reference',
    enabled: false,
    mode: 'monitor',
    priority: 30,
    directions: ['outbound'],
    ruleCount: 3,
  },
];
const DLP_PATTERNS: ListItem<'DlpPatternsController_list_v1'>[] = [
  {
    ...dlpBase('pattern', 1),
    name: 'Employee ID',
    pattern: 'EMP-[0-9]{6}',
    caseInsensitive: true,
    validator: 'none',
    contextKeywords: ['employee'],
    requireContext: false,
    severity: 'medium',
    baseConfidence: 0.7,
    maskStyle: 'last4',
    enabled: true,
  },
  {
    ...dlpBase('pattern', 2),
    name: 'Project codename <b>',
    pattern: '(?i)project\\s+(falcon|heron)',
    caseInsensitive: true,
    validator: 'none',
    contextKeywords: [],
    requireContext: true,
    severity: 'high',
    baseConfidence: 0.6,
    maskStyle: 'full',
    enabled: true,
  },
];
const DLP_DICTIONARIES: ListItem<'DlpDictionariesController_list_v1'>[] = [
  {
    ...dlpBase('dictionary', 1),
    name: 'Confidential project names',
    category: 'confidential',
    termCount: 24,
    severity: 'high',
    baseConfidence: 0.8,
    minMatches: 1,
    enabled: true,
  },
];
const DLP_EXCEPTIONS: ListItem<'DlpExceptionsController_list_v1'>[] = [
  {
    ...dlpBase('exception', 1),
    scope: 'recipient_domain',
    value: 'auditor.example.test',
    policyId: DLP_POLICIES[0]?.id ?? null,
    ruleId: null,
    filters: { categories: ['payment_card'] },
    reason: 'External auditors receive statements',
    expiresAt: new Date(anchor + 60 * DAY).toISOString(),
    expired: false,
    enabled: true,
  },
  {
    ...dlpBase('exception', 2),
    scope: 'sender_address',
    value: 'payroll@alpha.example.test',
    policyId: null,
    ruleId: null,
    filters: null,
    reason: 'Payroll run',
    expiresAt: iso(3),
    expired: true,
    enabled: true,
  },
];
const DLP_INCIDENTS: ListItem<'DlpIncidentsController_list_v1'>[] = FIXTURE_MESSAGES.filter(
  (m) => m.detail.direction === 'outbound',
)
  .slice(0, 12)
  .map((m, i) => ({
    messageId: m.detail.id,
    scanId: m.rounds[0]?.scanId ?? '0',
    lifecycleRound: 0,
    receivedAt: m.detail.receivedAt,
    direction: 'outbound',
    verdict: 'suspicious',
    action: i % 3 === 0 ? 'block' : 'alert',
    actionSource: 'tenant_policy',
    coverage: 'complete',
    findingCount: 1 + (i % 4),
    categories: [
      {
        category: i % 2 === 0 ? 'payment_card' : 'personal_info',
        count: 1 + (i % 4),
        maxSeverity: 'high',
        maxConfidence: 0.92,
      },
    ],
    findings: [
      {
        detector: i % 2 === 0 ? 'PC1' : 'PI1',
        code: i % 2 === 0 ? 'dlp.payment_card' : 'dlp.personal_info',
        category: i % 2 === 0 ? 'payment_card' : 'personal_info',
        severity: 'high',
        count: 1 + (i % 4),
        capped: false,
      },
    ],
    policy: {
      winner: {
        policyId: DLP_POLICIES[0]?.id ?? stableUuid('dlp:policy:1'),
        ruleId: stableUuid('dlp:rule:1'),
      },
      matched: [],
      exceptionsApplied: [],
    },
    detectedAt: new Date(Date.parse(m.detail.receivedAt) + 3_000).toISOString(),
  }));
const DLP_COMPLIANCE: SuccessBody<'DlpComplianceController_get_v1'> = {
  aadhaar: {
    enabled: false,
    active: false,
    basis: null,
    reference: null,
    attested: false,
    recordedByUserId: null,
    recordedAt: null,
    reviewDueAt: null,
  },
  version: 0,
  updatedAt: null,
};

const becBase = (key: string, i: number) => ({
  id: stableUuid(`bec:${key}:${i}`),
  createdByUserId: ADMIN,
  createdAt: iso(50 - i),
});
const EXECUTIVES: ListItem<'BecExecutivesController_list_v1'>[] = [
  {
    ...becBase('exec', 1),
    displayName: 'Dana Whitfield',
    normalizedName: 'dana whitfield',
    aliases: ['D. Whitfield'],
    knownAddresses: ['ceo@alpha.example.test'],
    title: 'Chief Executive Officer',
    enabled: true,
    updatedByUserId: ADMIN,
    version: 2,
    updatedAt: iso(5),
  },
  {
    ...becBase('exec', 2),
    displayName: 'Ravi Kumar',
    normalizedName: 'ravi kumar',
    aliases: [],
    knownAddresses: ['cfo@alpha.example.test'],
    title: 'CFO',
    enabled: true,
    updatedByUserId: ADMIN,
    version: 1,
    updatedAt: iso(40),
  },
];
const VENDORS: ListItem<'BecVendorsController_list_v1'>[] = [
  {
    ...becBase('vendor', 1),
    name: 'Bravo Logistics',
    normalizedName: 'bravo logistics',
    aliases: [],
    domains: ['bravo.example.test'],
    knownSenders: ['billing@bravo.example.test'],
    paymentChangeSensitive: true,
    enabled: true,
    updatedByUserId: ADMIN,
    version: 1,
    updatedAt: iso(30),
  },
];
const TRUSTED: ListItem<'BecTrustedSendersController_list_v1'>[] = [
  {
    ...becBase('trusted', 1),
    kind: 'domain',
    value: 'partner.example.test',
    reason: 'Long-standing partner',
    expiresAt: null,
    expired: false,
    version: 1,
    updatedAt: iso(20),
  },
  {
    ...becBase('trusted', 2),
    kind: 'address',
    value: 'board<b>@example.test',
    reason: 'Board secretary',
    expiresAt: iso(1),
    expired: true,
    version: 1,
    updatedAt: iso(25),
  },
];
const FEEDBACK: ListItem<'BecFeedbackController_list_v1'>[] = FIXTURE_MESSAGES.filter(
  (m) => m.detail.finalVerdict === 'bec',
)
  .slice(0, 6)
  .map((m, i) => ({
    ...becBase('feedback', i),
    kind: i % 2 === 0 ? 'false_positive' : 'false_negative',
    messageId: m.detail.id,
    scanId: m.rounds[0]?.scanId ?? '0',
    reasonCodes: ['bec.exec_impersonation'],
    note: i === 0 ? 'Known vendor <script>' : null,
  }));
const SUPPRESSIONS: ListItem<'BecFeedbackController_listSuppressions_v1'>[] = [
  {
    ...becBase('suppression', 1),
    reasonCode: 'bec.exec_impersonation',
    senderScope: 'domain',
    senderValue: 'partner.example.test',
    expiresAt: new Date(anchor + 30 * DAY).toISOString(),
    expired: false,
    feedbackId: FEEDBACK[0]?.id ?? null,
  },
];

function filtered<T>(
  items: readonly T[],
  request: FixtureRequest,
  predicate: (item: T, q: URLSearchParams) => boolean,
) {
  return v0Page(
    items.filter((item) => predicate(item, request.query)),
    request.query,
  );
}
const flag = (q: URLSearchParams, name: string, value: boolean) =>
  !q.get(name) || q.get(name) === String(value);

function withPolicy(
  handler: (seed: PolicySeed, policy: Policy, request: FixtureRequest) => FixtureResponse,
): FixtureHandler {
  return guarded((request) => {
    const found = BY_ID.get(request.params.policyId ?? '');
    if (!found?.policy) return apiError(404, 'policy_not_found', 'Policy not found');
    return handler(found.seed, found.policy, request);
  });
}

/** Read-only scan settings, used only when no other fixture file (Settings, WP3) defines them. */
const SCAN_SETTINGS: SuccessBody<'ScanSettingsController_list_v1'> = {
  note: 'Tenant overrides apply to the next scan round; platform bounds always win.',
  data: [
    {
      engine: 'rspamd',
      platform: {
        spamScore: 6,
        suspiciousScore: 4,
        scoreMin: 1,
        scoreMax: 20,
        phishingVerdict: 'malicious',
        dmarcRejectVerdict: 'suspicious',
        authFailureVerdict: 'reason_only',
      },
      bounds: {
        spamScore: { min: 3, max: 15 },
        suspiciousScore: { min: 2, max: 12 },
        phishingVerdict: ['suspicious', 'malicious'],
        dmarcRejectVerdict: ['suspicious', 'malicious'],
        authFailureVerdict: ['reason_only', 'suspicious'],
      },
      override: { spamScore: 7 },
      effective: {
        spamScore: 7,
        suspiciousScore: 4,
        phishingVerdict: 'malicious',
        dmarcRejectVerdict: 'suspicious',
        authFailureVerdict: 'reason_only',
      },
      required: true,
      tenantMayDisable: false,
      overrideApplied: true,
      violations: [],
      version: 2,
      updatedAt: iso(15),
    },
  ],
};

const scanSettingsOwned =
  'ScanSettingsController_list_v1' in settingsFixtures ||
  'ScanSettingsController_list_v1' in urlProtectionFixtures ||
  'ScanSettingsController_list_v1' in attachmentFixtures;

export const fixtures: FixtureHandlers = {
  PolicyManagementController_list_v1: guarded((request) => {
    const q = request.query;
    const rows = POLICIES.filter(
      (p) =>
        (!q.get('status') || q.get('status') === p.status) &&
        (!q.get('direction') || q.get('direction') === p.direction),
    ).map(rowOf);
    return ok('PolicyManagementController_list_v1', { ...v0Page(rows, q), generation: '42' });
  }),
  PolicyManagementController_get_v1: withPolicy((_seed, policy) =>
    ok('PolicyManagementController_get_v1', policy),
  ),
  PolicyManagementController_listVersions_v1: withPolicy((seed, _policy, request) => {
    const status = request.query.get('status');
    const versions = Array.from({ length: seed.versions }, (_, i) =>
      versionOf(seed, seed.versions - i),
    )
      .filter((v) => !status || v.status === status)
      .map((version) => {
        const { definition, validation, ...row } = version;
        void definition;
        void validation;
        return row;
      });
    return ok('PolicyManagementController_listVersions_v1', v0Page(versions, request.query));
  }),
  PolicyManagementController_getVersion_v1: withPolicy((seed, _policy, request) => {
    const versionNo = Number(request.params.versionNo);
    if (!Number.isInteger(versionNo) || versionNo < 1 || versionNo > seed.versions) {
      return apiError(404, 'policy_version_not_found', 'Policy version not found');
    }
    return ok('PolicyManagementController_getVersion_v1', versionOf(seed, versionNo));
  }),
  PolicyToolsController_history_v1: guarded(executions),
  PolicyToolsController_catalog_v1: guarded(() => ok('PolicyToolsController_catalog_v1', CATALOG)),
  PolicySettingsController_get_v1: guarded(() =>
    ok('PolicySettingsController_get_v1', POLICY_SETTINGS),
  ),
  RiskProfilesController_profile_v1: guarded(() =>
    ok('RiskProfilesController_profile_v1', RISK_PROFILE),
  ),
  RiskProfilesController_listVersions_v1: guarded((request) =>
    ok(
      'RiskProfilesController_listVersions_v1',
      filtered(RISK_VERSIONS, request, (v, q) => !q.get('status') || q.get('status') === v.status),
    ),
  ),
  DlpPoliciesController_list_v1: guarded((request) =>
    ok(
      'DlpPoliciesController_list_v1',
      filtered(DLP_POLICIES, request, (p, q) => flag(q, 'enabled', p.enabled)),
    ),
  ),
  DlpPatternsController_list_v1: guarded((request) =>
    ok(
      'DlpPatternsController_list_v1',
      filtered(DLP_PATTERNS, request, (p, q) => flag(q, 'enabled', p.enabled)),
    ),
  ),
  DlpDictionariesController_list_v1: guarded((request) =>
    ok(
      'DlpDictionariesController_list_v1',
      filtered(DLP_DICTIONARIES, request, (p, q) => flag(q, 'enabled', p.enabled)),
    ),
  ),
  DlpExceptionsController_list_v1: guarded((request) =>
    ok(
      'DlpExceptionsController_list_v1',
      filtered(
        DLP_EXCEPTIONS,
        request,
        (e, q) => (!q.get('scope') || q.get('scope') === e.scope) && flag(q, 'active', !e.expired),
      ),
    ),
  ),
  DlpIncidentsController_list_v1: guarded((request) =>
    ok(
      'DlpIncidentsController_list_v1',
      filtered(
        DLP_INCIDENTS,
        request,
        (i, q) =>
          (!q.get('action') || q.get('action') === i.action) &&
          (!q.get('direction') || q.get('direction') === i.direction),
      ),
    ),
  ),
  DlpComplianceController_get_v1: guarded(() =>
    ok('DlpComplianceController_get_v1', DLP_COMPLIANCE),
  ),
  BecExecutivesController_list_v1: guarded((request) =>
    ok(
      'BecExecutivesController_list_v1',
      filtered(EXECUTIVES, request, (e, q) => flag(q, 'enabled', e.enabled)),
    ),
  ),
  BecVendorsController_list_v1: guarded((request) =>
    ok(
      'BecVendorsController_list_v1',
      filtered(VENDORS, request, (v, q) => flag(q, 'enabled', v.enabled)),
    ),
  ),
  BecTrustedSendersController_list_v1: guarded((request) =>
    ok(
      'BecTrustedSendersController_list_v1',
      filtered(TRUSTED, request, (t, q) => !q.get('kind') || q.get('kind') === t.kind),
    ),
  ),
  BecFeedbackController_list_v1: guarded((request) =>
    ok(
      'BecFeedbackController_list_v1',
      filtered(FEEDBACK, request, (f, q) => !q.get('kind') || q.get('kind') === f.kind),
    ),
  ),
  BecFeedbackController_listSuppressions_v1: guarded((request) =>
    ok(
      'BecFeedbackController_listSuppressions_v1',
      filtered(SUPPRESSIONS, request, (s, q) => flag(q, 'active', !s.expired)),
    ),
  ),
  ...(scanSettingsOwned
    ? {}
    : {
        ScanSettingsController_list_v1: (request: FixtureRequest) =>
          fixtureGuard(request) ?? ok('ScanSettingsController_list_v1', SCAN_SETTINGS),
      }),
};
