import 'server-only';
import type { ListItem, OperationId, SuccessBody } from '@/lib/api/types';
import { fixtureAnchor, stableUuid } from '../generator';
import {
  apiError,
  noContent,
  ok,
  type FixtureHandler,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { idempotent } from './domains';
import { FIXTURE_MESSAGES, guarded } from './messages';
import { resolveFixturePrincipal } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the DLP and BEC editors (step 7.3 WP5, design §2 B15): realistic synthetic DLP
 * policies with rules, exceptions, custom patterns, dictionaries, the Aadhaar compliance basis,
 * incidents, and BEC executives, vendors, trusted senders, feedback and suppressions, kept per
 * organization in memory on `globalThis` (every `next dev` route bundle shares it). Writes follow
 * the API's rules closely enough for the portal flows: `version` compare-and-set
 * (`409 version_conflict`), unique names (`409 *_exists`), references and in-use refusals, limits,
 * free-mail refusals (`freemail.example.test`, `webmail.example.test` stand for free-mail
 * providers), the Aadhaar basis behind MFA and an Idempotency-Key. Registered last in
 * `FEATURE_FIXTURES`, so these handlers replace the read-only DLP/BEC lists of `policies.ts`.
 *
 * `POST /dlp/patterns/test` never evaluates the pattern: it answers a canned, labelled result (a
 * pattern containing `EXAMPLE_INVALID` is "refused" with `pattern_syntax`), 30 calls per caller
 * per minute like the API. Synthetic identifiers only (`*.example.test`, `example.com`).
 */

type Policy = ListItem<'DlpPoliciesController_list_v1'>;
type PolicyDetail = SuccessBody<'DlpPoliciesController_get_v1'>;
type Rule = PolicyDetail['rules'][number];
type Conditions = Rule['conditions'];
type Exception = ListItem<'DlpExceptionsController_list_v1'>;
type Pattern = ListItem<'DlpPatternsController_list_v1'>;
type Dictionary = SuccessBody<'DlpDictionariesController_get_v1'>;
type Compliance = SuccessBody<'DlpComplianceController_get_v1'>;
type Incident = ListItem<'DlpIncidentsController_list_v1'>;
type Executive = ListItem<'BecExecutivesController_list_v1'>;
type Vendor = ListItem<'BecVendorsController_list_v1'>;
type Trusted = ListItem<'BecTrustedSendersController_list_v1'>;
type Feedback = ListItem<'BecFeedbackController_list_v1'>;
type Suppression = ListItem<'BecFeedbackController_listSuppressions_v1'>;

interface OrgState {
  policies: Policy[];
  rules: Map<string, Rule[]>;
  exceptions: Exception[];
  patterns: Pattern[];
  dictionaries: Dictionary[];
  compliance: Compliance;
  incidents: Incident[];
  executives: Executive[];
  vendors: Vendor[];
  trusted: Trusted[];
  feedback: Feedback[];
  suppressions: Suppression[];
  idempotency: Map<string, FixtureResponse>;
}

interface Store {
  orgs: Map<string, OrgState>;
  /** Pattern-test calls per caller (timestamps of the last minute). */
  patternTests: Map<string, number[]>;
}

const globalStore = globalThis as typeof globalThis & { __egDevFixtureDlpBec?: Store };
const store: Store = (globalStore.__egDevFixtureDlpBec ??= {
  orgs: new Map(),
  patternTests: new Map(),
});

/** Limits of the fixture (the API's configured defaults). */
export const FIXTURE_DLP_BEC_LIMITS = {
  policies: 20,
  rulesPerPolicy: 50,
  exceptions: 500,
  patterns: 50,
  dictionaries: 20,
  dictionaryTerms: 1000,
  executives: 100,
  vendors: 200,
  trustedSenders: 500,
  patternTestsPerMinute: 30,
  exceptionMaxDays: 365,
} as const;

/** Domains the fixture treats as free-mail providers (synthetic stand-ins). */
export const FIXTURE_FREEMAIL_DOMAINS = ['freemail.example.test', 'webmail.example.test'];

/** The `masked` text of the canned pattern-test match (the pattern is never evaluated). */
export const CANNED_PATTERN_MATCH = '[dev fixture: canned result, pattern not evaluated]';

const DAY = 86_400_000;
const anchor = fixtureAnchor();
const ago = (days: number) => new Date(anchor - days * DAY).toISOString();
const ahead = (days: number) => new Date(anchor + days * DAY).toISOString();
const nowIso = () => new Date().toISOString();
const newId = () => crypto.randomUUID();

// ---------------------------------------------------------------------------------------------
// Seed data (per organization; deterministic ids)
// ---------------------------------------------------------------------------------------------

function seed(orgId: string): OrgState {
  const id = (key: string) => stableUuid(`dlp-bec:${orgId}:${key}`);
  const admin = stableUuid('user:organization_admin@example.com');
  const audit = (key: string, created: number, updated: number, version = 1) => ({
    id: id(key),
    version,
    createdByUserId: admin,
    updatedByUserId: admin,
    createdAt: ago(created),
    updatedAt: ago(updated),
  });
  const patterns: Pattern[] = [
    {
      ...audit('pattern:employee', 50, 12, 2),
      name: 'Employee ID',
      pattern: 'EMP-[0-9]{6}',
      caseInsensitive: true,
      validator: 'none',
      contextKeywords: ['employee', 'staff id'],
      requireContext: false,
      severity: 'medium',
      baseConfidence: 0.7,
      maskStyle: 'last4',
      enabled: true,
    },
    {
      ...audit('pattern:project', 44, 30),
      name: 'Project codename <b>',
      pattern: 'project\\s+(falcon|heron)',
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
  const dictionaries: Dictionary[] = [
    {
      ...audit('dictionary:projects', 48, 9),
      name: 'Confidential project names',
      category: 'confidential',
      terms: ['falcon roadmap', 'heron merger', 'blue harbor', 'atlas pricing'],
      termCount: 4,
      severity: 'high',
      baseConfidence: 0.8,
      minMatches: 1,
      enabled: true,
    },
    {
      ...audit('dictionary:finance', 40, 40),
      name: 'Finance terms',
      category: 'financial',
      terms: ['quarterly forecast', 'board pack', 'payroll export'],
      termCount: 3,
      severity: 'medium',
      baseConfidence: 0.7,
      minMatches: 2,
      enabled: false,
    },
  ];
  const cards = id('policy:cards');
  const source = id('policy:source');
  const legacy = id('policy:legacy');
  const rules = new Map<string, Rule[]>([
    [
      cards,
      [
        {
          ...audit('rule:cards-block', 58, 20, 3),
          policyId: cards,
          name: 'Block card numbers to external recipients',
          enabled: true,
          priority: 10,
          conditions: {
            selectors: { categories: ['payment_card'], detectors: ['PC1'] },
            minCount: 1,
            minSeverity: 'high',
            recipients: { externalOnly: true },
          },
          action: 'block',
        },
        {
          ...audit('rule:cards-alert', 58, 58),
          policyId: cards,
          name: 'Alert on bank details',
          enabled: true,
          priority: 20,
          conditions: { selectors: { categories: ['bank_account'] }, minConfidence: 0.8 },
          action: 'alert',
        },
      ],
    ],
    [
      source,
      [
        {
          ...audit('rule:source-review', 30, 30),
          policyId: source,
          name: 'Review source code and project names',
          enabled: true,
          priority: 100,
          conditions: {
            selectors: {
              detectors: ['SC1'],
              customPatternIds: [id('pattern:project')],
              dictionaryIds: [id('dictionary:projects')],
            },
            directions: ['outbound'],
            sender: { domains: ['alpha.example.test'] },
          },
          action: 'require_approval',
        },
      ],
    ],
    [
      legacy,
      [
        {
          ...audit('rule:legacy-encrypted', 70, 70),
          policyId: legacy,
          name: 'Hold encrypted attachments',
          enabled: false,
          priority: 100,
          conditions: {
            selectors: { coverageReasons: ['dlp.not_extracted.encrypted'] },
            attachmentsOnly: true,
          },
          action: 'quarantine',
        },
      ],
    ],
  ]);
  const policies: Policy[] = [
    {
      ...audit('policy:cards', 60, 20, 4),
      id: cards,
      name: 'Payment cards outbound',
      description: 'Block card numbers leaving the company',
      enabled: true,
      mode: 'enforce',
      priority: 10,
      directions: ['outbound'],
      ruleCount: 2,
    },
    {
      ...audit('policy:source', 35, 30),
      id: source,
      name: 'Source code monitoring',
      description: null,
      enabled: true,
      mode: 'monitor',
      priority: 20,
      directions: ['outbound', 'internal'],
      ruleCount: 1,
    },
    {
      ...audit('policy:legacy', 75, 70, 2),
      id: legacy,
      name: 'Legacy PII rule',
      description: 'Kept for reference',
      enabled: false,
      mode: 'monitor',
      priority: 30,
      directions: ['outbound'],
      ruleCount: 1,
    },
  ];
  const exceptions: Exception[] = [
    {
      ...audit('exception:auditor', 25, 25),
      scope: 'recipient_domain',
      value: 'auditor.example.test',
      policyId: cards,
      ruleId: null,
      filters: { categories: ['payment_card'] },
      reason: 'External auditors receive card statements',
      expiresAt: ahead(60),
      expired: false,
      enabled: true,
    },
    {
      ...audit('exception:payroll', 40, 40),
      scope: 'sender_address',
      value: 'payroll@alpha.example.test',
      policyId: null,
      ruleId: null,
      filters: null,
      reason: 'Payroll run',
      expiresAt: ago(3),
      expired: true,
      enabled: true,
    },
  ];
  const incidents: Incident[] = FIXTURE_MESSAGES.filter((m) => m.detail.direction === 'outbound')
    .slice(0, 12)
    .map((m, i) => {
      const card = i % 2 === 0;
      return {
        messageId: m.detail.id,
        scanId: m.rounds[0]?.scanId ?? '1',
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
            category: card ? 'payment_card' : 'bank_account',
            count: 1 + (i % 4),
            maxSeverity: 'high',
            maxConfidence: 0.92,
          },
        ],
        findings: [
          {
            detector: card ? 'PC1' : 'BA1',
            code: card ? 'dlp.payment_card.number' : 'dlp.bank_account.iban',
            category: card ? 'payment_card' : 'bank_account',
            severity: 'high',
            count: 1 + (i % 4),
            capped: false,
          },
        ],
        policy: {
          winner: { policyId: cards, ruleId: id(card ? 'rule:cards-block' : 'rule:cards-alert') },
          matched: [],
          exceptionsApplied: [],
        },
        detectedAt: new Date(Date.parse(m.detail.receivedAt) + 3_000).toISOString(),
      };
    });
  const becAudit = (key: string, created: number, updated: number, version = 1) => ({
    id: id(key),
    version,
    createdByUserId: admin,
    createdAt: ago(created),
    updatedAt: ago(updated),
  });
  const feedback: Feedback[] = FIXTURE_MESSAGES.filter((m) => m.detail.finalVerdict === 'bec')
    .slice(0, 6)
    .map((m, i) => ({
      id: id(`feedback:${i}`),
      kind: i % 2 === 0 ? 'false_positive' : 'false_negative',
      messageId: m.detail.id,
      scanId: m.rounds[0]?.scanId ?? '1',
      reasonCodes: ['bec.impersonation.executive_name'],
      note: i === 0 ? 'Known vendor <script>' : null,
      createdByUserId: admin,
      createdAt: ago(10 + i),
    }));
  return {
    policies,
    rules,
    exceptions,
    patterns,
    dictionaries,
    compliance: {
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
    },
    incidents,
    executives: [
      {
        ...becAudit('executive:ceo', 50, 5, 2),
        displayName: 'Dana Whitfield',
        normalizedName: 'dana whitfield',
        aliases: ['D. Whitfield'],
        knownAddresses: ['ceo@alpha.example.test'],
        title: 'Chief Executive Officer',
        enabled: true,
        updatedByUserId: admin,
      },
      {
        ...becAudit('executive:cfo', 49, 40),
        displayName: 'Ravi Kumar',
        normalizedName: 'ravi kumar',
        aliases: [],
        knownAddresses: ['cfo@alpha.example.test'],
        title: 'CFO',
        enabled: true,
        updatedByUserId: admin,
      },
    ],
    vendors: [
      {
        ...becAudit('vendor:bravo', 48, 30),
        name: 'Bravo Logistics',
        normalizedName: 'bravo logistics',
        aliases: ['Bravo Freight'],
        domains: ['bravo.example.test'],
        knownSenders: ['billing@bravo.example.test'],
        paymentChangeSensitive: true,
        enabled: true,
        updatedByUserId: admin,
      },
    ],
    trusted: [
      {
        ...becAudit('trusted:partner', 30, 20),
        kind: 'domain',
        value: 'partner.example.test',
        reason: 'Long-standing partner',
        expiresAt: null,
        expired: false,
      },
      {
        ...becAudit('trusted:board', 28, 25),
        kind: 'address',
        value: 'board<b>@example.test',
        reason: 'Board secretary',
        expiresAt: ago(1),
        expired: true,
      },
    ],
    feedback,
    suppressions: [
      {
        id: id('suppression:urgency'),
        reasonCode: 'bec.content.urgency',
        senderScope: 'domain',
        senderValue: 'partner.example.test',
        expiresAt: ahead(30),
        expired: false,
        feedbackId: feedback[0]?.id ?? null,
        createdByUserId: admin,
        createdAt: ago(9),
      },
    ],
    idempotency: new Map(),
  };
}

function stateOf(request: FixtureRequest): OrgState {
  const principal = resolveFixturePrincipal(request.token);
  const orgId = principal?.organizationId ?? 'anonymous';
  let state = store.orgs.get(orgId);
  if (!state) {
    state = seed(orgId);
    store.orgs.set(orgId, state);
  }
  return state;
}

function actorOf(request: FixtureRequest): string | null {
  return resolveFixturePrincipal(request.token)?.userId ?? null;
}

// ---------------------------------------------------------------------------------------------
// Request helpers (the API's envelope and checks, simplified)
// ---------------------------------------------------------------------------------------------

type Body = Record<string, unknown>;

function bodyOf(request: FixtureRequest): Body {
  return request.body && typeof request.body === 'object' && !Array.isArray(request.body)
    ? (request.body as Body)
    : {};
}

function invalid(messages: string[]): FixtureResponse {
  return apiError(400, 'validation_failed', messages);
}

/** `"<path>: <issue>"` lines for unknown keys (the API's bodies are strict). */
function unknownKeys(body: Body, allowed: readonly string[], prefix = ''): string[] {
  return Object.keys(body)
    .filter((key) => !allowed.includes(key))
    .map((key) => `${prefix || '(root)'}: Unrecognized key: "${key}"`);
}

function textProblem(
  body: Body,
  key: string,
  min: number,
  max: number,
  required: boolean,
): string | null {
  const value = body[key];
  if (value === undefined) return required ? `${key}: Required` : null;
  if (typeof value !== 'string') return `${key}: Expected string`;
  const trimmed = value.trim();
  if (trimmed.length < min) return `${key}: Too small: expected at least ${min} characters`;
  if (trimmed.length > max) return `${key}: Too big: expected at most ${max} characters`;
  return null;
}

function enumProblem(body: Body, key: string, values: readonly string[], required: boolean) {
  const value = body[key];
  if (value === undefined) return required ? `${key}: Required` : null;
  return typeof value === 'string' && values.includes(value) ? null : `${key}: Invalid option`;
}

function intProblem(body: Body, key: string, min: number, max: number): string | null {
  const value = body[key];
  if (value === undefined) return null;
  return Number.isInteger(value) && (value as number) >= min && (value as number) <= max
    ? null
    : `${key}: Expected an integer from ${min} to ${max}`;
}

function confidenceProblem(body: Body, key: string): string | null {
  const value = body[key];
  if (value === undefined) return null;
  return typeof value === 'number' &&
    value >= 0.5 &&
    value <= 1 &&
    Math.abs(Math.round(value * 100) - value * 100) < 1e-6
    ? null
    : `${key}: Expected a number from 0.5 to 1 with at most two decimals`;
}

function stringList(
  body: Body,
  key: string,
  options: { max: number; min?: number; itemMax: number; itemMin?: number; path?: string },
): { value: string[] | undefined; problems: string[] } {
  const raw = body[key];
  const path = options.path ?? key;
  if (raw === undefined) return { value: undefined, problems: [] };
  if (!Array.isArray(raw)) return { value: undefined, problems: [`${path}: Expected array`] };
  const problems: string[] = [];
  if (raw.length < (options.min ?? 0)) problems.push(`${path}: Too small`);
  if (raw.length > options.max) problems.push(`${path}: Too big: at most ${options.max} items`);
  raw.forEach((item, index) => {
    if (
      typeof item !== 'string' ||
      item.trim().length < (options.itemMin ?? 1) ||
      item.trim().length > options.itemMax
    ) {
      problems.push(`${path}.${index}: Invalid value`);
    }
  });
  return { value: raw.map((item) => String(item).trim()), problems };
}

const versionConflict = (currentVersion: number) =>
  apiError(409, 'version_conflict', 'The resource changed since version; read it and retry', {
    currentVersion,
  });

/** `version` of a PATCH body (required) against the row's. */
function checkVersion(body: Body, current: number): FixtureResponse | null {
  if (!Number.isInteger(body.version)) return invalid(['version: Required']);
  return body.version === current ? null : versionConflict(current);
}

/** `?version=` of a DELETE (optional compare-and-set). */
function checkDeleteVersion(request: FixtureRequest, current: number): FixtureResponse | null {
  const raw = request.query.get('version');
  if (raw === null) return null;
  return Number(raw) === current ? null : versionConflict(current);
}

function page<T>(
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

const flag = (query: URLSearchParams, name: string, value: boolean) =>
  !query.get(name) || query.get(name) === String(value);

const sameName = (a: string, b: string) =>
  a.trim().toLowerCase().replace(/\s+/g, ' ') === b.trim().toLowerCase().replace(/\s+/g, ' ');

/** The engine's display-name normalization, simplified: case, spacing and punctuation ignored. */
const normalizedName = (value: string) =>
  value
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, '')
    .replace(/\s+/g, ' ')
    .trim();

const limitReached = (resource: string, limit: number) =>
  apiError(
    409,
    `${resource.startsWith('bec') ? 'bec' : 'dlp'}_limit_reached`,
    'The organization reached its limit for this resource',
    {
      resource: resource.replace(/^bec_/, ''),
      limit,
    },
  );

function expiryProblem(
  value: unknown,
  path: string,
  maxDays: number,
  nullable: boolean,
): string | null {
  if (value === null && nullable) return null;
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    return `${path}: Invalid ISO datetime`;
  }
  const at = Date.parse(value);
  if (at <= Date.now()) return `${path}: Must be in the future`;
  if (at > Date.now() + maxDays * DAY) return `${path}: Must be at most ${maxDays} days ahead`;
  return null;
}

/** A registrable domain of the fixture's free-mail stand-ins. */
const isFreemail = (domain: string) => FIXTURE_FREEMAIL_DOMAINS.includes(domain.toLowerCase());

function handler(
  fn: (request: FixtureRequest, state: OrgState) => FixtureResponse,
): FixtureHandler {
  return guarded((request) => fn(request, stateOf(request)));
}

// ---------------------------------------------------------------------------------------------
// DLP policies and rules
// ---------------------------------------------------------------------------------------------

const DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
const MODES = ['enforce', 'monitor'] as const;
const ACTIONS = ['allow', 'alert', 'require_approval', 'quarantine', 'block'] as const;
const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
const VALIDATORS = ['none', 'luhn', 'verhoeff', 'mod97', 'gstin'] as const;
const MASK_STYLES = ['last4', 'full'] as const;
const DICTIONARY_CATEGORIES = [
  'confidential',
  'financial',
  'personal_info',
  'source_code',
  'custom',
] as const;
const EXCEPTION_SCOPES = [
  'sender_address',
  'sender_domain',
  'recipient_address',
  'recipient_domain',
] as const;
const AADHAAR_BASES = [
  'regulatory_obligation',
  'uidai_authorised_entity',
  'data_protection_policy',
  'other',
] as const;

function directionsProblem(value: unknown, path: string): string | null {
  if (value === undefined) return null;
  return Array.isArray(value) &&
    value.length >= 1 &&
    value.length <= 3 &&
    new Set(value).size === value.length &&
    value.every((d) => (DIRECTIONS as readonly unknown[]).includes(d))
    ? null
    : `${path}: Expected 1 to 3 distinct directions`;
}

function policyProblems(body: Body, create: boolean): string[] {
  return [
    ...unknownKeys(body, [
      ...(create ? [] : ['version']),
      'name',
      'description',
      'enabled',
      'mode',
      'priority',
      'directions',
    ]),
    textProblem(body, 'name', 1, 128, create),
    body.description === null ? null : textProblem(body, 'description', 1, 512, false),
    body.enabled === undefined || typeof body.enabled === 'boolean'
      ? null
      : 'enabled: Expected boolean',
    enumProblem(body, 'mode', MODES, false),
    intProblem(body, 'priority', 0, 1000),
    directionsProblem(body.directions, 'directions'),
  ].filter((p): p is string => p !== null);
}

function detailOf(state: OrgState, policy: Policy): PolicyDetail {
  const rules = [...(state.rules.get(policy.id) ?? [])].sort(
    (a, b) => a.priority - b.priority || a.createdAt.localeCompare(b.createdAt),
  );
  return { ...policy, ruleCount: rules.length, rules };
}

function findPolicy(state: OrgState, request: FixtureRequest): Policy | undefined {
  return state.policies.find((p) => p.id === request.params.id);
}

const policyNotFound = () => apiError(404, 'dlp_policy_not_found', 'DLP policy not found');

/** Normalizes and checks rule conditions (selectors, references, directions within the policy). */
function checkConditions(
  state: OrgState,
  policy: Policy,
  raw: unknown,
): { conditions: Conditions } | { response: FixtureResponse } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { response: invalid(['conditions: Expected object']) };
  }
  const input = raw as Body;
  const selectors = (input.selectors ?? {}) as Body;
  const problems = [
    ...unknownKeys(
      input,
      [
        'selectors',
        'minCount',
        'minConfidence',
        'minSeverity',
        'directions',
        'sender',
        'recipients',
        'attachmentsOnly',
      ],
      'conditions',
    ),
    ...unknownKeys(
      selectors,
      ['detectors', 'categories', 'customPatternIds', 'dictionaryIds', 'coverageReasons'],
      'conditions.selectors',
    ),
  ];
  const selected = Object.values(selectors).filter((v) => Array.isArray(v) && v.length > 0);
  if (selected.length === 0) {
    problems.push('conditions.selectors: At least one selector is required');
  }
  const lower = (scope: unknown, path: string) => {
    if (scope === undefined) return undefined;
    const s = (scope ?? {}) as Body;
    const addresses = stringList(s, 'addresses', {
      max: 100,
      itemMax: 320,
      itemMin: 3,
      path: `${path}.addresses`,
    });
    const domains = stringList(s, 'domains', { max: 100, itemMax: 253, path: `${path}.domains` });
    problems.push(...addresses.problems, ...domains.problems);
    (addresses.value ?? []).forEach((address, index) => {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) {
        problems.push(`${path}.addresses.${index}: Expected a lower-case address`);
      }
    });
    return {
      ...(addresses.value ? { addresses: addresses.value.map((a) => a.toLowerCase()) } : {}),
      ...(domains.value ? { domains: domains.value.map((d) => d.toLowerCase()) } : {}),
      ...(typeof s.externalOnly === 'boolean' ? { externalOnly: s.externalOnly } : {}),
    };
  };
  const sender = lower(input.sender, 'conditions.sender');
  const recipients = lower(input.recipients, 'conditions.recipients');
  const directionError = directionsProblem(input.directions, 'conditions.directions');
  if (directionError) problems.push(directionError);
  if (problems.length > 0) return { response: invalid(problems) };
  const directions = (input.directions as Policy['directions'] | undefined) ?? [];
  if (directions.some((d) => !policy.directions.includes(d))) {
    return {
      response: apiError(
        400,
        'dlp_directions_invalid',
        'Rule directions must be a subset of the policy directions',
        { references: 1 },
      ),
    };
  }
  const patternIds = (selectors.customPatternIds as string[] | undefined) ?? [];
  const badPattern = patternIds.findIndex((pid) => !state.patterns.some((p) => p.id === pid));
  if (badPattern >= 0) {
    return {
      response: apiError(
        400,
        'dlp_reference_invalid',
        'A referenced id is not the organization’s',
        {
          field: 'conditions.selectors.customPatternIds',
          index: badPattern,
        },
      ),
    };
  }
  const dictionaryIds = (selectors.dictionaryIds as string[] | undefined) ?? [];
  const badDictionary = dictionaryIds.findIndex(
    (did) => !state.dictionaries.some((d) => d.id === did),
  );
  if (badDictionary >= 0) {
    return {
      response: apiError(
        400,
        'dlp_reference_invalid',
        'A referenced id is not the organization’s',
        {
          field: 'conditions.selectors.dictionaryIds',
          index: badDictionary,
        },
      ),
    };
  }
  const conditions = {
    ...input,
    ...(sender ? { sender } : {}),
    ...(recipients ? { recipients } : {}),
  } as Conditions;
  return { conditions };
}

function ruleProblems(body: Body, create: boolean): string[] {
  return [
    ...unknownKeys(body, [
      ...(create ? [] : ['version']),
      'name',
      'enabled',
      'priority',
      'conditions',
      'action',
    ]),
    textProblem(body, 'name', 1, 128, create),
    intProblem(body, 'priority', 0, 1000),
    enumProblem(body, 'action', ACTIONS, create),
    create && body.conditions === undefined ? 'conditions: Required' : null,
  ].filter((p): p is string => p !== null);
}

const dlpPolicies: FixtureHandlers = {
  DlpPoliciesController_list_v1: handler((request, state) => {
    const rows = state.policies
      .filter((p) => flag(request.query, 'enabled', p.enabled))
      .map((p) => ({ ...p, ruleCount: state.rules.get(p.id)?.length ?? 0 }));
    return ok('DlpPoliciesController_list_v1', page(rows, request.query));
  }),
  DlpPoliciesController_get_v1: handler((request, state) => {
    const policy = findPolicy(state, request);
    return policy ? ok('DlpPoliciesController_get_v1', detailOf(state, policy)) : policyNotFound();
  }),
  DlpPoliciesController_create_v1: handler((request, state) => {
    const body = bodyOf(request);
    const problems = policyProblems(body, true);
    if (problems.length) return invalid(problems);
    const name = String(body.name).trim();
    const taken = state.policies.find((p) => sameName(p.name, name));
    if (taken)
      return apiError(409, 'dlp_policy_exists', 'A DLP policy with this name exists', {
        id: taken.id,
      });
    if (state.policies.length >= FIXTURE_DLP_BEC_LIMITS.policies) {
      return limitReached('policy', FIXTURE_DLP_BEC_LIMITS.policies);
    }
    const at = nowIso();
    const policy: Policy = {
      id: newId(),
      name,
      description: typeof body.description === 'string' ? body.description.trim() : null,
      enabled: body.enabled !== false,
      mode: (body.mode as Policy['mode'] | undefined) ?? 'enforce',
      priority: (body.priority as number | undefined) ?? 100,
      directions: (body.directions as Policy['directions'] | undefined) ?? ['outbound', 'internal'],
      ruleCount: 0,
      version: 1,
      createdByUserId: actorOf(request),
      updatedByUserId: actorOf(request),
      createdAt: at,
      updatedAt: at,
    };
    state.policies.unshift(policy);
    state.rules.set(policy.id, []);
    return ok('DlpPoliciesController_create_v1', detailOf(state, policy), 201);
  }),
  DlpPoliciesController_update_v1: handler((request, state) => {
    const policy = findPolicy(state, request);
    if (!policy) return policyNotFound();
    const body = bodyOf(request);
    const problems = policyProblems(body, false);
    if (problems.length) return invalid(problems);
    const conflict = checkVersion(body, policy.version);
    if (conflict) return conflict;
    if (typeof body.name === 'string') {
      const taken = state.policies.find(
        (p) => p.id !== policy.id && sameName(p.name, String(body.name)),
      );
      if (taken)
        return apiError(409, 'dlp_policy_exists', 'A DLP policy with this name exists', {
          id: taken.id,
        });
    }
    if (Array.isArray(body.directions)) {
      const next = body.directions as Policy['directions'];
      const outside = (state.rules.get(policy.id) ?? []).filter((rule) =>
        (rule.conditions.directions ?? []).some((d) => !next.includes(d)),
      ).length;
      if (outside > 0) {
        return apiError(
          400,
          'dlp_directions_invalid',
          'Rule directions must be a subset of the policy directions',
          {
            references: outside,
          },
        );
      }
    }
    Object.assign(policy, {
      ...(typeof body.name === 'string' ? { name: body.name.trim() } : {}),
      ...('description' in body
        ? { description: typeof body.description === 'string' ? body.description.trim() : null }
        : {}),
      ...(typeof body.enabled === 'boolean' ? { enabled: body.enabled } : {}),
      ...(typeof body.mode === 'string' ? { mode: body.mode } : {}),
      ...(typeof body.priority === 'number' ? { priority: body.priority } : {}),
      ...(Array.isArray(body.directions) ? { directions: body.directions } : {}),
      version: policy.version + 1,
      updatedByUserId: actorOf(request),
      updatedAt: nowIso(),
    });
    return ok('DlpPoliciesController_update_v1', detailOf(state, policy));
  }),
  DlpPoliciesController_remove_v1: handler((request, state) => {
    const policy = findPolicy(state, request);
    if (!policy) return policyNotFound();
    const conflict = checkDeleteVersion(request, policy.version);
    if (conflict) return conflict;
    const ruleIds = new Set((state.rules.get(policy.id) ?? []).map((r) => r.id));
    const references = state.exceptions.filter(
      (e) => e.policyId === policy.id || (e.ruleId !== null && ruleIds.has(e.ruleId)),
    ).length;
    if (references > 0) {
      return apiError(
        409,
        'dlp_policy_in_use',
        'Exceptions target this policy or one of its rules',
        { references },
      );
    }
    state.policies = state.policies.filter((p) => p.id !== policy.id);
    state.rules.delete(policy.id);
    return noContent();
  }),
  DlpPoliciesController_createRule_v1: handler((request, state) => {
    const policy = findPolicy(state, request);
    if (!policy) return policyNotFound();
    const body = bodyOf(request);
    const problems = ruleProblems(body, true);
    if (problems.length) return invalid(problems);
    const checked = checkConditions(state, policy, body.conditions);
    if ('response' in checked) return checked.response;
    const rules = state.rules.get(policy.id) ?? [];
    const name = String(body.name).trim();
    const taken = rules.find((r) => sameName(r.name, name));
    if (taken)
      return apiError(409, 'dlp_rule_exists', 'A rule with this name exists in the policy', {
        id: taken.id,
      });
    if (rules.length >= FIXTURE_DLP_BEC_LIMITS.rulesPerPolicy) {
      return limitReached('rule', FIXTURE_DLP_BEC_LIMITS.rulesPerPolicy);
    }
    const at = nowIso();
    const rule: Rule = {
      id: newId(),
      policyId: policy.id,
      name,
      enabled: body.enabled !== false,
      priority: (body.priority as number | undefined) ?? 100,
      conditions: checked.conditions,
      action: body.action as Rule['action'],
      version: 1,
      createdByUserId: actorOf(request),
      updatedByUserId: actorOf(request),
      createdAt: at,
      updatedAt: at,
    };
    state.rules.set(policy.id, [...rules, rule]);
    return ok('DlpPoliciesController_createRule_v1', rule, 201);
  }),
  DlpPoliciesController_updateRule_v1: handler((request, state) => {
    const policy = findPolicy(state, request);
    const rules = policy ? (state.rules.get(policy.id) ?? []) : [];
    const rule = rules.find((r) => r.id === request.params.ruleId);
    if (!policy || !rule) return apiError(404, 'dlp_rule_not_found', 'DLP rule not found');
    const body = bodyOf(request);
    const problems = ruleProblems(body, false);
    if (problems.length) return invalid(problems);
    const conflict = checkVersion(body, rule.version);
    if (conflict) return conflict;
    let conditions = rule.conditions;
    if (body.conditions !== undefined) {
      const checked = checkConditions(state, policy, body.conditions);
      if ('response' in checked) return checked.response;
      conditions = checked.conditions;
    }
    if (typeof body.name === 'string') {
      const taken = rules.find((r) => r.id !== rule.id && sameName(r.name, String(body.name)));
      if (taken)
        return apiError(409, 'dlp_rule_exists', 'A rule with this name exists in the policy', {
          id: taken.id,
        });
    }
    Object.assign(rule, {
      ...(typeof body.name === 'string' ? { name: body.name.trim() } : {}),
      ...(typeof body.enabled === 'boolean' ? { enabled: body.enabled } : {}),
      ...(typeof body.priority === 'number' ? { priority: body.priority } : {}),
      ...(typeof body.action === 'string' ? { action: body.action } : {}),
      conditions,
      version: rule.version + 1,
      updatedByUserId: actorOf(request),
      updatedAt: nowIso(),
    });
    return ok('DlpPoliciesController_updateRule_v1', rule);
  }),
  DlpPoliciesController_removeRule_v1: handler((request, state) => {
    const policy = findPolicy(state, request);
    const rules = policy ? (state.rules.get(policy.id) ?? []) : [];
    const rule = rules.find((r) => r.id === request.params.ruleId);
    if (!policy || !rule) return apiError(404, 'dlp_rule_not_found', 'DLP rule not found');
    const conflict = checkDeleteVersion(request, rule.version);
    if (conflict) return conflict;
    const references = state.exceptions.filter((e) => e.ruleId === rule.id).length;
    if (references > 0) {
      return apiError(409, 'dlp_rule_in_use', 'Exceptions target this rule', { references });
    }
    state.rules.set(
      policy.id,
      rules.filter((r) => r.id !== rule.id),
    );
    return noContent();
  }),
};

// ---------------------------------------------------------------------------------------------
// DLP exceptions
// ---------------------------------------------------------------------------------------------

function filtersProblem(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) return 'filters: Expected object';
  const filters = value as Body;
  const extra = unknownKeys(filters, ['detectors', 'categories'], 'filters');
  if (extra.length) return extra[0] ?? null;
  const lists = Object.values(filters).filter((v) => v !== undefined);
  if (lists.length === 0) return 'filters: Empty filters: omit them instead';
  return lists.every((v) => Array.isArray(v) && v.length > 0) ? null : 'filters: Invalid filters';
}

const withExpired = (e: Exception): Exception => ({
  ...e,
  expired: Date.parse(e.expiresAt) <= Date.now(),
});

const dlpExceptions: FixtureHandlers = {
  DlpExceptionsController_list_v1: handler((request, state) => {
    const q = request.query;
    const rows = state.exceptions
      .map(withExpired)
      .filter(
        (e) =>
          (!q.get('scope') || q.get('scope') === e.scope) &&
          flag(q, 'active', e.enabled && !e.expired),
      );
    return ok('DlpExceptionsController_list_v1', page(rows, q));
  }),
  DlpExceptionsController_create_v1: handler((request, state) => {
    const body = bodyOf(request);
    const problems = [
      ...unknownKeys(body, [
        'scope',
        'value',
        'policyId',
        'ruleId',
        'filters',
        'reason',
        'expiresAt',
        'enabled',
      ]),
      enumProblem(body, 'scope', EXCEPTION_SCOPES, true),
      textProblem(body, 'value', 1, 320, true),
      textProblem(body, 'reason', 1, 512, true),
      filtersProblem(body.filters),
      body.policyId !== undefined && body.ruleId !== undefined
        ? 'policyId: One target at most'
        : null,
      expiryProblem(body.expiresAt, 'expiresAt', FIXTURE_DLP_BEC_LIMITS.exceptionMaxDays, false),
    ].filter((p): p is string => p !== null);
    if (problems.length) return invalid(problems);
    if (typeof body.policyId === 'string' && !state.policies.some((p) => p.id === body.policyId)) {
      return apiError(400, 'dlp_reference_invalid', 'A referenced id is not the organization’s', {
        field: 'policyId',
      });
    }
    if (
      typeof body.ruleId === 'string' &&
      ![...state.rules.values()].some((rules) => rules.some((r) => r.id === body.ruleId))
    ) {
      return apiError(400, 'dlp_reference_invalid', 'A referenced id is not the organization’s', {
        field: 'ruleId',
      });
    }
    const scope = body.scope as Exception['scope'];
    const value = String(body.value).trim().toLowerCase();
    const policyId = typeof body.policyId === 'string' ? body.policyId : null;
    const ruleId = typeof body.ruleId === 'string' ? body.ruleId : null;
    const taken = state.exceptions.find(
      (e) =>
        e.scope === scope && e.value === value && e.policyId === policyId && e.ruleId === ruleId,
    );
    if (taken) {
      return apiError(
        409,
        'dlp_exception_exists',
        'An exception for this scope, value and target exists',
        { id: taken.id },
      );
    }
    if (state.exceptions.length >= FIXTURE_DLP_BEC_LIMITS.exceptions) {
      return limitReached('exception', FIXTURE_DLP_BEC_LIMITS.exceptions);
    }
    const at = nowIso();
    const exception: Exception = {
      id: newId(),
      scope,
      value,
      policyId,
      ruleId,
      filters: (body.filters as Exception['filters'] | undefined) ?? null,
      reason: String(body.reason).trim(),
      expiresAt: String(body.expiresAt),
      expired: false,
      enabled: body.enabled !== false,
      version: 1,
      createdByUserId: actorOf(request),
      updatedByUserId: actorOf(request),
      createdAt: at,
      updatedAt: at,
    };
    state.exceptions.unshift(exception);
    return ok('DlpExceptionsController_create_v1', exception, 201);
  }),
  DlpExceptionsController_update_v1: handler((request, state) => {
    const exception = state.exceptions.find((e) => e.id === request.params.id);
    if (!exception) return apiError(404, 'dlp_exception_not_found', 'DLP exception not found');
    const body = bodyOf(request);
    const problems = [
      ...unknownKeys(body, ['version', 'reason', 'expiresAt', 'enabled', 'filters']),
      textProblem(body, 'reason', 1, 512, false),
      filtersProblem(body.filters),
      body.expiresAt === undefined
        ? null
        : expiryProblem(
            body.expiresAt,
            'expiresAt',
            FIXTURE_DLP_BEC_LIMITS.exceptionMaxDays,
            false,
          ),
    ].filter((p): p is string => p !== null);
    if (problems.length) return invalid(problems);
    const conflict = checkVersion(body, exception.version);
    if (conflict) return conflict;
    Object.assign(exception, {
      ...(typeof body.reason === 'string' ? { reason: body.reason.trim() } : {}),
      ...(typeof body.expiresAt === 'string' ? { expiresAt: body.expiresAt } : {}),
      ...(typeof body.enabled === 'boolean' ? { enabled: body.enabled } : {}),
      ...('filters' in body ? { filters: body.filters ?? null } : {}),
      version: exception.version + 1,
      updatedByUserId: actorOf(request),
      updatedAt: nowIso(),
    });
    return ok('DlpExceptionsController_update_v1', withExpired(exception));
  }),
  DlpExceptionsController_remove_v1: handler((request, state) => {
    const exception = state.exceptions.find((e) => e.id === request.params.id);
    if (!exception) return apiError(404, 'dlp_exception_not_found', 'DLP exception not found');
    const conflict = checkDeleteVersion(request, exception.version);
    if (conflict) return conflict;
    state.exceptions = state.exceptions.filter((e) => e.id !== exception.id);
    return noContent();
  }),
};

// ---------------------------------------------------------------------------------------------
// Custom patterns and the pattern test (canned, never evaluated)
// ---------------------------------------------------------------------------------------------

/** The literal that makes the fixture refuse a pattern (`pattern_syntax`), like WP3's validate. */
export const FIXTURE_INVALID_PATTERN = 'EXAMPLE_INVALID';

function patternProblems(body: Body, create: boolean): string[] {
  const keywords = stringList(body, 'contextKeywords', { max: 20, itemMax: 64 });
  return [
    ...unknownKeys(body, [
      ...(create ? [] : ['version']),
      'name',
      'pattern',
      'caseInsensitive',
      'validator',
      'contextKeywords',
      'requireContext',
      'severity',
      'baseConfidence',
      'maskStyle',
      'enabled',
    ]),
    textProblem(body, 'name', 1, 128, create),
    body.pattern === undefined
      ? create
        ? 'pattern: Required'
        : null
      : typeof body.pattern === 'string' && body.pattern.length >= 1 && body.pattern.length <= 512
        ? null
        : 'pattern: Expected 1 to 512 characters',
    enumProblem(body, 'validator', VALIDATORS, false),
    enumProblem(body, 'severity', SEVERITIES, create),
    enumProblem(body, 'maskStyle', MASK_STYLES, false),
    confidenceProblem(body, 'baseConfidence'),
    ...keywords.problems,
  ].filter((p): p is string => p !== null);
}

function refusedPattern(pattern: unknown): FixtureResponse | null {
  return typeof pattern === 'string' && pattern.includes(FIXTURE_INVALID_PATTERN)
    ? apiError(400, 'pattern_syntax', 'The custom pattern was refused by the safety validation', {
        repetitionProduct: 0,
        length: pattern.length,
      })
    : null;
}

function patternTest(request: FixtureRequest): FixtureResponse {
  const caller = resolveFixturePrincipal(request.token)?.userId ?? 'anonymous';
  const now = Date.now();
  const recent = (store.patternTests.get(caller) ?? []).filter((t) => t > now - 60_000);
  if (recent.length >= FIXTURE_DLP_BEC_LIMITS.patternTestsPerMinute) {
    const retryAfter = Math.max(1, Math.ceil(((recent[0] ?? now) + 60_000 - now) / 1000));
    store.patternTests.set(caller, recent);
    return {
      ...apiError(429, 'rate_limited', 'Too many requests', { scope: 'route' }),
      headers: { 'retry-after': String(retryAfter) },
    };
  }
  store.patternTests.set(caller, [...recent, now]);
  const body = bodyOf(request);
  const problems = [
    ...unknownKeys(body, [
      'pattern',
      'caseInsensitive',
      'validator',
      'contextKeywords',
      'requireContext',
      'maskStyle',
      'sample',
    ]),
    typeof body.pattern === 'string' && body.pattern.length <= 1024
      ? null
      : 'pattern: Expected a string of at most 1024 characters',
    typeof body.sample === 'string' && body.sample.length <= 4096
      ? null
      : 'sample: Expected a string of at most 4096 characters',
    enumProblem(body, 'validator', VALIDATORS, false),
    enumProblem(body, 'maskStyle', MASK_STYLES, false),
  ].filter((p): p is string => p !== null);
  if (problems.length) return invalid(problems);
  const pattern = String(body.pattern);
  const sample = String(body.sample);
  const labelled = { 'x-eg-dev-fixture': 'canned pattern test; the pattern was not evaluated' };
  if (pattern.includes(FIXTURE_INVALID_PATTERN)) {
    return {
      ...ok('DlpPatternsController_test_v1', {
        valid: false,
        code: 'pattern_syntax',
        complexity: { repetitionProduct: 0, length: pattern.length },
        matches: [],
      }),
      headers: labelled,
    };
  }
  return {
    ...ok('DlpPatternsController_test_v1', {
      valid: true,
      code: null,
      complexity: { repetitionProduct: 1, length: pattern.length },
      matches: sample
        ? [
            {
              start: 0,
              end: 0,
              masked: CANNED_PATTERN_MATCH,
              validated: false,
              contextMatched: false,
            },
          ]
        : [],
    }),
    headers: labelled,
  };
}

const dlpPatterns: FixtureHandlers = {
  DlpPatternsController_list_v1: handler((request, state) =>
    ok(
      'DlpPatternsController_list_v1',
      page(
        state.patterns.filter((p) => flag(request.query, 'enabled', p.enabled)),
        request.query,
      ),
    ),
  ),
  DlpPatternsController_get_v1: handler((request, state) => {
    const pattern = state.patterns.find((p) => p.id === request.params.id);
    return pattern
      ? ok('DlpPatternsController_get_v1', pattern)
      : apiError(404, 'dlp_pattern_not_found', 'DLP custom pattern not found');
  }),
  DlpPatternsController_create_v1: handler((request, state) => {
    const body = bodyOf(request);
    const problems = patternProblems(body, true);
    if (problems.length) return invalid(problems);
    const refused = refusedPattern(body.pattern);
    if (refused) return refused;
    const name = String(body.name).trim();
    const taken = state.patterns.find((p) => sameName(p.name, name));
    if (taken)
      return apiError(409, 'dlp_pattern_exists', 'A custom pattern with this name exists', {
        id: taken.id,
      });
    if (state.patterns.length >= FIXTURE_DLP_BEC_LIMITS.patterns) {
      return limitReached('pattern', FIXTURE_DLP_BEC_LIMITS.patterns);
    }
    const at = nowIso();
    const pattern: Pattern = {
      id: newId(),
      name,
      pattern: String(body.pattern),
      caseInsensitive: body.caseInsensitive === true,
      validator: (body.validator as Pattern['validator'] | undefined) ?? 'none',
      contextKeywords: (body.contextKeywords as string[] | undefined) ?? [],
      requireContext: body.requireContext === true,
      severity: body.severity as Pattern['severity'],
      baseConfidence: (body.baseConfidence as number | undefined) ?? 0.8,
      maskStyle: (body.maskStyle as Pattern['maskStyle'] | undefined) ?? 'last4',
      enabled: body.enabled !== false,
      version: 1,
      createdByUserId: actorOf(request),
      updatedByUserId: actorOf(request),
      createdAt: at,
      updatedAt: at,
    };
    state.patterns.unshift(pattern);
    return ok('DlpPatternsController_create_v1', pattern, 201);
  }),
  DlpPatternsController_update_v1: handler((request, state) => {
    const pattern = state.patterns.find((p) => p.id === request.params.id);
    if (!pattern) return apiError(404, 'dlp_pattern_not_found', 'DLP custom pattern not found');
    const body = bodyOf(request);
    const problems = patternProblems(body, false);
    if (problems.length) return invalid(problems);
    const conflict = checkVersion(body, pattern.version);
    if (conflict) return conflict;
    const refused = refusedPattern(body.pattern);
    if (refused) return refused;
    if (typeof body.name === 'string') {
      const taken = state.patterns.find(
        (p) => p.id !== pattern.id && sameName(p.name, String(body.name)),
      );
      if (taken)
        return apiError(409, 'dlp_pattern_exists', 'A custom pattern with this name exists', {
          id: taken.id,
        });
    }
    const { version: _version, ...changes } = body;
    void _version;
    Object.assign(pattern, {
      ...changes,
      ...(typeof body.name === 'string' ? { name: body.name.trim() } : {}),
      version: pattern.version + 1,
      updatedByUserId: actorOf(request),
      updatedAt: nowIso(),
    });
    return ok('DlpPatternsController_update_v1', pattern);
  }),
  DlpPatternsController_remove_v1: handler((request, state) => {
    const pattern = state.patterns.find((p) => p.id === request.params.id);
    if (!pattern) return apiError(404, 'dlp_pattern_not_found', 'DLP custom pattern not found');
    const conflict = checkDeleteVersion(request, pattern.version);
    if (conflict) return conflict;
    const references = [...state.rules.values()]
      .flat()
      .filter((r) => r.conditions.selectors.customPatternIds?.includes(pattern.id)).length;
    if (references > 0) {
      return apiError(409, 'dlp_pattern_in_use', 'Rules select this custom pattern', {
        references,
      });
    }
    state.patterns = state.patterns.filter((p) => p.id !== pattern.id);
    return noContent();
  }),
  DlpPatternsController_test_v1: guarded(patternTest),
};

// ---------------------------------------------------------------------------------------------
// Keyword dictionaries
// ---------------------------------------------------------------------------------------------

/** `dictionary_terms_count` / `dictionary_term_invalid` (`index`; never the term). */
function termsRefusal(terms: unknown): FixtureResponse | null {
  if (terms === undefined) return null;
  if (
    !Array.isArray(terms) ||
    terms.length < 1 ||
    terms.length > FIXTURE_DLP_BEC_LIMITS.dictionaryTerms
  ) {
    return apiError(400, 'dictionary_terms_count', 'The dictionary terms were refused');
  }
  const seen = new Set<string>();
  for (let index = 0; index < terms.length; index += 1) {
    const term: unknown = terms[index];
    const normal = typeof term === 'string' ? term.trim().toLowerCase().replace(/\s+/g, ' ') : '';
    const tokens = normal ? normal.split(' ').length : 0;
    if (!normal || normal.length > 64 || tokens > 8 || seen.has(normal)) {
      return apiError(400, 'dictionary_term_invalid', 'The dictionary terms were refused', {
        index,
      });
    }
    seen.add(normal);
  }
  return null;
}

function dictionaryProblems(body: Body, create: boolean): string[] {
  return [
    ...unknownKeys(body, [
      ...(create ? [] : ['version']),
      'name',
      'category',
      'terms',
      'severity',
      'baseConfidence',
      'minMatches',
      'enabled',
    ]),
    textProblem(body, 'name', 1, 128, create),
    enumProblem(body, 'category', DICTIONARY_CATEGORIES, create),
    enumProblem(body, 'severity', SEVERITIES, create),
    create && body.terms === undefined ? 'terms: Required' : null,
    confidenceProblem(body, 'baseConfidence'),
    intProblem(body, 'minMatches', 1, 100),
  ].filter((p): p is string => p !== null);
}

const listView = (d: Dictionary): ListItem<'DlpDictionariesController_list_v1'> => {
  const { terms, ...row } = d;
  return { ...row, termCount: terms.length };
};

const dlpDictionaries: FixtureHandlers = {
  DlpDictionariesController_list_v1: handler((request, state) =>
    ok(
      'DlpDictionariesController_list_v1',
      page(
        state.dictionaries.filter((d) => flag(request.query, 'enabled', d.enabled)).map(listView),
        request.query,
      ),
    ),
  ),
  DlpDictionariesController_get_v1: handler((request, state) => {
    const dictionary = state.dictionaries.find((d) => d.id === request.params.id);
    return dictionary
      ? ok('DlpDictionariesController_get_v1', dictionary)
      : apiError(404, 'dlp_dictionary_not_found', 'DLP keyword dictionary not found');
  }),
  DlpDictionariesController_create_v1: handler((request, state) => {
    const body = bodyOf(request);
    const problems = dictionaryProblems(body, true);
    if (problems.length) return invalid(problems);
    const refused = termsRefusal(body.terms);
    if (refused) return refused;
    const name = String(body.name).trim();
    const taken = state.dictionaries.find((d) => sameName(d.name, name));
    if (taken)
      return apiError(409, 'dlp_dictionary_exists', 'A keyword dictionary with this name exists', {
        id: taken.id,
      });
    if (state.dictionaries.length >= FIXTURE_DLP_BEC_LIMITS.dictionaries) {
      return limitReached('dictionary', FIXTURE_DLP_BEC_LIMITS.dictionaries);
    }
    const at = nowIso();
    const terms = (body.terms as string[]).map((t) => t.trim());
    const dictionary: Dictionary = {
      id: newId(),
      name,
      category: body.category as Dictionary['category'],
      terms,
      termCount: terms.length,
      severity: body.severity as Dictionary['severity'],
      baseConfidence: (body.baseConfidence as number | undefined) ?? 0.7,
      minMatches: (body.minMatches as number | undefined) ?? 1,
      enabled: body.enabled !== false,
      version: 1,
      createdByUserId: actorOf(request),
      updatedByUserId: actorOf(request),
      createdAt: at,
      updatedAt: at,
    };
    state.dictionaries.unshift(dictionary);
    return ok('DlpDictionariesController_create_v1', dictionary, 201);
  }),
  DlpDictionariesController_update_v1: handler((request, state) => {
    const dictionary = state.dictionaries.find((d) => d.id === request.params.id);
    if (!dictionary)
      return apiError(404, 'dlp_dictionary_not_found', 'DLP keyword dictionary not found');
    const body = bodyOf(request);
    const problems = dictionaryProblems(body, false);
    if (problems.length) return invalid(problems);
    const conflict = checkVersion(body, dictionary.version);
    if (conflict) return conflict;
    const refused = termsRefusal(body.terms);
    if (refused) return refused;
    if (typeof body.name === 'string') {
      const taken = state.dictionaries.find(
        (d) => d.id !== dictionary.id && sameName(d.name, String(body.name)),
      );
      if (taken)
        return apiError(
          409,
          'dlp_dictionary_exists',
          'A keyword dictionary with this name exists',
          { id: taken.id },
        );
    }
    const { version: _version, ...changes } = body;
    void _version;
    const terms = Array.isArray(body.terms)
      ? (body.terms as string[]).map((t) => t.trim())
      : dictionary.terms;
    Object.assign(dictionary, {
      ...changes,
      ...(typeof body.name === 'string' ? { name: body.name.trim() } : {}),
      terms,
      termCount: terms.length,
      version: dictionary.version + 1,
      updatedByUserId: actorOf(request),
      updatedAt: nowIso(),
    });
    return ok('DlpDictionariesController_update_v1', dictionary);
  }),
  DlpDictionariesController_remove_v1: handler((request, state) => {
    const dictionary = state.dictionaries.find((d) => d.id === request.params.id);
    if (!dictionary)
      return apiError(404, 'dlp_dictionary_not_found', 'DLP keyword dictionary not found');
    const conflict = checkDeleteVersion(request, dictionary.version);
    if (conflict) return conflict;
    const references = [...state.rules.values()]
      .flat()
      .filter((r) => r.conditions.selectors.dictionaryIds?.includes(dictionary.id)).length;
    if (references > 0) {
      return apiError(409, 'dlp_dictionary_in_use', 'Rules select this keyword dictionary', {
        references,
      });
    }
    state.dictionaries = state.dictionaries.filter((d) => d.id !== dictionary.id);
    return noContent();
  }),
};

// ---------------------------------------------------------------------------------------------
// Compliance (Aadhaar basis: MFA, user only, Idempotency-Key) and incidents
// ---------------------------------------------------------------------------------------------

function requireMfa(request: FixtureRequest): FixtureResponse | null {
  return resolveFixturePrincipal(request.token)?.mfaAuthenticated
    ? null
    : apiError(403, 'mfa_required', 'This operation requires an MFA-authenticated session');
}

function complianceView(compliance: Compliance): Compliance {
  const a = compliance.aadhaar;
  const active =
    a.enabled &&
    a.attested &&
    a.basis !== null &&
    a.reference !== null &&
    a.reviewDueAt !== null &&
    Date.parse(a.reviewDueAt) > Date.now();
  return { ...compliance, aadhaar: { ...a, active } };
}

const dlpCompliance: FixtureHandlers = {
  DlpComplianceController_get_v1: handler((_request, state) =>
    ok('DlpComplianceController_get_v1', complianceView(state.compliance)),
  ),
  DlpComplianceController_enable_v1: handler((request, state) => {
    const mfa = requireMfa(request);
    if (mfa) return mfa;
    return idempotent(state.idempotency, request, () => {
      const body = bodyOf(request);
      const problems = [
        ...unknownKeys(body, ['expectedVersion', 'basis', 'reference', 'attested', 'reviewDueAt']),
        Number.isInteger(body.expectedVersion) ? null : 'expectedVersion: Required',
        enumProblem(body, 'basis', AADHAAR_BASES, true),
        textProblem(body, 'reference', 1, 256, true),
        body.attested === true ? null : 'attested: Invalid input: expected true',
        expiryProblem(body.reviewDueAt, 'reviewDueAt', 365, false),
      ].filter((p): p is string => p !== null);
      if (problems.length) return invalid(problems);
      if (body.expectedVersion !== state.compliance.version) {
        return versionConflict(state.compliance.version);
      }
      const at = nowIso();
      state.compliance = {
        aadhaar: {
          enabled: true,
          active: true,
          basis: body.basis as NonNullable<Compliance['aadhaar']['basis']>,
          reference: String(body.reference).trim(),
          attested: true,
          recordedByUserId: actorOf(request),
          recordedAt: at,
          reviewDueAt: String(body.reviewDueAt),
        },
        version: state.compliance.version + 1,
        updatedAt: at,
      };
      return ok('DlpComplianceController_enable_v1', complianceView(state.compliance));
    });
  }),
  DlpComplianceController_disable_v1: handler((request, state) => {
    const mfa = requireMfa(request);
    if (mfa) return mfa;
    return idempotent(state.idempotency, request, () => {
      const expected = request.query.get('expectedVersion');
      if (expected !== null && Number(expected) !== state.compliance.version) {
        return versionConflict(state.compliance.version);
      }
      if (!state.compliance.aadhaar.enabled) {
        return ok('DlpComplianceController_disable_v1', complianceView(state.compliance));
      }
      state.compliance = {
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
        version: state.compliance.version + 1,
        updatedAt: nowIso(),
      };
      return ok('DlpComplianceController_disable_v1', complianceView(state.compliance));
    });
  }),
  DlpIncidentsController_list_v1: handler((request, state) => {
    const q = request.query;
    const rows = state.incidents.filter(
      (i) =>
        (!q.get('action') || q.get('action') === i.action) &&
        (!q.get('direction') || q.get('direction') === i.direction),
    );
    return ok('DlpIncidentsController_list_v1', page(rows, q));
  }),
};

// ---------------------------------------------------------------------------------------------
// BEC executives, vendors, trusted senders, feedback (read) and suppressions (lift)
// ---------------------------------------------------------------------------------------------

function listProblems(body: Body, key: string, max: number, itemMin: number, itemMax: number) {
  return stringList(body, key, { max, itemMin, itemMax }).problems;
}

const executiveNotFound = () =>
  apiError(404, 'bec_executive_not_found', 'Executive profile not found');
const vendorNotFound = () => apiError(404, 'bec_vendor_not_found', 'Vendor profile not found');

const becProfiles: FixtureHandlers = {
  BecExecutivesController_list_v1: handler((request, state) =>
    ok(
      'BecExecutivesController_list_v1',
      page(
        state.executives.filter((e) => flag(request.query, 'enabled', e.enabled)),
        request.query,
      ),
    ),
  ),
  BecExecutivesController_get_v1: handler((request, state) => {
    const executive = state.executives.find((e) => e.id === request.params.id);
    return executive ? ok('BecExecutivesController_get_v1', executive) : executiveNotFound();
  }),
  BecExecutivesController_create_v1: handler((request, state) => {
    const body = bodyOf(request);
    const problems = [
      ...unknownKeys(body, ['displayName', 'aliases', 'knownAddresses', 'title', 'enabled']),
      textProblem(body, 'displayName', 2, 128, true),
      body.title === null ? null : textProblem(body, 'title', 1, 128, false),
      ...listProblems(body, 'aliases', 10, 2, 128),
      ...listProblems(body, 'knownAddresses', 20, 3, 320),
    ].filter((p): p is string => p !== null);
    if (problems.length) return invalid(problems);
    const displayName = String(body.displayName).trim();
    const key = normalizedName(displayName);
    const taken = state.executives.find((e) => e.normalizedName === key);
    if (taken)
      return apiError(
        409,
        'executive_exists',
        'An executive profile with this normalized name exists',
        { id: taken.id },
      );
    if (state.executives.length >= FIXTURE_DLP_BEC_LIMITS.executives) {
      return limitReached('bec_executive', FIXTURE_DLP_BEC_LIMITS.executives);
    }
    const at = nowIso();
    const executive: Executive = {
      id: newId(),
      displayName,
      normalizedName: key,
      aliases: ((body.aliases as string[] | undefined) ?? []).map((a) => a.trim()),
      knownAddresses: [
        ...new Set(
          ((body.knownAddresses as string[] | undefined) ?? []).map((a) => a.trim().toLowerCase()),
        ),
      ],
      title: typeof body.title === 'string' ? body.title.trim() : null,
      enabled: body.enabled !== false,
      updatedByUserId: actorOf(request),
      version: 1,
      createdByUserId: actorOf(request),
      createdAt: at,
      updatedAt: at,
    };
    state.executives.unshift(executive);
    return ok('BecExecutivesController_create_v1', executive, 201);
  }),
  BecExecutivesController_update_v1: handler((request, state) => {
    const executive = state.executives.find((e) => e.id === request.params.id);
    if (!executive) return executiveNotFound();
    const body = bodyOf(request);
    const problems = [
      ...unknownKeys(body, [
        'version',
        'displayName',
        'aliases',
        'knownAddresses',
        'title',
        'enabled',
      ]),
      textProblem(body, 'displayName', 2, 128, false),
      body.title === null ? null : textProblem(body, 'title', 1, 128, false),
      ...listProblems(body, 'aliases', 10, 2, 128),
      ...listProblems(body, 'knownAddresses', 20, 3, 320),
    ].filter((p): p is string => p !== null);
    if (problems.length) return invalid(problems);
    const conflict = checkVersion(body, executive.version);
    if (conflict) return conflict;
    if (typeof body.displayName === 'string') {
      const key = normalizedName(body.displayName);
      const taken = state.executives.find((e) => e.id !== executive.id && e.normalizedName === key);
      if (taken)
        return apiError(
          409,
          'executive_exists',
          'An executive profile with this normalized name exists',
          { id: taken.id },
        );
    }
    Object.assign(executive, {
      ...(typeof body.displayName === 'string'
        ? { displayName: body.displayName.trim(), normalizedName: normalizedName(body.displayName) }
        : {}),
      ...(Array.isArray(body.aliases) ? { aliases: body.aliases } : {}),
      ...(Array.isArray(body.knownAddresses)
        ? {
            knownAddresses: [
              ...new Set((body.knownAddresses as string[]).map((a) => a.trim().toLowerCase())),
            ],
          }
        : {}),
      ...('title' in body
        ? { title: typeof body.title === 'string' ? body.title.trim() : null }
        : {}),
      ...(typeof body.enabled === 'boolean' ? { enabled: body.enabled } : {}),
      version: executive.version + 1,
      updatedByUserId: actorOf(request),
      updatedAt: nowIso(),
    });
    return ok('BecExecutivesController_update_v1', executive);
  }),
  BecExecutivesController_remove_v1: handler((request, state) => {
    const executive = state.executives.find((e) => e.id === request.params.id);
    if (!executive) return executiveNotFound();
    const conflict = checkDeleteVersion(request, executive.version);
    if (conflict) return conflict;
    state.executives = state.executives.filter((e) => e.id !== executive.id);
    return noContent();
  }),
  BecVendorsController_list_v1: handler((request, state) =>
    ok(
      'BecVendorsController_list_v1',
      page(
        state.vendors.filter((v) => flag(request.query, 'enabled', v.enabled)),
        request.query,
      ),
    ),
  ),
  BecVendorsController_get_v1: handler((request, state) => {
    const vendor = state.vendors.find((v) => v.id === request.params.id);
    return vendor ? ok('BecVendorsController_get_v1', vendor) : vendorNotFound();
  }),
  BecVendorsController_create_v1: handler((request, state) => vendorWrite(request, state, null)),
  BecVendorsController_update_v1: handler((request, state) => {
    const vendor = state.vendors.find((v) => v.id === request.params.id);
    return vendor ? vendorWrite(request, state, vendor) : vendorNotFound();
  }),
  BecVendorsController_remove_v1: handler((request, state) => {
    const vendor = state.vendors.find((v) => v.id === request.params.id);
    if (!vendor) return vendorNotFound();
    const conflict = checkDeleteVersion(request, vendor.version);
    if (conflict) return conflict;
    state.vendors = state.vendors.filter((v) => v.id !== vendor.id);
    return noContent();
  }),
};

function vendorWrite(
  request: FixtureRequest,
  state: OrgState,
  vendor: Vendor | null,
): FixtureResponse {
  const body = bodyOf(request);
  const create = vendor === null;
  const domains = stringList(body, 'domains', { min: 1, max: 20, itemMax: 253 });
  const problems = [
    ...unknownKeys(body, [
      ...(create ? [] : ['version']),
      'name',
      'aliases',
      'domains',
      'knownSenders',
      'paymentChangeSensitive',
      'enabled',
    ]),
    textProblem(body, 'name', 2, 128, create),
    create && body.domains === undefined ? 'domains: Required' : null,
    ...domains.problems,
    ...listProblems(body, 'aliases', 10, 2, 128),
    ...listProblems(body, 'knownSenders', 50, 3, 320),
  ].filter((p): p is string => p !== null);
  if (problems.length) return invalid(problems);
  if (vendor) {
    const conflict = checkVersion(body, vendor.version);
    if (conflict) return conflict;
  }
  const freemail = (domains.value ?? []).findIndex(isFreemail);
  if (freemail >= 0) {
    return apiError(
      422,
      'vendor_domain_freemail',
      'A free-mail domain cannot be a vendor domain; list the vendor addresses as knownSenders',
      { index: freemail },
    );
  }
  if (typeof body.name === 'string') {
    const key = normalizedName(body.name);
    const taken = state.vendors.find((v) => v.id !== vendor?.id && v.normalizedName === key);
    if (taken)
      return apiError(409, 'vendor_exists', 'A vendor profile with this normalized name exists', {
        id: taken.id,
      });
  }
  const at = nowIso();
  const lower = (list: unknown) => [
    ...new Set((list as string[]).map((v) => v.trim().toLowerCase())),
  ];
  if (!vendor) {
    if (state.vendors.length >= FIXTURE_DLP_BEC_LIMITS.vendors) {
      return limitReached('bec_vendor', FIXTURE_DLP_BEC_LIMITS.vendors);
    }
    const created: Vendor = {
      id: newId(),
      name: String(body.name).trim(),
      normalizedName: normalizedName(String(body.name)),
      aliases: ((body.aliases as string[] | undefined) ?? []).map((a) => a.trim()),
      domains: lower(body.domains),
      knownSenders: lower(body.knownSenders ?? []),
      paymentChangeSensitive: body.paymentChangeSensitive !== false,
      enabled: body.enabled !== false,
      updatedByUserId: actorOf(request),
      version: 1,
      createdByUserId: actorOf(request),
      createdAt: at,
      updatedAt: at,
    };
    state.vendors.unshift(created);
    return ok('BecVendorsController_create_v1', created, 201);
  }
  Object.assign(vendor, {
    ...(typeof body.name === 'string'
      ? { name: body.name.trim(), normalizedName: normalizedName(body.name) }
      : {}),
    ...(Array.isArray(body.aliases) ? { aliases: body.aliases } : {}),
    ...(Array.isArray(body.domains) ? { domains: lower(body.domains) } : {}),
    ...(Array.isArray(body.knownSenders) ? { knownSenders: lower(body.knownSenders) } : {}),
    ...(typeof body.paymentChangeSensitive === 'boolean'
      ? { paymentChangeSensitive: body.paymentChangeSensitive }
      : {}),
    ...(typeof body.enabled === 'boolean' ? { enabled: body.enabled } : {}),
    version: vendor.version + 1,
    updatedByUserId: actorOf(request),
    updatedAt: at,
  });
  return ok('BecVendorsController_update_v1', vendor);
}

const withTrustExpiry = (t: Trusted): Trusted => ({
  ...t,
  expired: t.expiresAt !== null && Date.parse(t.expiresAt) <= Date.now(),
});
const trustedNotFound = () =>
  apiError(404, 'bec_trusted_sender_not_found', 'Trusted sender not found');

const becSenders: FixtureHandlers = {
  BecTrustedSendersController_list_v1: handler((request, state) =>
    ok(
      'BecTrustedSendersController_list_v1',
      page(
        state.trusted
          .map(withTrustExpiry)
          .filter((t) => !request.query.get('kind') || request.query.get('kind') === t.kind),
        request.query,
      ),
    ),
  ),
  BecTrustedSendersController_create_v1: handler((request, state) => {
    const body = bodyOf(request);
    const problems = [
      ...unknownKeys(body, ['kind', 'value', 'reason', 'expiresAt']),
      enumProblem(body, 'kind', ['address', 'domain'], true),
      textProblem(body, 'value', 3, 320, true),
      textProblem(body, 'reason', 1, 512, true),
      body.expiresAt === undefined ? null : expiryProblem(body.expiresAt, 'expiresAt', 365, true),
    ].filter((p): p is string => p !== null);
    if (problems.length) return invalid(problems);
    const kind = body.kind as Trusted['kind'];
    const value = String(body.value).trim().toLowerCase();
    if (kind === 'address' && !/^[^\s@]+@[^\s@]+$/.test(value)) {
      return invalid(['value: Expected an e-mail address']);
    }
    if (kind === 'domain' && isFreemail(value)) {
      return apiError(
        422,
        'trusted_domain_freemail',
        'A free-mail domain cannot be a trusted sender domain; trust the address instead',
      );
    }
    const taken = state.trusted.find((t) => t.kind === kind && t.value === value);
    if (taken)
      return apiError(409, 'trusted_sender_exists', 'This trusted sender exists', { id: taken.id });
    if (state.trusted.length >= FIXTURE_DLP_BEC_LIMITS.trustedSenders) {
      return limitReached('bec_trusted_sender', FIXTURE_DLP_BEC_LIMITS.trustedSenders);
    }
    const at = nowIso();
    const trusted: Trusted = {
      id: newId(),
      kind,
      value,
      reason: String(body.reason).trim(),
      expiresAt: typeof body.expiresAt === 'string' ? body.expiresAt : null,
      expired: false,
      version: 1,
      createdByUserId: actorOf(request),
      createdAt: at,
      updatedAt: at,
    };
    state.trusted.unshift(trusted);
    return ok('BecTrustedSendersController_create_v1', trusted, 201);
  }),
  BecTrustedSendersController_update_v1: handler((request, state) => {
    const trusted = state.trusted.find((t) => t.id === request.params.id);
    if (!trusted) return trustedNotFound();
    const body = bodyOf(request);
    const problems = [
      ...unknownKeys(body, ['version', 'reason', 'expiresAt']),
      textProblem(body, 'reason', 1, 512, false),
      body.expiresAt === undefined ? null : expiryProblem(body.expiresAt, 'expiresAt', 365, true),
    ].filter((p): p is string => p !== null);
    if (problems.length) return invalid(problems);
    const conflict = checkVersion(body, trusted.version);
    if (conflict) return conflict;
    Object.assign(trusted, {
      ...(typeof body.reason === 'string' ? { reason: body.reason.trim() } : {}),
      ...('expiresAt' in body ? { expiresAt: body.expiresAt ?? null } : {}),
      version: trusted.version + 1,
      updatedAt: nowIso(),
    });
    return ok('BecTrustedSendersController_update_v1', withTrustExpiry(trusted));
  }),
  BecTrustedSendersController_remove_v1: handler((request, state) => {
    const trusted = state.trusted.find((t) => t.id === request.params.id);
    if (!trusted) return trustedNotFound();
    const conflict = checkDeleteVersion(request, trusted.version);
    if (conflict) return conflict;
    state.trusted = state.trusted.filter((t) => t.id !== trusted.id);
    return noContent();
  }),
  BecFeedbackController_list_v1: handler((request, state) =>
    ok(
      'BecFeedbackController_list_v1',
      page(
        state.feedback.filter(
          (f) => !request.query.get('kind') || request.query.get('kind') === f.kind,
        ),
        request.query,
      ),
    ),
  ),
  BecFeedbackController_listSuppressions_v1: handler((request, state) => {
    const rows = state.suppressions.map((s) => ({
      ...s,
      expired: Date.parse(s.expiresAt) <= Date.now(),
    }));
    return ok(
      'BecFeedbackController_listSuppressions_v1',
      page(
        rows.filter((s) => flag(request.query, 'active', !s.expired)),
        request.query,
      ),
    );
  }),
  BecFeedbackController_deleteSuppression_v1: handler((request, state) => {
    const suppression = state.suppressions.find((s) => s.id === request.params.id);
    if (!suppression)
      return apiError(404, 'bec_suppression_not_found', 'Suppression rule not found');
    state.suppressions = state.suppressions.filter((s) => s.id !== suppression.id);
    return noContent();
  }),
};

/** Every DLP and BEC operation the portal's DLP and BEC tabs call (the fixture test checks it). */
export const DLP_BEC_OPERATIONS: readonly OperationId[] = [
  ...Object.keys(dlpPolicies),
  ...Object.keys(dlpExceptions),
  ...Object.keys(dlpPatterns),
  ...Object.keys(dlpDictionaries),
  ...Object.keys(dlpCompliance),
  ...Object.keys(becProfiles),
  ...Object.keys(becSenders),
] as OperationId[];

export const fixtures: FixtureHandlers = {
  ...dlpPolicies,
  ...dlpExceptions,
  ...dlpPatterns,
  ...dlpDictionaries,
  ...dlpCompliance,
  ...becProfiles,
  ...becSenders,
};
