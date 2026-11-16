import 'server-only';
import { createHash } from 'node:crypto';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { fixtureAnchor, stableUuid } from '../generator';
import { apiError, type FixtureRequest, type FixtureResponse } from '../types';

export { DEV_MOCK_MARKER } from '../types';

/**
 * The in-memory, per-process store behind the policy fixtures of dev fixture mode (step 7.3
 * design B15): per organization, the email policies with their versions (superseded legacy,
 * published, active, newer published-not-active, drafts), the policy settings, the risk-profile
 * versions, the organization generation and the audit rows of every change. Mutations follow
 * the api's rules: compare-and-set on row versions (`409 policy_conflict` with
 * `currentRowVersion`), immutable published versions, generation increments, Idempotency-Key
 * replays. Definitions are valid `policy-dsl/1` documents by construction (shapes of
 * docs/architecture/policy-dsl.md); validation answers are canned (`EXAMPLE_INVALID`), nothing
 * is ever evaluated. Everything is synthetic; state lives on globalThis (each `next dev` route
 * handler is its own bundle).
 */

export type Policy = SuccessBody<'PolicyManagementController_get_v1'>;
export type PolicyRow = ListItem<'PolicyManagementController_list_v1'>;
export type Version = SuccessBody<'PolicyManagementController_getVersion_v1'>;
export type VersionRow = ListItem<'PolicyManagementController_listVersions_v1'>;
export type Settings = SuccessBody<'PolicySettingsController_get_v1'>;
export type AuditRow = ListItem<'AuditLogsController_search_v1'>;
type Violation = { path: string; code: string; message: string };
type Direction = Policy['direction'];

const DAY = 86_400_000;
const anchor = fixtureAnchor();
const iso = (daysAgo: number) => new Date(anchor - daysAgo * DAY).toISOString();
export const DSL = 'policy-dsl/1';
/** The literal that makes a canned validation fail (design B15). */
export const INVALID_LITERAL = 'EXAMPLE_INVALID';
export const POLICY_LIMIT = 100;
export const VERSION_LIMIT = 200;

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Canonical JSON (sorted keys), as the api hashes definitions. */
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

export const sha256 = (value: unknown): string =>
  createHash('sha256').update(canonical(value)).digest('hex');

/** The first JSON path whose key or string value contains `needle` (a plain walk). */
export function firstPathContaining(value: unknown, needle: string, path = ''): string | null {
  if (typeof value === 'string') return value.includes(needle) ? path : null;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      const found = firstPathContaining(value[i], needle, `${path}[${i}]`);
      if (found !== null) return found;
    }
    return null;
  }
  if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      const child = path ? `${path}.${key}` : key;
      if (key.includes(needle)) return child;
      const found = firstPathContaining(item, needle, child);
      if (found !== null) return found;
    }
  }
  return null;
}

/**
 * The canned validation of a definition (design B15): a non-object or another DSL version is
 * refused at `dslVersion`; otherwise valid unless the document contains `EXAMPLE_INVALID`, then
 * one `value_invalid` violation at the first path containing it. Never a real DSL check.
 */
export function cannedViolations(definition: unknown): Violation[] {
  if (!isRecord(definition) || definition.dslVersion !== DSL) {
    return [
      {
        path: 'dslVersion',
        code: 'version_unsupported',
        message: 'The document is not a policy-dsl/1 document',
      },
    ];
  }
  const path = firstPathContaining(definition, INVALID_LITERAL);
  return path === null
    ? []
    : [
        {
          path,
          code: 'value_invalid',
          message: `The value is not accepted (dev fixture: it contains ${INVALID_LITERAL})`,
        },
      ];
}

function rulesOf(definition: unknown): Record<string, unknown>[] {
  return isRecord(definition) && Array.isArray(definition.rules)
    ? definition.rules.filter(isRecord)
    : [];
}

export const ruleCountOf = (definition: unknown) => rulesOf(definition).length;
export const hasOverrideRules = (definition: unknown) =>
  rulesOf(definition).some((rule) => rule.override === true);

/** Department and user ids of `*.department` / `*.user` conditions (a plain JSON walk). */
export function referencesOf(definition: unknown): { departmentIds: string[]; userIds: string[] } {
  const departments = new Set<string>();
  const users = new Set<string>();
  const walk = (node: unknown) => {
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (!isRecord(node)) return;
    if (typeof node.field === 'string' && Array.isArray(node.value)) {
      const target = node.field.endsWith('.department')
        ? departments
        : node.field.endsWith('.user')
          ? users
          : null;
      for (const id of node.value) if (target && typeof id === 'string') target.add(id);
    }
    Object.values(node).forEach(walk);
  };
  walk(definition);
  return { departmentIds: [...departments], userIds: [...users] };
}

// ---------------------------------------------------------------------------------------------
// Seeds (valid policy-dsl/1 documents; the shapes of docs/architecture/policy-dsl.md §11)
// ---------------------------------------------------------------------------------------------

interface SeedVersion {
  readonly status: 'draft' | 'published' | 'superseded';
  readonly definition: unknown;
  readonly changeNote: string | null;
  readonly daysAgo: number;
}

interface PolicySeed {
  readonly key: string;
  readonly name: string;
  readonly description: string | null;
  /** `draft` = never activated; `disabled` keeps its active version. */
  readonly status: Policy['status'];
  readonly active: number | null;
  readonly versions: readonly SeedVersion[];
}

const doc = (direction: Direction, priority: number, rules: unknown[], exceptions?: unknown[]) => ({
  dslVersion: DSL,
  direction,
  priority,
  rules,
  ...(exceptions ? { exceptions } : {}),
});

function inboundThreatRules(
  organizationId: string,
  options: { highScore?: number; documents?: boolean; links?: boolean } = {},
) {
  const security = stableUuid(`${organizationId}:department:3`);
  const rules: unknown[] = [
    {
      id: 'block-high-risk',
      priority: 10,
      description: 'High and critical risk, or a malicious link from an untrusted sender',
      when: {
        any: [
          options.highScore
            ? { field: 'risk.score', op: 'gte', value: options.highScore }
            : { field: 'risk.level', op: 'gte', value: 'high' },
          {
            all: [
              { field: 'url.verdict', op: 'equals', value: 'malicious', quantifier: 'any' },
              { not: { field: 'sender.trusted', op: 'is', value: true } },
            ],
          },
        ],
      },
      unless: [{ field: 'recipient.department', op: 'in', value: [security], quantifier: 'all' }],
      actions: [{ type: 'QUARANTINE' }, { type: 'ALERT', severity: 'warning' }],
    },
    {
      id: 'suspicious-bec',
      priority: 20,
      description: 'Deterministic BEC suspicions wait for approval',
      when: { field: 'bec.deterministic_verdict', op: 'in', value: ['suspicious', 'malicious'] },
      actions: [
        { type: 'REQUIRE_APPROVAL' },
        { type: 'TAG', label: 'bec-review', subjectPrefix: '[REVIEW]' },
      ],
    },
    {
      id: 'tag-external',
      priority: 30,
      when: { field: 'sender.envelope.domain', op: 'not_in', value: ['alpha.example.test'] },
      actions: [{ type: 'TAG', label: 'external', subjectPrefix: '[EXTERNAL]' }],
      stop: false,
    },
  ];
  if (options.documents) {
    rules.push({
      id: 'unauthenticated-documents',
      priority: 15,
      description: 'Documents from senders that fail DMARC get a caution banner',
      when: {
        all: [
          { field: 'attachment.type_family', op: 'equals', value: 'document', quantifier: 'any' },
          { field: 'auth.dmarc', op: 'in', value: ['fail', 'none'] },
        ],
      },
      actions: [{ type: 'WARN', level: 'caution', text: 'Check the attachment before opening it' }],
    });
  }
  if (options.links) {
    rules.push({
      id: 'links-rewritten',
      priority: 40,
      when: { field: 'urls.count', op: 'gt', value: 0 },
      actions: [{ type: 'URL_REWRITE', ifNotRewritten: 'quarantine' }],
    });
  }
  return rules;
}

const SCANNER_EXCEPTION = [
  { field: 'sender.authenticated.domain', op: 'domain_in', value: ['scanner.alpha.example.test'] },
];

function seeds(organizationId: string): PolicySeed[] {
  const finance = stableUuid(`${organizationId}:department:0`);
  const executive = stableUuid(`${organizationId}:department:1`);
  return [
    {
      key: 'inbound-threats',
      name: 'Inbound threat response',
      description: 'Quarantine high-risk inbound mail, hold BEC suspicions, tag external mail.',
      status: 'active',
      active: 3,
      versions: [
        {
          status: 'superseded',
          // A retired pre-DSL row (legacy rows have no dslVersion): shown as JSON only.
          definition: { version: 1, rules: [{ match: 'risk >= 600', action: 'quarantine' }] },
          changeNote: 'Imported from the legacy rule set',
          daysAgo: 120,
        },
        {
          status: 'published',
          definition: doc('inbound', 10, [
            {
              id: 'block-high-risk',
              priority: 10,
              description: 'High and critical risk is quarantined',
              when: { field: 'risk.level', op: 'gte', value: 'high' },
              actions: [{ type: 'QUARANTINE' }],
            },
          ]),
          changeNote: 'First DSL version',
          daysAgo: 90,
        },
        {
          status: 'published',
          definition: doc('inbound', 10, inboundThreatRules(organizationId), SCANNER_EXCEPTION),
          changeNote: 'Malicious links, BEC review and external tagging',
          daysAgo: 45,
        },
        {
          status: 'published',
          definition: doc(
            'inbound',
            10,
            inboundThreatRules(organizationId, { documents: true }),
            SCANNER_EXCEPTION,
          ),
          changeNote: 'Caution banner on unauthenticated documents (not activated yet)',
          daysAgo: 12,
        },
        {
          status: 'draft',
          definition: doc(
            'inbound',
            10,
            inboundThreatRules(organizationId, { documents: true, links: true, highScore: 700 }),
            SCANNER_EXCEPTION,
          ),
          changeNote: 'Require rewritten links; score threshold instead of level',
          daysAgo: 2,
        },
      ],
    },
    {
      key: 'exec-impersonation',
      name: 'Executive impersonation warning',
      description: 'Warn when mail claims to come from executives but fails DMARC.',
      status: 'active',
      active: 1,
      versions: [
        {
          status: 'published',
          definition: doc('inbound', 30, [
            {
              id: 'exec-impersonation',
              priority: 10,
              when: {
                all: [
                  {
                    field: 'sender.header_from.address',
                    op: 'in',
                    value: ['ceo@alpha.example.test', 'cfo@alpha.example.test'],
                  },
                  {
                    field: 'auth.dmarc',
                    op: 'in',
                    value: ['fail', 'none', 'temperror', 'permerror'],
                  },
                ],
              },
              actions: [
                {
                  type: 'WARN',
                  level: 'danger',
                  text: 'Possible executive impersonation',
                  subjectPrefix: '[CAUTION]',
                },
                { type: 'ALERT', severity: 'warning' },
              ],
            },
          ]),
          changeNote: 'Initial version',
          daysAgo: 60,
        },
        {
          status: 'draft',
          definition: doc('inbound', 30, [
            {
              id: 'exec-impersonation',
              priority: 10,
              when: {
                all: [
                  {
                    field: 'sender.header_from.address',
                    op: 'in',
                    value: [
                      'ceo@alpha.example.test',
                      'cfo@alpha.example.test',
                      'coo@alpha.example.test',
                    ],
                  },
                  {
                    field: 'auth.dmarc',
                    op: 'in',
                    value: ['fail', 'none', 'temperror', 'permerror'],
                  },
                ],
              },
              actions: [
                {
                  type: 'WARN',
                  level: 'danger',
                  text: 'Possible executive impersonation',
                  subjectPrefix: '[CAUTION]',
                },
                { type: 'ALERT', severity: 'critical' },
              ],
            },
          ]),
          changeNote: 'Add the COO; critical alerts',
          daysAgo: 1,
        },
      ],
    },
    {
      key: 'outbound-cards',
      name: 'Outbound card numbers need approval',
      description: null,
      status: 'active',
      active: 1,
      versions: [
        {
          status: 'published',
          definition: doc('outbound', 40, [
            {
              id: 'cards-external',
              priority: 10,
              when: {
                all: [
                  { field: 'dlp.categories', op: 'contains_any', value: ['payment_card'] },
                  {
                    field: 'recipient.domain',
                    op: 'not_in',
                    value: ['alpha.example.test'],
                    quantifier: 'any',
                  },
                ],
              },
              actions: [{ type: 'REQUIRE_APPROVAL' }, { type: 'ALERT', severity: 'info' }],
            },
          ]),
          changeNote: 'Initial version',
          daysAgo: 50,
        },
      ],
    },
    {
      key: 'finance-attachments',
      name: 'External attachments to finance',
      description: 'Quarantine external attachments unless every recipient is in finance.',
      status: 'active',
      active: 1,
      versions: [
        {
          status: 'published',
          definition: doc('inbound', 20, [
            {
              id: 'external-attachments',
              priority: 10,
              when: { field: 'attachments.count', op: 'gt', value: 0 },
              unless: [
                { field: 'recipient.department', op: 'in', value: [finance], quantifier: 'all' },
              ],
              actions: [{ type: 'QUARANTINE' }],
            },
          ]),
          changeNote: 'Invoices arrive this way',
          daysAgo: 40,
        },
      ],
    },
    {
      key: 'partner-allow',
      name: 'Partner newsletters',
      description: 'Allow authenticated partner mail over level-only recommendations.',
      status: 'disabled',
      active: 1,
      versions: [
        {
          status: 'published',
          definition: doc('inbound', 50, [
            {
              id: 'partner-allow',
              priority: 10,
              description: 'Authenticated partner mail is allowed over a level-only recommendation',
              when: {
                field: 'sender.authenticated.domain',
                op: 'domain_in',
                value: ['partner.example.test'],
              },
              actions: [{ type: 'ALLOW' }],
              override: true,
            },
          ]),
          changeNote: 'Override rule (needs the organization setting)',
          daysAgo: 30,
        },
      ],
    },
    {
      key: 'after-hours',
      name: 'After-hours outbound review',
      description: 'Outbound mail at night (New York time) waits in quarantine.',
      status: 'active',
      active: 1,
      versions: [
        {
          status: 'published',
          definition: doc('outbound', 60, [
            {
              id: 'after-hours',
              priority: 10,
              when: {
                field: 'time.window',
                op: 'within',
                value: {
                  timeZone: 'America/New_York',
                  days: ['mon', 'tue', 'wed', 'thu', 'fri'],
                  from: '19:00',
                  to: '07:00',
                },
              },
              actions: [{ type: 'QUARANTINE' }],
            },
          ]),
          changeNote: 'Trading desk control',
          daysAgo: 25,
        },
      ],
    },
    {
      key: 'disk-images',
      name: 'Block disk images',
      description: 'Disk images are a common malware carrier.',
      status: 'active',
      active: 1,
      versions: [
        {
          status: 'published',
          definition: doc('any', 70, [
            {
              id: 'no-disk-images',
              priority: 10,
              when: {
                any: [
                  {
                    field: 'attachment.extension',
                    op: 'in',
                    value: ['iso', 'img', 'vhd', 'vhdx'],
                  },
                  { field: 'attachment.type_family', op: 'equals', value: 'disk_image' },
                ],
              },
              actions: [{ type: 'REJECT', notifySender: false }],
            },
          ]),
          changeNote: 'Initial version',
          daysAgo: 20,
        },
      ],
    },
    {
      key: 'executive-archive',
      name: 'Archive executive mail',
      description: 'Draft for the archive rollout (step 8.1).',
      status: 'draft',
      active: null,
      versions: [
        {
          status: 'draft',
          definition: doc('any', 100, [
            {
              id: 'executive-archive',
              priority: 10,
              when: {
                any: [
                  { field: 'recipient.department', op: 'in', value: [executive] },
                  { field: 'sender.department', op: 'in', value: [executive] },
                ],
              },
              actions: [{ type: 'ARCHIVE' }],
            },
          ]),
          changeNote: null,
          daysAgo: 3,
        },
      ],
    },
  ];
}

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

export interface StoredVersion {
  versionNo: number;
  status: 'draft' | 'published' | 'superseded';
  definition: unknown;
  changeNote: string | null;
  rowVersion: number;
  createdBy: string | null;
  updatedBy: string | null;
  publishedBy: string | null;
  createdAt: string;
  updatedAt: string;
  publishedAt: string | null;
  deleted: boolean;
}

export interface StoredPolicy {
  id: string;
  name: string;
  description: string | null;
  status: Policy['status'];
  activeVersionNo: number | null;
  rowVersion: number;
  archived: boolean;
  createdBy: string | null;
  updatedBy: string | null;
  createdAt: string;
  updatedAt: string;
  versions: StoredVersion[];
}

export interface PolicyOrgState {
  policies: StoredPolicy[];
  generation: number;
  settings: {
    stored: Record<string, unknown>;
    rowVersion: number;
    updatedAt: string | null;
    updatedBy: string | null;
  };
  audit: AuditRow[];
  auditSeq: number;
  idempotency: Map<string, FixtureResponse>;
}

const globalState = globalThis as typeof globalThis & {
  __egDevFixturePolicies?: Map<string, PolicyOrgState>;
};
const orgs: Map<string, PolicyOrgState> = (globalState.__egDevFixturePolicies ??= new Map<
  string,
  PolicyOrgState
>());

/** The fixture organization admin (the users fixture lists it, so names resolve). */
export const FIXTURE_ADMIN_ID = stableUuid('user:organization_admin@example.com');

/** The id of a seeded policy (`inbound-threats`, …) in an organization. */
export const seededPolicyId = (organizationId: string, key: string) =>
  stableUuid(`${organizationId}:policy:${key}`);

function seedOrg(organizationId: string): PolicyOrgState {
  const admin = FIXTURE_ADMIN_ID;
  const state: PolicyOrgState = {
    policies: [],
    generation: 42,
    settings: {
      stored: { allowRecommendationOverrides: true },
      rowVersion: 3,
      updatedAt: iso(14),
      updatedBy: admin,
    },
    audit: [],
    auditSeq: 7_000_000,
    idempotency: new Map(),
  };
  seeds(organizationId).forEach((seed, index) => {
    const id = seededPolicyId(organizationId, seed.key);
    const versions = seed.versions.map((v, i): StoredVersion => {
      const published = v.status !== 'draft';
      return {
        versionNo: i + 1,
        status: v.status,
        definition: v.definition,
        changeNote: v.changeNote,
        rowVersion: published ? 2 : 1,
        createdBy: admin,
        updatedBy: admin,
        publishedBy: published && v.status !== 'superseded' ? admin : null,
        createdAt: iso(v.daysAgo + 1),
        updatedAt: iso(v.daysAgo),
        publishedAt: v.status === 'published' ? iso(v.daysAgo) : null,
        deleted: false,
      };
    });
    state.policies.push({
      id,
      name: seed.name,
      description: seed.description,
      status: seed.status,
      activeVersionNo: seed.active,
      rowVersion: seed.versions.length + 2,
      archived: false,
      createdBy: admin,
      updatedBy: admin,
      createdAt: iso(130 - index),
      updatedAt: iso(Math.min(...seed.versions.map((v) => v.daysAgo))),
      versions,
    });
  });
  // The audit trail of the main policy (rows the policy detail's Audit tab merges).
  const main = state.policies[0];
  if (main) {
    const rows: Array<[number, string, string, Record<string, unknown>]> = [
      [120, 'policy.created', 'email_policy', { versionNo: 1, rowVersion: 1 }],
      [90, 'policy.version_draft_created', 'policy_version', { versionNo: 2, rowVersion: 1 }],
      [90, 'policy.version_published', 'policy_version', { versionNo: 2, rowVersion: 2 }],
      [
        90,
        'policy.version_activated',
        'policy_version',
        { versionNo: 2, previousVersionNo: null, generation: 38 },
      ],
      [45, 'policy.version_published', 'policy_version', { versionNo: 3, rowVersion: 2 }],
      [
        45,
        'policy.version_activated',
        'policy_version',
        { versionNo: 3, previousVersionNo: 2, generation: 40 },
      ],
      [12, 'policy.version_published', 'policy_version', { versionNo: 4, rowVersion: 2 }],
      [2, 'policy.version_draft_created', 'policy_version', { versionNo: 5, rowVersion: 1 }],
    ];
    for (const [daysAgo, action, resourceType, metadata] of rows) {
      state.audit.push(
        auditRow(
          state,
          admin,
          action,
          resourceType,
          main.id,
          { policyId: main.id, ...metadata },
          iso(daysAgo),
        ),
      );
    }
  }
  return state;
}

export function policyOrg(organizationId: string): PolicyOrgState {
  let state = orgs.get(organizationId);
  if (!state) {
    state = seedOrg(organizationId);
    orgs.set(organizationId, state);
  }
  return state;
}

/** Test support: forget every organization's state (the next read seeds it again). */
export function resetPolicyStore(): void {
  orgs.clear();
}

export function auditRow(
  state: PolicyOrgState,
  actorId: string | null,
  action: string,
  resourceType: string,
  resourceId: string,
  metadata: Record<string, unknown>,
  at: string = new Date().toISOString(),
): AuditRow {
  state.auditSeq += 1;
  return {
    id: String(state.auditSeq),
    createdAt: at,
    actor: { type: actorId ? 'user' : 'system', id: actorId },
    action,
    resourceType,
    resourceId,
    correlationId: stableUuid(`audit:${state.auditSeq}`),
    sourceIp: actorId ? '198.51.100.24' : null,
    metadata,
  };
}

export function audit(
  state: PolicyOrgState,
  actorId: string | null,
  action: string,
  resourceType: string,
  resourceId: string,
  metadata: Record<string, unknown>,
): void {
  state.audit.unshift(auditRow(state, actorId, action, resourceType, resourceId, metadata));
}

/** Idempotency-Key replay per organization and operation (required on publish/activate/reset). */
export function idempotent(
  state: PolicyOrgState,
  request: FixtureRequest,
  run: () => FixtureResponse,
): FixtureResponse {
  const key = request.headers.get('idempotency-key');
  if (!key) {
    return apiError(400, 'idempotency_key_required', 'An Idempotency-Key header is required');
  }
  const scoped = `${request.operationId}:${JSON.stringify(request.params)}:${key}`;
  const stored = state.idempotency.get(scoped);
  if (stored) {
    return { ...stored, headers: { ...(stored.headers ?? {}), 'idempotency-replayed': 'true' } };
  }
  const response = run();
  if (response.status < 300) state.idempotency.set(scoped, response);
  return response;
}

// ---------------------------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------------------------

const liveVersions = (policy: StoredPolicy) => policy.versions.filter((v) => !v.deleted);

export function versionView(policy: StoredPolicy, version: StoredVersion): Version {
  const legacy = !isRecord(version.definition) || version.definition.dslVersion !== DSL;
  const violations = cannedViolations(version.definition);
  return {
    policyId: policy.id,
    versionNo: version.versionNo,
    status: version.status,
    active: policy.activeVersionNo === version.versionNo,
    dslVersion: legacy ? null : DSL,
    definitionSha256: sha256(version.definition),
    ruleCount: ruleCountOf(version.definition),
    hasOverrideRules: hasOverrideRules(version.definition),
    references: version.status === 'published' ? referencesOf(version.definition) : null,
    changeNote: version.changeNote,
    rowVersion: version.rowVersion,
    createdByUserId: version.createdBy,
    updatedByUserId: version.updatedBy,
    publishedByUserId: version.publishedBy,
    publishedAt: version.publishedAt,
    createdAt: version.createdAt,
    updatedAt: version.updatedAt,
    definition: version.definition,
    validation: { valid: violations.length === 0, violations },
  };
}

export function versionRowView(policy: StoredPolicy, version: StoredVersion): VersionRow {
  const { definition, validation, ...row } = versionView(policy, version);
  void definition;
  void validation;
  return row;
}

export function policyView(policy: StoredPolicy): Policy {
  const versions = liveVersions(policy);
  const active = versions.find((v) => v.versionNo === policy.activeVersionNo) ?? null;
  const newestDraft = [...versions].reverse().find((v) => v.status === 'draft') ?? null;
  const source = active ?? newestDraft ?? versions[versions.length - 1] ?? null;
  const sourceDoc = isRecord(source?.definition) ? source.definition : {};
  const latest = versions.length > 0 ? Math.max(...versions.map((v) => v.versionNo)) : null;
  return {
    id: policy.id,
    name: policy.name,
    description: policy.description,
    status: policy.status,
    direction: (typeof sourceDoc.direction === 'string' ? sourceDoc.direction : 'any') as Direction,
    priority: typeof sourceDoc.priority === 'number' ? sourceDoc.priority : 0,
    activeVersionNo: policy.activeVersionNo,
    latestVersionNo: latest,
    rowVersion: policy.rowVersion,
    createdByUserId: policy.createdBy,
    updatedByUserId: policy.updatedBy,
    createdAt: policy.createdAt,
    updatedAt: policy.updatedAt,
    activeVersion: active
      ? {
          versionNo: active.versionNo,
          definitionSha256: sha256(active.definition),
          ruleCount: ruleCountOf(active.definition),
          hasOverrideRules: hasOverrideRules(active.definition),
          publishedAt: active.publishedAt,
        }
      : null,
    counts: {
      drafts: versions.filter((v) => v.status === 'draft').length,
      published: versions.filter((v) => v.status === 'published').length,
      superseded: versions.filter((v) => v.status === 'superseded').length,
      limit: VERSION_LIMIT,
    },
  };
}

export function policyRowView(policy: StoredPolicy): PolicyRow {
  const { activeVersion, counts, ...row } = policyView(policy);
  void activeVersion;
  void counts;
  return row;
}

const SETTINGS_DEFAULTS = {
  allowRecommendationOverrides: false,
  recipientSplit: true,
  notices: { senderNonDelivery: true },
  alerts: { enabled: true },
  tagging: { platformTagHeader: true, platformTagOutbound: false },
};

export function settingsView(state: PolicyOrgState): Settings {
  const s = state.settings.stored;
  const sub = (key: string) => (isRecord(s[key]) ? s[key] : {});
  const bool = (value: unknown, fallback: boolean) =>
    typeof value === 'boolean' ? value : fallback;
  return {
    settings: s,
    effective: {
      allowRecommendationOverrides: bool(
        s.allowRecommendationOverrides,
        SETTINGS_DEFAULTS.allowRecommendationOverrides,
      ),
      recipientSplit: bool(s.recipientSplit, SETTINGS_DEFAULTS.recipientSplit),
      notices: {
        senderNonDelivery: bool(
          sub('notices').senderNonDelivery,
          SETTINGS_DEFAULTS.notices.senderNonDelivery,
        ),
      },
      alerts: { enabled: bool(sub('alerts').enabled, SETTINGS_DEFAULTS.alerts.enabled) },
      tagging: {
        platformTagHeader: bool(
          sub('tagging').platformTagHeader,
          SETTINGS_DEFAULTS.tagging.platformTagHeader,
        ),
        platformTagOutbound: bool(
          sub('tagging').platformTagOutbound,
          SETTINGS_DEFAULTS.tagging.platformTagOutbound,
        ),
      },
    },
    violations: [],
    generation: String(state.generation),
    rowVersion: state.settings.rowVersion,
    settingsSha256: Object.keys(s).length > 0 ? sha256(s) : null,
    updatedByUserId: state.settings.updatedBy,
    updatedAt: state.settings.updatedAt,
  };
}

export function findPolicy(state: PolicyOrgState, id: string | undefined): StoredPolicy | null {
  return state.policies.find((p) => p.id === id && !p.archived) ?? null;
}

export function findVersion(policy: StoredPolicy, versionNo: string | undefined) {
  const n = Number(versionNo);
  return liveVersions(policy).find((v) => v.versionNo === n) ?? null;
}

export const nextVersionNo = (policy: StoredPolicy) =>
  Math.max(0, ...policy.versions.map((v) => v.versionNo)) + 1;

export const liveVersionCount = (policy: StoredPolicy) => liveVersions(policy).length;
