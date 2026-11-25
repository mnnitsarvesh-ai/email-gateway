/**
 * Step AI-1 seed (docs/plan/steps/28-ai-chat-management.md §9 item 7, WP6): the tenants of the
 * assistant spec, kept apart from alpha/beta so no other spec sees the assistant turned on.
 *
 * - `delta` (enterprise plan): feature `ai_assistant` enabled the way the seed enables operator
 *   features (`ato_detection`, seed/ato.ts: an `organization_features` row), then the tenant
 *   setting turned on **through the api** by its organization admin (`PUT /assistant/settings`
 *   with the external-processing acknowledgement, so the row, `rowVersion` and the
 *   `assistant.settings_updated` audit row are exactly what the product writes); three policies
 *   created and published through the api (two active, one draft) and a few messages (two held in
 *   quarantine today) so the read tools return rows.
 * - `epsilon` (enterprise plan): feature `ai_assistant` enabled, tenant setting never turned on:
 *   its organization admin sees "turned off for your organization" with the settings link.
 *
 * - Step AI-5 (docs/plan/steps/33-ai-chat-compliance-integrations.md §9 item 6): delta (enterprise
 *   plan, so the `archiving` plan feature is on) gets a default retention policy and its archive
 *   settings (capture stays off, like alpha's), a 365-day retention policy the spec shortens
 *   through chat, and an eDiscovery case with an active legal hold the spec asks chat to release.
 *   All of it is written **through the api** by delta's compliance officer (MFA session: the
 *   archive settings and the hold are MFA routes), like `prepareArchive` (seed/archive.ts).
 *
 * The spec runs the deterministic fake provider only (`ASSISTANT_PROVIDER=fake`, the api's
 * assistant override); nothing here or in the spec reaches an LLM or the internet. Synthetic
 * `.test` values only.
 */
import type { PrismaClient } from '@email-gateway/database';
import type { ApiSession } from './api';
import { MINUTE, type MessagePlan } from './plan';

export const DELTA = { slug: 'e2e-portal-delta', name: 'E2E Portal Delta Assistant' } as const;
export const EPSILON = { slug: 'e2e-portal-epsilon', name: 'E2E Portal Epsilon' } as const;
export const DELTA_DOMAIN = 'delta.e2e-portal.test';
export const EPSILON_DOMAIN = 'epsilon.e2e-portal.test';
export const ASSISTANT_FEATURE = 'ai_assistant';

/**
 * Step AI-3 (docs/plan/steps/30-ai-chat-identity-tenant-admin.md §9 item 7): a delta user no other
 * spec signs in as (read-only role, no password anyone knows), disabled through the assistant by
 * `assistant.spec.ts` ("disable user …").
 */
export const DELTA_OFFBOARD_USER = {
  email: `leaver@${DELTA_DOMAIN}`,
  displayName: 'Delta Leaver',
  roles: ['read_only_user'],
} as const;

/** Delta's policies in creation order (the list route returns newest first). */
export const DELTA_POLICIES = [
  { name: 'E2E Assistant inbound guard', direction: 'inbound', activate: true },
  { name: 'E2E Assistant outbound guard', direction: 'outbound', activate: true },
  { name: 'E2E Assistant draft rule', direction: 'inbound', activate: false },
] as const;

export interface SeededAssistant {
  delta: {
    policies: Array<{ id: string; name: string; status: 'active' | 'draft' }>;
    /** Subjects of delta's messages held in quarantine today. */
    quarantinedSubjects: string[];
    /** Step AI-3: the public id of `deltaMfaAdmin` (the self-guard directive targets it). */
    mfaAdminUserId: string;
    /** Step AI-3: the seeded user the assistant disables (DELTA_OFFBOARD_USER). */
    offboardUser: { id: string; email: string };
    /** Step AI-5: delta's compliance rows (prepareAssistantCompliance). */
    compliance: SeededAssistantCompliance;
  };
}

/** Step AI-5: the compliance officer of delta (MFA; archive, eDiscovery and legal holds). */
export const DELTA_COMPLIANCE_EMAIL = `compliance@${DELTA_DOMAIN}`;
/** Step AI-5: delta's default retention policy (the archive settings point at it). */
export const DELTA_DEFAULT_RETENTION = 'E2E delta default seven years';

export interface SeededAssistantCompliance {
  /** The default policy (2555 days); never changed by the spec. */
  defaultPolicyId: string;
  /** "E2E retention <tag>": 365 days, `onExpiry` delete, priority and criteria defaults. */
  retentionPolicy: { id: string; name: string; retentionDays: number };
  /** An open case with one active legal hold (the custodian is the compliance officer). */
  holdCase: { id: string; name: string };
  hold: { id: string; name: string };
}

/** Delta's messages: four of the last hour, two of them held in quarantine. */
export function planDeltaMessages(now: number): MessagePlan[] {
  const at = (minutesAgo: number) => new Date(now - minutesAgo * MINUTE);
  const base = {
    direction: 'inbound' as const,
    domain: 'primary' as const,
    recipient: `analyst@${DELTA_DOMAIN}`,
    envelopeFrom: 'sender@external.e2e-portal.test',
  };
  return [
    {
      ...base,
      key: 'delta-clean-1',
      receivedAt: at(5),
      verdict: 'clean',
      action: 'deliver',
      riskScore: 40,
      subject: 'Delta weekly report',
      deliveries: [{ status: 'delivered', deliveredAfterMs: 2_000 }],
      scan: { status: 'completed', completedAfterMs: 900 },
      quarantine: null,
    },
    {
      ...base,
      key: 'delta-spam-1',
      receivedAt: at(7),
      verdict: 'spam',
      action: 'quarantine',
      riskScore: 650,
      subject: 'Delta held offer',
      deliveries: [],
      scan: { status: 'completed', completedAfterMs: 1_100 },
      quarantine: { state: 'held', reason: 'spam', afterMs: 5_000 },
    },
    {
      ...base,
      key: 'delta-phish-1',
      receivedAt: at(9),
      verdict: 'phishing',
      action: 'quarantine',
      riskScore: 880,
      subject: 'Delta held password notice',
      deliveries: [],
      scan: { status: 'completed', completedAfterMs: 1_300 },
      quarantine: { state: 'held', reason: 'phishing', afterMs: 5_000 },
    },
    {
      ...base,
      key: 'delta-clean-2',
      receivedAt: at(11),
      verdict: 'clean',
      action: 'deliver',
      riskScore: 20,
      subject: 'Delta meeting notes',
      deliveries: [{ status: 'delivered', deliveredAfterMs: 1_500 }],
      scan: { status: 'completed', completedAfterMs: 700 },
      quarantine: null,
    },
  ];
}

function policyDefinition(direction: 'inbound' | 'outbound', index: number) {
  return {
    dslVersion: 'policy-dsl/1',
    direction,
    priority: 100 + index,
    rules: [
      {
        id: `assistant-e2e-${index}`,
        priority: 10,
        description: 'Tag messages that fail SPF (e2e seed)',
        when: { all: [{ field: 'auth.spf', op: 'equals', value: 'fail' }] },
        actions: [{ type: 'TAG', label: `assistant-e2e-${index}` }],
      },
    ],
  };
}

function idOf(body: Record<string, unknown>, key: string): string {
  const source = body[key] as { id?: string } | undefined;
  if (!source?.id) throw new Error(`assistant seed: response without ${key}.id`);
  return source.id;
}

/** `ai_assistant` on for an organization (the operator path of the seed, as `ato_detection`). */
export async function enableAssistantFeature(
  p: PrismaClient,
  organizationId: bigint,
): Promise<void> {
  await p.organizationFeature.upsert({
    where: { organizationId_featureKey: { organizationId, featureKey: ASSISTANT_FEATURE } },
    create: { organizationId, featureKey: ASSISTANT_FEATURE, enabled: true },
    update: { enabled: true },
  });
}

/**
 * Turns the assistant on for delta (feature + tenant setting through the api), seeds delta's
 * policies, and turns the feature on for epsilon (tenant setting stays off).
 */
export async function prepareAssistant(
  p: PrismaClient,
  input: { deltaOrg: bigint; epsilonOrg: bigint; deltaAdmin: ApiSession },
): Promise<SeededAssistant['delta']['policies']> {
  await enableAssistantFeature(p, input.deltaOrg);
  await enableAssistantFeature(p, input.epsilonOrg);

  const api = input.deltaAdmin;
  const status = await api.call<{ available: boolean; reason?: string }>(
    'GET',
    '/assistant/status',
    undefined,
    { expect: 200 },
  );
  if (status.body.reason === 'platform_disabled') {
    throw new Error(
      'assistant seed: the api runs with ASSISTANT_ENABLED=false. Recreate it with ' +
        'tests/portal-e2e/assistant.override.yml (the fake provider, see that file).',
    );
  }
  const current = await api.call<{ rowVersion: number }>('GET', '/assistant/settings', undefined, {
    expect: 200,
  });
  await api.call(
    'PUT',
    '/assistant/settings',
    {
      expectedRowVersion: current.body.rowVersion,
      enabled: true,
      externalProcessingAcknowledged: true,
      dailyTokenBudget: null,
      retentionDays: 30,
    },
    { expect: 200 },
  );

  const policies: SeededAssistant['delta']['policies'] = [];
  for (const [index, spec] of DELTA_POLICIES.entries()) {
    const created = await api.call(
      'POST',
      '/policies',
      {
        name: spec.name,
        description: 'Seeded by the portal end-to-end suite (assistant)',
        definition: policyDefinition(spec.direction, index),
        changeNote: 'Initial version (e2e seed)',
      },
      { expect: 201 },
    );
    const id = idOf(created.body, 'policy');
    if (spec.activate) {
      await api.call(
        'POST',
        `/policies/${id}/versions/1/publish`,
        {
          activate: true,
          expectedRowVersion: (created.body.version as { rowVersion: number }).rowVersion,
        },
        { idempotent: true, expect: 200 },
      );
    }
    policies.push({ id, name: spec.name, status: spec.activate ? 'active' : 'draft' });
  }
  return policies;
}

/**
 * Step AI-5: delta's archive rows through the api as its compliance officer (an MFA session):
 * a default retention policy and the archive settings pointing at it (capture disabled; the
 * capture settings document stays at its defaults, since its scope needs `journal:manage`, which
 * the compliance officer does not hold), the 365-day policy "E2E retention <tag>" with
 * the route's defaults for priority and criteria, and an eDiscovery case with an active hold.
 */
export async function prepareAssistantCompliance(
  compliance: ApiSession,
  tag: string,
): Promise<SeededAssistantCompliance> {
  const defaultPolicy = await compliance.call<{ id: string }>(
    'POST',
    '/archive/retention-policies',
    { name: DELTA_DEFAULT_RETENTION, retentionDays: 2555, onExpiry: 'delete', priority: 1000 },
    { idempotent: true, expect: 201 },
  );
  const settings = await compliance.call<{ rowVersion: number }>(
    'GET',
    '/archive/settings',
    undefined,
    { expect: 200 },
  );
  await compliance.call(
    'PUT',
    '/archive/settings',
    {
      expectedRowVersion: settings.body.rowVersion,
      enabled: false,
      immutability: 'none',
      defaultRetentionPolicyId: defaultPolicy.body.id,
    },
    { idempotent: true, expect: 200 },
  );
  const retentionName = `E2E retention ${tag}`;
  const retention = await compliance.call<{ id: string; retentionDays: number }>(
    'POST',
    '/archive/retention-policies',
    { name: retentionName, retentionDays: 365, onExpiry: 'delete' },
    { idempotent: true, expect: 201 },
  );
  const caseName = `E2E hold case ${tag}`;
  const created = await compliance.call<{ id: string }>(
    'POST',
    '/ediscovery/cases',
    {
      name: caseName,
      description: 'Seeded by the portal end-to-end suite (assistant, step AI-5)',
      custodians: [DELTA_COMPLIANCE_EMAIL],
    },
    { idempotent: true, expect: 201 },
  );
  const holdName = `E2E chat hold ${tag}`;
  const hold = await compliance.call<{ id: string }>(
    'POST',
    `/ediscovery/cases/${created.body.id}/holds`,
    {
      name: holdName,
      reason: 'E2E seed: preserve the custodian mailbox',
      useCaseCustodians: true,
    },
    { idempotent: true, expect: 201 },
  );
  return {
    defaultPolicyId: defaultPolicy.body.id,
    retentionPolicy: {
      id: retention.body.id,
      name: retentionName,
      retentionDays: retention.body.retentionDays,
    },
    holdCase: { id: created.body.id, name: caseName },
    hold: { id: hold.body.id, name: holdName },
  };
}
