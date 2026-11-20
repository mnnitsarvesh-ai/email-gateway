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
  };
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
