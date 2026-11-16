/**
 * Step 7.3 seed (design §9.4): tenant configuration of the policy builder, DLP and BEC specs,
 * written **through the api** as the seeded administrators (so versions, generations, audit rows
 * and outbox events are exactly what the product writes), plus BEC suppressions, which only the
 * feedback flow creates (out of 7.3's scope; rows in the repository's column set, as
 * apps/api/integration/bec.test.ts writes them).
 *
 * Alpha: two departments with members (directory pickers, the policy exception), the policy
 * "E2E outbound data guard" with v1 published then superseded, v2 active (nested AND/OR groups,
 * a NOT, an exception, QUARANTINE + ALERT + TAG) and a draft v3; a DLP policy without rules; a
 * BEC suppression to lift. Beta: one active policy, a DLP custom pattern, a BEC executive and a
 * suppression (isolation targets, all marked `BETA-ONLY`). Synthetic `.test` values only.
 */
import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import type { ApiSession } from './api';

export const SEEDED_POLICY_NAME = 'E2E outbound data guard';
export const BETA_POLICY_NAME = 'BETA-ONLY inbound policy';
export const DEPARTMENTS = ['E2E Finance', 'E2E Legal'] as const;
export const ALPHA_DLP_POLICY_NAME = 'E2E outbound card data';
export const ALPHA_SUPPRESSION = {
  reasonCode: 'bec.content.urgency',
  senderValue: 'vendor-one.e2e-portal.test',
} as const;

export interface SeededPolicies {
  departments: Array<{ id: string; name: string }>;
  policyId: string;
  betaPolicyId: string;
  dlpPolicyId: string;
  suppressionId: string;
  beta: { patternId: string; executiveId: string; suppressionId: string };
}

/** v1: one rule, outbound confidential data → quarantine. */
export function definitionV1(): Record<string, unknown> {
  return {
    dslVersion: 'policy-dsl/1',
    direction: 'outbound',
    priority: 100,
    rules: [
      {
        id: 'hold-confidential',
        priority: 10,
        description: 'Hold confidential data leaving the organization',
        when: { all: [{ field: 'dlp.categories', op: 'contains_any', value: ['confidential'] }] },
        actions: [{ type: 'QUARANTINE' }],
      },
    ],
  };
}

/**
 * v2: nested groups (AND of a count and an OR group holding a NOT), an exception for the finance
 * department, three actions with parameters.
 */
export function definitionV2(financeId: string): Record<string, unknown> {
  return {
    dslVersion: 'policy-dsl/1',
    direction: 'outbound',
    priority: 100,
    rules: [
      {
        id: 'hold-confidential',
        priority: 10,
        description: 'Hold confidential data leaving the organization',
        when: {
          all: [
            {
              field: 'dlp.categories',
              op: 'contains_any',
              value: ['confidential', 'payment_card'],
            },
            {
              any: [
                { field: 'recipients.count', op: 'gt', value: 5 },
                { not: { field: 'auth.dkim', op: 'equals', value: 'pass' } },
              ],
            },
          ],
        },
        unless: [{ field: 'sender.department', op: 'in', value: [financeId] }],
        actions: [
          { type: 'QUARANTINE' },
          { type: 'ALERT', severity: 'warning' },
          { type: 'TAG', label: 'e2e-dlp' },
        ],
      },
    ],
  };
}

function idOf(body: Record<string, unknown>, key?: string): string {
  const source = (key ? body[key] : body) as { id?: string } | undefined;
  if (!source?.id) throw new Error(`seed: response without id (${key ?? 'root'})`);
  return source.id;
}

export async function seedPolicies(
  p: PrismaClient,
  alphaApi: ApiSession,
  betaApi: ApiSession,
  ids: { alphaOrg: bigint; betaOrg: bigint; alphaMemberUserId: string; domainName: string },
): Promise<SeededPolicies> {
  // Departments (user:manage) with an address member and a user member each.
  const departments: Array<{ id: string; name: string }> = [];
  for (const [index, name] of DEPARTMENTS.entries()) {
    const dept = await alphaApi.call('POST', '/departments', { name }, { expect: 201 });
    const id = idOf(dept.body);
    departments.push({ id, name });
    await alphaApi.call(
      'POST',
      `/departments/${id}/members`,
      { address: `${index === 0 ? 'finance' : 'legal'}@${ids.domainName}` },
      { expect: 201 },
    );
    if (index === 0) {
      await alphaApi.call(
        'POST',
        `/departments/${id}/members`,
        { userId: ids.alphaMemberUserId },
        { expect: 201 },
      );
    }
  }

  // Alpha policy: v1 published (active), v2 published and activated (v1 superseded), v3 draft.
  const created = await alphaApi.call(
    'POST',
    '/policies',
    {
      name: SEEDED_POLICY_NAME,
      description: 'Seeded by the portal end-to-end suite',
      definition: definitionV1(),
      changeNote: 'Initial version (e2e seed)',
    },
    { expect: 201 },
  );
  const policyId = idOf(created.body, 'policy');
  const v1Row = (created.body.version as { rowVersion: number }).rowVersion;
  await alphaApi.call(
    'POST',
    `/policies/${policyId}/versions/1/publish`,
    { activate: true, expectedRowVersion: v1Row },
    { idempotent: true, expect: 200 },
  );
  const v2 = await alphaApi.call(
    'POST',
    `/policies/${policyId}/versions`,
    { definition: definitionV2(departments[0]!.id), changeNote: 'Nested groups (e2e seed)' },
    { expect: 201 },
  );
  await alphaApi.call(
    'POST',
    `/policies/${policyId}/versions/2/publish`,
    { activate: true, expectedRowVersion: (v2.body as { rowVersion: number }).rowVersion },
    { idempotent: true, expect: 200 },
  );
  await alphaApi.call(
    'POST',
    `/policies/${policyId}/versions`,
    { basedOnVersionNo: 2, changeNote: 'Work in progress (e2e seed)' },
    { expect: 201 },
  );

  // Alpha DLP policy (the spec adds a rule to it) and a BEC suppression (the spec lifts it).
  const dlp = await alphaApi.call(
    'POST',
    '/dlp/policies',
    { name: ALPHA_DLP_POLICY_NAME, mode: 'monitor', directions: ['outbound'] },
    { expect: 201 },
  );
  const suppressionId = randomUUID();
  await p.becSuppressionRule.create({
    data: {
      publicId: suppressionId,
      organizationId: ids.alphaOrg,
      reasonCode: ALPHA_SUPPRESSION.reasonCode,
      senderScope: 'domain',
      senderValue: ALPHA_SUPPRESSION.senderValue,
      expiresAt: new Date(Date.now() + 30 * 86_400_000),
    },
  });

  // Beta isolation targets.
  const beta = await betaApi.call(
    'POST',
    '/policies',
    {
      name: BETA_POLICY_NAME,
      definition: {
        dslVersion: 'policy-dsl/1',
        direction: 'inbound',
        priority: 50,
        rules: [
          {
            id: 'beta-only-rule',
            priority: 10,
            when: { all: [{ field: 'auth.spf', op: 'equals', value: 'fail' }] },
            actions: [{ type: 'TAG', label: 'beta-only' }],
          },
        ],
      },
    },
    { expect: 201 },
  );
  const betaPolicyId = idOf(beta.body, 'policy');
  await betaApi.call(
    'POST',
    `/policies/${betaPolicyId}/versions/1/publish`,
    {
      activate: true,
      expectedRowVersion: (beta.body.version as { rowVersion: number }).rowVersion,
    },
    { idempotent: true, expect: 200 },
  );
  const pattern = await betaApi.call(
    'POST',
    '/dlp/patterns',
    { name: 'BETA-ONLY pattern', pattern: 'BETA-[0-9]{6}', severity: 'medium' },
    { expect: 201 },
  );
  const executive = await betaApi.call(
    'POST',
    '/bec/executives',
    { displayName: 'BETA-ONLY Executive', title: 'Chief Executive' },
    { expect: 201 },
  );
  const betaSuppressionId = randomUUID();
  await p.becSuppressionRule.create({
    data: {
      publicId: betaSuppressionId,
      organizationId: ids.betaOrg,
      reasonCode: ALPHA_SUPPRESSION.reasonCode,
      senderScope: 'domain',
      senderValue: 'beta-only-vendor.e2e-portal.test',
      expiresAt: new Date(Date.now() + 30 * 86_400_000),
    },
  });

  return {
    departments,
    policyId,
    betaPolicyId,
    dlpPolicyId: idOf(dlp.body),
    suppressionId,
    beta: {
      patternId: idOf(pattern.body),
      executiveId: idOf(executive.body),
      suppressionId: betaSuppressionId,
    },
  };
}
