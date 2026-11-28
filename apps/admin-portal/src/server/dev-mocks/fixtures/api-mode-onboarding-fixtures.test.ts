// @vitest-environment node
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { beforeEach, describe, expect, it } from 'vitest';
import { operations } from '@/lib/api/operations.gen';
import type { OperationId } from '@/lib/api/types';
import { createMockFetch, mergedFixtures } from '@/server/dev-mocks';
import { toJsonSchema } from '@/test/contract';
import { resetApiModeFixtures } from './api-mode';
import {
  API_MODE_ONBOARDING_OPERATIONS,
  resetApiModeOnboardingFixtures,
} from './api-mode-onboarding';
import { PROVIDER_CHECK_DELAY_MS } from './domains';
import { resetProviderFixtures } from './provider-connections';

/**
 * Dev fixtures of API-mode parity and onboarding (step API-4 WP6): the four onboarding
 * operations and the provider ownership check answer with OpenAPI-valid bodies; the changed
 * views (detections with policy and DLP fields, the policy view with the mapping and the
 * detect-only period, the overview's new blocks, settings with the two flags) stay valid; the
 * scope PUT keeps CAS, the provider check settles into `provider_tenant` ownership and the
 * remediation PUT validates `policyMapping` and `detectOnly`.
 */

const API = 'http://api.test:3000';
const fetchImpl = createMockFetch(mergedFixtures());
const REPO = join(__dirname, '../../../../../..');
const spec = JSON.parse(readFileSync(join(REPO, 'docs/api/openapi.json'), 'utf8')) as {
  paths: Record<
    string,
    Record<string, { responses: Record<string, { content?: Record<string, { schema: unknown }> }> }>
  >;
};
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);

function responseErrors(operationId: OperationId, status: number, body: unknown): string[] {
  const op = operations[operationId];
  const schema =
    spec.paths[op.path]?.[op.method.toLowerCase()]?.responses[String(status)]?.content?.[
      'application/json'
    ]?.schema;
  if (!schema) return [`no ${status} schema for ${operationId}`];
  const validate = ajv.compile(toJsonSchema(schema) as object);
  return validate(body)
    ? []
    : (validate.errors ?? []).map((e) => `${e.instancePath || '(root)'} ${e.message ?? ''}`);
}

async function login(email: string): Promise<string> {
  const response = await fetchImpl(`${API}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'any' }),
  });
  const first = (await response.json()) as { accessToken?: string; mfaToken?: string };
  if (first.accessToken) return first.accessToken;
  const verified = await fetchImpl(`${API}/api/v1/auth/mfa/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ mfaToken: first.mfaToken, code: '000000' }),
  });
  return ((await verified.json()) as { accessToken: string }).accessToken;
}

let key = 0;
async function call(token: string, method: string, path: string, body?: unknown) {
  const response = await fetchImpl(`${API}/api/v1${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...(method === 'GET' ? {} : { 'idempotency-key': `onb-${(key += 1)}` }),
    },
    body: body === undefined ? null : JSON.stringify(body),
  });
  const text = await response.text();
  return {
    status: response.status,
    headers: response.headers,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in a test
    body: (text ? JSON.parse(text) : null) as Record<string, any>,
  };
}

beforeEach(() => {
  resetProviderFixtures();
  resetApiModeFixtures();
  resetApiModeOnboardingFixtures();
});

describe('api-mode onboarding dev fixtures (step API-4 WP6)', () => {
  it('cover the five new operations of the OpenAPI document', () => {
    const handlers = mergedFixtures();
    for (const op of API_MODE_ONBOARDING_OPERATIONS) expect(handlers[op], op).toBeDefined();
    const fromSpec = Object.keys(operations).filter(
      (id) => id.startsWith('ApiModeOnboardingController') || id.includes('providerOwnership'),
    );
    expect([...fromSpec].sort()).toEqual([...API_MODE_ONBOARDING_OPERATIONS].sort());
  });

  it('answer protection coverage, onboarding, scope and the changed views with valid bodies', async () => {
    const t = await login('organization_admin@example.com');
    const check = (op: OperationId, res: { status: number; body: unknown }) =>
      expect(responseErrors(op, res.status, res.body), op).toEqual([]);

    const coverage = await call(t, 'GET', '/api-mode/protection-coverage?limit=5');
    check('ApiModeOnboardingController_protectionCoverage_v1', coverage);
    expect(coverage.body.capabilities).toHaveLength(12);
    expect(coverage.body.items).toHaveLength(5);
    expect(coverage.body.nextCursor).toEqual(expect.any(String));
    const next = await call(
      t,
      'GET',
      `/api-mode/protection-coverage?limit=5&cursor=${coverage.body.nextCursor as string}`,
    );
    check('ApiModeOnboardingController_protectionCoverage_v1', next);
    const apiOnly = await call(t, 'GET', '/api-mode/protection-coverage?effectiveMode=api');
    check('ApiModeOnboardingController_protectionCoverage_v1', apiOnly);
    const apiItem = (
      apiOnly.body.items as Array<{
        domainId: string;
        api: { applies: boolean };
        inline: { applies: boolean };
      }>
    )[0]!;
    expect(apiItem.api.applies).toBe(true);
    expect(apiItem.inline.applies).toBe(false);

    const onboarding = await call(t, 'GET', `/api-mode/domains/${apiItem.domainId}/onboarding`);
    check('ApiModeOnboardingController_domainOnboarding_v1', onboarding);
    expect(onboarding.body.steps.map((s: { key: string }) => s.key)).toEqual([
      'ownership',
      'connect',
      'intake',
      'mailboxes',
      'action',
      'review',
    ]);

    const scope = await call(t, 'GET', `/api-mode/domains/${apiItem.domainId}/scope`);
    check('ApiModeOnboardingController_getScope_v1', scope);
    expect(scope.body).toMatchObject({ kind: 'all', rowVersion: null });
    const put = await call(t, 'PUT', `/api-mode/domains/${apiItem.domainId}/scope`, {
      scope: { kind: 'mailboxes' },
      mailboxIds: [],
      reason: 'Pilot',
      expectedRowVersion: null,
    });
    check('ApiModeOnboardingController_putScope_v1', put);
    expect(put.body).toMatchObject({ kind: 'mailboxes', rowVersion: 1, created: true, inScope: 0 });
    const stale = await call(t, 'PUT', `/api-mode/domains/${apiItem.domainId}/scope`, {
      scope: { kind: 'all' },
      reason: 'Back',
      expectedRowVersion: null,
    });
    expect(stale.status).toBe(409);
    expect(stale.body.code).toBe('api_mode_scope_conflict');

    const detections = await call(t, 'GET', '/api-mode/detections?direction=outbound');
    check('ApiModeController_listDetections_v1', detections);
    expect(detections.body.data.length).toBeGreaterThan(0);
    const outbound = await call(t, 'GET', `/api-mode/detections/${detections.body.data[0].id}`);
    check('ApiModeController_getDetection_v1', outbound);
    expect(outbound.body.policy.actions[0].reason).toBe('outbound_already_sent');
    const blocked = await call(t, 'GET', '/api-mode/detections?dlpAction=block&limit=100');
    expect(
      (blocked.body.data as Array<{ dlpAction: string }>).every((d) => d.dlpAction === 'block'),
    ).toBe(true);

    const overview = await call(t, 'GET', '/api-mode/overview');
    check('ApiModeController_overview_v1', overview);
    expect(overview.body.outbound.detections24h).toBeGreaterThan(0);
    const settings = await call(t, 'GET', '/api-mode/settings');
    check('ApiModeSettingsController_get_v1', settings);
    expect(settings.body.settings.policyEvaluationEnabled).toBe(true);
  });

  it('remediation policy: policyMapping and detectOnly validated, the view shows both', async () => {
    const t = await login('organization_admin@example.com');
    const view = await call(t, 'GET', '/api-mode/remediation-policy');
    expect(view.body.organization.effectivePolicyMapping.quarantine).toBe('move_quarantine');
    const document = { ...view.body.presets.p1.document, policyMapping: { reject: 'move_junk' } };
    const until = new Date(Date.now() + 7 * 86_400_000).toISOString();
    const refused = await call(t, 'PUT', '/api-mode/remediation-policy', {
      mode: 'enforce',
      document,
      detectOnly: { until, then: 'remind' },
      reason: 'Try',
      expectedRowVersion: null,
    });
    expect(refused.status).toBe(422);
    expect(refused.body).toMatchObject({ code: 'api_mode_detect_only_invalid' });
    const hard = await call(t, 'PUT', '/api-mode/remediation-policy', {
      mode: 'enforce',
      document: { ...document, policyMapping: { reject: 'hard_delete' } },
      reason: 'Try',
      expectedRowVersion: null,
    });
    expect(hard.status).toBe(400);
    const saved = await call(t, 'PUT', '/api-mode/remediation-policy', {
      mode: 'detect_only',
      document,
      detectOnly: { until, then: 'remind' },
      reason: 'Start detect only',
      expectedRowVersion: null,
    });
    expect(responseErrors('ApiModeRemediationController_putPolicy_v1', 200, saved.body)).toEqual(
      [],
    );
    expect(saved.body.effectivePolicyMapping.reject).toBe('move_junk');
    expect(saved.body.detectOnly).toMatchObject({ then: 'remind', ended: false });
    const after = await call(t, 'GET', '/api-mode/remediation-policy');
    expect(responseErrors('ApiModeRemediationController_getPolicy_v1', 200, after.body)).toEqual(
      [],
    );
  });

  it('provider ownership check: pending, then verified through the bound tenant; rate limited', async () => {
    const t = await login('organization_admin@example.com');
    const created = await call(t, 'POST', '/domains', {
      name: 'prov-check.example.test',
      inboundEnabled: false,
      dkim: { ed25519: false },
      protectionMode: 'api',
    });
    expect(created.status).toBe(201);
    expect(created.body.ownership.providerCheckAvailable).toBe(true);
    const id = created.body.id as string;
    const check = await call(t, 'POST', `/domains/${id}/ownership/provider-check`, {});
    expect(responseErrors('DomainsController_providerOwnershipCheck_v1', 202, check.body)).toEqual(
      [],
    );
    expect(check.status).toBe(202);
    const pending = await call(t, 'GET', `/domains/${id}`);
    expect(pending.body.ownership.providerCheck.status).toBe('pending');
    const realNow = Date.now;
    Date.now = () => realNow() + PROVIDER_CHECK_DELAY_MS + 1000;
    try {
      const verified = await call(t, 'GET', `/domains/${id}`);
      expect(responseErrors('DomainsController_get_v1', 200, verified.body)).toEqual([]);
      expect(verified.body.status).toBe('verified');
      expect(verified.body.ownership).toMatchObject({
        method: 'provider_tenant',
        providerCheck: { status: 'verified', result: 'verified' },
      });
      const again = await call(t, 'POST', `/domains/${id}/ownership/provider-check`, {});
      expect(again.status).toBe(409);
      expect(again.body.code).toBe('domain_not_pending');
    } finally {
      Date.now = realNow;
    }
  });
});
