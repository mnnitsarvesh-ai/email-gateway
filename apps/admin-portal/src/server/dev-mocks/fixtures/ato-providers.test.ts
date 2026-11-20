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
import { resetAtoFixtures } from './ato';
import { ATO_PROVIDER_OPERATIONS, resetAtoProviderFixtures } from './ato-providers';

/**
 * Dev fixtures of the identity-provider pages (step 8.5 WP6): every one of the 13 operations
 * answers with a body matching its OpenAPI response, and the rules the pages rely on hold (MFA,
 * Idempotency-Key replay, CAS, eligibility, companion streams, backfill bounds, a provider
 * response confirmed only after the approval).
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

let keyCounter = 0;
const k = () => `provider-key-${(keyCounter += 1)}`;

async function call(token: string, method: string, path: string, body?: unknown, key?: string) {
  const response = await fetchImpl(`${API}/api/v1${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...(key ? { 'idempotency-key': key } : {}),
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
  resetAtoFixtures();
  resetAtoProviderFixtures();
});

describe('identity-provider dev fixtures (step 8.5 WP6)', () => {
  it('cover the 13 identity-provider operations of §6', () => {
    const handlers = mergedFixtures();
    expect(ATO_PROVIDER_OPERATIONS).toHaveLength(13);
    for (const op of ATO_PROVIDER_OPERATIONS) expect(handlers[op], op).toBeDefined();
    const fromSpec = Object.keys(operations).filter((id) =>
      /^(AtoProviders|AtoAccountMailbox)/.test(id),
    );
    expect([...fromSpec].sort()).toEqual([...ATO_PROVIDER_OPERATIONS].sort());
  });

  it('answer every operation with an OpenAPI-valid body and keep the rules', async () => {
    const admin = await login('mfa.organization_admin@example.com');
    const noMfa = await login('organization_admin@example.com');
    const check = (op: OperationId, res: { status: number; body: unknown }) => {
      expect(res.status, op).toBeLessThan(300);
      expect(responseErrors(op, res.status, res.body), op).toEqual([]);
    };
    const list = await call(admin, 'GET', '/ato/providers');
    check('AtoProvidersController_list_v1', list);
    expect(list.body.data).toHaveLength(1);
    const integration = list.body.data[0];
    check(
      'AtoProvidersController_requirements_v1',
      await call(admin, 'GET', '/ato/providers/requirements'),
    );
    const connections = await call(admin, 'GET', '/ato/providers/connections');
    check('AtoProvidersController_connections_v1', connections);
    const google = connections.body.data.find(
      (c: { eligibility: string }) => c.eligibility === 'eligible',
    );
    const inactive = connections.body.data.find(
      (c: { eligibility: string }) => c.eligibility === 'inactive',
    );

    // Connect: MFA, eligibility, companion rule, Idempotency-Key replay.
    expect(
      (await call(noMfa, 'POST', '/ato/providers', { connectionId: google.id }, k())).body.code,
    ).toBe('mfa_required');
    expect(
      (await call(admin, 'POST', '/ato/providers', { connectionId: inactive.id }, k())).body.code,
    ).toBe('ato_provider_connection_ineligible');
    const detail = await call(admin, 'GET', `/ato/providers/${integration.id}`);
    check('AtoProvidersController_get_v1', detail);
    const badSettings = structuredClone(detail.body.settings);
    badSettings.streams.forwarding_changes.enabled = true;
    badSettings.streams.sign_ins.enabled = false;
    badSettings.streams.risk_events.enabled = true;
    const invalid = await call(
      admin,
      'POST',
      '/ato/providers',
      { connectionId: google.id, settings: badSettings },
      k(),
    );
    expect(invalid.body.code).toBe('ato_provider_settings_invalid');
    expect(invalid.body.issues).toEqual([
      { path: 'streams.risk_events.enabled', message: 'companion_requires_primary' },
    ]);
    const key = k();
    const created = await call(admin, 'POST', '/ato/providers', { connectionId: google.id }, key);
    check('AtoProvidersController_create_v1', created);
    expect(created.status).toBe(201);
    const replay = await call(admin, 'POST', '/ato/providers', { connectionId: google.id }, key);
    expect(replay.headers.get('idempotency-replayed')).toBe('true');
    expect(replay.body.id).toBe(created.body.id);
    expect(
      (await call(admin, 'POST', '/ato/providers', { connectionId: google.id }, k())).body.code,
    ).toBe('ato_provider_already_bound');

    // Settings: CAS on rowVersion.
    const id = created.body.id as string;
    const updated = await call(
      admin,
      'PATCH',
      `/ato/providers/${id}`,
      { rowVersion: created.body.rowVersion, settings: created.body.settings },
      k(),
    );
    check('AtoProvidersController_update_v1', updated);
    const stale = await call(
      admin,
      'PATCH',
      `/ato/providers/${id}`,
      { rowVersion: created.body.rowVersion, settings: created.body.settings },
      k(),
    );
    expect(stale.body).toMatchObject({ code: 'ato_provider_conflict' });

    // Pause, resume, health check, backfill (bounds and already active), remove.
    check(
      'AtoProvidersController_pause_v1',
      await call(admin, 'POST', `/ato/providers/${id}/pause`, { reason: 'maintenance' }, k()),
    );
    check(
      'AtoProvidersController_resume_v1',
      await call(admin, 'POST', `/ato/providers/${id}/resume`, undefined, k()),
    );
    check(
      'AtoProvidersController_healthCheck_v1',
      await call(admin, 'POST', `/ato/providers/${id}/health-check`, undefined, k()),
    );
    const old = new Date(Date.now() - 40 * 86_400_000).toISOString();
    expect(
      (await call(admin, 'POST', `/ato/providers/${integration.id}/backfill`, { from: old }, k()))
        .body.code,
    ).toBe('ato_provider_backfill_range_invalid');
    const from = new Date(Date.now() - 2 * 86_400_000).toISOString();
    check(
      'AtoProvidersController_backfill_v1',
      await call(admin, 'POST', `/ato/providers/${integration.id}/backfill`, { from }, k()),
    );
    expect(
      (await call(admin, 'POST', `/ato/providers/${integration.id}/backfill`, { from }, k())).body
        .code,
    ).toBe('ato_provider_backfill_active');
    const removed = await call(
      admin,
      'DELETE',
      `/ato/providers/${id}`,
      { reason: 'no longer used' },
      k(),
    );
    check('AtoProvidersController_remove_v1', removed);
    expect(removed.body.status).toBe('disabled');
    const withRemoved = await call(admin, 'GET', '/ato/providers?includeDisabled=true');
    expect(withRemoved.body.data).toHaveLength(2);

    // Settings of 8.4 list the integrations.
    const atoSettings = await call(admin, 'GET', '/ato/settings');
    expect(
      atoSettings.body.identityProviders.find(
        (p: { provider: string }) => p.provider === 'microsoft_entra',
      ).integrations,
    ).toHaveLength(1);
    check('AtoSettingsController_get_v1', atoSettings);
  });

  it('mailbox state, refresh and a provider response confirmed only after the approval', async () => {
    const admin = await login('mfa.organization_admin@example.com');
    const analyst = await login('mfa.security_analyst@example.com');
    const accounts = await call(admin, 'GET', '/ato/accounts?kind=mailbox&sort=-riskScore');
    const withItems = [];
    for (const a of accounts.body.data as Array<{ id: string }>) {
      const state = await call(admin, 'GET', `/ato/accounts/${a.id}/mailbox-state`);
      expect(responseErrors('AtoAccountMailboxController_get_v1', 200, state.body)).toEqual([]);
      if (state.body.items.length > 0) withItems.push({ account: a, state: state.body });
    }
    expect(withItems).toHaveLength(1);
    const { account, state } = withItems[0]!;
    const refreshed = await call(
      admin,
      'POST',
      `/ato/accounts/${account.id}/mailbox-state/refresh`,
      undefined,
      k(),
    );
    expect(refreshed.status).toBe(202);
    expect(responseErrors('AtoAccountMailboxController_refresh_v1', 202, refreshed.body)).toEqual(
      [],
    );
    const rule = state.items.find(
      (i: { kind: string; state: string }) => i.kind === 'inbox_rule' && i.state === 'present',
    );
    const detail = await call(admin, 'GET', `/ato/accounts/${account.id}`);
    const incidentId = detail.body.activeIncident?.id as string | undefined;
    expect(incidentId).toBeDefined();
    expect(
      (
        await call(
          analyst,
          'POST',
          `/ato/incidents/${incidentId}/responses`,
          {
            actionType: 'remove_forwarding_rule',
            reason: 'External forwarding rule',
            params: { itemId: '0193c1a0-dddd-7a00-8000-0000000000ff' },
          },
          k(),
        )
      ).body.code,
    ).toBe('ato_response_invalid');
    const requested = await call(
      analyst,
      'POST',
      `/ato/incidents/${incidentId}/responses`,
      {
        actionType: 'remove_forwarding_rule',
        reason: 'External forwarding rule',
        params: { itemId: rule.id },
      },
      k(),
    );
    expect(requested.status).toBe(201);
    expect(requested.body).toMatchObject({
      status: 'pending_approval',
      provider: 'microsoft_entra',
    });
    const approved = await call(
      admin,
      'POST',
      `/ato/responses/${requested.body.id}/approve`,
      {},
      k(),
    );
    expect(approved.body).toMatchObject({
      status: 'succeeded',
      providerStatus: 'confirmed',
      canRollback: true,
    });
    const after = await call(admin, 'GET', `/ato/accounts/${account.id}/mailbox-state`);
    expect(after.body.items.find((i: { id: string }) => i.id === rule.id).state).toBe('removed');
  });
});
