// @vitest-environment node
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { operations } from '@/lib/api/operations.gen';
import type { OperationId } from '@/lib/api/types';
import { createMockFetch, mergedFixtures } from '@/server/dev-mocks';
import { toJsonSchema } from '@/test/contract';
import { API_MODE_OPERATIONS, resetApiModeFixtures } from './api-mode';
import { refreshDomainModes } from './domains';
import { resetProtectionModes } from './protection-modes';
import { resetProviderFixtures } from './provider-connections';

/**
 * Dev fixtures of API-mode protection (step API-1 WP6): each of the 14 operations answers with a
 * body that matches its OpenAPI response, and the rules the pages rely on hold (entitlement, MX
 * conflict with the domain names, inherit, unchanged = `changed: false`, CAS on the connection
 * settings, the mailbox-access requirement, the `remediation:write` gate of the mailbox grant, and
 * the domain and organization views following a change).
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
  let parsed: unknown = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  return {
    status: response.status,
    headers: response.headers,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in a test
    body: parsed as Record<string, any>,
  };
}

beforeEach(() => {
  resetProviderFixtures();
  resetApiModeFixtures();
});

afterAll(async () => {
  resetProtectionModes();
  const me = await call(await login('organization_admin@example.com'), 'GET', '/auth/me');
  refreshDomainModes(me.body.organization.id as string);
});

describe('api-mode dev fixtures (step API-1 WP6)', () => {
  it('cover the 14 protection-mode and API-mode operations of the OpenAPI document', () => {
    const handlers = mergedFixtures();
    for (const op of API_MODE_OPERATIONS) expect(handlers[op], op).toBeDefined();
    const fromSpec = Object.keys(operations).filter((id) =>
      /^(ApiMode|ProtectionMode)Controller/.test(id),
    );
    expect([...fromSpec].sort()).toEqual([...API_MODE_OPERATIONS].sort());
  });

  it('answer every operation with an OpenAPI-valid body and follow the D2 rules', async () => {
    const t = await login('organization_admin@example.com');
    const check = (op: OperationId, res: { status: number; body: unknown }) =>
      expect(responseErrors(op, res.status, res.body), op).toEqual([]);
    let key = 0;
    const k = () => `key-${(key += 1)}`;
    const me = await call(t, 'GET', '/auth/me');
    const orgId = me.body.organization.id as string;

    const mode = await call(t, 'GET', `/organizations/${orgId}/protection-mode`);
    check('ProtectionModeController_getOrganization_v1', mode);
    expect(mode.body.entitled).toBe(true);
    const org = await call(t, 'GET', `/organizations/${orgId}`);
    check('OrganizationsController_get_v1', org);
    expect(org.body.protectionMode).toEqual(mode.body);

    const domains = await call(t, 'GET', '/domains?limit=100');
    check('DomainsController_list_v1', domains);
    const rows = domains.body.data as Array<{
      id: string;
      status: string;
      protectionMode: { configured: string | null; effective: string; inherited: boolean };
    }>;
    expect(rows.some((d) => d.protectionMode.effective === 'api')).toBe(true);
    // An inheriting, active domain: its MX points to the gateway in the fixtures.
    const target = rows.find((d) => d.protectionMode.inherited && d.status === 'active')!;
    const conflict = await call(
      t,
      'PUT',
      `/domains/${target.id}/protection-mode`,
      { mode: 'api', reason: 'fixture' },
      k(),
    );
    expect(conflict.status).toBe(409);
    expect(conflict.body.code).toBe('protection_mode_mx_points_to_gateway');
    expect(conflict.body.domains[0].id).toBe(target.id);
    const missingReason = await call(
      t,
      'PUT',
      `/domains/${target.id}/protection-mode`,
      { mode: 'hybrid', reason: '' },
      k(),
    );
    expect(missingReason.status).toBe(400);
    const hybrid = await call(
      t,
      'PUT',
      `/domains/${target.id}/protection-mode`,
      { mode: 'hybrid', reason: 'fixture' },
      k(),
    );
    check('ProtectionModeController_putDomain_v1', hybrid);
    expect(hybrid.body).toMatchObject({ changed: true, protectionMode: { effective: 'hybrid' } });
    const again = await call(
      t,
      'PUT',
      `/domains/${target.id}/protection-mode`,
      { mode: 'hybrid', reason: 'fixture' },
      k(),
    );
    expect(again.body.changed).toBe(false);
    const inherit = await call(
      t,
      'PUT',
      `/domains/${target.id}/protection-mode`,
      { mode: 'inherit', reason: 'fixture' },
      k(),
    );
    expect(inherit.body.protectionMode).toMatchObject({ configured: null, inherited: true });

    const orgConflict = await call(
      t,
      'PUT',
      `/organizations/${orgId}/protection-mode`,
      { mode: 'api', reason: 'fixture' },
      k(),
    );
    expect(orgConflict.status).toBe(409);
    const orgHybrid = await call(
      t,
      'PUT',
      `/organizations/${orgId}/protection-mode`,
      { mode: 'hybrid', reason: 'fixture' },
      k(),
    );
    check('ProtectionModeController_putOrganization_v1', orgHybrid);
    expect(orgHybrid.body.changed).toBe(true);
    expect(orgHybrid.body.inheritingDomains).toBeGreaterThan(0);
    const after = await call(t, 'GET', `/domains/${target.id}`);
    check('DomainsController_get_v1', after);
    expect(after.body.protectionMode.effective).toBe('hybrid');

    const overview = await call(t, 'GET', '/api-mode/overview');
    check('ApiModeController_overview_v1', overview);
    const connections = await call(t, 'GET', '/api-mode/connections');
    check('ApiModeController_listConnections_v1', connections);
    const [first, second] = connections.body.data as Array<{
      id: string;
      rowVersion: number;
      grant: { status: string } | null;
    }>;
    expect(first?.grant?.status).toBe('active');
    check(
      'ApiModeController_getConnection_v1',
      await call(t, 'GET', `/api-mode/connections/${first!.id}`),
    );
    check(
      'ApiModeController_setupGuide_v1',
      await call(t, 'GET', `/api-mode/connections/${first!.id}/setup-guide?format=json`),
    );
    const md = await call(
      t,
      'GET',
      `/api-mode/connections/${first!.id}/setup-guide?format=markdown`,
    );
    expect(md.headers.get('content-type')).toMatch(/text\/markdown/);
    const stale = await call(
      t,
      'PUT',
      `/api-mode/connections/${first!.id}/settings`,
      { feedsEnabled: true, feedMode: 'poll', expectedRowVersion: first!.rowVersion - 1 },
      k(),
    );
    expect(stale.body.code).toBe('api_mode_connection_conflict');
    const settings = await call(
      t,
      'PUT',
      `/api-mode/connections/${first!.id}/settings`,
      { feedsEnabled: true, feedMode: 'notify', expectedRowVersion: first!.rowVersion },
      k(),
    );
    check('ApiModeController_updateSettings_v1', settings);
    const noGrant = await call(
      t,
      'PUT',
      `/api-mode/connections/${second!.id}/settings`,
      { feedsEnabled: true, expectedRowVersion: second!.rowVersion },
      k(),
    );
    expect(noGrant.body.code).toBe('api_mode_mailbox_access_required');
    check(
      'ApiModeController_inventorySync_v1',
      await call(t, 'POST', `/api-mode/connections/${first!.id}/inventory-sync`, undefined, k()),
    );
    const mailboxes = await call(t, 'GET', '/api-mode/mailboxes?coverage=covered');
    check('ApiModeController_listMailboxes_v1', mailboxes);
    const mailboxId = mailboxes.body.data[0].id as string;
    check(
      'ApiModeController_getMailbox_v1',
      await call(t, 'GET', `/api-mode/mailboxes/${mailboxId}`),
    );
    check(
      'ApiModeController_resyncMailbox_v1',
      await call(t, 'POST', `/api-mode/mailboxes/${mailboxId}/resync`, undefined, k()),
    );
    const detections = await call(t, 'GET', '/api-mode/detections');
    check('ApiModeController_listDetections_v1', detections);
    expect(JSON.stringify(detections.body.data)).not.toMatch(
      /subscription|clientState|feedCursor/i,
    );
    check(
      'ApiModeController_getDetection_v1',
      await call(t, 'GET', `/api-mode/detections/${detections.body.data[0].id as string}`),
    );
  });

  it('refuses read-only users on writes and gates the mailbox grant on remediation:write', async () => {
    const ro = await login('read_only_user@example.com');
    const connections = await call(ro, 'GET', '/api-mode/connections');
    expect(connections.status).toBe(200);
    const id = connections.body.data[0].id as string;
    const write = await call(
      ro,
      'POST',
      `/api-mode/connections/${id}/inventory-sync`,
      undefined,
      'ro-1',
    );
    expect(write.status).toBe(403);
    // domain_admin holds integration:manage but not remediation:write.
    const da = await login('domain_admin@example.com');
    const grant = await call(
      da,
      'POST',
      `/provider-connections/${id}/grants`,
      { profile: 'm365.mailbox_remediation', authMethod: 'platform_app' },
      'da-1',
    );
    expect(grant.status).toBe(403);
    expect(grant.body.code).toBe('remediation_permission_required');
  });
});
