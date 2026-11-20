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
import { ATO_OPERATIONS, resetAtoFixtures } from './ato';
import { INCIDENT_OPERATIONS } from './incidents';

/**
 * Dev fixtures of the account takeover and incident pages (step 8.4 WP6): every one of the 34
 * operations answers with a body matching its OpenAPI response, and the rules the pages rely on
 * hold (MFA, four eyes, restriction applied and lifted, CAS, Idempotency-Key replay, category
 * permissions).
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
  if (!schema) return status === 204 ? [] : [`no ${status} schema for ${operationId}`];
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
const k = () => `key-${(keyCounter += 1)}`;

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

beforeEach(() => resetAtoFixtures());

describe('ATO and incident dev fixtures (step 8.4 WP6)', () => {
  it('cover the 26 ATO and 8 incident operations of §5', () => {
    const handlers = mergedFixtures();
    expect(ATO_OPERATIONS).toHaveLength(26);
    expect(INCIDENT_OPERATIONS).toHaveLength(8);
    for (const op of [...ATO_OPERATIONS, ...INCIDENT_OPERATIONS])
      expect(handlers[op], op).toBeDefined();
    // Step 8.5's identity-provider operations have their own fixtures (ato-providers.ts).
    const fromSpec = Object.keys(operations).filter(
      (id) => /^(Ato|Incidents)/.test(id) && !/^(AtoProviders|AtoAccountMailbox)/.test(id),
    );
    expect([...fromSpec].sort()).toEqual([...ATO_OPERATIONS, ...INCIDENT_OPERATIONS].sort());
  });

  it('answer every operation with an OpenAPI-valid body and keep the workflow rules', async () => {
    const admin = await login('mfa.organization_admin@example.com');
    const analyst = await login('mfa.security_analyst@example.com');
    const check = (op: OperationId, res: { status: number; body: unknown }) => {
      expect(res.status, op).toBeLessThan(300);
      expect(responseErrors(op, res.status, res.body), op).toEqual([]);
    };
    check('AtoOverviewController_overview_v1', await call(admin, 'GET', '/ato/overview?range=24h'));
    check('AtoOverviewController_attention_v1', await call(admin, 'GET', '/ato/attention'));
    const accounts = await call(admin, 'GET', '/ato/accounts?level=high,critical');
    check('AtoAccountsController_list_v1', accounts);
    expect(accounts.body.data.length).toBe(2);
    const account = accounts.body.data[0];
    const detail = await call(admin, 'GET', `/ato/accounts/${account.id}`);
    check('AtoAccountsController_get_v1', detail);
    for (const [op, path] of [
      ['AtoAccountsController_signals_v1', 'signals'],
      ['AtoAccountsController_authEvents_v1', 'auth-events'],
      ['AtoAccountsController_activity_v1', 'activity'],
      ['AtoAccountsController_scoreHistory_v1', 'score-history'],
    ] as const) {
      check(op, await call(admin, 'GET', `/ato/accounts/${account.id}/${path}`));
    }
    const protect = await call(
      admin,
      'PATCH',
      `/ato/accounts/${account.id}`,
      { protected: true, reason: 'VIP mailbox', expectedRowVersion: detail.body.rowVersion },
      k(),
    );
    check('AtoAccountsController_update_v1', protect);
    expect(
      (
        await call(
          admin,
          'PATCH',
          `/ato/accounts/${account.id}`,
          { protected: false, reason: 'stale', expectedRowVersion: detail.body.rowVersion },
          k(),
        )
      ).body.code,
    ).toBe('ato_account_conflict');
    check(
      'AtoAccountsController_setOverride_v1',
      await call(
        admin,
        'PUT',
        `/ato/accounts/${account.id}/override`,
        { verdict: 'benign', reason: 'Known travel of the user', expiresInHours: 24 },
        k(),
      ),
    );
    check(
      'AtoAccountsController_clearOverride_v1',
      await call(
        admin,
        'POST',
        `/ato/accounts/${account.id}/override/clear`,
        { reason: 'Travel ended, back to normal' },
        k(),
      ),
    );
    const ctx = await call(
      admin,
      'POST',
      `/ato/accounts/${account.id}/trusted-contexts`,
      { kind: 'ip_cidr', value: '198.51.100.0/24', reason: 'office', expiresInDays: 30 },
      k(),
    );
    check('AtoAccountsController_addTrustedContext_v1', ctx);
    expect(
      (
        await call(
          admin,
          'DELETE',
          `/ato/accounts/${account.id}/trusted-contexts/${ctx.body.id}`,
          undefined,
          k(),
        )
      ).status,
    ).toBe(204);

    const incidents = await call(admin, 'GET', '/incidents?category=account_takeover');
    check('IncidentsController_list_v1', incidents);
    const critical = incidents.body.data.find(
      (i: { severity: string }) => i.severity === 'critical',
    );
    const incident = await call(admin, 'GET', `/incidents/${critical.id}`);
    check('IncidentsController_get_v1', incident);
    expect(incident.body.allowedTransitions.map((t: { to: string }) => t.to)).toEqual([
      'investigating',
      'confirmed',
      'false_positive',
      'resolved',
    ]);
    check(
      'IncidentsController_timeline_v1',
      await call(admin, 'GET', `/incidents/${critical.id}/timeline`),
    );
    check(
      'IncidentsController_messages_v1',
      await call(admin, 'GET', `/incidents/${critical.id}/messages`),
    );
    check(
      'IncidentsController_report_v1',
      await call(admin, 'GET', `/incidents/${critical.id}/report`),
    );
    check(
      'AtoIncidentEvidenceController_signals_v1',
      await call(admin, 'GET', `/ato/incidents/${critical.id}/signals`),
    );
    check(
      'AtoIncidentEvidenceController_authEvents_v1',
      await call(admin, 'GET', `/ato/incidents/${critical.id}/auth-events`),
    );
    check(
      'IncidentsController_addNote_v1',
      await call(admin, 'POST', `/incidents/${critical.id}/notes`, { note: 'Looking at it' }, k()),
    );
    const investigating = await call(
      admin,
      'PATCH',
      `/incidents/${critical.id}`,
      { expectedRowVersion: incident.body.rowVersion, status: 'investigating' },
      k(),
    );
    check('IncidentsController_update_v1', investigating);

    // Request by the admin, self-approval refused, approval by the analyst applies a restriction.
    const requested = await call(
      admin,
      'POST',
      `/ato/incidents/${critical.id}/responses`,
      {
        actionType: 'block_smtp_auth',
        reason: 'Credentials used from a hostile network',
        durationMinutes: 60,
      },
      k(),
    );
    check('AtoResponsesController_request_v1', requested);
    expect(requested.body.status).toBe('pending_approval');
    expect(requested.body.canDecide).toBe(false);
    expect(
      (await call(admin, 'POST', `/ato/responses/${requested.body.id}/approve`, {}, k())).body.code,
    ).toBe('ato_approval_self');
    const approved = await call(
      analyst,
      'POST',
      `/ato/responses/${requested.body.id}/approve`,
      {},
      k(),
    );
    check('AtoResponsesController_approve_v1', approved);
    expect(approved.body.status).toBe('succeeded');
    expect(approved.body.canRollback).toBe(true);
    check(
      'AtoRestrictionsController_list_v1',
      await call(admin, 'GET', '/ato/restrictions?status=active'),
    );
    check(
      'AtoResponsesController_get_v1',
      await call(admin, 'GET', `/ato/responses/${requested.body.id}`),
    );
    check(
      'AtoResponsesController_list_v1',
      await call(admin, 'GET', '/ato/responses?status=succeeded'),
    );
    const rolled = await call(
      analyst,
      'POST',
      `/ato/responses/${requested.body.id}/rollback`,
      { reason: 'The legitimate server was identified' },
      k(),
    );
    check('AtoResponsesController_rollback_v1', rolled);
    expect(rolled.body.status).toBe('rolled_back');

    const pending = (await call(admin, 'GET', '/ato/responses?status=pending_approval')).body
      .data[0];
    check(
      'AtoResponsesController_reject_v1',
      await call(
        analyst,
        'POST',
        `/ato/responses/${pending.id}/reject`,
        { reason: 'Not needed after review' },
        k(),
      ),
    );
    const another = await call(
      admin,
      'POST',
      `/ato/incidents/${critical.id}/responses`,
      {
        actionType: 'restrict_smtp_sending',
        reason: 'Stop the phishing run now',
        durationMinutes: 240,
        mode: 'reject',
      },
      k(),
    );
    check(
      'AtoResponsesController_cancel_v1',
      await call(admin, 'POST', `/ato/responses/${another.body.id}/cancel`, {}, k()),
    );

    const settings = await call(admin, 'GET', '/ato/settings');
    check('AtoSettingsController_get_v1', settings);
    const saved = await call(
      admin,
      'PUT',
      '/ato/settings',
      { expectedRowVersion: settings.body.rowVersion, settings: { mode: 'enforce' } },
      k(),
    );
    check('AtoSettingsController_update_v1', saved);
    expect(
      (
        await call(
          admin,
          'PUT',
          '/ato/settings',
          { expectedRowVersion: settings.body.rowVersion, settings: { mode: 'monitor' } },
          k(),
        )
      ).body.code,
    ).toBe('ato_settings_conflict');
    check('AtoRulesController_list_v1', await call(admin, 'GET', '/ato/rules'));

    const created = await call(
      admin,
      'POST',
      '/incidents',
      {
        category: 'account_takeover',
        subject: {
          type: 'ato_account',
          id:
            accounts.body.data[1].id === account.id
              ? accounts.body.data[0].id
              : (await call(admin, 'GET', '/ato/accounts?q=user1')).body.data[0].id,
        },
        reason: 'The user reported a strange sign-in prompt',
      },
      k(),
    );
    expect([201, 409]).toContain(created.status);
  });

  it('replays an Idempotency-Key and refuses MFA routes without MFA', async () => {
    const admin = await login('organization_admin@example.com');
    const incidents = await call(admin, 'GET', '/incidents');
    const id = incidents.body.data[0].id;
    const key = k();
    const first = await call(admin, 'POST', `/incidents/${id}/notes`, { note: 'once' }, key);
    const replay = await call(admin, 'POST', `/incidents/${id}/notes`, { note: 'once' }, key);
    expect(replay.headers.get('idempotency-replayed')).toBe('true');
    expect(replay.body).toEqual(first.body);
    const pending = (await call(admin, 'GET', '/ato/responses?status=pending_approval')).body
      .data[0];
    expect(
      (await call(admin, 'POST', `/ato/responses/${pending.id}/approve`, {}, k())).body.code,
    ).toBe('mfa_required');
  });

  it('answer 403 without ato:read and hide incidents from a role without a category permission', async () => {
    const reader = await login('read_only_user@example.com');
    expect((await call(reader, 'GET', '/ato/overview')).status).toBe(403);
    expect((await call(reader, 'GET', '/incidents')).status).toBe(403);
    const auditor = await login('compliance_auditor@example.com');
    expect((await call(auditor, 'GET', '/incidents')).status).toBe(200);
    expect((await call(auditor, 'POST', '/incidents/x/notes', { note: 'no' }, k())).status).toBe(
      403,
    );
  });
});
