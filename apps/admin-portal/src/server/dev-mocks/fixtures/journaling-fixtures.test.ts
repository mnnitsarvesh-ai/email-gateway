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
import { resetArchiveFixtures } from './archive';
import { JOURNALING_OPERATIONS, resetJournalingFixtures } from './journaling';

/**
 * Dev fixtures of Journaling (step 8.6 WP6): each of the 12 operations answers with a body that
 * matches its OpenAPI response, and the rules the pages rely on hold (masking and audited reveal,
 * one-time address with a redacted replay, MFA, CAS, network validation, terminal disable, the
 * archive settings row shared with the Archive area, per-path archive settings authorization).
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
  resetArchiveFixtures();
  resetJournalingFixtures();
});

describe('journaling dev fixtures (step 8.6 WP6)', () => {
  it('cover the 12 journaling operations of the OpenAPI document', () => {
    const handlers = mergedFixtures();
    for (const op of JOURNALING_OPERATIONS) expect(handlers[op], op).toBeDefined();
    const fromSpec = Object.keys(operations).filter((id) =>
      /^(Journaling|IntakeSources)Controller/.test(id),
    );
    expect([...fromSpec].sort()).toEqual([...JOURNALING_OPERATIONS].sort());
  });

  it('answer every operation with an OpenAPI-valid body (MFA organization admin)', async () => {
    const t = await login('mfa.organization_admin@example.com');
    const check = (op: OperationId, res: { status: number; body: unknown }) =>
      expect(responseErrors(op, res.status, res.body), op).toEqual([]);
    let key = 0;
    const k = () => `key-${(key += 1)}`;
    const settings = await call(t, 'GET', '/journaling/settings');
    check('JournalingController_get_v1', settings);
    check(
      'JournalingController_update_v1',
      await call(
        t,
        'PUT',
        '/journaling/settings',
        {
          expectedRowVersion: settings.body.rowVersion,
          settings: { intake: { scanEnabled: true } },
        },
        k(),
      ),
    );
    check('JournalingController_status_v1', await call(t, 'GET', '/journaling/status'));
    const list = await call(t, 'GET', '/journaling/intake-sources');
    check('IntakeSourcesController_list_v1', list);
    const createKey = k();
    const body = { kind: 'smtp_bcc', displayName: 'EXAMPLE BCC', networks: ['203.0.113.16/28'] };
    const created = await call(t, 'POST', '/journaling/intake-sources', body, createKey);
    check('IntakeSourcesController_create_v1', created);
    expect(created.body.address).toMatch(/^journal-[a-z2-7]{26}@/);
    expect(created.body.source.address).toMatch(/••••/);
    const replay = await call(t, 'POST', '/journaling/intake-sources', body, createKey);
    expect(replay.headers.get('idempotency-replayed')).toBe('true');
    expect(replay.body.address).toBeNull();
    const id = created.body.source.id as string;
    const got = await call(t, 'GET', `/journaling/intake-sources/${id}`);
    check('IntakeSourcesController_get_v1', got);
    expect(got.body.revealed).toBe(false);
    const shown = await call(t, 'GET', `/journaling/intake-sources/${id}?reveal=true`);
    check('IntakeSourcesController_get_v1', shown);
    expect(shown.body.address).toBe(created.body.address);
    check(
      'IntakeSourcesController_wizard_v1',
      await call(t, 'GET', `/journaling/intake-sources/${id}/wizard`),
    );
    check(
      'IntakeSourcesController_guide_v1',
      await call(t, 'GET', `/journaling/intake-sources/${id}/setup-guide?format=json`),
    );
    const md = await call(t, 'GET', `/journaling/intake-sources/${id}/setup-guide?format=markdown`);
    expect(md.headers.get('content-type')).toMatch(/text\/markdown/);
    check(
      'IntakeSourcesController_attest_v1',
      await call(t, 'POST', `/journaling/intake-sources/${id}/attestations`, {
        code: 'journal.smtp.bcc_configured',
        attested: true,
      }),
    );
    const current = await call(t, 'GET', `/journaling/intake-sources/${id}`);
    check(
      'IntakeSourcesController_update_v1',
      await call(
        t,
        'PATCH',
        `/journaling/intake-sources/${id}`,
        { expectedRowVersion: current.body.rowVersion, status: 'paused' },
        k(),
      ),
    );
    const rotated = await call(
      t,
      'POST',
      `/journaling/intake-sources/${id}/rotate-address`,
      undefined,
      k(),
    );
    check('IntakeSourcesController_rotate_v1', rotated);
    expect(rotated.body.address).not.toBe(created.body.address);
    check(
      'IntakeSourcesController_disable_v1',
      await call(t, 'DELETE', `/journaling/intake-sources/${id}`),
    );
    const again = await call(t, 'DELETE', `/journaling/intake-sources/${id}`);
    expect(again.status).toBe(409);
    expect(again.body.code).toBe('journal_intake_source_disabled');
  });

  it('keeps the api rules: reveal needs journal:manage, MFA, networks, CAS, shared settings row', async () => {
    const readOnly = await login('read_only_user@example.com');
    const list = await call(readOnly, 'GET', '/journaling/intake-sources');
    expect(list.status).toBe(200);
    const id = list.body.data[0].id as string;
    expect(
      (await call(readOnly, 'GET', `/journaling/intake-sources/${id}?reveal=true`)).status,
    ).toBe(403);
    const noMfa = await login('organization_admin@example.com');
    const refused = await call(
      noMfa,
      'POST',
      '/journaling/intake-sources',
      { kind: 'smtp_bcc', displayName: 'x', networks: ['203.0.113.0/28'] },
      'k1',
    );
    expect(refused.body.code).toBe('mfa_required');
    const t = await login('mfa.organization_admin@example.com');
    const overlap = await call(
      t,
      'POST',
      '/journaling/intake-sources',
      { kind: 'smtp_bcc', displayName: 'x', networks: ['40.92.0.0/16'] },
      'k2',
    );
    expect(overlap.status).toBe(422);
    expect(overlap.body.code).toBe('journal_intake_networks_invalid');
    const stale = await call(t, 'PUT', '/journaling/settings', { expectedRowVersion: 1 }, 'k3');
    expect(stale.status).toBe(409);
    expect(typeof stale.body.currentRowVersion).toBe('number');
    // One row: a journaling change is visible to the Archive area (and the reverse).
    const before = await call(t, 'GET', '/journaling/settings');
    await call(
      t,
      'PUT',
      '/journaling/settings',
      { expectedRowVersion: before.body.rowVersion, settings: { directions: { internal: false } } },
      'k4',
    );
    const archive = await call(t, 'GET', '/archive/settings');
    expect(archive.body.settings.directions.internal).toBe(false);
    // An organization admin may not change the archive paths of the shared row (step 8.6).
    const denied = await call(
      t,
      'PUT',
      '/archive/settings',
      { expectedRowVersion: archive.body.rowVersion, immutability: 'none' },
      'k5',
    );
    expect(denied.status).toBe(403);
    expect(denied.body.code).toBe('archive_settings_forbidden_path');
    expect(denied.body.paths).toEqual([{ path: 'immutability', permission: 'archive:manage' }]);
  });

  it('serves an archive-only organization to the archive. dev hint (step 8.6)', async () => {
    const t = await login('archive.organization_admin@example.com');
    const me = await call(t, 'GET', '/auth/me');
    expect(me.body.organization.serviceProfile).toBe('archive_only');
  });
});
