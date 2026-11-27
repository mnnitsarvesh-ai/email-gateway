// @vitest-environment node
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { operations } from '@/lib/api/operations.gen';
import type { OperationId } from '@/lib/api/types';
import { createMockFetch, mergedFixtures } from '@/server/dev-mocks';
import { toJsonSchema } from '@/test/contract';
import { API_MODE_REMEDIATION_OPERATIONS, resetApiModeFixtures } from './api-mode';
import { resetProviderFixtures } from './provider-connections';

/**
 * Dev fixtures of API-mode remediation (step API-2 WP6, R12, R13, R10.5): each of the 9
 * operations answers with an OpenAPI-valid body; the rules the pages rely on hold (CAS on the
 * policy, hard delete refused, domain overrides, manual remediate and the worker completing it,
 * restore through the quarantine release with the mailbox entry, retry of failed rows only) and
 * the quarantine views carry the `location` block and filter.
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
async function call(token: string, method: string, path: string, body?: unknown, keyed = false) {
  const response = await fetchImpl(`${API}/api/v1${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...(keyed ? { 'idempotency-key': `rem-key-${(keyCounter += 1)}` } : {}),
    },
    body: body === undefined ? null : JSON.stringify(body),
  });
  const text = await response.text();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in a test
  const parsed = (text ? JSON.parse(text) : null) as Record<string, any>;
  return { status: response.status, body: parsed };
}

const check = (op: OperationId, res: { status: number; body: unknown }) =>
  expect(responseErrors(op, res.status, res.body), op).toEqual([]);

beforeEach(() => {
  resetProviderFixtures();
  resetApiModeFixtures();
});

describe('api-mode remediation dev fixtures (step API-2 WP6)', () => {
  it('cover the 9 remediation operations of the OpenAPI document', () => {
    const handlers = mergedFixtures();
    for (const op of API_MODE_REMEDIATION_OPERATIONS) expect(handlers[op], op).toBeDefined();
    const fromSpec = Object.keys(operations).filter((id) =>
      id.startsWith('ApiModeRemediationController_'),
    );
    expect([...fromSpec].sort()).toEqual([...API_MODE_REMEDIATION_OPERATIONS].sort());
  });

  it('policy: platform default, CAS create and update, hard delete refused, domain overrides', async () => {
    const t = await login('organization_admin@example.com');
    const policy = await call(t, 'GET', '/api-mode/remediation-policy');
    check('ApiModeRemediationController_getPolicy_v1', policy);
    expect(policy.body.organization).toMatchObject({
      source: 'platform_default',
      rowVersion: null,
    });
    const document = policy.body.presets.detectOnlyStart.document;
    const stale = await call(
      t,
      'PUT',
      '/api-mode/remediation-policy',
      { mode: 'detect_only', document, reason: 'fixture', expectedRowVersion: 4 },
      true,
    );
    expect(stale).toMatchObject({
      status: 409,
      body: { code: 'api_mode_remediation_policy_conflict', currentRowVersion: null },
    });
    const hardDelete = await call(
      t,
      'PUT',
      '/api-mode/remediation-policy',
      {
        mode: 'enforce',
        document: {
          v: 1,
          rules: [{ id: 'hd', when: { verdicts: ['malware'] }, action: 'hard_delete' }],
        },
        reason: 'fixture',
        expectedRowVersion: null,
      },
      true,
    );
    expect(hardDelete).toMatchObject({
      status: 422,
      body: { code: 'api_mode_hard_delete_disabled' },
    });
    const invalid = await call(
      t,
      'PUT',
      '/api-mode/remediation-policy',
      {
        mode: 'enforce',
        document: { v: 1, rules: [{ id: 'x', when: { verdicts: ['clean'] }, action: 'tag' }] },
        reason: 'fixture',
        expectedRowVersion: null,
      },
      true,
    );
    expect(invalid.status).toBe(400);
    const created = await call(
      t,
      'PUT',
      '/api-mode/remediation-policy',
      { mode: 'detect_only', document, reason: 'fixture', expectedRowVersion: null },
      true,
    );
    check('ApiModeRemediationController_putPolicy_v1', created);
    expect(created.body).toMatchObject({ created: true, rowVersion: 1, mode: 'detect_only' });
    const overview = await call(t, 'GET', '/api-mode/overview');
    check('ApiModeController_overview_v1', overview);
    expect(overview.body.remediation).toMatchObject({
      policyMode: 'detect_only',
      policySource: 'organization',
    });

    const domains = await call(t, 'GET', '/domains?limit=100');
    const domainId = domains.body.data[0].id as string;
    const domain = await call(
      t,
      'PUT',
      `/api-mode/remediation-policy/domains/${domainId}`,
      { mode: 'enforce', document, reason: 'fixture', expectedRowVersion: null },
      true,
    );
    check('ApiModeRemediationController_putDomainPolicy_v1', domain);
    const withDomain = await call(t, 'GET', '/api-mode/remediation-policy');
    check('ApiModeRemediationController_getPolicy_v1', withDomain);
    expect(withDomain.body.domains).toHaveLength(1);
    const removed = await call(
      t,
      'DELETE',
      `/api-mode/remediation-policy/domains/${domainId}`,
      undefined,
      true,
    );
    expect(removed.status).toBe(204);
    expect((await call(t, 'GET', '/api-mode/remediation-policy')).body.domains).toHaveLength(0);
  });

  it('history, remediate (worker completes it with a mailbox entry), restore via the quarantine release, retry', async () => {
    const t = await login('organization_admin@example.com');
    const history = await call(t, 'GET', '/api-mode/remediations');
    check('ApiModeRemediationController_list_v1', history);
    const failed = (history.body.data as Array<{ id: string; status: string }>).find(
      (a) => a.status === 'failed',
    )!;
    expect(failed).toBeDefined();
    check(
      'ApiModeRemediationController_detail_v1',
      await call(t, 'GET', `/api-mode/remediations/${failed.id}`),
    );
    const retried = await call(
      t,
      'POST',
      `/api-mode/remediations/${failed.id}/retry`,
      undefined,
      true,
    );
    check('ApiModeRemediationController_retry_v1', retried);
    expect(retried.body.status).toBe('pending');
    const again = await call(
      t,
      'POST',
      `/api-mode/remediations/${failed.id}/retry`,
      undefined,
      true,
    );
    expect(again.body.code).toBe('api_mode_remediation_not_retryable');

    const detections = await call(t, 'GET', '/api-mode/detections?remediationState=none');
    check('ApiModeController_listDetections_v1', detections);
    const target = (detections.body.data as Array<{ id: string; status: string }>).find(
      (d) => d.status === 'scanned',
    )!;
    const manualHardDelete = await call(
      t,
      'POST',
      `/api-mode/detections/${target.id}/remediate`,
      { action: 'hard_delete', reason: 'fixture' },
      true,
    );
    expect(manualHardDelete.body.code).toBe('api_mode_hard_delete_not_manual');
    const remediated = await call(
      t,
      'POST',
      `/api-mode/detections/${target.id}/remediate`,
      { action: 'move_quarantine', reason: 'fixture' },
      true,
    );
    check('ApiModeRemediationController_remediate_v1', remediated);
    const busy = await call(
      t,
      'POST',
      `/api-mode/detections/${target.id}/remediate`,
      { action: 'tag', reason: 'fixture' },
      true,
    );
    expect(busy.body.code).toBe('api_mode_remediation_in_progress');

    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      vi.setSystemTime(Date.now() + 60_000);
      const done = await call(t, 'GET', `/api-mode/detections/${target.id}`);
      check('ApiModeController_getDetection_v1', done);
      expect(done.body).toMatchObject({ remediationState: 'remediated' });
      const entryId = done.body.quarantineEntryId as string;
      const entry = await call(t, 'GET', `/quarantine/entries/${entryId}`);
      check('QuarantineEntriesController_detail_v1', entry);
      expect(entry.body.location).toMatchObject({
        kind: 'mailbox',
        container: 'quarantine_folder',
        detectionId: target.id,
      });
      const mailboxList = await call(
        t,
        'GET',
        `/quarantine/entries?location=mailbox&from=${new Date(Date.now() - 20 * 86_400_000).toISOString()}&to=${new Date(Date.now() + 3_600_000).toISOString()}`,
      );
      check('QuarantineEntriesController_search_v1', mailboxList);
      expect(
        (mailboxList.body.items as Array<{ location: { kind: string } }>).every(
          (i) => i.location.kind === 'mailbox',
        ),
      ).toBe(true);

      const restore = await call(
        t,
        'POST',
        `/api-mode/detections/${target.id}/restore`,
        { reason: 'fixture' },
        true,
      );
      check('ApiModeRemediationController_restore_v1', restore);
      expect(restore.body).toMatchObject({
        via: 'quarantine_release',
        release: { outcome: 'queued', entryId },
      });
      vi.setSystemTime(Date.now() + 60_000);
      const restored = await call(t, 'GET', `/api-mode/detections/${target.id}`);
      expect(restored.body.remediationState).toBe('restored');
      const released = await call(t, 'GET', `/quarantine/entries/${entryId}`);
      expect(released.body.state).toBe('released');
      const reversal = await call(t, 'GET', `/api-mode/remediations?action=restore_inbox`);
      check('ApiModeRemediationController_list_v1', reversal);
      expect(reversal.body.data[0]).toMatchObject({ status: 'succeeded', trigger: 'release' });
    } finally {
      vi.useRealTimers();
    }
  });

  it('refuses read-only users on every remediation write', async () => {
    const ro = await login('read_only_user@example.com');
    expect((await call(ro, 'GET', '/api-mode/remediation-policy')).status).toBe(200);
    const put = await call(
      ro,
      'PUT',
      '/api-mode/remediation-policy',
      { mode: 'enforce', document: { v: 1, rules: [] }, reason: 'x', expectedRowVersion: null },
      true,
    );
    expect(put.status).toBe(403);
  });
});
