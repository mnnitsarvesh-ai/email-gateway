// @vitest-environment node
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { operations } from '@/lib/api/operations.gen';
import type { OperationId } from '@/lib/api/types';
import { createMockFetch, mergedFixtures } from '@/server/dev-mocks';
import { toJsonSchema } from '@/test/contract';
import { resetApiModeFixtures } from './api-mode';
import {
  API_MODE_CLAWBACK_OPERATIONS,
  MATERIALIZE_DELAY_MS,
  QUEUE_DELAY_MS,
  resetApiModeClawbackFixtures,
} from './api-mode-clawback';
import { resetProviderFixtures } from './provider-connections';

/**
 * Dev fixtures of API-mode clawback, search and purge, reported phishing and the organization
 * settings (step API-3 WP6, C4–C14): every one of the 19 operations answers with an OpenAPI-valid
 * body, and the main flows hold — a Message-ID search materialized by the simulated worker, a
 * purge below the threshold run to completion and restored, a purge above a lowered threshold
 * approved by a second user only (separation of duties), cancel, report triage with the group and
 * feedback, a clawback from a report, report mailboxes, settings CAS and read-only gating.
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
      ...(keyed ? { 'idempotency-key': `claw-key-${(keyCounter += 1)}` } : {}),
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

const advance = (ms: number) => vi.setSystemTime(Date.now() + ms);
const range = () =>
  `from=${encodeURIComponent(new Date(Date.now() - 7 * 86_400_000).toISOString())}&to=${encodeURIComponent(new Date(Date.now() + 3_600_000).toISOString())}`;

/** A Message-ID search over the last 6 days (copies of campaign group 2 share it). */
const searchBody = (reason = 'fixture search') => ({
  criteria: {
    messageId: '<campaign-2@mail.sender-2.example.test>',
    from: new Date(Date.now() - 6 * 86_400_000).toISOString(),
    to: new Date(Date.now() + 60_000).toISOString(),
  },
  reason,
});

beforeEach(() => {
  resetProviderFixtures();
  resetApiModeFixtures();
  resetApiModeClawbackFixtures();
  vi.useFakeTimers({ toFake: ['Date'] });
});
afterEach(() => vi.useRealTimers());

describe('api-mode clawback dev fixtures (step API-3 WP6)', () => {
  it('cover the 19 clawback, report and settings operations of the OpenAPI document', () => {
    const handlers = mergedFixtures();
    for (const op of API_MODE_CLAWBACK_OPERATIONS) expect(handlers[op], op).toBeDefined();
    const fromSpec = Object.keys(operations).filter((id) =>
      /^ApiMode(Clawback|Reports|Settings)Controller_/.test(id),
    );
    expect([...fromSpec].sort()).toEqual([...API_MODE_CLAWBACK_OPERATIONS].sort());
  });

  it('seeded states, overview blocks and detections are OpenAPI-valid', async () => {
    const t = await login('organization_admin@example.com');
    const list = await call(t, 'GET', `/api-mode/clawbacks?${range()}`);
    check('ApiModeClawbackController_list_v1', list);
    const statuses = list.body.data.map((c: { status: string }) => c.status).sort();
    expect(statuses).toEqual(['completed', 'pending_approval', 'review_required']);
    for (const row of list.body.data) {
      const detail = await call(t, 'GET', `/api-mode/clawbacks/${row.id}`);
      check('ApiModeClawbackController_detail_v1', detail);
      const targets = await call(t, 'GET', `/api-mode/clawbacks/${row.id}/targets`);
      check('ApiModeClawbackController_targets_v1', targets);
      expect(targets.body.data.length).toBeGreaterThan(0);
    }
    const overview = await call(t, 'GET', '/api-mode/overview');
    check('ApiModeController_overview_v1', overview);
    expect(overview.body.clawback).toMatchObject({ reviewRequired: 1, pendingApproval: 1 });
    expect(overview.body.reports).toMatchObject({
      pendingTriage: 2,
      inReview: 1,
      reportMailboxes: 1,
    });
    const detections = await call(t, 'GET', `/api-mode/detections?${range()}&direction=internal`);
    check('ApiModeController_listDetections_v1', detections);
    expect(
      detections.body.data.every((d: { direction: string }) => d.direction === 'internal'),
    ).toBe(true);
    const settings = await call(t, 'GET', '/api-mode/settings');
    check('ApiModeSettingsController_get_v1', settings);
    expect(settings.body).toMatchObject({ source: 'defaults', rowVersion: null });
  });

  it('search by Message-ID → materialized → purge (Junk) below the threshold → completed → restore', async () => {
    const t = await login('organization_admin@example.com');
    const invalid = await call(
      t,
      'POST',
      '/api-mode/clawbacks',
      { criteria: { messageId: '<x@y.example.test>' }, reason: 'no window' },
      true,
    );
    expect(invalid).toMatchObject({
      status: 422,
      body: { code: 'api_mode_clawback_criteria_invalid', codes: 'window_required' },
    });
    const created = await call(t, 'POST', '/api-mode/clawbacks', searchBody(), true);
    check('ApiModeClawbackController_create_v1', { ...created, status: 202 });
    expect(created).toMatchObject({ status: 202, body: { status: 'searching', trigger: 'admin' } });
    const id = created.body.id as string;
    expect((await call(t, 'GET', `/api-mode/clawbacks/${id}`)).body.status).toBe('searching');

    advance(MATERIALIZE_DELAY_MS + 100);
    let detail = await call(t, 'GET', `/api-mode/clawbacks/${id}`);
    check('ApiModeClawbackController_detail_v1', detail);
    expect(detail.body).toMatchObject({ status: 'ready', hints: { canSubmit: true } });
    expect(detail.body.counts.targetsTotal).toBeGreaterThan(1);
    const targets = await call(t, 'GET', `/api-mode/clawbacks/${id}/targets`);
    check('ApiModeClawbackController_targets_v1', targets);
    expect(targets.body.data[0].matchKeys).toEqual(['message_id']);
    expect(targets.body.data[0].headerFrom).toBe('billing@sender-2.example.test');

    const stale = await call(
      t,
      'POST',
      `/api-mode/clawbacks/${id}/submit`,
      { mode: 'explicit', action: 'move_junk', reason: 'go', expectedRowVersion: 1 },
      true,
    );
    expect(stale).toMatchObject({
      status: 409,
      body: { code: 'api_mode_clawback_state_conflict' },
    });
    const submitted = await call(
      t,
      'POST',
      `/api-mode/clawbacks/${id}/submit`,
      {
        mode: 'explicit',
        action: 'move_junk',
        reason: 'go',
        expectedRowVersion: detail.body.rowVersion,
      },
      true,
    );
    check('ApiModeClawbackController_submit_v1', submitted);
    expect(submitted.body).toMatchObject({ status: 'queued', requiresApproval: false });

    advance(QUEUE_DELAY_MS + 100);
    detail = await call(t, 'GET', `/api-mode/clawbacks/${id}`);
    expect(detail.body.status).toBe('running');
    const history = await call(t, 'GET', `/api-mode/remediations?${range()}&trigger=purge`);
    check('ApiModeRemediationController_list_v1', history);
    expect(history.body.data.length).toBeGreaterThan(0);
    expect(history.body.data[0]).toMatchObject({ action: 'move_junk', clawbackId: id });

    advance(9_000);
    detail = await call(t, 'GET', `/api-mode/clawbacks/${id}`);
    expect(detail.body.status).toBe('completed');
    expect(detail.body.counts.succeeded).toBeGreaterThan(0);
    expect(detail.body.hints.canRestore).toBe(true);

    const restore = await call(
      t,
      'POST',
      `/api-mode/clawbacks/${id}/restore`,
      { reason: 'false positive' },
      true,
    );
    check('ApiModeClawbackController_restore_v1', restore);
    expect(restore.body.restore.status).toBe('requested');
    for (let i = 0; i < 4; i += 1) {
      advance(10_000);
      await call(t, 'GET', `/api-mode/clawbacks/${id}`);
    }
    detail = await call(t, 'GET', `/api-mode/clawbacks/${id}`);
    expect(detail.body.restore.status).toMatch(/^completed/);
    expect(detail.body.restore.succeeded + detail.body.restore.skipped).toBeGreaterThan(0);
    const again = await call(t, 'POST', `/api-mode/clawbacks/${id}/restore`, { reason: 'x' }, true);
    if (detail.body.restore.status === 'completed')
      expect(again.body.code).toBe('api_mode_clawback_not_restorable');
  });

  it('above a lowered threshold: approval by another purge holder only; settings CAS', async () => {
    const admin = await login('organization_admin@example.com');
    const analyst = await login('security_analyst@example.com');
    const current = await call(admin, 'GET', '/api-mode/settings');
    const put = (expectedRowVersion: number | null) =>
      call(
        admin,
        'PUT',
        '/api-mode/settings',
        { ...current.body.settings, purgeApprovalMailboxes: 1, reason: 'test', expectedRowVersion },
        true,
      );
    expect(await put(3)).toMatchObject({
      status: 409,
      body: { code: 'api_mode_settings_conflict', currentRowVersion: null },
    });
    const saved = await put(null);
    check('ApiModeSettingsController_put_v1', saved);
    expect(saved.body).toMatchObject({
      created: true,
      rowVersion: 1,
      changed: ['purgeApprovalMailboxes'],
    });

    const created = await call(admin, 'POST', '/api-mode/clawbacks', searchBody(), true);
    advance(MATERIALIZE_DELAY_MS + 100);
    const id = created.body.id as string;
    const ready = await call(admin, 'GET', `/api-mode/clawbacks/${id}`);
    expect(ready.body.counts.mailboxesEligible).toBeGreaterThan(1);
    const submitted = await call(
      admin,
      'POST',
      `/api-mode/clawbacks/${id}/submit`,
      {
        mode: 'policy',
        verdict: 'phishing',
        level: 'critical',
        reason: 'go',
        expectedRowVersion: ready.body.rowVersion,
      },
      true,
    );
    expect(submitted.body).toMatchObject({
      status: 'pending_approval',
      requiresApproval: true,
      approvalReasons: ['mailbox_threshold'],
    });
    const mine = await call(admin, 'GET', `/api-mode/clawbacks/${id}`);
    expect(mine.body.hints.canApprove).toBe(false);
    const self = await call(
      admin,
      'POST',
      `/api-mode/clawbacks/${id}/approve`,
      { reason: 'self', expectedRowVersion: mine.body.rowVersion },
      true,
    );
    expect(self).toMatchObject({
      status: 403,
      body: { code: 'api_mode_purge_approval_forbidden', reason: 'requester' },
    });
    const theirs = await call(analyst, 'GET', `/api-mode/clawbacks/${id}`);
    expect(theirs.body.hints.canApprove).toBe(true);
    const approved = await call(
      analyst,
      'POST',
      `/api-mode/clawbacks/${id}/approve`,
      { reason: 'checked', expectedRowVersion: theirs.body.rowVersion },
      true,
    );
    check('ApiModeClawbackController_approve_v1', approved);
    expect(approved.body).toMatchObject({ status: 'queued', approval: { status: 'approved' } });
    const late = await call(
      analyst,
      'POST',
      `/api-mode/clawbacks/${id}/deny`,
      { reason: 'late', expectedRowVersion: approved.body.rowVersion },
      true,
    );
    expect(late).toMatchObject({
      status: 409,
      body: { code: 'api_mode_purge_approval_not_pending' },
    });
    const hard = await call(
      admin,
      'POST',
      `/api-mode/clawbacks/${id}/submit-hard-delete`,
      { reason: 'hd', expectedRowVersion: 1 },
      true,
    );
    expect(hard).toMatchObject({ status: 422, body: { code: 'api_mode_hard_delete_disabled' } });
  });

  it('cancel: immediately when ready, after the worker tick when queued; finished ones refused', async () => {
    const t = await login('organization_admin@example.com');
    const first = await call(t, 'POST', '/api-mode/clawbacks', searchBody(), true);
    advance(MATERIALIZE_DELAY_MS + 100);
    const cancelled = await call(
      t,
      'POST',
      `/api-mode/clawbacks/${first.body.id}/cancel`,
      { reason: 'wrong search' },
      true,
    );
    check('ApiModeClawbackController_cancel_v1', cancelled);
    expect(cancelled.body).toMatchObject({ status: 'cancelled', cancelRequested: true });

    const second = await call(t, 'POST', '/api-mode/clawbacks', searchBody('second'), true);
    advance(MATERIALIZE_DELAY_MS + 100);
    const ready = await call(t, 'GET', `/api-mode/clawbacks/${second.body.id}`);
    await call(
      t,
      'POST',
      `/api-mode/clawbacks/${second.body.id}/submit`,
      {
        mode: 'explicit',
        action: 'soft_delete',
        reason: 'go',
        expectedRowVersion: ready.body.rowVersion,
      },
      true,
    );
    const requested = await call(
      t,
      'POST',
      `/api-mode/clawbacks/${second.body.id}/cancel`,
      { reason: 'stop' },
      true,
    );
    expect(requested.body).toMatchObject({ status: 'queued', cancelRequested: true });
    const after = await call(t, 'GET', `/api-mode/clawbacks/${second.body.id}`);
    expect(after.body.status).toBe('cancelled');
    const seeded = (await call(t, 'GET', `/api-mode/clawbacks?${range()}&status=completed`)).body
      .data[0];
    const refused = await call(
      t,
      'POST',
      `/api-mode/clawbacks/${seeded.id}/cancel`,
      { reason: 'x' },
      true,
    );
    expect(refused).toMatchObject({
      status: 409,
      body: { code: 'api_mode_clawback_not_cancellable' },
    });
  });

  it('reports: triage with CAS, resolve the group with feedback, clawback from the report', async () => {
    const t = await login('security_analyst@example.com');
    const list = await call(t, 'GET', `/api-mode/reports?${range()}&status=pending_triage`);
    check('ApiModeReportsController_list_v1', list);
    expect(list.body.data).toHaveLength(2);
    expect(list.body.data[0].groupSize).toBe(2);
    const report = await call(t, 'GET', `/api-mode/reports/${list.body.data[0].id}`);
    check('ApiModeReportsController_detail_v1', report);
    const stale = await call(
      t,
      'POST',
      `/api-mode/reports/${report.body.id}/triage`,
      { status: 'in_review', expectedRowVersion: 99 },
      true,
    );
    expect(stale).toMatchObject({ status: 409, body: { code: 'api_mode_report_state_conflict' } });
    const resolved = await call(
      t,
      'POST',
      `/api-mode/reports/${report.body.id}/triage`,
      {
        status: 'resolved',
        verdict: 'malicious',
        note: 'credential phishing',
        notifyReporter: true,
        applyToGroup: true,
        expectedRowVersion: report.body.rowVersion,
      },
      true,
    );
    check('ApiModeReportsController_triage_v1', resolved);
    expect(resolved.body).toMatchObject({ groupResolved: 2, feedbackQueued: 2 });
    const after = await call(t, 'GET', `/api-mode/reports/${report.body.id}`);
    expect(after.body).toMatchObject({
      status: 'resolved',
      analystVerdict: 'malicious',
      feedback: { result: 'queued' },
    });
    expect(after.body.history.at(-1)).toMatchObject({ to: 'resolved', verdict: 'malicious' });

    const clawback = await call(
      t,
      'POST',
      `/api-mode/reports/${report.body.id}/clawback`,
      { expand: { attachments: true }, reason: 'reported phishing' },
      true,
    );
    check('ApiModeReportsController_clawback_v1', clawback);
    expect(clawback.body).toMatchObject({ status: 'searching', trigger: 'campaign' });
    const linked = await call(t, 'GET', `/api-mode/reports/${report.body.id}`);
    expect(linked.body.clawbackId).toBe(clawback.body.clawbackId);
    const claw = await call(t, 'GET', `/api-mode/clawbacks/${clawback.body.clawbackId}`);
    expect(claw.body).toMatchObject({ trigger: 'campaign', reportId: report.body.id });

    const rejected = (await call(t, 'GET', `/api-mode/reports?${range()}&status=rejected`)).body
      .data[0];
    const unknown = await call(
      t,
      'POST',
      `/api-mode/reports/${rejected.id}/clawback`,
      { reason: 'x' },
      true,
    );
    expect(unknown).toMatchObject({
      status: 409,
      body: { code: 'api_mode_report_original_unknown' },
    });
  });

  it('report mailboxes: list, add by address, out of scope, designate and remove', async () => {
    const t = await login('organization_admin@example.com');
    const list = await call(t, 'GET', '/api-mode/report-mailboxes');
    check('ApiModeReportsController_listMailboxes_v1', list);
    expect(list.body).toMatchObject({ max: 5 });
    expect(list.body.data).toHaveLength(1);
    const domain = list.body.data[0].domain.name as string;
    const added = await call(
      t,
      'POST',
      '/api-mode/report-mailboxes',
      { address: `report-phish@${domain}`, reason: 'new shared mailbox' },
      true,
    );
    check('ApiModeReportsController_addMailbox_v1', added);
    expect(added.body).toMatchObject({
      created: true,
      changed: true,
      mailbox: { status: 'discovered' },
    });
    const outside = await call(
      t,
      'POST',
      '/api-mode/report-mailboxes',
      { address: 'report@elsewhere.example.test', reason: 'x' },
      true,
    );
    expect(outside).toMatchObject({
      status: 422,
      body: { code: 'api_mode_report_address_out_of_scope' },
    });
    const removed = await call(
      t,
      'PUT',
      `/api-mode/mailboxes/${added.body.mailbox.id}/report-mailbox`,
      { enabled: false, reason: 'not needed' },
      true,
    );
    check('ApiModeReportsController_setMailbox_v1', removed);
    expect(removed.body).toMatchObject({ changed: true, mailbox: { reportMailbox: false } });
  });

  it('read-only users read without write rights; targets are masked without remediation:purge', async () => {
    const t = await login('read_only_user@example.com');
    const list = await call(t, 'GET', `/api-mode/clawbacks?${range()}&status=pending_approval`);
    const id = list.body.data[0].id as string;
    const detail = await call(t, 'GET', `/api-mode/clawbacks/${id}`);
    expect(detail.body.hints).toEqual({
      canSubmit: false,
      canApprove: false,
      canCancel: false,
      canRestore: false,
    });
    const targets = await call(t, 'GET', `/api-mode/clawbacks/${id}/targets`);
    check('ApiModeClawbackController_targets_v1', targets);
    expect(targets.body.data[0].mailbox.address).toContain('***@');
    expect(targets.body.data[0].headerFrom).toBeNull();
    for (const [method, path] of [
      ['POST', '/api-mode/clawbacks'],
      ['POST', `/api-mode/clawbacks/${id}/approve`],
      ['PUT', '/api-mode/settings'],
      ['POST', '/api-mode/report-mailboxes'],
    ] as const) {
      expect((await call(t, method, path, { reason: 'x' }, true)).status, path).toBe(403);
    }
  });
});
