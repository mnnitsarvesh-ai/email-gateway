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
import { ARCHIVE_OPERATIONS, FIXTURE_JOB_DELAY_MS, resetArchiveFixtures } from './archive';

/**
 * Dev fixtures of the step 8.1 compliance pages (WP5): every one of the 42 operations (41 of step 8.1 plus the
 * AI-5 single capture-issue read) answers
 * with a body that matches its OpenAPI response, and the rules the pages rely on hold (masking,
 * reveal and hold filter gates, MFA, override refusal, CAS, Idempotency-Key replay, jobs).
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

const range = () => {
  const to = new Date(Date.now() + 3_600_000).toISOString();
  const from = new Date(Date.now() - 365 * 86_400_000).toISOString();
  return `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
};

beforeEach(() => resetArchiveFixtures());

describe('archive dev fixtures (step 8.1 WP5)', () => {
  it('cover all 42 operations (§4.4 plus AI-5)', () => {
    const handlers = mergedFixtures();
    expect(ARCHIVE_OPERATIONS).toHaveLength(42);
    for (const op of ARCHIVE_OPERATIONS) expect(handlers[op], op).toBeDefined();
    const fromSpec = Object.keys(operations).filter((id) =>
      /^(Archive|LegalHolds|Ediscovery)/.test(id),
    );
    expect([...fromSpec].sort()).toEqual([...ARCHIVE_OPERATIONS].sort());
  });

  it('answer every operation with an OpenAPI-valid body (MFA compliance officer, step 8.6)', async () => {
    const t = await login('mfa.compliance_officer@example.com');
    const check = (op: OperationId, res: { status: number; body: unknown }) =>
      expect(responseErrors(op, res.status, res.body), op).toEqual([]);
    let key = 0;
    const k = () => `key-${(key += 1)}`;
    check('ArchiveAdminController_get_v1', await call(t, 'GET', '/archive/settings'));
    const settings = await call(t, 'GET', '/archive/settings');
    check(
      'ArchiveAdminController_update_v1',
      await call(
        t,
        'PUT',
        '/archive/settings',
        {
          expectedRowVersion: settings.body.rowVersion,
          settings: { access: { previewEnabled: true, downloadEnabled: true } },
        },
        k(),
      ),
    );
    check('ArchiveAdminController_status_v1', await call(t, 'GET', '/archive/status'));
    check('ArchiveAdminController_listKeys_v1', await call(t, 'GET', '/archive/keys'));
    check(
      'ArchiveAdminController_rotate_v1',
      await call(t, 'POST', '/archive/keys/rotate', { reason: 'EXAMPLE' }, k()),
    );
    const issues = await call(t, 'GET', '/archive/capture-issues');
    check('ArchiveAdminController_captureIssues_v1', issues);
    const failed = issues.body.data.find((i: { status: string }) => i.status === 'failed');
    check(
      'ArchiveAdminController_captureIssue_v1',
      await call(t, 'GET', `/archive/capture-issues/${failed.messageId}`),
    );
    expect(
      (await call(t, 'GET', '/archive/capture-issues/00000000-0000-4000-8000-000000000000')).status,
    ).toBe(404);
    check(
      'ArchiveAdminController_retry_v1',
      await call(t, 'POST', `/archive/capture-issues/${failed.messageId}/retry`, undefined, k()),
    );
    check('ArchiveAdminController_disposals_v1', await call(t, 'GET', '/archive/disposals'));
    check(
      'ArchiveAdminController_signingKeys_v1',
      await call(t, 'GET', '/archive/export-signing-keys'),
    );
    const policies = await call(t, 'GET', '/archive/retention-policies');
    check('ArchiveRetentionController_list_v1', policies);
    const created = await call(
      t,
      'POST',
      '/archive/retention-policies',
      { name: 'EXAMPLE', retentionDays: 30 },
      k(),
    );
    check('ArchiveRetentionController_create_v1', created);
    check(
      'ArchiveRetentionController_get_v1',
      await call(t, 'GET', `/archive/retention-policies/${created.body.id}`),
    );
    check(
      'ArchiveRetentionController_update_v1',
      await call(
        t,
        'PUT',
        `/archive/retention-policies/${created.body.id}`,
        { expectedRowVersion: 1, name: 'EXAMPLE 2', retentionDays: 60 },
        k(),
      ),
    );
    expect(
      (await call(t, 'DELETE', `/archive/retention-policies/${created.body.id}`, undefined, k()))
        .status,
    ).toBe(204);
    const list = await call(t, 'GET', `/archive/messages?${range()}`);
    check('ArchiveMessagesController_list_v1', list);
    const id = list.body.data.find((m: { malicious: boolean }) => !m.malicious).messageId as string;
    check('ArchiveMessagesController_detail_v1', await call(t, 'GET', `/archive/messages/${id}`));
    check(
      'ArchiveMessagesController_journal_v1',
      await call(t, 'GET', `/archive/messages/${id}/journal`),
    );
    check(
      'ArchiveMessagesController_security_v1',
      await call(t, 'GET', `/archive/messages/${id}/security`),
    );
    check(
      'ArchiveMessagesController_reveal_v1',
      await call(t, 'POST', `/archive/messages/${id}/reveal`, {
        fields: ['subject', 'recipients', 'headers'],
      }),
    );
    check(
      'ArchiveMessagesController_preview_v1',
      await call(t, 'GET', `/archive/messages/${id}/preview`),
    );
    const grant = await call(t, 'POST', `/archive/messages/${id}/download-grants`, {
      password: 'EXAMPLE',
    });
    check('ArchiveMessagesController_grant_v1', grant);
    const download = await call(t, 'GET', `/archive/downloads/${grant.body.token}`);
    expect(download.status).toBe(200);
    expect(download.headers.get('content-disposition')).toMatch(/^attachment/);
    expect((await call(t, 'GET', `/archive/downloads/${grant.body.token}`)).status).toBe(410);
    const review = (
      await call(t, 'GET', `/archive/messages?${range()}&status=expiry_review`)
    ).body.data.find((m: { legalHold: boolean }) => !m.legalHold);
    check(
      'ArchiveMessagesController_dispose_v1',
      await call(
        t,
        'POST',
        `/archive/messages/${review.messageId}/dispose`,
        { reason: 'EXAMPLE' },
        k(),
      ),
    );
    const holds = await call(t, 'GET', '/legal-holds');
    check('LegalHoldsController_list_v1', holds);
    check(
      'LegalHoldsController_get_v1',
      await call(t, 'GET', `/legal-holds/${holds.body.data[0].id}`),
    );
    const cases = await call(t, 'GET', '/ediscovery/cases');
    check('EdiscoveryCasesController_list_v1', cases);
    const c = await call(
      t,
      'POST',
      '/ediscovery/cases',
      { name: 'EXAMPLE case', custodians: ['a@corp.example.test'] },
      k(),
    );
    check('EdiscoveryCasesController_create_v1', c);
    check(
      'EdiscoveryCasesController_get_v1',
      await call(t, 'GET', `/ediscovery/cases/${c.body.id}`),
    );
    check(
      'EdiscoveryCasesController_update_v1',
      await call(
        t,
        'PATCH',
        `/ediscovery/cases/${c.body.id}`,
        { expectedRowVersion: 1, matterReference: 'M' },
        k(),
      ),
    );
    const hold = await call(
      t,
      'POST',
      `/ediscovery/cases/${c.body.id}/holds`,
      { name: 'H', reason: 'R', useCaseCustodians: true },
      k(),
    );
    check('EdiscoveryCasesController_createHold_v1', hold);
    check(
      'LegalHoldsController_release_v1',
      await call(t, 'POST', `/legal-holds/${hold.body.id}/release`, { reason: 'EXAMPLE' }, k()),
    );
    const existingCase = cases.body.data[0].id as string;
    const searches = await call(t, 'GET', `/ediscovery/cases/${existingCase}/searches`);
    check('EdiscoverySearchesController_list_v1', searches);
    const searchId = searches.body.data[0].id as string;
    check(
      'EdiscoverySearchesController_get_v1',
      await call(t, 'GET', `/ediscovery/cases/${existingCase}/searches/${searchId}`),
    );
    const hits = await call(
      t,
      'GET',
      `/ediscovery/cases/${existingCase}/searches/${searchId}/hits`,
    );
    check('EdiscoverySearchesController_hits_v1', hits);
    check(
      'EdiscoverySearchesController_review_v1',
      await call(
        t,
        'POST',
        `/ediscovery/cases/${existingCase}/searches/${searchId}/review`,
        { tag: 'relevant', messageIds: [hits.body.data[0].messageId] },
        k(),
      ),
    );
    check(
      'EdiscoverySearchesController_create_v1',
      await call(
        t,
        'POST',
        `/ediscovery/cases/${existingCase}/searches`,
        { criteria: { from: '2026-01-01', to: '2026-12-31', custodians: 'case' } },
        k(),
      ),
    );
    const exports = await call(t, 'GET', `/ediscovery/cases/${existingCase}/exports`);
    check('EdiscoveryExportsController_list_v1', exports);
    const exportId = exports.body.data[0].id as string;
    check(
      'EdiscoveryExportsController_get_v1',
      await call(t, 'GET', `/ediscovery/cases/${existingCase}/exports/${exportId}`),
    );
    check(
      'EdiscoveryExportsController_grant_v1',
      await call(
        t,
        'POST',
        `/ediscovery/cases/${existingCase}/exports/${exportId}/download-grants`,
        { password: 'EXAMPLE' },
      ),
    );
    const newExport = await call(
      t,
      'POST',
      `/ediscovery/cases/${existingCase}/exports`,
      { searchId, acknowledgeMalicious: true },
      k(),
    );
    check('EdiscoveryExportsController_create_v1', newExport);
    check(
      'EdiscoveryCasesController_close_v1',
      await call(t, 'POST', `/ediscovery/cases/${c.body.id}/close`, undefined, k()),
    );
  });

  it('masks results for everyone and gates reveal, reveal-gated filters and the hold filter', async () => {
    const analyst = await login('security_analyst@example.com');
    const list = await call(analyst, 'GET', `/archive/messages?${range()}`);
    expect(list.status).toBe(200);
    expect(list.headers.get('x-eg-index-lag-seconds')).not.toBeNull();
    for (const row of list.body.data) {
      expect(row.subject).toBeNull();
      expect(row.recipients.every((r: string) => r.includes('***@'))).toBe(true);
    }
    expect(
      (
        await call(
          analyst,
          'GET',
          `/archive/messages?${range()}&holdId=01930000-0000-7000-8000-000000000000`,
        )
      ).body.code,
    ).toBe('archive_filter_forbidden');
    const auditor = await login('compliance_auditor@example.com');
    const detail = await call(auditor, 'GET', `/archive/messages/${list.body.data[0].messageId}`);
    expect(detail.body.holds).not.toBeNull();
    const analystDetail = await call(
      analyst,
      'GET',
      `/archive/messages/${list.body.data[0].messageId}`,
    );
    expect(analystDetail.body.holds).toBeNull();
    const readOnly = await login('read_only_user@example.com');
    expect((await call(readOnly, 'GET', `/archive/messages?${range()}`)).status).toBe(403);
    expect(
      (
        await call(readOnly, 'POST', `/archive/messages/${list.body.data[0].messageId}/reveal`, {
          fields: ['subject'],
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await call(
          analyst,
          'GET',
          `/archive/messages?from=2020-01-01T00:00:00Z&to=2026-01-01T00:00:00Z`,
        )
      ).body.code,
    ).toBe('archive_search_range_invalid');
  });

  it('requires MFA, refuses content under an override, keeps CAS and replays Idempotency-Keys', async () => {
    const noMfa = await login('compliance_officer@example.com');
    const id = (await call(noMfa, 'GET', `/archive/messages?${range()}`)).body.data[0]
      .messageId as string;
    expect((await call(noMfa, 'GET', `/archive/messages/${id}/preview`)).body.code).toBe(
      'mfa_required',
    );
    const t = await login('mfa.compliance_officer@example.com');
    const settings = await call(t, 'GET', '/archive/settings');
    const stale = await call(
      t,
      'PUT',
      '/archive/settings',
      { expectedRowVersion: settings.body.rowVersion - 1 },
      'cas-1',
    );
    expect(stale.status).toBe(409);
    expect(stale.body.currentRowVersion).toBe(settings.body.rowVersion);
    const first = await call(
      t,
      'PUT',
      '/archive/settings',
      { expectedRowVersion: settings.body.rowVersion, immutability: 'compliance' },
      'cas-2',
    );
    const replay = await call(
      t,
      'PUT',
      '/archive/settings',
      { expectedRowVersion: settings.body.rowVersion, immutability: 'compliance' },
      'cas-2',
    );
    expect(first.status).toBe(200);
    expect(replay.headers.get('idempotency-replayed')).toBe('true');
    const downgrade = await call(
      t,
      'PUT',
      '/archive/settings',
      { expectedRowVersion: first.body.rowVersion, immutability: 'governance' },
      'cas-3',
    );
    expect(downgrade.body.code).toBe('archive_immutability_downgrade_forbidden');
    expect((await call(t, 'POST', '/archive/keys/rotate', { reason: 'x' })).body.code).toBe(
      'idempotency_key_required',
    );
    const malicious = (await call(t, 'GET', `/archive/messages?${range()}&malicious=true`)).body
      .data[0].messageId as string;
    expect(
      (await call(t, 'POST', `/archive/messages/${malicious}/download-grants`, { password: 'x' }))
        .body.code,
    ).toBe('archive_download_blocked');
    expect(
      (await call(t, 'POST', `/archive/messages/${id}/download-grants`, { password: 'wrong' }))
        .status,
    ).toBe(401);
  });

  it('runs case searches and exports to completion and enforces the malicious acknowledgement', async () => {
    const t = await login('mfa.compliance_auditor@example.com');
    const caseId = (await call(t, 'GET', '/ediscovery/cases')).body.data[0].id as string;
    const queued = await call(
      t,
      'POST',
      `/ediscovery/cases/${caseId}/searches`,
      { criteria: { from: '2020-01-01', to: '2026-12-31' } },
      's-1',
    );
    expect(queued.body.status).toBe('queued');
    expect(
      (await call(t, 'GET', `/ediscovery/cases/${caseId}/searches/${queued.body.id}/hits`)).body
        .code,
    ).toBe('ediscovery_search_not_completed');
    await new Promise((r) => setTimeout(r, FIXTURE_JOB_DELAY_MS + 100));
    const done = await call(t, 'GET', `/ediscovery/cases/${caseId}/searches/${queued.body.id}`);
    expect(done.body).toMatchObject({ status: 'completed', indexComplete: true });
    const refused = await call(
      t,
      'POST',
      `/ediscovery/cases/${caseId}/exports`,
      { searchId: queued.body.id },
      'e-1',
    );
    expect(refused.body.code).toBe('ediscovery_export_malicious_ack_required');
    const accepted = await call(
      t,
      'POST',
      `/ediscovery/cases/${caseId}/exports`,
      { searchId: queued.body.id, acknowledgeMalicious: true },
      'e-2',
    );
    expect(accepted.status).toBe(202);
    expect(
      (
        await call(
          t,
          'POST',
          `/ediscovery/cases/${caseId}/exports/${accepted.body.id}/download-grants`,
          { password: 'x' },
        )
      ).body.code,
    ).toBe('ediscovery_export_not_ready');
    // A compliance auditor has no archive:legal_hold: placing a hold is refused.
    expect(
      (
        await call(
          t,
          'POST',
          `/ediscovery/cases/${caseId}/holds`,
          { name: 'H', reason: 'R', useCaseCustodians: true },
          'h-1',
        )
      ).status,
    ).toBe(403);
  }, 15_000);
});
