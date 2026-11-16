// @vitest-environment node
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import { operations } from '@/lib/api/operations.gen';
import type { OperationId } from '@/lib/api/types';
import { FEATURE_FIXTURES, createMockFetch, mergedFixtures } from '@/server/dev-mocks';
import { DEV_MOCK_MARKER } from '@/server/dev-mocks/types';
import { toJsonSchema } from '@/test/contract';
import {
  CANNED_PATTERN_MATCH,
  DLP_BEC_OPERATIONS,
  FIXTURE_DLP_BEC_LIMITS,
  FIXTURE_FREEMAIL_DOMAINS,
  FIXTURE_INVALID_PATTERN,
  DEV_MOCK_MARKER as MODULE_MARKER,
  fixtures,
} from './dlp-bec';

/**
 * Dev fixtures of the DLP and BEC editors (step 7.3 WP5, design §2 B15): registered last, every
 * DLP/BEC operation the portal tabs call answers, writes keep the API's rules (versions, unique
 * names, references, in-use, free-mail, MFA, Idempotency-Key, the pattern-test rate limit), the
 * pattern test is canned and labelled (never evaluated), and bodies match the OpenAPI responses.
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

async function call(
  token: string,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
) {
  const response = await fetchImpl(`${API}/api/v1${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...headers },
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

const unique = (label: string) => `${label} ${Date.now()}-${Math.round(Math.random() * 1e6)}`;

describe('DLP/BEC dev fixtures (WP5)', () => {
  it('is registered last and replaces the read-only DLP/BEC handlers of the policies fixtures', () => {
    expect(MODULE_MARKER).toBe(DEV_MOCK_MARKER);
    const names = Object.keys(FEATURE_FIXTURES);
    expect(names[names.length - 1]).toBe('dlp-bec');
    expect(names.indexOf('dlp-bec')).toBeGreaterThan(names.indexOf('policies'));
    const merged = mergedFixtures();
    for (const operationId of DLP_BEC_OPERATIONS) {
      expect(merged[operationId], operationId).toBe(fixtures[operationId]);
    }
  });

  it('answers every DLP/BEC operation the portal tabs call', () => {
    const dir = join(__dirname, '../../../features/policies');
    const sources = [
      join(dir, 'dlp-bec.tsx'),
      ...readdirSync(join(dir, 'dlp-bec'))
        .filter((file) => /\.tsx?$/.test(file) && !/\.test\.tsx?$/.test(file))
        .map((file) => join(dir, 'dlp-bec', file)),
    ];
    const used = new Set<string>();
    for (const file of sources) {
      for (const match of readFileSync(file, 'utf8').matchAll(
        /'((?:Dlp|Bec)\w+Controller_\w+_v1)'/g,
      )) {
        used.add(match[1] as string);
      }
    }
    expect(used.size).toBeGreaterThan(30);
    const merged = mergedFixtures();
    for (const operationId of used) {
      expect(operations[operationId as OperationId], operationId).toBeDefined();
      expect(merged[operationId as OperationId], operationId).toBeDefined();
    }
    for (const notInScope of [
      'BecFeedbackController_purgeHistory_v1',
      'BecFeedbackController_export_v1',
      'DlpEvidenceController_purgeAll_v1',
      'DlpMessageEvidenceController_read_v1',
    ]) {
      expect(used.has(notInScope), notInScope).toBe(false);
    }
  });

  it('DLP policies and rules: list, create, version compare-and-set, references and in-use refusals', async () => {
    const token = await login('organization_admin@example.com');
    const list = await call(token, 'GET', '/dlp/policies?limit=25');
    expect(list.status).toBe(200);
    expect(responseErrors('DlpPoliciesController_list_v1', 200, list.body)).toEqual([]);
    expect(list.body.data.map((p: { name: string }) => p.name)).toContain('Payment cards outbound');

    const name = unique('Fixture policy');
    const created = await call(token, 'POST', '/dlp/policies', { name, directions: ['outbound'] });
    expect(created.status).toBe(201);
    expect(responseErrors('DlpPoliciesController_create_v1', 201, created.body)).toEqual([]);
    expect((await call(token, 'POST', '/dlp/policies', { name })).body.code).toBe(
      'dlp_policy_exists',
    );
    expect((await call(token, 'POST', '/dlp/policies', { name: '', extra: 1 })).status).toBe(400);

    const id = created.body.id as string;
    const stale = await call(token, 'PATCH', `/dlp/policies/${id}`, { version: 9, enabled: false });
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({ code: 'version_conflict', currentVersion: 1 });
    const updated = await call(token, 'PATCH', `/dlp/policies/${id}`, {
      version: 1,
      enabled: false,
    });
    expect(updated.body).toMatchObject({ enabled: false, version: 2 });

    const unknownPattern = await call(token, 'POST', `/dlp/policies/${id}/rules`, {
      name: 'Rule',
      action: 'alert',
      conditions: { selectors: { customPatternIds: ['01933c3a-1b2c-7d4e-8f00-00000000ffff'] } },
    });
    expect(unknownPattern.body).toMatchObject({ code: 'dlp_reference_invalid', index: 0 });
    const noSelector = await call(token, 'POST', `/dlp/policies/${id}/rules`, {
      name: 'Rule',
      action: 'alert',
      conditions: { selectors: {} },
    });
    expect(noSelector.body.message).toEqual([
      'conditions.selectors: At least one selector is required',
    ]);
    const outside = await call(token, 'POST', `/dlp/policies/${id}/rules`, {
      name: 'Rule',
      action: 'alert',
      conditions: { selectors: { categories: ['credential'] }, directions: ['internal'] },
    });
    expect(outside.body.code).toBe('dlp_directions_invalid');
    const rule = await call(token, 'POST', `/dlp/policies/${id}/rules`, {
      name: 'Rule',
      action: 'alert',
      conditions: {
        selectors: { categories: ['credential'] },
        sender: { addresses: ['Ops@Alpha.Example.Test'] },
      },
    });
    expect(rule.status).toBe(201);
    expect(responseErrors('DlpPoliciesController_createRule_v1', 201, rule.body)).toEqual([]);
    expect(rule.body.conditions.sender.addresses).toEqual(['ops@alpha.example.test']);
    const detail = await call(token, 'GET', `/dlp/policies/${id}`);
    expect(detail.body.ruleCount).toBe(1);
    expect(responseErrors('DlpPoliciesController_get_v1', 200, detail.body)).toEqual([]);

    const exception = await call(token, 'POST', '/dlp/exceptions', {
      scope: 'recipient_domain',
      value: 'Audit.Example.Test',
      ruleId: rule.body.id,
      reason: 'Fixture test',
      expiresAt: new Date(Date.now() + 10 * 86_400_000).toISOString(),
    });
    expect(exception.status).toBe(201);
    expect(exception.body.value).toBe('audit.example.test');
    expect(
      (await call(token, 'DELETE', `/dlp/policies/${id}/rules/${rule.body.id}`)).body.code,
    ).toBe('dlp_rule_in_use');
    expect((await call(token, 'DELETE', `/dlp/policies/${id}`)).body.code).toBe(
      'dlp_policy_in_use',
    );
    expect(
      (await call(token, 'DELETE', `/dlp/exceptions/${exception.body.id}?version=1`)).status,
    ).toBe(204);
    expect((await call(token, 'DELETE', `/dlp/policies/${id}?version=1`)).status).toBe(409);
    expect((await call(token, 'DELETE', `/dlp/policies/${id}?version=2`)).status).toBe(204);
  });

  it('exceptions refuse expiries beyond the platform bound; patterns and dictionaries in use cannot be deleted', async () => {
    const token = await login('security_analyst@example.com');
    const tooFar = await call(token, 'POST', '/dlp/exceptions', {
      scope: 'sender_domain',
      value: 'far.example.test',
      reason: 'x',
      expiresAt: new Date(
        Date.now() + (FIXTURE_DLP_BEC_LIMITS.exceptionMaxDays + 5) * 86_400_000,
      ).toISOString(),
    });
    expect(tooFar.body.message).toEqual(['expiresAt: Must be at most 365 days ahead']);

    const patterns = await call(token, 'GET', '/dlp/patterns');
    expect(responseErrors('DlpPatternsController_list_v1', 200, patterns.body)).toEqual([]);
    const projectPattern = patterns.body.data.find((p: { name: string }) =>
      p.name.startsWith('Project'),
    );
    expect((await call(token, 'DELETE', `/dlp/patterns/${projectPattern.id}`)).body).toMatchObject({
      code: 'dlp_pattern_in_use',
      references: 1,
    });
    const refused = await call(token, 'POST', '/dlp/patterns', {
      name: unique('Refused'),
      pattern: `a${FIXTURE_INVALID_PATTERN}`,
      severity: 'low',
    });
    expect(refused.body).toMatchObject({ code: 'pattern_syntax', length: 16 });

    const dictionaries = await call(token, 'GET', '/dlp/dictionaries');
    expect(responseErrors('DlpDictionariesController_list_v1', 200, dictionaries.body)).toEqual([]);
    const projects = dictionaries.body.data.find((d: { name: string }) =>
      d.name.startsWith('Confidential'),
    );
    expect(projects.terms).toBeUndefined();
    const withTerms = await call(token, 'GET', `/dlp/dictionaries/${projects.id}`);
    expect(withTerms.body.terms.length).toBe(withTerms.body.termCount);
    expect(responseErrors('DlpDictionariesController_get_v1', 200, withTerms.body)).toEqual([]);
    expect((await call(token, 'DELETE', `/dlp/dictionaries/${projects.id}`)).body.code).toBe(
      'dlp_dictionary_in_use',
    );
    const duplicate = await call(token, 'POST', '/dlp/dictionaries', {
      name: unique('Dict'),
      category: 'custom',
      severity: 'low',
      terms: ['alpha', 'Alpha'],
    });
    expect(duplicate.body).toMatchObject({ code: 'dictionary_term_invalid', index: 1 });
  });

  it('the pattern test is canned and labelled (never evaluated) and limited to 30 calls per caller per minute', async () => {
    const token = await login('super_admin@example.com');
    const tested = await call(token, 'POST', '/dlp/patterns/test', {
      pattern: '[0-9]{4}',
      sample: 'synthetic 1234',
    });
    expect(tested.status).toBe(200);
    expect(tested.headers.get('x-eg-dev-fixture')).toMatch(/not evaluated/);
    expect(tested.body).toMatchObject({ valid: true, code: null });
    expect(tested.body.matches).toEqual([
      { start: 0, end: 0, masked: CANNED_PATTERN_MATCH, validated: false, contextMatched: false },
    ]);
    expect(responseErrors('DlpPatternsController_test_v1', 200, tested.body)).toEqual([]);
    const invalid = await call(token, 'POST', '/dlp/patterns/test', {
      pattern: FIXTURE_INVALID_PATTERN,
      sample: '',
    });
    expect(invalid.body).toMatchObject({ valid: false, code: 'pattern_syntax', matches: [] });
    expect(
      (await call(token, 'POST', '/dlp/patterns/test', { pattern: 'x', sample: 'y'.repeat(4097) }))
        .body.message,
    ).toEqual(['sample: Expected a string of at most 4096 characters']);
    // Three calls so far; the rest of the minute's budget is still accepted, then 429.
    let last = invalid;
    for (let i = 4; i <= FIXTURE_DLP_BEC_LIMITS.patternTestsPerMinute; i += 1) {
      last = await call(token, 'POST', '/dlp/patterns/test', { pattern: 'x', sample: '' });
    }
    expect(last.status).toBe(200);
    const limited = await call(token, 'POST', '/dlp/patterns/test', { pattern: 'x', sample: '' });
    expect(limited.status).toBe(429);
    expect(limited.body.code).toBe('rate_limited');
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
  });

  it('the Aadhaar basis needs dlp:compliance_manage, an MFA session and an Idempotency-Key', async () => {
    const analyst = await login('security_analyst@example.com');
    expect((await call(analyst, 'PUT', '/dlp/compliance/aadhaar', {})).status).toBe(403);
    const plain = await login('organization_admin@example.com');
    const noMfa = await call(
      plain,
      'PUT',
      '/dlp/compliance/aadhaar',
      {},
      { 'idempotency-key': 'k-0' },
    );
    expect(noMfa.body.code).toBe('mfa_required');

    const admin = await login('mfa.organization_admin@example.com');
    const before = await call(admin, 'GET', '/dlp/compliance');
    expect(responseErrors('DlpComplianceController_get_v1', 200, before.body)).toEqual([]);
    const body = {
      expectedVersion: before.body.version,
      basis: 'regulatory_obligation',
      reference: 'REF-1',
      attested: true,
      reviewDueAt: new Date(Date.now() + 100 * 86_400_000).toISOString(),
    };
    expect((await call(admin, 'PUT', '/dlp/compliance/aadhaar', body)).body.code).toBe(
      'idempotency_key_required',
    );
    const key = `fixture-${Date.now()}`;
    const recorded = await call(admin, 'PUT', '/dlp/compliance/aadhaar', body, {
      'idempotency-key': key,
    });
    expect(recorded.status).toBe(200);
    expect(recorded.body.aadhaar).toMatchObject({
      enabled: true,
      active: true,
      basis: 'regulatory_obligation',
    });
    expect(responseErrors('DlpComplianceController_enable_v1', 200, recorded.body)).toEqual([]);
    const replay = await call(admin, 'PUT', '/dlp/compliance/aadhaar', body, {
      'idempotency-key': key,
    });
    expect(replay.headers.get('idempotency-replayed')).toBe('true');
    const stale = await call(admin, 'PUT', '/dlp/compliance/aadhaar', body, {
      'idempotency-key': `${key}-b`,
    });
    expect(stale.body.code).toBe('version_conflict');
    const withdrawn = await call(
      admin,
      'DELETE',
      `/dlp/compliance/aadhaar?expectedVersion=${recorded.body.version}`,
      undefined,
      { 'idempotency-key': `${key}-c` },
    );
    expect(withdrawn.body.aadhaar).toMatchObject({ enabled: false, active: false, basis: null });
  });

  it('BEC: normalized-name duplicates, free-mail refusals with the index, trusted senders, suppression lift', async () => {
    const token = await login('security_analyst@example.com');
    const executives = await call(token, 'GET', '/bec/executives?limit=25');
    expect(responseErrors('BecExecutivesController_list_v1', 200, executives.body)).toEqual([]);
    expect(
      (await call(token, 'POST', '/bec/executives', { displayName: 'DANA  whitfield!' })).body.code,
    ).toBe('executive_exists');
    const executive = await call(token, 'POST', '/bec/executives', {
      displayName: unique('Exec'),
      knownAddresses: ['Boss@Alpha.Example.Test'],
    });
    expect(executive.status).toBe(201);
    expect(executive.body.knownAddresses).toEqual(['boss@alpha.example.test']);
    expect(responseErrors('BecExecutivesController_create_v1', 201, executive.body)).toEqual([]);
    const patched = await call(token, 'PATCH', `/bec/executives/${executive.body.id}`, {
      version: 1,
      title: null,
      enabled: false,
    });
    expect(patched.body).toMatchObject({ version: 2, enabled: false, title: null });

    const freemail = await call(token, 'POST', '/bec/vendors', {
      name: unique('Vendor'),
      domains: ['vendor.example.test', FIXTURE_FREEMAIL_DOMAINS[0]],
    });
    expect(freemail.status).toBe(422);
    expect(freemail.body).toMatchObject({ code: 'vendor_domain_freemail', index: 1 });
    const vendors = await call(token, 'GET', '/bec/vendors');
    expect(responseErrors('BecVendorsController_list_v1', 200, vendors.body)).toEqual([]);

    expect(
      (
        await call(token, 'POST', '/bec/trusted-senders', {
          kind: 'domain',
          value: FIXTURE_FREEMAIL_DOMAINS[1],
          reason: 'x',
        })
      ).body.code,
    ).toBe('trusted_domain_freemail');
    const value = `${Date.now()}.example.test`;
    const trusted = await call(token, 'POST', '/bec/trusted-senders', {
      kind: 'domain',
      value,
      reason: 'x',
    });
    expect(trusted.status).toBe(201);
    expect(responseErrors('BecTrustedSendersController_create_v1', 201, trusted.body)).toEqual([]);
    expect(
      (await call(token, 'POST', '/bec/trusted-senders', { kind: 'domain', value, reason: 'y' }))
        .body.code,
    ).toBe('trusted_sender_exists');
    const cleared = await call(token, 'PATCH', `/bec/trusted-senders/${trusted.body.id}`, {
      version: 1,
      expiresAt: null,
    });
    expect(cleared.body).toMatchObject({ version: 2, expiresAt: null, expired: false });

    const suppressions = await call(token, 'GET', '/bec/suppressions');
    expect(
      responseErrors('BecFeedbackController_listSuppressions_v1', 200, suppressions.body),
    ).toEqual([]);
    const first = suppressions.body.data[0] as { id: string } | undefined;
    if (first) {
      expect((await call(token, 'DELETE', `/bec/suppressions/${first.id}`)).status).toBe(204);
      expect((await call(token, 'DELETE', `/bec/suppressions/${first.id}`)).status).toBe(404);
    }
    const feedback = await call(token, 'GET', '/bec/feedback');
    expect(responseErrors('BecFeedbackController_list_v1', 200, feedback.body)).toEqual([]);
    const incidents = await call(token, 'GET', '/dlp/incidents?limit=5');
    expect(responseErrors('DlpIncidentsController_list_v1', 200, incidents.body)).toEqual([]);
  });

  it('roles without the permission are refused (read-only users have no DLP/BEC access)', async () => {
    const readOnly = await login('read_only_user@example.com');
    expect((await call(readOnly, 'GET', '/dlp/policies')).status).toBe(403);
    expect((await call(readOnly, 'GET', '/bec/executives')).status).toBe(403);
    const auditor = await login('compliance_auditor@example.com');
    expect((await call(auditor, 'GET', '/dlp/policies')).status).toBe(200);
    expect((await call(auditor, 'POST', '/dlp/policies', { name: 'x' })).status).toBe(403);
    expect(
      (await call(auditor, 'POST', '/dlp/patterns/test', { pattern: 'x', sample: '' })).status,
    ).toBe(403);
  });
});
