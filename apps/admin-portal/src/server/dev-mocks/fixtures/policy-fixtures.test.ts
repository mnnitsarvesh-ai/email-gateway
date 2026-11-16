// @vitest-environment node
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { beforeEach, describe, expect, it } from 'vitest';
import { operations } from '@/lib/api/operations.gen';
import type { OperationId } from '@/lib/api/types';
import { createMockFetch, mergedFixtures } from '@/server/dev-mocks';
import { DEV_MOCK_MARKER } from '@/server/dev-mocks/types';
import { fixtures, DEV_MOCK_MARKER as POLICIES_MARKER } from './policies';
import { POLICY_CATALOG_SNAPSHOT } from './policy-catalog.data';
import { resetRiskStore } from './policy-risk';
import { INVALID_LITERAL, resetPolicyStore } from './policy-store';
import { fixtureCatalog, runtimeTimeZones } from './policy-tools';

/**
 * Dev fixtures of the policy builder pages (step 7.3 WP3, design §2 B15): the catalogue is a
 * verbatim copy of docs/api/policy-catalog.json (drift test), the in-memory store keeps the
 * API's rules (row-version compare-and-set, immutable published versions, Idempotency-Key
 * replays, generation increments, tenant from the session), and validate/test/dry-run answer
 * canned bodies that match the OpenAPI responses and never evaluate.
 */

const API = 'http://api.test:3000';
const fetchImpl = createMockFetch(mergedFixtures());
const REPO = join(__dirname, '../../../../../..');
const spec = JSON.parse(readFileSync(join(REPO, 'docs/api/openapi.json'), 'utf8')) as {
  paths: Record<
    string,
    Record<string, { responses: Record<string, { content?: Record<string, { schema: unknown }> }> }>
  >;
  components: { schemas: Record<string, unknown> };
};

type Json = Record<string, unknown>;

/**
 * OpenAPI 3.0 → JSON Schema for response checks. Like `toJsonSchema` of src/test/contract.ts,
 * plus the two nullable forms the policy responses use: `nullable` on an `anyOf` without `type`
 * (catalogue parameter defaults) and `nullable` on `enum: [null]` (test result parameters).
 */
function responseSchema(schema: unknown, depth = 0): unknown {
  if (depth > 60 || schema === null || typeof schema !== 'object') return schema;
  if (Array.isArray(schema)) return schema.map((s) => responseSchema(s, depth + 1));
  const node = schema as Json;
  if (typeof node.$ref === 'string') {
    return responseSchema(spec.components.schemas[node.$ref.split('/').pop() ?? ''], depth + 1);
  }
  const out: Json = {};
  for (const [key, value] of Object.entries(node)) {
    if (key === 'nullable' || key === 'example' || key === 'examples' || key.startsWith('x-'))
      continue;
    out[key] = responseSchema(value, depth + 1);
  }
  if (node.nullable === true) {
    if (typeof out.type === 'string') out.type = [out.type, 'null'];
    if (Array.isArray(out.enum) && !out.enum.includes(null)) out.enum = [...out.enum, null];
    if (Array.isArray(out.anyOf) && out.type === undefined) {
      out.anyOf = [...out.anyOf, { type: 'null' }];
    }
  }
  if (
    out.type === 'object' &&
    out.properties &&
    out.additionalProperties === undefined &&
    !out.allOf
  ) {
    out.additionalProperties = false;
  }
  return out;
}
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);

function responseErrors(operationId: OperationId, status: number, body: unknown): string[] {
  const op = operations[operationId];
  const schema =
    spec.paths[op.path]?.[op.method.toLowerCase()]?.responses[String(status)]?.content?.[
      'application/json'
    ]?.schema;
  if (!schema) return [`no ${status} schema for ${operationId}`];
  const validate = ajv.compile(responseSchema(schema) as object);
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

const expectSchema = (operationId: OperationId, status: number, body: unknown) =>
  expect(responseErrors(operationId, status, body), operationId).toEqual([]);

const unique = (label: string) => `${label} ${Date.now()}-${Math.round(Math.random() * 1e6)}`;

const DEFINITION = {
  dslVersion: 'policy-dsl/1',
  direction: 'outbound',
  priority: 100,
  rules: [
    {
      id: 'quarantine-confidential',
      priority: 10,
      description: 'Hold confidential data leaving the organization',
      when: { all: [{ field: 'dlp.categories', op: 'contains_any', value: ['confidential'] }] },
      actions: [{ type: 'QUARANTINE' }, { type: 'ALERT', severity: 'warning' }],
    },
  ],
};

beforeEach(() => {
  resetPolicyStore();
  resetRiskStore();
});

describe('policy dev fixtures (step 7.3 WP3, design B15)', () => {
  it('the catalogue is a verbatim copy of docs/api/policy-catalog.json; time zones come from the runtime', async () => {
    expect(POLICIES_MARKER).toBe(DEV_MOCK_MARKER);
    const snapshot = JSON.parse(
      readFileSync(join(REPO, 'docs/api/policy-catalog.json'), 'utf8'),
    ) as Record<string, unknown>;
    const { timeZones: snapshotZones, ...snapshotRest } = snapshot;
    const { timeZones: copyZones, ...copyRest } = POLICY_CATALOG_SNAPSHOT;
    expect(copyRest).toEqual(snapshotRest);
    expect(copyZones).toEqual(snapshotZones);
    const zones = runtimeTimeZones();
    expect(zones).toContain('UTC');
    expect(zones).toEqual([...new Set(zones)].sort());
    expect(fixtureCatalog().timeZones).toEqual(zones);

    const token = await login('organization_admin@example.com');
    const catalog = await call(token, 'GET', '/policies/catalog');
    expect(catalog.status).toBe(200);
    expectSchema('PolicyToolsController_catalog_v1', 200, catalog.body);
    expect(catalog.body.timeZones).toContain('Europe/Berlin');
  });

  it('every policy, settings and risk operation of the portal answers from these fixtures', () => {
    const merged = mergedFixtures();
    const owned = Object.keys(operations).filter((id) =>
      /^(PolicyManagementController|PolicyToolsController|PolicySettingsController|RiskProfilesController)_/.test(
        id,
      ),
    ) as OperationId[];
    const notInScope = new Set<OperationId>(['RiskProfilesController_dryRun_v1' as OperationId]);
    for (const operationId of owned) {
      if (notInScope.has(operationId)) continue;
      expect(fixtures[operationId], operationId).toBeDefined();
      expect(merged[operationId], operationId).toBe(fixtures[operationId]);
    }
    expect(merged.PolicyMessagesController_dryRun_v1).toBe(
      fixtures.PolicyMessagesController_dryRun_v1,
    );
  });

  it('seeds realistic policies: superseded, active, newer published-not-active and draft versions', async () => {
    const token = await login('organization_admin@example.com');
    const list = await call(token, 'GET', '/policies?limit=25');
    expect(list.status).toBe(200);
    expectSchema('PolicyManagementController_list_v1', 200, list.body);
    const main = list.body.data.find(
      (p: { name: string }) => p.name === 'Inbound threat response',
    ) as { id: string };
    expect(main).toBeDefined();
    const versions = await call(token, 'GET', `/policies/${main.id}/versions`);
    expectSchema('PolicyManagementController_listVersions_v1', 200, versions.body);
    const statuses = (
      versions.body.data as Array<{ versionNo: number; status: string; active: boolean }>
    )
      .map((v) => `${v.versionNo}:${v.status}${v.active ? '*' : ''}`)
      .sort();
    expect(statuses).toEqual([
      '1:superseded',
      '2:published',
      '3:published*',
      '4:published',
      '5:draft',
    ]);
    const legacy = await call(token, 'GET', `/policies/${main.id}/versions/1`);
    expect(legacy.body.dslVersion).toBeNull();
    const active = await call(token, 'GET', `/policies/${main.id}/versions/3`);
    expectSchema('PolicyManagementController_getVersion_v1', 200, active.body);
    expect(active.body.definition.dslVersion).toBe('policy-dsl/1');
    // A foreign or unknown id is 404, never another organization's row.
    const missing = await call(token, 'GET', '/policies/00000000-0000-7000-8000-00000000abcd');
    expect(missing.status).toBe(404);
    expect(missing.body.code).toBe('policy_not_found');
  });

  it('create, draft compare-and-set (409 policy_conflict with currentRowVersion) and immutable published versions', async () => {
    const token = await login('organization_admin@example.com');
    const name = unique('Outbound confidential');
    const created = await call(token, 'POST', '/policies', {
      name,
      description: 'Hold confidential data',
      changeNote: 'First draft',
      definition: DEFINITION,
    });
    expect(created.status).toBe(201);
    expectSchema('PolicyManagementController_create_v1', 201, created.body);
    const id = created.body.policy.id as string;
    expect(created.body.version).toMatchObject({ versionNo: 1, status: 'draft', rowVersion: 1 });

    const taken = await call(token, 'POST', '/policies', { name, definition: DEFINITION });
    expect(taken.status).toBe(409);
    expect(taken.body.code).toBe('policy_name_taken');

    const changed = { ...DEFINITION, priority: 50 };
    const saved = await call(token, 'PUT', `/policies/${id}/versions/1`, {
      definition: changed,
      changeNote: 'Earlier',
      expectedRowVersion: 1,
    });
    expect(saved.status).toBe(200);
    expectSchema('PolicyManagementController_updateDraft_v1', 200, saved.body);
    expect(saved.body.rowVersion).toBe(2);

    const stale = await call(token, 'PUT', `/policies/${id}/versions/1`, {
      definition: DEFINITION,
      expectedRowVersion: 1,
    });
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({ code: 'policy_conflict', currentRowVersion: 2 });

    const invalid = await call(token, 'PUT', `/policies/${id}/versions/1`, {
      definition: { ...DEFINITION, rules: [{ ...DEFINITION.rules[0], id: INVALID_LITERAL }] },
      expectedRowVersion: 2,
    });
    expect(invalid.status).toBe(400);
    expect(invalid.body.code).toBe('policy_definition_invalid');
    expect(invalid.body.violations).toEqual([
      expect.objectContaining({ path: 'rules[0].id', code: 'value_invalid' }),
    ]);

    const key = crypto.randomUUID();
    const published = await call(
      token,
      'POST',
      `/policies/${id}/versions/1/publish`,
      { activate: false, expectedRowVersion: 2 },
      { 'idempotency-key': key },
    );
    expect(published.status).toBe(200);
    expectSchema('PolicyManagementController_publish_v1', 200, published.body);
    expect(published.body.version.status).toBe('published');
    expect(published.body.policy.activeVersionNo).toBeNull();

    const afterPublish = await call(token, 'PUT', `/policies/${id}/versions/1`, {
      definition: DEFINITION,
      expectedRowVersion: 3,
    });
    expect(afterPublish.status).toBe(409);
    expect(afterPublish.body.code).toBe('policy_version_immutable');

    const fromVersion = await call(token, 'POST', `/policies/${id}/versions`, {
      basedOnVersionNo: 1,
      changeNote: 'Copy',
    });
    expect(fromVersion.status).toBe(201);
    expect(fromVersion.body).toMatchObject({ versionNo: 2, status: 'draft' });
    expect(fromVersion.body.definition).toEqual(changed);
  });

  it('publish and activate need an Idempotency-Key, replay it, increment the generation and audit a rollback', async () => {
    const token = await login('organization_admin@example.com');
    const created = await call(token, 'POST', '/policies', {
      name: unique('Rollback'),
      definition: DEFINITION,
    });
    const id = created.body.policy.id as string;
    const before = Number((await call(token, 'GET', '/policy-settings')).body.generation);

    const noKey = await call(token, 'POST', `/policies/${id}/versions/1/publish`, {
      activate: true,
      expectedRowVersion: 1,
    });
    expect(noKey.status).toBe(400);
    expect(noKey.body.code).toBe('idempotency_key_required');

    const key = crypto.randomUUID();
    const first = await call(
      token,
      'POST',
      `/policies/${id}/versions/1/publish`,
      { activate: true, expectedRowVersion: 1 },
      { 'idempotency-key': key },
    );
    expect(first.status).toBe(200);
    expect(Number(first.body.generation)).toBe(before + 1);
    const replay = await call(
      token,
      'POST',
      `/policies/${id}/versions/1/publish`,
      { activate: true, expectedRowVersion: 1 },
      { 'idempotency-key': key },
    );
    expect(replay.status).toBe(200);
    expect(replay.headers.get('idempotency-replayed')).toBe('true');
    expect(replay.body).toEqual(first.body);

    // v2: publish and activate, then roll back to v1.
    await call(token, 'POST', `/policies/${id}/versions`, { basedOnVersionNo: 1 });
    const v2 = await call(
      token,
      'POST',
      `/policies/${id}/versions/2/publish`,
      { activate: true, expectedRowVersion: 1 },
      { 'idempotency-key': crypto.randomUUID() },
    );
    expect(v2.body.policy.activeVersionNo).toBe(2);
    const policyRow = v2.body.policy.rowVersion as number;

    const stale = await call(
      token,
      'POST',
      `/policies/${id}/versions/1/activate`,
      { expectedRowVersion: policyRow - 1 },
      { 'idempotency-key': crypto.randomUUID() },
    );
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({ code: 'policy_conflict', currentRowVersion: policyRow });

    const rollback = await call(
      token,
      'POST',
      `/policies/${id}/versions/1/activate`,
      { expectedRowVersion: policyRow },
      { 'idempotency-key': crypto.randomUUID() },
    );
    expect(rollback.status).toBe(200);
    expectSchema('PolicyManagementController_activate_v1', 200, rollback.body);
    expect(rollback.body.policy.activeVersionNo).toBe(1);
    expect(Number(rollback.body.generation)).toBe(before + 3);

    const auditRows = await call(
      token,
      'GET',
      `/audit/logs?resourceType=policy_version&resourceId=${id}&limit=50`,
    );
    expect(auditRows.status).toBe(200);
    expectSchema('AuditLogsController_search_v1', 200, auditRows.body);
    const activated = (
      auditRows.body.data as Array<{ action: string; metadata: Record<string, unknown> }>
    ).find(
      (row) =>
        row.action === 'policy.version_activated' &&
        row.metadata.versionNo === 1 &&
        row.metadata.previousVersionNo === 2,
    );
    expect(activated).toBeDefined();
  });

  it('validate, test and dry-run answer canned bodies (EXAMPLE_INVALID → one value_invalid) and store nothing', async () => {
    const token = await login('security_analyst@example.com');
    const listBefore = await call(token, 'GET', '/policies?limit=100');

    const valid = await call(token, 'POST', '/policies/validate', { definition: DEFINITION });
    expect(valid.status).toBe(200);
    expectSchema('PolicyToolsController_validate_v1', 200, valid.body);
    expect(valid.body).toMatchObject({ valid: true, violations: [], ruleCount: 1 });

    const withMarker = structuredClone<typeof DEFINITION>(DEFINITION);
    (withMarker.rules[0] as { description: string }).description = `x ${INVALID_LITERAL}`;
    const invalid = await call(token, 'POST', '/policies/validate', { definition: withMarker });
    expect(invalid.status).toBe(200);
    expectSchema('PolicyToolsController_validate_v1', 200, invalid.body);
    expect(invalid.body.valid).toBe(false);
    expect(invalid.body.violations).toEqual([
      expect.objectContaining({ path: 'rules[0].description', code: 'value_invalid' }),
    ]);
    expect(invalid.body.definitionSha256).toBeNull();

    const test = await call(token, 'POST', '/policies/test', {
      target: { definition: DEFINITION },
      facts: { direction: 'outbound' },
    });
    expect(test.status).toBe(200);
    expectSchema('PolicyToolsController_test_v1', 200, test.body);
    expect(test.body.result.explanation.text).toMatch(/canned/);

    const sample = await call(token, 'POST', '/policies/dry-run', {
      target: 'active',
      sample: { limit: 10 },
    });
    expect(sample.status).toBe(200);
    expectSchema('PolicyToolsController_sampleDryRun_v1', 200, sample.body);
    expect(sample.body.items.length).toBeLessThanOrEqual(10);

    const tooMany = await call(token, 'POST', '/policies/dry-run', {
      target: 'active',
      sample: { limit: (POLICY_CATALOG_SNAPSHOT.limits.dryRunSampleMax ?? 50) + 1 },
    });
    expect(tooMany.status).toBe(400);

    const listAfter = await call(token, 'GET', '/policies?limit=100');
    expect(listAfter.body).toEqual(listBefore.body);
  });

  it('settings and risk drafts use compare-and-set; analysts cannot publish; read-only users cannot write', async () => {
    const admin = await login('organization_admin@example.com');
    const settings = await call(admin, 'GET', '/policy-settings');
    expectSchema('PolicySettingsController_get_v1', 200, settings.body);
    const rowVersion = settings.body.rowVersion as number;
    const put = await call(admin, 'PUT', '/policy-settings', {
      settings: { allowRecommendationOverrides: false, alerts: { enabled: true } },
      expectedRowVersion: rowVersion,
    });
    expect(put.status).toBe(200);
    expectSchema('PolicySettingsController_put_v1', 200, put.body);
    expect(Number(put.body.generation)).toBe(Number(settings.body.generation) + 1);
    const stale = await call(admin, 'PUT', '/policy-settings', {
      settings: {},
      expectedRowVersion: rowVersion,
    });
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({
      code: 'policy_conflict',
      currentRowVersion: rowVersion + 1,
    });

    const draft = await call(admin, 'POST', '/risk-scoring/profile/versions', {
      overrides: { thresholds: { high: 500 } },
      changeNote: 'Stricter',
    });
    expect(draft.status).toBe(201);
    expectSchema('RiskProfilesController_createDraft_v1', 201, draft.body);
    const versionId = draft.body.id as string;
    const saved = await call(admin, 'PUT', `/risk-scoring/profile/versions/${versionId}`, {
      overrides: { thresholds: { high: 520 } },
      expectedRowVersion: 1,
    });
    expect(saved.status).toBe(200);
    const riskStale = await call(admin, 'PUT', `/risk-scoring/profile/versions/${versionId}`, {
      overrides: {},
      expectedRowVersion: 1,
    });
    expect(riskStale.status).toBe(409);
    expect(riskStale.body.code).toBe('risk_profile_version_conflict');
    const riskKey = crypto.randomUUID();
    const riskPublish = await call(
      admin,
      'POST',
      `/risk-scoring/profile/versions/${versionId}/publish`,
      { activate: true, expectedRowVersion: 2 },
      { 'idempotency-key': riskKey },
    );
    expect(riskPublish.status).toBe(200);
    expectSchema('RiskProfilesController_publish_v1', 200, riskPublish.body);

    const analyst = await login('security_analyst@example.com');
    const created = await call(analyst, 'POST', '/policies', {
      name: unique('Analyst draft'),
      definition: DEFINITION,
    });
    expect(created.status).toBe(201);
    const publish = await call(
      analyst,
      'POST',
      `/policies/${created.body.policy.id as string}/versions/1/publish`,
      { activate: true, expectedRowVersion: 1 },
      { 'idempotency-key': crypto.randomUUID() },
    );
    expect(publish.status).toBe(403);

    const reader = await login('read_only_user@example.com');
    expect((await call(reader, 'GET', '/policies?limit=5')).status).toBe(200);
    expect(
      (await call(reader, 'POST', '/policies', { name: unique('Nope'), definition: DEFINITION }))
        .status,
    ).toBe(403);
    expect(
      (await call(reader, 'POST', '/policies/validate', { definition: DEFINITION })).status,
    ).toBe(403);
  });
});
