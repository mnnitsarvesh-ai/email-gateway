// @vitest-environment node
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  SNAPSHOT_PATH,
  buildMatchers,
  check,
  extractOperations,
} from '../../../scripts/generate-api.mjs';

const snapshot = readFileSync(SNAPSHOT_PATH, 'utf8');

describe('generate-api (design P7)', () => {
  it('committed generated files match docs/api/openapi.json (drift check)', async () => {
    expect(await check()).toEqual([]);
  }, 120_000);

  it('detects drift when the snapshot changes', async () => {
    const spec = JSON.parse(snapshot) as { paths: Record<string, Record<string, unknown>> };
    spec.paths['/api/v1/drift-probe'] = {
      get: {
        operationId: 'DriftProbeController_get_v1',
        tags: ['meta'],
        responses: { '204': { description: '' } },
      },
    };
    const drift = await check(JSON.stringify(spec));
    expect(drift.map((d) => d.path.split('/').pop())).toEqual(
      expect.arrayContaining(['schema.gen.ts', 'operations.gen.ts']),
    );
    expect(drift[0]?.summary).toMatch(/line\(s\) differ/);
  }, 120_000);

  it('extracts the portal metadata of each operation', () => {
    const ops = extractOperations(JSON.parse(snapshot));
    const byId = new Map(ops.map((op) => [op.operationId, op]));
    expect(byId.get('QuarantineEntriesController_search_v1')?.listKey).toBe('items');
    expect(byId.get('DomainsController_list_v1')).toMatchObject({
      listKey: 'data',
      cursor: 'v0',
      sort: null,
    });
    expect(byId.get('MessagesController_list_v1')?.sort).toEqual(['-receivedAt', 'receivedAt']);
    expect(byId.get('AuthController_login_v1')).toMatchObject({
      public: true,
      bffOnly: true,
      permissions: null,
    });
    expect(byId.get('MetaController_get_v1')).toMatchObject({ public: true, bffOnly: false });
    expect(byId.get('OrganizationsController_list_v1')?.permissions).toEqual([
      { mode: 'any', permissions: ['organization:read', 'platform:organizations'] },
    ]);
    expect(byId.get('ApiKeysController_create_v1')?.returnsSecret).toBe(true);
    expect(ops.filter((op) => op.idempotency !== null).length).toBeGreaterThan(30);
  });

  it('orders matchers so static segments win over parameters', () => {
    const matchers = buildMatchers(extractOperations(JSON.parse(snapshot)));
    const search = matchers.findIndex(
      (m) => m.operationId === 'QuarantineEntriesController_search_v1',
    );
    expect(search).toBeGreaterThanOrEqual(0);
    const key = (m: (typeof matchers)[number]) =>
      m.segments.map((s) => (typeof s === 'string' ? s : `{${s.param}}`)).join('/');
    expect(
      matchers
        .slice(0, 3)
        .map(key)
        .every((k) => k.length > 0),
    ).toBe(true);
  });
});
