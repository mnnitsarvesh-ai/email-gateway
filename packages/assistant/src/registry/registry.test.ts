import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { staleOutputs } from '../../scripts/generate-registry';
import {
  buildRegistry,
  freeFormResponsePaths,
  isPlatformOnly,
  normalizeSchema,
  successResponseSchema,
  toolNameOf,
  untrustedFieldsOf,
  type OpenApiDocument,
} from './build';
import {
  ASSISTANT_PROGRAM_PHASE,
  CONTROLLER_HINTS,
  NOT_APPLICABLE_TAGS,
  OPERATION_OVERRIDES,
  READ_TOOLS_TESTED_BY,
  classifyOperation,
} from './manifest';
import {
  NOT_APPLICABLE_OPERATIONS,
  OPERATION_TOOLS,
  REGISTRY_VERSION,
  compileValidator,
  describeTool,
  enabledTools,
  findOperation,
  findTool,
  renderCatalogueIndex,
  satisfiesRequirement,
  toolSignature,
} from './registry';
import { PROGRAM_PHASES } from './types';

const REPO = join(__dirname, '../../../..');
const openapi = JSON.parse(
  readFileSync(join(REPO, 'docs/api/openapi.json'), 'utf8'),
) as OpenApiDocument;
const METHODS = ['get', 'put', 'post', 'delete', 'patch'] as const;
const operations = Object.entries(openapi.paths).flatMap(([path, item]) =>
  METHODS.flatMap((method) => (item[method] ? [{ path, method, op: item[method] }] : [])),
);
const phase = (p: string) => PROGRAM_PHASES.indexOf(p as (typeof PROGRAM_PHASES)[number]);

describe('registry check (generated outputs)', () => {
  it('operations.generated.ts and UI_TO_CHAT_CAPABILITY_MATRIX.md are in sync', async () => {
    expect(await staleOutputs()).toEqual([]);
  }, 60_000);

  it('the version is the first 16 hex of the content hash', () => {
    expect(REGISTRY_VERSION).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('registry completeness and consistency (D3)', () => {
  it('classifies every OpenAPI operation exactly once', () => {
    const ids = operations.map((o) => o.op.operationId).sort();
    const classified = [
      ...OPERATION_TOOLS.map((t) => t.operationId),
      ...NOT_APPLICABLE_OPERATIONS.map((o) => o.operationId),
    ].sort();
    expect(classified).toEqual(ids);
    for (const op of NOT_APPLICABLE_OPERATIONS)
      expect(op.reason.length, op.operationId).toBeGreaterThan(0);
  });

  it('requirement equals x-eg-permissions (authenticated when absent)', () => {
    for (const { op } of operations) {
      const record = findOperation(op.operationId!)!;
      const expected = op['x-eg-permissions'] ?? { mode: 'authenticated' };
      expect(record.requirement, op.operationId).toEqual(expected);
    }
  });

  it('x-eg-returns-secret operations and the auth/mfa/sessions/meta/assistant tags are not applicable', () => {
    for (const { op } of operations) {
      const notApplicable = NOT_APPLICABLE_OPERATIONS.some((o) => o.operationId === op.operationId);
      if (op['x-eg-returns-secret'] === true) expect(notApplicable, op.operationId).toBe(true);
      if ((op.tags ?? []).some((tag) => tag in NOT_APPLICABLE_TAGS))
        expect(notApplicable, op.operationId).toBe(true);
    }
    expect(Object.keys(NOT_APPLICABLE_TAGS).sort()).toEqual([
      'assistant',
      'auth',
      'meta',
      'mfa',
      'sessions',
    ]);
  });

  it('no write is enabled in AI-1; enabled tools are within the program phase; writes need testedBy', () => {
    expect(ASSISTANT_PROGRAM_PHASE).toBe('AI-1');
    for (const tool of OPERATION_TOOLS) {
      if (tool.enabled) {
        expect(phase(tool.phase), tool.name).toBeLessThanOrEqual(phase(ASSISTANT_PROGRAM_PHASE));
        expect(tool.access, tool.name).toBe('read');
        expect(tool.status, tool.name).toBe('IMPLEMENTED');
        expect(tool.testedBy, tool.name).toBe(READ_TOOLS_TESTED_BY);
      } else {
        expect(tool.status, tool.name).toBe('MISSING');
      }
      if (tool.access === 'write' && tool.enabled) expect(tool.testedBy).toBeTruthy();
    }
  });

  it('tool names match ^[a-z0-9_]{1,64}$, are unique and derive from the operation id', () => {
    const names = OPERATION_TOOLS.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
    for (const tool of OPERATION_TOOLS) {
      expect(tool.name).toMatch(/^[a-z0-9_]{1,64}$/);
      expect(tool.name).toBe(toolNameOf(tool.operationId));
    }
    expect(toolNameOf('PolicyManagementController_list_v1')).toBe('policy_management_list');
    expect(toolNameOf('MessageScansController_scansOf_v1')).toBe('message_scans_scans_of');
  });

  it('agrees with the design baseline totals (Appendix A at 403 operations)', () => {
    if (operations.length !== 403) return; // later steps add operations; the per-rule tests still hold
    const count = (pred: (t: (typeof OPERATION_TOOLS)[number]) => boolean) =>
      OPERATION_TOOLS.filter(pred).length;
    expect(OPERATION_TOOLS).toHaveLength(348);
    expect(NOT_APPLICABLE_OPERATIONS).toHaveLength(55);
    expect(count((t) => t.enabled)).toBe(174);
    expect(Object.fromEntries(PROGRAM_PHASES.map((p) => [p, count((t) => t.phase === p)]))).toEqual(
      { 'AI-1': 174, 'AI-2': 35, 'AI-3': 47, 'AI-4': 66, 'AI-5': 26, 'AI-6': 0 },
    );
    expect(NOT_APPLICABLE_OPERATIONS.filter((o) => o.risk === 'critical')).toHaveLength(9);
  });

  it('every tool has a portal route; overrides and hints name real operations and controllers', () => {
    for (const tool of OPERATION_TOOLS) expect(tool.portalRoute, tool.name).toMatch(/^\//);
    for (const id of Object.keys(OPERATION_OVERRIDES)) expect(findOperation(id), id).toBeDefined();
    const controllers = new Set(operations.map((o) => o.op.operationId!.split('_')[0]));
    for (const controller of Object.keys(CONTROLLER_HINTS))
      expect(controllers.has(controller), controller).toBe(true);
  });

  it('untrustedFields name paths of the operation’s success (200/201) response schema', () => {
    const resolve = (schema: unknown, segments: string[]): boolean => {
      let node = normalizeSchema(schema, openapi.components?.schemas ?? {});
      for (const segment of segments) {
        const array = segment.endsWith('[]');
        const key = array ? segment.slice(0, -2) : segment;
        const variants = [node, ...((node.anyOf as Record<string, unknown>[] | undefined) ?? [])];
        const holder = variants.find(
          (v) => (v.properties as Record<string, unknown> | undefined)?.[key] !== undefined,
        );
        if (!holder) return false;
        node = (holder.properties as Record<string, Record<string, unknown>>)[key]!;
        if (array) {
          const inner =
            (node.items as Record<string, unknown> | undefined) ??
            ((node.anyOf as Record<string, unknown>[] | undefined) ?? []).find((v) => v.items)
              ?.items;
          if (!inner) return false;
          node = inner as Record<string, unknown>;
        }
      }
      return true;
    };
    for (const tool of OPERATION_TOOLS) {
      if (tool.untrustedFields.length === 0) continue;
      const op = operations.find((o) => o.op.operationId === tool.operationId)!.op;
      const schema = successResponseSchema(op);
      for (const path of tool.untrustedFields)
        expect(path === '' || resolve(schema, path.split('.')), `${tool.name}: ${path}`).toBe(true);
    }
  });

  it('every free-form response path of every tool is untrusted (no unclassified free-form value)', () => {
    const components = openapi.components?.schemas ?? {};
    const covered = (path: string, fields: readonly string[]) =>
      fields.some(
        (entry) =>
          entry === '' ||
          path === entry ||
          path.startsWith(`${entry}.`) ||
          path.startsWith(`${entry}[]`),
      );
    let freeForm = 0;
    for (const tool of OPERATION_TOOLS) {
      const op = operations.find((o) => o.op.operationId === tool.operationId)!.op;
      for (const path of freeFormResponsePaths(op, components)) {
        freeForm += 1;
        expect(covered(path, tool.untrustedFields), `${tool.name}: ${path}`).toBe(true);
      }
    }
    expect(freeForm).toBeGreaterThan(0);
    const signals = ['ato_accounts_signals', 'ato_incident_evidence_signals'].map((name) =>
      findTool(name)!,
    );
    for (const tool of signals)
      expect(tool.untrustedFields).toEqual(
        expect.arrayContaining(['data[].evidence', 'data[].explanation']),
      );
    expect(findTool('incidents_get')!.untrustedFields).toEqual(
      expect.arrayContaining(['evidence', 'detail']),
    );
  });

  it('freeFormResponsePaths: open objects, maps and untyped values; typed objects are walked', () => {
    const op = {
      operationId: 'XController_get_v1',
      responses: {
        '200': {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  name: { type: 'string' },
                  evidence: { type: 'object', additionalProperties: {} },
                  counts: { type: 'object', additionalProperties: { type: 'number' } },
                  rows: {
                    type: 'array',
                    items: {
                      type: 'object',
                      properties: { any: {}, typed: { type: 'object', properties: {} } },
                    },
                  },
                  maybe: { anyOf: [{ type: 'object' }, { type: 'null' }] },
                  closed: {
                    type: 'object',
                    properties: { a: { type: 'string' } },
                    additionalProperties: false,
                  },
                },
              },
            },
          },
        },
      },
    };
    expect(freeFormResponsePaths(op, {}).sort()).toEqual(
      ['counts', 'evidence', 'maybe', 'rows[].any', 'rows[].typed'].sort(),
    );
    expect(freeFormResponsePaths({ operationId: 'XController_none_v1' }, {})).toEqual([]);
    expect(untrustedFieldsOf(['subject', 'evidence'], ['evidence.x', 'detail', 'subject'])).toEqual(
      ['subject', 'evidence', 'detail'],
    );
  });
});

describe('classification rules (synthetic operations)', () => {
  it('classifies tags, secrets, content, consent, critical and risk verbs', () => {
    const facts = (
      method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
      path: string,
      tags: string[],
      extra = {},
    ) => ({
      operationId: 'XController_y_v1',
      method,
      path,
      tags,
      returnsSecret: false,
      ...extra,
    });
    expect(classifyOperation(facts('GET', '/assistant/status', ['assistant']))).toMatchObject({
      kind: 'not_applicable',
    });
    expect(
      classifyOperation(facts('POST', '/things', ['domains'], { returnsSecret: true })),
    ).toMatchObject({
      kind: 'not_applicable',
      reason: 'returns a secret (never through chat)',
    });
    expect(classifyOperation(facts('GET', '/things/{id}/preview', ['domains']))).toMatchObject({
      kind: 'not_applicable',
    });
    expect(classifyOperation(facts('GET', '/things', ['domains']))).toMatchObject({
      kind: 'tool',
      access: 'read',
      risk: 'read',
      phase: 'AI-1',
    });
    expect(classifyOperation(facts('POST', '/things/validate', ['policies']))).toMatchObject({
      access: 'read',
      phase: 'AI-2',
    });
    expect(classifyOperation(facts('DELETE', '/things/{id}', ['domains']))).toMatchObject({
      risk: 'high',
      confirm: 'confirm+impact+reauth',
    });
    expect(classifyOperation(facts('POST', '/things/{id}/enable', ['domains']))).toMatchObject({
      risk: 'medium',
      confirm: 'confirm+impact',
    });
    expect(classifyOperation(facts('PATCH', '/things/{id}', ['domains']))).toMatchObject({
      risk: 'low',
      confirm: 'confirm',
    });
    expect(() => classifyOperation(facts('POST', '/x', ['brand-new-module']))).toThrow(
      /MODULE_WRITE_PHASE/,
    );
  });

  it('a new operation without classification fails the build (unknown module)', () => {
    const doc: OpenApiDocument = {
      paths: {
        '/api/v1/widgets': {
          post: { operationId: 'WidgetsController_create_v1', tags: ['widgets'] },
        },
      },
    };
    expect(() => buildRegistry(doc, new Map())).toThrow(/widgets/);
  });
});

describe('input schemas (strict Ajv)', () => {
  it('compiles every tool schema in Ajv strict mode', () => {
    for (const tool of OPERATION_TOOLS)
      expect(() => compileValidator(tool), tool.name).not.toThrow();
  });

  it('validates arguments: formats, enums, required path params, no additional properties (paths only, never values)', () => {
    const get = compileValidator(findTool('policy_management_get')!);
    expect(get({ policyId: '0190aaaa-0000-7000-8000-000000000001' })).toEqual({ ok: true });
    const bad = get({ policyId: 'not-a-uuid', extra: 'SECRETVALUE' });
    expect(bad.ok).toBe(false);
    if (!bad.ok) {
      expect([...new Set(bad.issues.map((i) => i.path))].sort()).toEqual(['/extra', '/policyId']);
      expect(JSON.stringify(bad.issues)).not.toContain('SECRETVALUE');
    }
    const missing = get({});
    expect(missing.ok === false && missing.issues[0]!.path).toBe('/policyId');
    const list = compileValidator(findTool('policy_management_list')!);
    expect(list({ status: 'active', limit: 10 }).ok).toBe(true);
    expect(list({ status: 'bogus' }).ok).toBe(false);
    expect(list({ limit: 1000 }).ok).toBe(false);
  });

  it('bound parameters are optional for the model (filled server-side)', () => {
    const tool = findTool('organizations_get')!;
    expect(tool.bind).toEqual({ id: 'self_organization' });
    expect(tool.inputSchema.required).toBeUndefined();
    expect(compileValidator(tool)({}).ok).toBe(true);
  });

  it('normalizes OpenAPI schemas: $ref inlined, nullable, example dropped, descriptions trimmed', () => {
    const components = {
      Thing: { type: 'object', properties: { a: { type: 'string' } }, example: { a: 'x' } },
    };
    expect(
      normalizeSchema(
        {
          type: 'object',
          properties: {
            ref: { $ref: '#/components/schemas/Thing' },
            maybe: { type: 'string', nullable: true, enum: ['a', 'b'] },
            any: {
              nullable: true,
              oneOf: [{ type: 'string' }, { type: 'integer' }],
              description: 'd'.repeat(400),
            },
          },
          additionalProperties: false,
        },
        components,
      ),
    ).toEqual({
      type: 'object',
      properties: {
        ref: { type: 'object', properties: { a: { type: 'string' } } },
        maybe: { type: ['string', 'null'], enum: ['a', 'b', null] },
        any: {
          description: `${'d'.repeat(299)}…`,
          anyOf: [{ oneOf: [{ type: 'string' }, { type: 'integer' }] }, { type: 'null' }],
        },
      },
      additionalProperties: false,
    });
    expect(() => normalizeSchema({ $ref: '#/components/schemas/Missing' }, {})).toThrow(
      /unresolved/,
    );
  });

  it('header parameters (Idempotency-Key) never reach the input schema', () => {
    for (const tool of OPERATION_TOOLS)
      expect(Object.keys(tool.inputSchema.properties as object), tool.name).not.toContain(
        'Idempotency-Key',
      );
  });
});

describe('permission pre-filter, catalogue index, describe', () => {
  it('enabledTools filters by permission, phase and platform-only', () => {
    const reader = enabledTools(['policy:read'], false);
    expect(reader.map((t) => t.name)).toContain('policy_management_list');
    expect(
      reader.every(
        (t) => t.enabled && satisfiesRequirement(t.requirement, new Set(['policy:read'])),
      ),
    ).toBe(true);
    expect(reader.some((t) => t.name === 'users_list')).toBe(false);
    const platformPerms = OPERATION_TOOLS.filter((t) => t.platformOnly).flatMap((t) =>
      t.requirement.mode === 'authenticated' ? [] : t.requirement.permissions,
    );
    expect(enabledTools(platformPerms, false).some((t) => t.platformOnly)).toBe(false);
    expect(enabledTools(platformPerms, true).some((t) => t.name === 'dead_letters_stats')).toBe(
      true,
    );
    expect(enabledTools([], false).every((t) => t.requirement.mode === 'authenticated')).toBe(true);
    expect(
      isPlatformOnly({ mode: 'any', permissions: ['organization:read', 'platform:organizations'] }),
    ).toBe(false);
    expect(isPlatformOnly({ mode: 'all', permissions: ['platform:dead_letters'] })).toBe(true);
  });

  it('renders a deterministic, module-grouped index with one signature line per tool', () => {
    const tools = OPERATION_TOOLS.filter((t) => t.enabled);
    const a = renderCatalogueIndex(tools);
    const b = renderCatalogueIndex([...tools].reverse());
    expect(a).toBe(b);
    const lines = a.split('\n').filter((l) => l && !l.startsWith('## '));
    expect(lines).toHaveLength(tools.length);
    const modules = a
      .split('\n')
      .filter((l) => l.startsWith('## '))
      .map((l) => l.slice(3));
    expect(modules).toEqual([...modules].sort((x, y) => x.localeCompare(y, 'en')));
    expect(toolSignature(findTool('policy_management_list')!)).toBe(
      'policy_management_list(status?: draft|active|disabled, direction?: inbound|outbound|internal|any, limit?, cursor?) - List policies',
    );
    expect(toolSignature(findTool('policy_management_get')!)).toMatch(
      /^policy_management_get\(policyId\) - /,
    );
  });

  it('describeTool returns the schema, risk and availability', () => {
    const tool = findTool('policy_management_remove')!;
    expect(describeTool(tool)).toMatchObject({
      name: 'policy_management_remove',
      access: 'write',
      risk: 'high',
      confirm: 'confirm+impact+reauth',
      available: false,
      unavailableReason: 'disabled',
    });
    expect(
      describeTool(findTool('users_list')!, { available: false, reason: 'permission' }),
    ).toMatchObject({
      available: false,
      unavailableReason: 'permission',
    });
  });
});
