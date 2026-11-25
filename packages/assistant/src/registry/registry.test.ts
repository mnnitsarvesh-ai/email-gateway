import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { readPortalUsage, staleOutputs } from '../../scripts/generate-registry';
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
  CONFIRMATION_SPECS,
  confirmationSpecOf,
  type ConfirmationSpec,
} from '../confirmations/specs';
import { registryConsistencyIssues } from './consistency';
import {
  AI2_WRITES_TESTED_BY,
  AI3_WRITES_TESTED_BY,
  AI4_WRITES_TESTED_BY,
  ASSISTANT_PROGRAM_PHASE,
  ATO_WRITES_TESTED_BY,
  DETECTION_WRITES_TESTED_BY,
  PLATFORM_OPS_WRITES_TESTED_BY,
  DOMAIN_WRITES_TESTED_BY,
  IDENTITY_WRITES_TESTED_BY,
  TENANT_ADMIN_WRITES_TESTED_BY,
  CONTROLLER_HINTS,
  MAIL_OPS_WRITES_TESTED_BY,
  POLICY_WRITES_TESTED_BY,
  NOT_APPLICABLE_TAGS,
  OPERATION_OVERRIDES,
  READ_TOOLS_TESTED_BY,
  classifyOperation,
} from './manifest';
import {
  ALL_TOOLS,
  NATIVE_TOOLS,
  NOT_APPLICABLE_OPERATIONS,
  OPERATION_TOOLS,
  REDACTED_PARAM,
  REGISTRY_VERSION,
  isNativeTool,
  redactToolArguments,
  compileValidator,
  describeTool,
  enabledTools,
  findOperation,
  findTool,
  renderCatalogueIndex,
  satisfiesRequirement,
  toolSignature,
} from './registry';
import { PROGRAM_PHASES, type OperationOverride, type OperationTool } from './types';

const REPO = join(__dirname, '../../../..');
const openapi = JSON.parse(
  readFileSync(join(REPO, 'docs/api/openapi.json'), 'utf8'),
) as OpenApiDocument;
const METHODS = ['get', 'put', 'post', 'delete', 'patch'] as const;
const operations = Object.entries(openapi.paths).flatMap(([path, item]) =>
  METHODS.flatMap((method) => (item[method] ? [{ path, method, op: item[method] }] : [])),
);
const phase = (p: string) => PROGRAM_PHASES.indexOf(p as (typeof PROGRAM_PHASES)[number]);
const OPENAPI_IDS: ReadonlySet<string> = new Set(operations.map((o) => o.op.operationId!));

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

  it('AI-4: enabled tools are within the program phase; writes are enabled only with testedBy, a spec and a template', () => {
    expect(ASSISTANT_PROGRAM_PHASE).toBe('AI-4');
    expect(PROGRAM_PHASES).toEqual(['AI-1', 'AI-2', 'AI-3', 'AI-R', 'AI-4', 'AI-5', 'AI-6']);
    expect(registryConsistencyIssues(ALL_TOOLS, { openApiOperationIds: OPENAPI_IDS })).toEqual([]);
    // AI-R adds no OpenAPI tool; every generated tool of AI-5 and later stays disabled.
    expect(OPERATION_TOOLS.some((t) => t.phase === 'AI-R')).toBe(false);
    for (const tool of OPERATION_TOOLS) {
      if (tool.enabled) {
        expect(phase(tool.phase), tool.name).toBeLessThanOrEqual(phase(ASSISTANT_PROGRAM_PHASE));
        expect(tool.status, tool.name).toBe('IMPLEMENTED');
        if (tool.access === 'read') expect(tool.testedBy, tool.name).toBe(READ_TOOLS_TESTED_BY);
        else {
          expect(tool.testedBy, tool.name).toBe(
            AI2_WRITES_TESTED_BY[tool.operationId] ??
              AI3_WRITES_TESTED_BY[tool.operationId] ??
              AI4_WRITES_TESTED_BY[tool.operationId],
          );
          expect(confirmationSpecOf(tool.operationId), tool.name).toBeDefined();
          expect(['low', 'medium', 'high'], tool.name).toContain(tool.risk);
        }
      } else {
        expect(tool.status, tool.name).toBe('MISSING');
        expect(phase(tool.phase), tool.name).toBeGreaterThan(phase(ASSISTANT_PROGRAM_PHASE));
      }
    }
    const policyWrites = Object.values(AI2_WRITES_TESTED_BY).filter(
      (suite) => suite === POLICY_WRITES_TESTED_BY,
    );
    const mailOps = Object.values(AI2_WRITES_TESTED_BY).filter(
      (suite) => suite === MAIL_OPS_WRITES_TESTED_BY,
    );
    expect([policyWrites.length, mailOps.length]).toEqual([11, 20]);
    const ai3 = (suite: string) =>
      Object.values(AI3_WRITES_TESTED_BY).filter((value) => value === suite).length;
    expect([
      ai3(IDENTITY_WRITES_TESTED_BY),
      ai3(DOMAIN_WRITES_TESTED_BY),
      ai3(TENANT_ADMIN_WRITES_TESTED_BY),
    ]).toEqual([18, 10, 19]);
    const ai4 = (suite: string) =>
      Object.values(AI4_WRITES_TESTED_BY).filter((value) => value === suite).length;
    expect([
      ai4(ATO_WRITES_TESTED_BY),
      ai4(DETECTION_WRITES_TESTED_BY),
      ai4(PLATFORM_OPS_WRITES_TESTED_BY),
    ]).toEqual([22, 34, 8]);
    expect(Object.keys(AI4_WRITES_TESTED_BY)).toHaveLength(64);
    expect(NOT_APPLICABLE_OPERATIONS.filter((o) => o.risk === 'critical')).toHaveLength(9);
    for (const op of NOT_APPLICABLE_OPERATIONS.filter((o) => o.risk === 'critical'))
      expect(findTool(toolNameOf(op.operationId)), op.operationId).toBeUndefined();
  });

  it('AI-2 totals: 348 tools, 209 enabled (174 AI-1 + 35 AI-2), 139 missing', () => {
    if (OPERATION_TOOLS.length !== 348) return; // later steps add tools; the rules above still hold
    const count = (pred: (t: (typeof OPERATION_TOOLS)[number]) => boolean) =>
      OPERATION_TOOLS.filter(pred).length;
    expect(count((t) => t.enabled)).toBe(209);
    expect(count((t) => t.status === 'IMPLEMENTED')).toBe(209);
    expect(count((t) => t.status === 'MISSING')).toBe(139);
    expect(count((t) => t.enabled && t.phase === 'AI-2')).toBe(35);
    expect(count((t) => t.enabled && t.phase === 'AI-2' && t.access === 'write')).toBe(31);
    expect(count((t) => t.enabled && t.phase !== 'AI-1' && t.phase !== 'AI-2')).toBe(0);
  });

  it('AI-3 totals (design 30 D1): 422 operations, 349 tools, 257 enabled (179 reads, 78 writes)', () => {
    if (operations.length !== 422) return; // later steps add operations; the rules above still hold
    const count = (pred: (t: (typeof OPERATION_TOOLS)[number]) => boolean) =>
      OPERATION_TOOLS.filter(pred).length;
    expect(OPERATION_TOOLS).toHaveLength(349);
    expect(NOT_APPLICABLE_OPERATIONS).toHaveLength(73);
    expect(count((t) => t.enabled)).toBe(257);
    expect(count((t) => t.enabled && t.access === 'read')).toBe(179);
    expect(count((t) => t.enabled && t.access === 'write')).toBe(78);
    expect(count((t) => t.status === 'MISSING')).toBe(92);
    expect(count((t) => t.status === 'MISSING' && t.access === 'read')).toBe(3);
    expect(Object.fromEntries(PROGRAM_PHASES.map((p) => [p, count((t) => t.phase === p)]))).toEqual(
      { 'AI-1': 174, 'AI-2': 35, 'AI-3': 48, 'AI-R': 0, 'AI-4': 66, 'AI-5': 26, 'AI-6': 0 },
    );
    expect(count((t) => t.enabled && phase(t.phase) > phase('AI-3'))).toBe(0);
    const writesByRisk = Object.fromEntries(
      ['low', 'medium', 'high'].map((r) => [
        r,
        count((t) => t.enabled && t.access === 'write' && t.phase === 'AI-3' && t.risk === r),
      ]),
    );
    expect(writesByRisk).toEqual({ low: 8, medium: 13, high: 26 });
  });

  it('AI-3 manifest: risks of D2, webhooks_test is a low write, api_keys_get an AI-3 read', () => {
    const risks = Object.fromEntries(
      [
        'users_invite',
        'roles_update',
        'domain_destinations_replace',
        'scan_settings_replace',
        'smtp_connectors_update',
        'organizations_create',
        'webhooks_test',
      ].map((name) => [name, findTool(name)!.risk]),
    );
    expect(risks).toEqual({
      users_invite: 'high',
      roles_update: 'high',
      domain_destinations_replace: 'high',
      scan_settings_replace: 'high',
      smtp_connectors_update: 'medium',
      organizations_create: 'medium',
      webhooks_test: 'low',
    });
    expect(findTool('webhooks_test')).toMatchObject({
      access: 'write',
      confirm: 'confirm',
      phase: 'AI-3',
      enabled: true,
      testedBy: TENANT_ADMIN_WRITES_TESTED_BY,
    });
    expect(findTool('api_keys_get')).toMatchObject({
      access: 'read',
      phase: 'AI-3',
      enabled: true,
      testedBy: READ_TOOLS_TESTED_BY,
    });
    expect(findTool('roles_create')!.display.refField).toBe('key');
    expect(findTool('users_list_sessions')!.untrustedFields).toContain('data[].userAgent');
    expect(findTool('users_list')!.untrustedFields).toContain('data[].displayName');
    expect(findTool('webhook_deliveries_get')!.untrustedFields).toEqual(
      expect.arrayContaining(['attempts[].responseSnippet', 'attempts[].errorCode', 'lastError']),
    );
  });

  it('AI-4 manifest: risks of D2, the four new reads, untrusted fields of D7, redactParams of D9', () => {
    const risks = Object.fromEntries(
      [
        'ato_accounts_add_trusted_context',
        'bec_trusted_senders_create',
        'dlp_exceptions_create',
        'ato_settings_update',
        'ato_providers_update',
        'ato_providers_create',
        'ato_providers_health_check',
        'ato_account_mailbox_refresh',
        // unchanged §4.4 rules (design D2 "unchanged and right")
        'ato_responses_request',
        'ato_responses_approve',
        'ato_responses_rollback',
        'ato_responses_reject',
        'ato_responses_cancel',
        'ato_accounts_update',
        'ato_accounts_set_override',
        'ato_accounts_clear_override',
        'ato_accounts_remove_trusted_context',
        'ato_providers_remove',
        'ato_providers_backfill',
        'bec_feedback_delete_suppression',
        'dlp_compliance_enable',
        'risk_profiles_update_draft',
        'risk_profiles_publish',
        'risk_profiles_reset',
        'threat_hashes_add',
        'dead_letters_replay',
      ].map((name) => [name, findTool(name)!.risk]),
    );
    expect(risks).toEqual({
      ato_accounts_add_trusted_context: 'high',
      bec_trusted_senders_create: 'high',
      dlp_exceptions_create: 'high',
      ato_settings_update: 'high',
      ato_providers_update: 'high',
      ato_providers_create: 'medium',
      ato_providers_health_check: 'low',
      ato_account_mailbox_refresh: 'low',
      ato_responses_request: 'high',
      ato_responses_approve: 'high',
      ato_responses_rollback: 'high',
      ato_responses_reject: 'medium',
      ato_responses_cancel: 'medium',
      ato_accounts_update: 'low',
      ato_accounts_set_override: 'medium',
      ato_accounts_clear_override: 'low',
      ato_accounts_remove_trusted_context: 'high',
      ato_providers_remove: 'high',
      ato_providers_backfill: 'medium',
      bec_feedback_delete_suppression: 'medium',
      dlp_compliance_enable: 'high',
      risk_profiles_update_draft: 'medium',
      risk_profiles_publish: 'medium',
      risk_profiles_reset: 'high',
      threat_hashes_add: 'high',
      dead_letters_replay: 'high',
    });
    for (const name of [
      'bec_trusted_senders_get',
      'bec_feedback_get_suppression',
      'dlp_exceptions_get',
      'threat_indicators_get',
    ])
      expect(findTool(name), name).toMatchObject({
        access: 'read',
        phase: 'AI-4',
        enabled: true,
        testedBy: READ_TOOLS_TESTED_BY,
      });
    expect(findTool('threat_indicators_get')!.platformOnly).toBe(true);
    expect(findTool('bec_feedback_get_suppression')!.untrustedFields).toEqual(['senderValue']);
    expect(findTool('threat_indicators_get')!.untrustedFields).toEqual(['value']);
    expect(findTool('bec_trusted_senders_get')!.untrustedFields).toEqual([]);
    expect(findTool('dlp_exceptions_get')!.untrustedFields).toEqual([]);
    expect(findTool('ato_responses_get')!.untrustedFields).toEqual([
      'requestReason',
      'decisionReason',
      'rollbackReason',
      'params.description',
    ]);
    expect(findTool('ato_responses_list')!.untrustedFields).toEqual(
      expect.arrayContaining(['data[].requestReason', 'data[].params.description']),
    );
    expect(findTool('ato_account_mailbox_get')!.untrustedFields).toEqual(
      expect.arrayContaining(['items[].targetDomain', 'identities[].userPrincipalName']),
    );
    expect(findTool('risk_dry_run_dry_run')!.untrustedFields).toEqual(
      expect.arrayContaining(['result.explanation.text', 'result.explanation.lines[].params']),
    );
    expect(findTool('dlp_patterns_test')!.redactParams).toEqual(['body.sample', 'body.pattern']);
    expect(ALL_TOOLS.filter((t) => t.redactParams.length > 0).map((t) => t.name)).toEqual([
      'dlp_patterns_test',
    ]);
    expect(findTool('threat_hashes_add')!.display.refField).toBe('sha256');
    // D11: the platform writes are platform-only (absent for customers and under an override).
    for (const name of [
      'attachment_rescans_request',
      'attachment_rescans_cancel',
      'dead_letters_replay',
      'scan_training_train',
      'threat_hashes_add',
      'threat_hashes_remove',
      'threat_indicators_add',
      'threat_indicators_remove',
    ]) {
      expect(findTool(name)!.platformOnly, name).toBe(true);
      expect(findTool(name)!.testedBy, name).toBe(PLATFORM_OPS_WRITES_TESTED_BY);
    }
    const customer = enabledTools(
      [
        ...new Set(
          ALL_TOOLS.flatMap((t) =>
            t.requirement.mode === 'authenticated' ? [] : t.requirement.permissions,
          ),
        ),
      ].filter((p) => !p.startsWith('platform:')),
      false,
    );
    expect(customer.some((t) => t.platformOnly)).toBe(false);
    const matrix = readFileSync(
      join(REPO, 'docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md'),
      'utf8',
    );
    expect(matrix).toMatch(
      /`dlp_patterns_test` \(redacted: body\.sample, body\.pattern, stored as \[redacted\]/,
    );
    expect(matrix).toMatch(
      /`ato_responses_approve` \(guard: not requester; guard: canDecide = true\)/,
    );
    expect(matrix).toMatch(/confirm ↑ high when body\.protected = true/);
  });

  it('redactToolArguments replaces the redactParams paths with [redacted] in a copy (D9)', () => {
    const test = findTool('dlp_patterns_test')!;
    const args = {
      body: { pattern: '\\b\\d{4}\\b', sample: 'the sample text 1234', validator: 'none' },
    };
    const { args: stored, redacted } = redactToolArguments(test, args);
    expect(redacted).toBe(true);
    expect(stored).toEqual({
      body: { pattern: REDACTED_PARAM, sample: REDACTED_PARAM, validator: 'none' },
    });
    expect(REDACTED_PARAM).toBe('[redacted]');
    // The loopback arguments keep the real values.
    expect(args.body.sample).toBe('the sample text 1234');
    // Absent paths are not added; tools without redactParams are copied unchanged.
    expect(redactToolArguments(test, { body: { validator: 'luhn' } })).toEqual({
      args: { body: { validator: 'luhn' } },
      redacted: false,
    });
    expect(redactToolArguments(test, { body: 'x' })).toEqual({
      args: { body: 'x' },
      redacted: false,
    });
    const list = findTool('policy_management_list')!;
    expect(redactToolArguments(list, { status: 'active' })).toEqual({
      args: { status: 'active' },
      redacted: false,
    });
  });

  it('an access override may only make a read a write (generator check)', () => {
    const overrides = OPERATION_OVERRIDES as Record<string, OperationOverride>;
    const doc: OpenApiDocument = {
      paths: {
        '/api/v1/domains/{id}/widgets': {
          get: { operationId: 'WidgetsController_get_v1', tags: ['domains'] },
          post: { operationId: 'WidgetsController_create_v1', tags: ['domains'] },
        },
        '/api/v1/domains/{id}/widgets/test': {
          post: { operationId: 'WidgetsController_test_v1', tags: ['domains'] },
        },
      },
    };
    try {
      overrides.WidgetsController_create_v1 = { access: 'read' as 'write' };
      expect(() => buildRegistry(doc, new Map())).toThrow(/only make a read a write/);
      delete overrides.WidgetsController_create_v1;
      overrides.WidgetsController_test_v1 = { access: 'write' };
      expect(() => buildRegistry(doc, new Map())).toThrow(/needs a risk override/);
      overrides.WidgetsController_test_v1 = { access: 'write', risk: 'low' };
      const built = buildRegistry(doc, new Map());
      expect(built.tools.find((t) => t.operationId === 'WidgetsController_test_v1')).toMatchObject({
        access: 'write',
        risk: 'low',
        confirm: 'confirm',
        phase: 'AI-3',
        enabled: false,
      });
    } finally {
      delete overrides.WidgetsController_create_v1;
      delete overrides.WidgetsController_test_v1;
    }
  });

  it('the created policy is row ref r<seq>.1 (refField policy.id)', () => {
    expect(findTool('policy_management_create')!.display.refField).toBe('policy.id');
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
      { 'AI-1': 174, 'AI-2': 35, 'AI-3': 47, 'AI-R': 0, 'AI-4': 66, 'AI-5': 26, 'AI-6': 0 },
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
      available: true,
      unavailableReason: null,
    });
    expect(describeTool(findTool('archive_retention_create')!)).toMatchObject({
      access: 'write',
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

describe('native tools (step AI-R D1)', () => {
  const generate = findTool('report_generate')!;
  const send = findTool('report_send_email')!;

  it('are exactly report_generate and report_send_email with the design D1 records', () => {
    expect(NATIVE_TOOLS.map((t) => t.name)).toEqual(['report_generate', 'report_send_email']);
    expect(ALL_TOOLS).toEqual([...OPERATION_TOOLS, ...NATIVE_TOOLS]);
    expect(generate).toMatchObject({
      operationId: 'AssistantNative_reportGenerate',
      method: 'POST',
      pathTemplate: 'native:report_generate',
      native: true,
      module: 'reports',
      phase: 'AI-R',
      access: 'read',
      risk: 'read_audited',
      confirm: 'none',
      requirement: { mode: 'all', permissions: ['report:read'] },
      enabled: true,
      status: 'IMPLEMENTED',
      display: { title: 'Generate security report' },
      untrustedFields: [],
      bind: {},
      portalRoute: null,
      testedBy: 'apps/api/integration/assistant-reports.test.ts',
    });
    expect(send).toMatchObject({
      operationId: 'AssistantNative_reportSendEmail',
      method: 'POST',
      pathTemplate: 'native:report_send_email',
      native: true,
      module: 'reports',
      phase: 'AI-R',
      access: 'write',
      risk: 'medium',
      confirm: 'confirm+impact',
      requirement: { mode: 'all', permissions: ['report:read'] },
      enabled: true,
      status: 'IMPLEMENTED',
      display: { title: 'Email security report' },
      untrustedFields: [],
      bind: {},
      portalRoute: '/assistant',
      testedBy: 'apps/api/integration/assistant-report-emails.test.ts',
    });
    for (const tool of NATIVE_TOOLS) {
      expect(isNativeTool(tool)).toBe(true);
      expect(tool.operationId).toMatch(/^AssistantNative_[A-Za-z]+$/);
      expect(OPENAPI_IDS.has(tool.operationId)).toBe(false);
      expect(tool.pathTemplate.startsWith('native:')).toBe(true);
      expect(tool.inputSchema.additionalProperties).toBe(false);
      expect([tool.pathParams, tool.queryParams, tool.hasBody]).toEqual([[], [], false]);
      expect(findOperation(tool.operationId)).toBe(tool);
      expect(findTool(tool.name)).toBe(tool);
      expect(() => compileValidator(tool)).not.toThrow();
    }
    expect(OPERATION_TOOLS.some(isNativeTool)).toBe(false);
    expect(new Set(ALL_TOOLS.map((t) => t.name)).size).toBe(ALL_TOOLS.length);
    expect(confirmationSpecOf('AssistantNative_reportSendEmail')?.native).toBe('report_send_email');
    expect(confirmationSpecOf('AssistantNative_reportGenerate')).toBeUndefined();
  });

  it('are in the pre-filter view, the catalogue index and describe_tool', () => {
    const names = enabledTools(['report:read'], false).map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(['report_generate', 'report_send_email']));
    expect(enabledTools(['policy:read'], false).some((t) => t.native)).toBe(false);
    expect(toolSignature(generate)).toBe(
      'report_generate(range?: 24h|7d|30d, from?, to?, sections?) - Generate a security report (HTML dashboard) for a period',
    );
    expect(toolSignature(send)).toBe(
      'report_send_email(reportId?, to?) - Email a generated security report',
    );
    const index = renderCatalogueIndex(enabledTools(['report:read'], false));
    expect(index).toContain('\nreport_generate(');
    expect(index).toContain('\nreport_send_email(');
    expect(describeTool(send)).toMatchObject({
      name: 'report_send_email',
      access: 'write',
      risk: 'medium',
      available: true,
      inputSchema: send.inputSchema,
    });
  });

  it('validate arguments strictly (Ajv)', () => {
    const g = compileValidator(generate);
    expect(g({}).ok).toBe(true);
    expect(g({ range: '24h', sections: ['summary', 'ato'] }).ok).toBe(true);
    expect(g({ from: '2026-11-01T00:00:00Z', to: '2026-11-08T00:00:00Z' }).ok).toBe(true);
    for (const bad of [
      { range: '90d' },
      { from: '2026-11-01T00:00:00Z' },
      { to: '2026-11-01T00:00:00Z' },
      { from: 'yesterday', to: '2026-11-01T00:00:00Z' },
      { sections: [] },
      { sections: ['traffic', 'traffic'] },
      { sections: ['top_senders'] },
      { format: 'pdf' },
    ])
      expect(g(bad).ok, JSON.stringify(bad)).toBe(false);
    const s = compileValidator(send);
    expect(s({}).ok).toBe(true);
    expect(s({ reportId: '@r3.1', to: 'ada@example.test' }).ok).toBe(true);
    expect(s({ reportId: '0193aaaa-0000-7000-8000-000000000040' }).ok).toBe(true);
    for (const bad of [
      { reportId: 'r3.1' },
      { reportId: '@r3' },
      { to: 'Ada <ada@example.test>' },
      { to: 'ada@example.test\r\nBcc: x@example.test' },
      { to: 'ada@example.test,bob@example.test' },
      { to: 'ada@example.test bob@example.test' },
      { to: 'jürgen@example.test' },
      { to: `${'a'.repeat(250)}@x.test` },
      { to: 'ada@example.test', cc: 'bob@example.test' },
    ])
      expect(s(bad).ok, JSON.stringify(bad)).toBe(false);
  });

  it('consistency rules for native records (synthetic breaks)', () => {
    const issues = (
      natives: OperationTool[],
      specs?: Parameters<typeof registryConsistencyIssues>[1],
    ) =>
      registryConsistencyIssues([...OPERATION_TOOLS, ...natives], {
        openApiOperationIds: OPENAPI_IDS,
        ...specs,
      });
    expect(issues([...NATIVE_TOOLS])).toEqual([]);
    expect(issues([send, { ...generate, operationId: 'ReportsController_traffic_v1' }])).toEqual(
      expect.arrayContaining([
        'report_generate: native operation id must match ^AssistantNative_[A-Za-z]+$',
        'report_generate: native operation id ReportsController_traffic_v1 exists in OpenAPI',
        'ReportsController_traffic_v1: duplicate operation id',
      ]),
    );
    expect(issues([send, { ...generate, pathTemplate: '/api/v1/reports/generate' }])).toEqual([
      'report_generate: native path template must start with native:',
    ]);
    expect(issues([send, { ...generate, testedBy: null }])).toEqual([
      'report_generate: native tool without testedBy',
    ]);
    expect(issues([send, { ...generate, name: 'reports_traffic' }])).toEqual([
      'reports_traffic: duplicate tool name',
    ]);
    expect(issues([send, { ...generate, queryParams: ['range'] }])).toEqual([
      'report_generate: a native tool has no path, query or body parameters',
    ]);
    expect(
      issues([
        send,
        {
          ...generate,
          inputSchema: {
            type: 'object',
            properties: { apiToken: { type: 'string' } },
            additionalProperties: true,
          },
        },
      ]),
    ).toEqual([
      'report_generate: native input schema must set additionalProperties: false',
      'report_generate: input property apiToken matches the credential-key pattern',
    ]);
    const plainSpec = CONFIRMATION_SPECS_WITHOUT_NATIVE();
    expect(issues([...NATIVE_TOOLS], { specs: plainSpec })).toEqual([
      'report_send_email: enabled native write without a native confirmation spec',
    ]);
    // A generated tool may not borrow the native markers.
    const traffic = findTool('reports_traffic')!;
    expect(
      registryConsistencyIssues(
        ALL_TOOLS.map((t) =>
          t.name === 'reports_traffic' ? { ...traffic, native: true as const } : t,
        ),
      ),
    ).toEqual(
      expect.arrayContaining([
        'reports_traffic: native operation id must match ^AssistantNative_[A-Za-z]+$',
        'reports_traffic: native path template must start with native:',
      ]),
    );
    expect(
      registryConsistencyIssues(
        ALL_TOOLS.map((t) =>
          t.name === 'reports_traffic' ? { ...traffic, pathTemplate: 'native:reports_traffic' } : t,
        ),
      ),
    ).toEqual(['reports_traffic: only native tools may use native ids or native: paths']);
  });

  it('§4.4 totals: 349 operation tools, 2 native tools, 259 enabled (180 reads, 79 writes)', () => {
    if (OPERATION_TOOLS.length !== 349) return; // later steps add tools; the AI-4 totals follow
    const enabled = ALL_TOOLS.filter((t) => t.enabled);
    expect(OPERATION_TOOLS).toHaveLength(349);
    expect(NATIVE_TOOLS).toHaveLength(2);
    // Not-applicable operations are derived from the document (step AI-R adds one assistant route).
    expect(NOT_APPLICABLE_OPERATIONS).toHaveLength(operations.length - OPERATION_TOOLS.length);
    expect(enabled).toHaveLength(259);
    expect(enabled.filter((t) => t.access === 'read')).toHaveLength(180);
    expect(enabled.filter((t) => t.access === 'write')).toHaveLength(79);
    expect(ALL_TOOLS.filter((t) => t.enabled && t.phase === 'AI-R').map((t) => t.name)).toEqual([
      'report_generate',
      'report_send_email',
    ]);
    expect(ALL_TOOLS.some((t) => t.enabled && phase(t.phase) > phase('AI-R'))).toBe(false);
  });

  it('AI-4 totals (design 32 D1): 427 operations, 353 operation tools (327 enabled), 329 enabled tools (186 reads, 143 writes)', () => {
    if (operations.length !== 427) return; // later steps add operations; the rules above still hold
    const count = (pred: (t: OperationTool) => boolean) => OPERATION_TOOLS.filter(pred).length;
    const enabled = ALL_TOOLS.filter((t) => t.enabled);
    expect(OPERATION_TOOLS).toHaveLength(353);
    expect(NATIVE_TOOLS).toHaveLength(2);
    expect(NOT_APPLICABLE_OPERATIONS).toHaveLength(74);
    expect(count((t) => t.enabled)).toBe(327);
    expect(enabled).toHaveLength(329);
    expect(enabled.filter((t) => t.access === 'read')).toHaveLength(186);
    expect(enabled.filter((t) => t.access === 'write')).toHaveLength(143);
    expect(count((t) => t.status === 'MISSING')).toBe(26);
    expect(count((t) => t.status === 'MISSING' && t.phase !== 'AI-5')).toBe(0);
    expect(Object.fromEntries(PROGRAM_PHASES.map((p) => [p, count((t) => t.phase === p)]))).toEqual(
      { 'AI-1': 174, 'AI-2': 35, 'AI-3': 48, 'AI-R': 0, 'AI-4': 70, 'AI-5': 26, 'AI-6': 0 },
    );
    // AI-4: 66 planned operations (64 writes, 2 side-effect-free reads) + the 4 new reads.
    const ai4 = OPERATION_TOOLS.filter((t) => t.phase === 'AI-4');
    expect(ai4.every((t) => t.enabled && t.status === 'IMPLEMENTED')).toBe(true);
    expect(ai4.filter((t) => t.access === 'write')).toHaveLength(64);
    expect(
      ai4
        .filter((t) => t.access === 'read')
        .map((t) => t.name)
        .sort(),
    ).toEqual([
      'bec_feedback_get_suppression',
      'bec_trusted_senders_get',
      'dlp_exceptions_get',
      'dlp_patterns_test',
      'risk_dry_run_dry_run',
      'threat_indicators_get',
    ]);
    const writesByRisk = Object.fromEntries(
      ['low', 'medium', 'high'].map((r) => [
        r,
        ai4.filter((t) => t.access === 'write' && t.risk === r).length,
      ]),
    );
    expect(writesByRisk).toEqual({ low: 23, medium: 11, high: 30 });
    expect(ALL_TOOLS.some((t) => t.enabled && phase(t.phase) > phase('AI-4'))).toBe(false);
  });

  it('are part of the REGISTRY_VERSION hash input and of the capability matrix', () => {
    const built = buildRegistry(openapi, readPortalUsage());
    const hash = (input: unknown) =>
      createHash('sha256').update(JSON.stringify(input)).digest('hex').slice(0, 16);
    expect(built.version).toBe(REGISTRY_VERSION);
    expect(
      hash({ tools: built.tools, notApplicable: built.notApplicable, native: NATIVE_TOOLS }),
    ).toBe(REGISTRY_VERSION);
    expect(hash({ tools: built.tools, notApplicable: built.notApplicable })).not.toBe(
      REGISTRY_VERSION,
    );
    const matrix = readFileSync(
      join(REPO, 'docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md'),
      'utf8',
    );
    expect(matrix).toContain('## Native assistant tools');
    expect(matrix).toMatch(
      /\| `report_generate` +\| `AssistantNative_reportGenerate` +\| `native:report_generate` +\| `report:read` +\| R +\| read_audited +\| none +\| IMPLEMENTED +\| AI-R +\| - +\| `apps\/api\/integration\/assistant-reports\.test\.ts` +\|/,
    );
    expect(matrix).toMatch(
      /\| `report_send_email` .*\| W +\| medium +\| confirm\+impact +\| IMPLEMENTED +\| AI-R +\| \/assistant +\|/,
    );
  });
});

function CONFIRMATION_SPECS_WITHOUT_NATIVE(): ConfirmationSpec[] {
  return CONFIRMATION_SPECS.map((spec) => {
    if (!spec.native) return spec;
    const { native: _native, ...rest } = spec;
    return rest;
  });
}
