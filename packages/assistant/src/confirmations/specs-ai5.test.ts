import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { readOpenApi, readPortalUsage } from '../../scripts/generate-registry';
import {
  buildInputSchema,
  buildRegistry,
  omitInputs,
  type OpenApiOperation,
} from '../registry/build';
import { argumentSchema, registryConsistencyIssues } from '../registry/consistency';
import {
  AI5_WRITES_TESTED_BY,
  CREDENTIAL_FIELD_EXCEPTIONS,
  OPERATION_OVERRIDES,
} from '../registry/manifest';
import {
  ALL_TOOLS,
  compileValidator,
  describeTool,
  findTool,
  toolSignature,
} from '../registry/registry';
import type { OperationTool } from '../registry/types';
import { stateDigest } from './digest';
import {
  CONFIRMATION_SPECS,
  IMPACT_PREVIEW_KEY,
  IMPACT_PREVIEW_TOOLS,
  IMPACT_TOKEN_PLACEHOLDER,
  MAIL_FLOW_PREVIEW_STATE,
  buildSnapshot,
  confirmationSpecOf,
  impactPreviewArgs,
  withCasPlaceholder,
  withImpactPreview,
  withImpactTokenPlaceholder,
  withInjectedImpactToken,
  type ConfirmationSpec,
  type SinglePrecondition,
} from './specs';

const CONNECTION = '0193aaaa-0000-7000-8000-000000000501';
const DOMAIN = '0193aaaa-0000-7000-8000-000000000502';
const spec = (operationId: string): ConfirmationSpec => confirmationSpecOf(operationId)!;
const single = (operationId: string) => spec(operationId).precondition as SinglePrecondition;
const tool = (name: string): OperationTool => findTool(name)!;
const patchSpec = (operationId: string, change: Partial<ConfirmationSpec>) =>
  CONFIRMATION_SPECS.map((s) => (s.operationId === operationId ? { ...s, ...change } : s));

describe('AI-5 confirmation specs (design 33 D6)', () => {
  it('one spec per AI-5 write', () => {
    const ai5 = CONFIRMATION_SPECS.filter((s) => s.operationId in AI5_WRITES_TESTED_BY);
    expect(ai5.map((s) => s.operationId).sort()).toEqual(Object.keys(AI5_WRITES_TESTED_BY).sort());
  });

  it('names the design D6 preconditions, selects, state fields and CAS injections', () => {
    const table = Object.fromEntries(
      CONFIRMATION_SPECS.filter((s) => s.operationId in AI5_WRITES_TESTED_BY).map((s) => {
        const pre = s.precondition;
        if (pre?.kind !== 'single') return [s.operationId, pre];
        return [
          s.operationId,
          {
            read: `${pre.tool} ${JSON.stringify(pre.params)}${pre.select ? ` select ${pre.select.array}.${pre.select.field}=${pre.select.arg}` : ''}`,
            state: pre.stateFields.join(','),
            cas: s.inject ? `${s.inject.in}.${s.inject.field}>=${s.inject.min}` : null,
            impactToken: s.impactToken
              ? `${s.impactToken.previewTool} ${JSON.stringify(s.impactToken.change)}`
              : null,
          },
        ];
      }),
    );
    expect(table).toEqual({
      ArchiveRetentionController_create_v1: null,
      ArchiveRetentionController_update_v1: {
        read: 'archive_retention_get {"policyId":"policyId"}',
        state: 'rowVersion,retentionDays,onExpiry,priority,criteria,isDefault',
        cas: 'body.expectedRowVersion>=1',
        impactToken: null,
      },
      ArchiveRetentionController_delete_v1: {
        read: 'archive_retention_get {"policyId":"policyId"}',
        state: 'rowVersion,isDefault',
        cas: null,
        impactToken: null,
      },
      ArchiveAdminController_retry_v1: {
        read: 'archive_admin_capture_issue {"messageId":"messageId"}',
        state: 'status,attempts',
        cas: null,
        impactToken: null,
      },
      ArchiveAdminController_update_v1: {
        read: 'archive_admin_get {}',
        state: 'rowVersion,enabled,immutability,defaultRetentionPolicyId',
        cas: 'body.expectedRowVersion>=0',
        impactToken: null,
      },
      JournalingController_update_v1: {
        read: 'journaling_get {}',
        state: 'rowVersion,enabled',
        cas: 'body.expectedRowVersion>=0',
        impactToken: null,
      },
      IntakeSourcesController_update_v1: {
        read: 'intake_sources_get {"sourceId":"sourceId"}',
        state: 'rowVersion,status,maxMessageBytes',
        cas: 'body.expectedRowVersion>=1',
        impactToken: null,
      },
      IntakeSourcesController_disable_v1: {
        read: 'intake_sources_get {"sourceId":"sourceId"}',
        state: 'status',
        cas: null,
        impactToken: null,
      },
      IntakeSourcesController_attest_v1: {
        read: 'intake_sources_get {"sourceId":"sourceId"}',
        state: 'status',
        cas: null,
        impactToken: null,
      },
      EdiscoveryCasesController_create_v1: null,
      EdiscoveryCasesController_update_v1: {
        read: 'ediscovery_cases_get {"caseId":"caseId"}',
        state: 'rowVersion,status',
        cas: 'body.expectedRowVersion>=1',
        impactToken: null,
      },
      EdiscoveryCasesController_close_v1: {
        read: 'ediscovery_cases_get {"caseId":"caseId"}',
        state: 'status,counts.activeHolds',
        cas: null,
        impactToken: null,
      },
      EdiscoveryCasesController_createHold_v1: {
        read: 'ediscovery_cases_get {"caseId":"caseId"}',
        state: 'status',
        cas: null,
        impactToken: null,
      },
      EdiscoverySearchesController_create_v1: {
        read: 'ediscovery_cases_get {"caseId":"caseId"}',
        state: 'status',
        cas: null,
        impactToken: null,
      },
      EdiscoverySearchesController_review_v1: {
        read: 'ediscovery_searches_get {"caseId":"caseId","searchId":"searchId"}',
        state: 'status',
        cas: null,
        impactToken: null,
      },
      EdiscoveryExportsController_create_v1: {
        read: 'ediscovery_searches_get {"caseId":"caseId","searchId":"body.searchId"}',
        state: 'status,hitCount',
        cas: null,
        impactToken: null,
      },
      ProviderConnectionsController_create_v1: null,
      ProviderConnectionsController_update_v1: {
        read: 'provider_connections_get {"id":"id"}',
        state: 'rowVersion',
        cas: 'body.rowVersion>=1',
        impactToken: null,
      },
      ProviderConnectionsController_disconnect_v1: {
        read: 'provider_connections_get {"id":"id"}',
        state: 'rowVersion,status,preview.changeSet,preview.warnings',
        cas: null,
        impactToken: 'provider_mail_flow_preview {"constant":{"kind":"disable"}}',
      },
      ProviderAttestationsController_record_v1: {
        read: 'provider_connections_get {"id":"id"}',
        state: 'status',
        cas: null,
        impactToken: null,
      },
      ProviderDomainsController_replace_v1: {
        read: 'provider_connections_get {"id":"id"}',
        state: 'rowVersion,status',
        cas: null,
        impactToken: null,
      },
      ProviderGrantsController_revoke_v1: {
        read: 'provider_connections_get {"id":"id"} select grants.profile=profile',
        state: 'status',
        cas: null,
        impactToken: null,
      },
      ProviderGrantsController_verify_v1: {
        read: 'provider_connections_get {"id":"id"} select grants.profile=profile',
        state: 'status',
        cas: null,
        impactToken: null,
      },
      ProviderHealthController_checkNow_v1: {
        read: 'provider_connections_get {"id":"id"}',
        state: 'status',
        cas: null,
        impactToken: null,
      },
      ProviderMailFlowController_apply_v1: {
        read: 'provider_connections_get {"id":"id"}',
        state: 'rowVersion,status,preview.changeSet,preview.warnings',
        cas: null,
        impactToken: 'provider_mail_flow_preview {"from":"body.change"}',
      },
    });
    expect(spec('ProviderGrantsController_revoke_v1').precondition).toMatchObject({
      select: { required: true },
    });
  });

  it('state fields are stable: no worker counters, health timestamps or impact tokens', () => {
    for (const s of CONFIRMATION_SPECS.filter((x) => x.operationId in AI5_WRITES_TESTED_BY)) {
      const pre = s.precondition;
      if (pre?.kind !== 'single') continue;
      for (const field of pre.stateFields) {
        expect(field, s.operationId).not.toMatch(
          /counters|health|lastAccepted|lastRefused|nextCheckAt|impactToken|expiresAt/,
        );
      }
    }
  });

  it('intake_sources_get preconditions never pass reveal (D7)', () => {
    for (const s of CONFIRMATION_SPECS) {
      const pre = s.precondition;
      if (pre?.kind === 'single' && pre.tool === 'intake_sources_get')
        expect(Object.keys(pre.params), s.operationId).toEqual(['sourceId']);
    }
    for (const id of [
      'IntakeSourcesController_update_v1',
      'IntakeSourcesController_disable_v1',
      'IntakeSourcesController_attest_v1',
    ])
      expect(single(id).displayFields ?? [], id).not.toContain('address');
  });
});

describe('server-filled impact tokens (design 33 D5)', () => {
  const apply = spec('ProviderMailFlowController_apply_v1');
  const disconnect = spec('ProviderConnectionsController_disconnect_v1');
  const applyArgs = { id: CONNECTION, body: { change: { kind: 'inbound', domainIds: [DOMAIN] } } };

  it('IMPACT_PREVIEW_TOOLS lists exactly provider_mail_flow_preview, an enabled side-effect-free POST read', () => {
    expect(IMPACT_PREVIEW_TOOLS).toEqual(['provider_mail_flow_preview']);
    expect(tool('provider_mail_flow_preview')).toMatchObject({
      access: 'read',
      method: 'POST',
      enabled: true,
      pathParams: ['id'],
    });
    expect(IMPACT_PREVIEW_KEY).toBe('preview');
    expect(
      CONFIRMATION_SPECS.filter((s) => s.impactToken)
        .map((s) => s.operationId)
        .sort(),
    ).toEqual([
      'ProviderConnectionsController_disconnect_v1',
      'ProviderMailFlowController_apply_v1',
    ]);
  });

  it('the placeholder fills impactToken and confirm only when absent and satisfies the schema', () => {
    const placed = withImpactTokenPlaceholder(applyArgs, apply);
    expect(placed).toEqual({
      id: CONNECTION,
      body: { ...applyArgs.body, impactToken: IMPACT_TOKEN_PLACEHOLDER, confirm: true },
    });
    expect(compileValidator(tool('provider_mail_flow_apply'))(placed)).toEqual({ ok: true });
    // The model's arguments are not mutated; present values are kept (the injection replaces them).
    expect(applyArgs.body).not.toHaveProperty('impactToken');
    const modelToken = {
      id: CONNECTION,
      body: { ...applyArgs.body, impactToken: 'x', confirm: true },
    };
    expect(withImpactTokenPlaceholder(modelToken, apply)).toEqual(modelToken);
    // Disconnect: the model passes only `id`; the placeholder creates the required body.
    const bare = withImpactTokenPlaceholder({ id: CONNECTION }, disconnect);
    expect(bare).toEqual({
      id: CONNECTION,
      body: { impactToken: IMPACT_TOKEN_PLACEHOLDER, confirm: true },
    });
    expect(compileValidator(tool('provider_connections_disconnect'))(bare)).toEqual({ ok: true });
    expect(compileValidator(tool('provider_connections_disconnect'))({ id: CONNECTION }).ok).toBe(
      false,
    );
    // Specs without impactToken: a copy, unchanged.
    const other = { id: CONNECTION, body: { displayName: 'x', rowVersion: 1 } };
    expect(
      withImpactTokenPlaceholder(other, spec('ProviderConnectionsController_update_v1')),
    ).toEqual(other);
  });

  it('builds the preview arguments from the write (body.change, or the constant change)', () => {
    const previewArgs = impactPreviewArgs(apply.impactToken!, applyArgs);
    expect(previewArgs).toEqual({ id: CONNECTION, body: { change: applyArgs.body.change } });
    expect(compileValidator(tool('provider_mail_flow_preview'))(previewArgs)).toEqual({ ok: true });
    const disable = impactPreviewArgs(disconnect.impactToken!, { id: CONNECTION });
    expect(disable).toEqual({ id: CONNECTION, body: { change: { kind: 'disable' } } });
    expect(compileValidator(tool('provider_mail_flow_preview'))(disable)).toEqual({ ok: true });
    // A copy: changing it never changes the spec's constant or the write's arguments.
    (disable.body as { change: Record<string, unknown> }).change.kind = 'x';
    expect(disconnect.impactToken!.change).toEqual({ constant: { kind: 'disable' } });
    expect(impactPreviewArgs(apply.impactToken!, { id: CONNECTION })).toEqual({
      id: CONNECTION,
      body: {},
    });
  });

  it('injects the preview token and confirm, always overriding the model; refuses a missing token', () => {
    const preview = { changeSet: { kind: 'inbound' }, impactToken: 'server-token', warnings: [] };
    const modelArgs = {
      id: CONNECTION,
      body: { ...applyArgs.body, impactToken: 'model-token', confirm: true },
    };
    const injected = withInjectedImpactToken(modelArgs, preview);
    expect(injected).toEqual({
      ok: true,
      args: {
        id: CONNECTION,
        body: { ...applyArgs.body, impactToken: 'server-token', confirm: true },
      },
    });
    expect(modelArgs.body.impactToken).toBe('model-token');
    expect(withInjectedImpactToken({ id: CONNECTION }, preview)).toEqual({
      ok: true,
      args: { id: CONNECTION, body: { impactToken: 'server-token', confirm: true } },
    });
    for (const bad of [
      {},
      null,
      'token',
      { impactToken: 42 },
      { impactToken: '' },
      { impactToken: 'x'.repeat(129) },
    ])
      expect(withInjectedImpactToken(modelArgs, bad), JSON.stringify(bad)).toEqual({
        ok: false,
        reason: 'impact_token_missing',
      });
  });

  it('the preview is merged under `preview`: digest and snapshot bind the change set, never the token', () => {
    const pre = single('ProviderMailFlowController_apply_v1');
    const read = {
      id: CONNECTION,
      displayName: 'C',
      provider: 'microsoft_365',
      status: 'active',
      rowVersion: 3,
    };
    const preview = (host: string) => ({
      changeSet: {
        kind: 'inbound',
        domains: [
          {
            domainId: DOMAIN,
            name: 'contoso.example',
            current: { provider: null, servers: [] },
            proposed: {
              provider: 'microsoft_365',
              servers: [{ host, port: 25, priority: 0, tlsMode: 'required' }],
            },
            changed: true,
          },
        ],
        connector: null,
        connection: [],
        grantsRevoked: 0,
      },
      impactToken: 'token-a',
      warnings: [],
    });
    const a = withImpactPreview(read, preview('a.example'));
    expect(a.preview).toEqual(preview('a.example'));
    expect(withImpactPreview(null, { x: 1 })).toEqual({ preview: { x: 1 } });
    const b = withImpactPreview(read, { ...preview('a.example'), impactToken: 'token-b' });
    const c = withImpactPreview(read, preview('b.example'));
    // A new token alone does not change the state (it is not a state field); a new change set does.
    expect(stateDigest(a, pre.stateFields)).toBe(stateDigest(b, pre.stateFields));
    expect(stateDigest(a, pre.stateFields)).not.toBe(stateDigest(c, pre.stateFields));
    expect(MAIL_FLOW_PREVIEW_STATE).toEqual(['preview.changeSet', 'preview.warnings']);
    const snapshot = buildSnapshot(a, pre);
    expect(JSON.stringify(snapshot)).not.toContain('token-a');
    expect(snapshot['preview.changeSet.kind']).toBe('inbound');
    expect(snapshot['preview.changeSet.domains[].name']).toBe('["contoso.example"]');
  });

  it('the CAS placeholder and the impact placeholder compose (executor order)', () => {
    const update = spec('ProviderConnectionsController_update_v1');
    expect(withCasPlaceholder({ id: CONNECTION, body: { displayName: 'x' } }, update)).toEqual({
      id: CONNECTION,
      body: { displayName: 'x', rowVersion: 1 },
    });
    expect(
      withCasPlaceholder(withImpactTokenPlaceholder({ id: CONNECTION }, disconnect), disconnect),
    ).toEqual({
      id: CONNECTION,
      body: { impactToken: IMPACT_TOKEN_PLACEHOLDER, confirm: true },
    });
  });
});

describe('AI-5 registry consistency rules (design 33 §4.3, synthetic breaks)', () => {
  const tools = ALL_TOOLS;

  it('the generated registry has no issue', () => {
    expect(registryConsistencyIssues(tools)).toEqual([]);
  });

  it('a read-relative escalation needs its field among the state fields of a single precondition', () => {
    const pre = single('ArchiveRetentionController_update_v1');
    expect(
      registryConsistencyIssues(tools, {
        specs: patchSpec('ArchiveRetentionController_update_v1', {
          precondition: { ...pre, stateFields: ['rowVersion'] },
        }),
      }),
    ).toEqual([
      'archive_retention_update: read-relative escalation field retentionDays must be a state field of a single precondition',
      'archive_retention_update: read-relative escalation field onExpiry must be a state field of a single precondition',
      'archive_retention_update: read-relative escalation field criteria must be a state field of a single precondition',
      'archive_retention_update: read-relative escalation field priority must be a state field of a single precondition',
    ]);
    expect(
      registryConsistencyIssues(tools, {
        specs: patchSpec('ArchiveRetentionController_update_v1', {
          escalate: [
            {
              when: { below: { path: 'body.missing', field: 'retentionDays' } },
              risk: 'high',
              warning: 'w',
            },
          ],
        }),
      }),
    ).toEqual(['archive_retention_update: escalation reads the missing argument body.missing']);
    // Without a precondition at all.
    expect(
      registryConsistencyIssues(tools, {
        specs: patchSpec('ArchiveRetentionController_create_v1', {
          escalate: [
            {
              when: { differs: { path: 'body.priority', field: 'priority' } },
              risk: 'high',
              warning: 'w',
            },
          ],
        }),
      }),
    ).toEqual([
      'archive_retention_create: read-relative escalation field priority must be a state field of a single precondition',
    ]);
  });

  it('impactToken: single precondition, allow-listed enabled preview, exact params, body.impactToken and body.confirm', () => {
    const injection = spec('ProviderMailFlowController_apply_v1').impactToken!;
    expect(
      registryConsistencyIssues(tools, {
        specs: patchSpec('ProviderMailFlowController_apply_v1', { precondition: null }),
      }),
    ).toEqual(['provider_mail_flow_apply: impactToken needs a single precondition']);
    expect(
      registryConsistencyIssues(tools, {
        specs: patchSpec('ProviderMailFlowController_apply_v1', {
          impactToken: {
            ...injection,
            previewTool: 'provider_connections_get' as 'provider_mail_flow_preview',
          },
        }),
      }),
    ).toEqual([
      'provider_mail_flow_apply: impactToken preview provider_connections_get is not allow-listed',
      'provider_mail_flow_apply: impactToken preview provider_connections_get takes no body.change',
    ]);
    expect(
      registryConsistencyIssues(tools, {
        specs: patchSpec('ProviderMailFlowController_apply_v1', {
          impactToken: { ...injection, params: { connectionId: 'id' } },
        }),
      }),
    ).toEqual([
      'provider_mail_flow_apply: impactToken params [connectionId] must map exactly the path parameters [id] of provider_mail_flow_preview',
    ]);
    expect(
      registryConsistencyIssues(tools, {
        specs: patchSpec('ProviderMailFlowController_apply_v1', {
          impactToken: { ...injection, params: { id: 'body.id' }, change: { from: 'body.change' } },
        }),
      }),
    ).toEqual(['provider_mail_flow_apply: impactToken param id maps the missing argument body.id']);
    // A write without body.impactToken / body.confirm cannot take a server-filled token.
    expect(
      registryConsistencyIssues(tools, {
        specs: patchSpec('ProviderConnectionsController_update_v1', {
          impactToken: { ...injection, change: { from: 'body.change' } },
        }),
      }),
    ).toEqual([
      'provider_connections_update: impactToken change reads the missing argument body.change',
      "provider_connections_update: impactToken needs body.impactToken in the write's input schema",
      "provider_connections_update: impactToken needs body.confirm in the write's input schema",
    ]);
  });

  it('body.impactToken passes the credential-key input rule only because it is server-filled', () => {
    const withoutToken = CONFIRMATION_SPECS.map((s) => {
      if (s.operationId !== 'ProviderMailFlowController_apply_v1') return s;
      const { impactToken: _dropped, ...rest } = s;
      return rest;
    });
    expect(registryConsistencyIssues(tools, { specs: withoutToken })).toEqual([
      'provider_mail_flow_apply: input property body.impactToken matches the credential-key pattern',
    ]);
  });

  it('no state or display field holds a credential-pattern key (named exceptions only)', () => {
    const pre = single('ProviderMailFlowController_apply_v1');
    expect(
      registryConsistencyIssues(tools, {
        specs: patchSpec('ProviderMailFlowController_apply_v1', {
          precondition: {
            ...pre,
            stateFields: [...pre.stateFields, 'preview.impactToken'],
            displayFields: [...(pre.displayFields ?? []), 'grants[].credentialFingerprint'],
          },
        }),
      }),
    ).toEqual([
      'provider_mail_flow_apply: state or display field preview.impactToken matches the credential-key pattern',
    ]);
    const retry = single('ArchiveAdminController_retry_v1');
    expect(retry.displayFields).toContain('code');
    expect(CREDENTIAL_FIELD_EXCEPTIONS.ArchiveAdminController_retry_v1).toHaveProperty('code');
    expect(
      registryConsistencyIssues(tools, {
        specs: patchSpec('ArchiveRetentionController_delete_v1', {
          precondition: {
            ...single('ArchiveRetentionController_delete_v1'),
            displayFields: ['code'],
          },
        }),
      }),
    ).toEqual([
      'archive_retention_delete: state or display field code matches the credential-key pattern',
    ]);
  });

  it('an omitted input must be gone from the input schema', () => {
    const intake = tool('intake_sources_get');
    const reverted = tools.map((t) =>
      t.name === 'intake_sources_get'
        ? {
            ...t,
            queryParams: ['reveal'],
            inputSchema: {
              ...t.inputSchema,
              properties: {
                ...(t.inputSchema.properties as object),
                reveal: { type: 'string', enum: ['true', 'false'] },
              },
            },
          }
        : t,
    );
    expect(intake.queryParams).toEqual([]);
    expect(registryConsistencyIssues(reverted)).toEqual([
      'intake_sources_get: the omitted input reveal is still in the input schema',
    ]);
  });
});

describe('omitInputs (design 33 D7)', () => {
  const openapi = readOpenApi();
  const operationOf = (operationId: string): OpenApiOperation => {
    for (const item of Object.values(openapi.paths))
      for (const op of Object.values(item)) if (op?.operationId === operationId) return op;
    throw new Error(operationId);
  };
  const components = openapi.components?.schemas ?? {};

  it('the manifest omits reveal, body.subjectEmail and (step API-1 D15) body.protectionMode', () => {
    expect(
      Object.fromEntries(
        Object.entries(OPERATION_OVERRIDES)
          .filter(([, o]) => o.omitInputs)
          .map(([id, o]) => [id, o.omitInputs]),
      ),
    ).toEqual({
      IntakeSourcesController_get_v1: ['reveal'],
      ProviderGrantsController_verify_v1: ['body.subjectEmail'],
      DomainsController_create_v1: ['body.protectionMode'],
    });
  });

  it('removes a query parameter from properties and queryParams; describe_tool and the catalogue line never show it', () => {
    const intake = tool('intake_sources_get');
    expect(Object.keys(intake.inputSchema.properties as object)).toEqual(['sourceId']);
    expect(intake.queryParams).toEqual([]);
    expect(intake.inputSchema.required).toEqual(['sourceId']);
    expect(toolSignature(intake)).not.toContain('reveal');
    expect(JSON.stringify(describeTool(intake).inputSchema)).not.toContain('reveal');
    // The description no longer offers `?reveal=true` (description override).
    expect(intake.description).not.toContain('reveal');
    expect(intake.description).toContain('always masked');
    // A forced `reveal` is refused by the strict schema (the executor's denied_schema).
    const validate = compileValidator(intake);
    const id = '0193aaaa-0000-7000-8000-000000000503';
    expect(validate({ sourceId: id })).toEqual({ ok: true });
    expect(validate({ sourceId: id, reveal: 'true' }).ok).toBe(false);
  });

  it('removes a body property (and keeps the body otherwise); a forced subjectEmail is refused', () => {
    const verify = tool('provider_grants_verify');
    const body = (verify.inputSchema.properties as Record<string, Record<string, unknown>>).body!;
    expect(body.properties).toEqual({});
    expect(body.required ?? []).not.toContain('subjectEmail');
    expect(argumentSchema(verify, 'body.subjectEmail')).toBeNull();
    const validate = compileValidator(verify);
    const args = { id: CONNECTION, profile: 'mail_flow', body: {} };
    expect(validate(args)).toEqual({ ok: true });
    expect(validate({ ...args, body: { subjectEmail: 'admin@example.com' } }).ok).toBe(false);
  });

  it('removes a body property from required as well (synthetic operation)', () => {
    const op: OpenApiOperation = {
      operationId: 'SyntheticController_x_v1',
      parameters: [{ name: 'q', in: 'query', required: false, schema: { type: 'string' } }],
      requestBody: {
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: { a: { type: 'string' }, b: { type: 'string' } },
              required: ['a'],
              additionalProperties: false,
            },
          },
        },
      },
    };
    const parts = buildInputSchema(op, {}, new Set());
    const out = omitInputs('SyntheticController_x_v1', parts, ['q', 'body.b']);
    expect(out.queryParams).toEqual([]);
    expect(out.inputSchema).toEqual({
      type: 'object',
      properties: {
        body: {
          type: 'object',
          properties: { a: { type: 'string' } },
          required: ['a'],
          additionalProperties: false,
        },
      },
      additionalProperties: false,
      required: ['body'],
    });
    // The input parts are not mutated.
    expect(Object.keys(parts.inputSchema.properties as object)).toEqual(['q', 'body']);
  });

  it('refuses required, path, missing and nested inputs (the generator fails)', () => {
    const parts = buildInputSchema(
      operationOf('IntakeSourcesController_get_v1'),
      components,
      new Set(),
    );
    expect(() => omitInputs('X', parts, ['sourceId'])).toThrow(/path parameter/);
    expect(() => omitInputs('X', parts, ['nope'])).toThrow(/not a query parameter/);
    expect(() => omitInputs('X', parts, ['body.x'])).toThrow(/no body/);
    const update = buildInputSchema(
      operationOf('IntakeSourcesController_update_v1'),
      components,
      new Set(),
    );
    expect(() => omitInputs('X', update, ['body.expectedRowVersion'])).toThrow(
      /required body property/,
    );
    expect(() => omitInputs('X', update, ['body.health.status'])).toThrow(
      /top-level body property/,
    );
    expect(() => omitInputs('X', update, ['body.unknown'])).toThrow(/not a body property/);
    const list = buildInputSchema(
      {
        operationId: 'S',
        parameters: [{ name: 'from', in: 'query', required: true, schema: { type: 'string' } }],
      },
      {},
      new Set(),
    );
    expect(() => omitInputs('X', list, ['from'])).toThrow(/required query parameter/);
  });

  it('the matrix row notes the omitted input; the build is deterministic', () => {
    const matrix = readFileSync(
      join(__dirname, '../../../../docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md'),
      'utf8',
    );
    expect(matrix).toContain('`intake_sources_get` (omitted: reveal)');
    expect(matrix).toContain('`provider_grants_verify` (omitted: body.subjectEmail)');
    const usage = readPortalUsage();
    expect(buildRegistry(openapi, usage).version).toBe(buildRegistry(openapi, usage).version);
  });
});
