import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { normalizeSchema, successResponseSchema, type OpenApiDocument } from '../registry/build';
import { credentialKeyPaths, registryConsistencyIssues } from '../registry/consistency';
import {
  AI2_WRITES_TESTED_BY,
  AI3_WRITES_TESTED_BY,
  AI4_WRITES_TESTED_BY,
  AI5_WRITES_TESTED_BY,
  CREDENTIAL_KEY_EXCEPTIONS,
} from '../registry/manifest';
import { ALL_TOOLS, compileValidator, findOperation, findTool } from '../registry/registry';
import type { OperationTool } from '../registry/types';
import { stateDigest } from './digest';
import {
  CONFIRMATION_SPECS,
  buildEachItem,
  buildSnapshot,
  confirmationSpecOf,
  eachReads,
  preconditionArgs,
  rowVersionOf,
  selectTarget,
  snapshotList,
  snapshotPathValue,
  targetOf,
  withCasPlaceholder,
  withInjectedCas,
  type ConfirmationSpec,
  type EachPrecondition,
  type SinglePrecondition,
} from './specs';

const spec = (operationId: string): ConfirmationSpec => confirmationSpecOf(operationId)!;
const POLICY = '0193aaaa-0000-7000-8000-000000000002';

describe('confirmation specs (D4)', () => {
  it('one spec per AI-2, AI-3, native AI-R, AI-4 and AI-5 write, every one an enabled write of the registry', () => {
    expect(CONFIRMATION_SPECS).toHaveLength(168);
    expect(Object.keys(AI4_WRITES_TESTED_BY)).toHaveLength(64);
    expect(Object.keys(AI5_WRITES_TESTED_BY)).toHaveLength(25);
    expect(CONFIRMATION_SPECS.map((s) => s.operationId).sort()).toEqual(
      [
        ...Object.keys(AI2_WRITES_TESTED_BY),
        ...Object.keys(AI3_WRITES_TESTED_BY),
        'AssistantNative_reportSendEmail',
        ...Object.keys(AI4_WRITES_TESTED_BY),
        ...Object.keys(AI5_WRITES_TESTED_BY),
      ].sort(),
    );
    expect(confirmationSpecOf('AssistantNative_reportSendEmail')).toEqual({
      operationId: 'AssistantNative_reportSendEmail',
      precondition: null,
      native: 'report_send_email',
    });
    expect(CONFIRMATION_SPECS.filter((s) => s.native).map((s) => s.operationId)).toEqual([
      'AssistantNative_reportSendEmail',
    ]);
    const enabledWrites = ALL_TOOLS.filter((t) => t.enabled && t.access === 'write');
    expect(enabledWrites.map((t) => t.operationId).sort()).toEqual(
      CONFIRMATION_SPECS.map((s) => s.operationId).sort(),
    );
    expect(confirmationSpecOf('PolicyManagementController_list_v1')).toBeUndefined();
  });

  it('the registry consistency rules hold for the generated registry', () => {
    expect(registryConsistencyIssues(ALL_TOOLS)).toEqual([]);
  });

  it('names the design D4 preconditions, state fields and CAS injections', () => {
    const table = Object.fromEntries(
      CONFIRMATION_SPECS.filter((s) => s.operationId in AI2_WRITES_TESTED_BY).map((s) => [
        findOperation(s.operationId) && (findOperation(s.operationId) as OperationTool).name,
        [
          s.precondition?.tool ?? null,
          s.precondition?.stateFields.join(',') ?? null,
          s.inject ? `${s.inject.in}.${s.inject.field}>=${s.inject.min}` : null,
          s.validateDefinition ?? null,
        ],
      ]),
    );
    expect(table).toMatchInlineSnapshot(`
      {
        "message_lifecycle_release": [
          "messages_detail",
          "status,version,lifecycleRound",
          "body.expectedVersion>=0",
          null,
        ],
        "message_lifecycle_rescan": [
          "messages_detail",
          "status,version,lifecycleRound",
          "body.expectedVersion>=0",
          null,
        ],
        "policy_management_activate": [
          "policy_management_get",
          "rowVersion,status,activeVersionNo",
          "body.expectedRowVersion>=1",
          null,
        ],
        "policy_management_create": [
          null,
          null,
          null,
          "body.definition",
        ],
        "policy_management_create_draft": [
          "policy_management_get",
          "rowVersion,status,latestVersionNo",
          null,
          "body.definition",
        ],
        "policy_management_delete_draft": [
          "policy_management_get_version",
          "rowVersion,status",
          "query.expectedRowVersion>=1",
          null,
        ],
        "policy_management_disable": [
          "policy_management_get",
          "rowVersion,status,activeVersionNo",
          "body.expectedRowVersion>=1",
          null,
        ],
        "policy_management_enable": [
          "policy_management_get",
          "rowVersion,status,activeVersionNo",
          "body.expectedRowVersion>=1",
          null,
        ],
        "policy_management_publish": [
          "policy_management_get_version",
          "rowVersion,status",
          "body.expectedRowVersion>=1",
          null,
        ],
        "policy_management_remove": [
          "policy_management_get",
          "rowVersion,status",
          "query.expectedRowVersion>=1",
          null,
        ],
        "policy_management_update": [
          "policy_management_get",
          "rowVersion,name,description,status",
          "body.expectedRowVersion>=1",
          null,
        ],
        "policy_management_update_draft": [
          "policy_management_get_version",
          "rowVersion,status",
          "body.expectedRowVersion>=1",
          "body.definition",
        ],
        "policy_settings_put": [
          "policy_settings_get",
          "rowVersion,settingsSha256",
          "body.expectedRowVersion>=0",
          null,
        ],
        "quarantine_approvals_approve": [
          "quarantine_approvals_get",
          "status",
          null,
          null,
        ],
        "quarantine_approvals_cancel": [
          "quarantine_approvals_get",
          "status",
          null,
          null,
        ],
        "quarantine_approvals_deny": [
          "quarantine_approvals_get",
          "status",
          null,
          null,
        ],
        "quarantine_entries_delete": [
          "quarantine_entries_detail",
          "rowVersion,state",
          "body.expectedRowVersion>=1",
          null,
        ],
        "quarantine_entries_manual": [
          "messages_detail",
          "status,version,lifecycleRound",
          null,
          null,
        ],
        "quarantine_entries_reject": [
          "quarantine_entries_detail",
          "rowVersion,state",
          "body.expectedRowVersion>=1",
          null,
        ],
        "quarantine_entries_release": [
          "quarantine_entries_detail",
          "rowVersion,state",
          "body.expectedRowVersion>=1",
          null,
        ],
        "quarantine_entries_request_release": [
          "quarantine_entries_detail",
          "rowVersion,state",
          null,
          null,
        ],
        "quarantine_self_put_preferences": [
          "quarantine_self_preferences",
          "digestOptOut",
          null,
          null,
        ],
        "quarantine_self_release": [
          "quarantine_self_detail",
          "rowVersion,state",
          "body.expectedRowVersion>=1",
          null,
        ],
        "quarantine_self_request_release": [
          "quarantine_self_detail",
          "rowVersion,state",
          null,
          null,
        ],
        "quarantine_tools_bulk": [
          "quarantine_entries_detail",
          "state,status,rowVersion",
          null,
          null,
        ],
        "quarantine_tools_put_settings": [
          "quarantine_tools_get_settings",
          "rowVersion",
          "body.expectedRowVersion>=0",
          null,
        ],
        "recipient_suppressions_create": [
          null,
          null,
          null,
          null,
        ],
        "recipient_suppressions_delete": [
          "recipient_suppressions_get",
          "active,expiresAt,reason",
          null,
          null,
        ],
        "saved_views_create": [
          null,
          null,
          null,
          null,
        ],
        "saved_views_remove": [
          "saved_views_get",
          "rowVersion",
          null,
          null,
        ],
        "saved_views_update": [
          "saved_views_get",
          "rowVersion,name",
          "body.expectedRowVersion>=1",
          null,
        ],
      }
    `);
  });
});

describe('registry consistency rules (synthetic breaks)', () => {
  const tools = ALL_TOOLS;
  const replace = (name: string, patch: Partial<OperationTool>) =>
    tools.map((t) => (t.name === name ? { ...t, ...patch } : t));

  it('an enabled write needs testedBy, a spec and a template; specs need an enabled write', () => {
    expect(
      registryConsistencyIssues(replace('policy_management_disable', { testedBy: null })),
    ).toEqual(['policy_management_disable: enabled write without testedBy']);
    const withoutSpec = CONFIRMATION_SPECS.filter(
      (s) => s.operationId !== 'PolicyManagementController_disable_v1',
    );
    expect(registryConsistencyIssues(tools, { specs: withoutSpec })).toEqual([
      'policy_management_disable: enabled write without a confirmation spec',
    ]);
    // A critical operation is never a tool (portal only), so its spec has no enabled write.
    const extra: ConfirmationSpec = {
      operationId: 'LegalHoldsController_release_v1',
      precondition: null,
    };
    expect(registryConsistencyIssues(tools, { specs: [...CONFIRMATION_SPECS, extra] })).toEqual([
      'LegalHoldsController_release_v1: confirmation spec without an enabled write tool',
    ]);
    expect(
      registryConsistencyIssues(tools, { specs: [...CONFIRMATION_SPECS, CONFIRMATION_SPECS[0]!] }),
    ).toEqual(['PolicyManagementController_create_v1: more than one confirmation spec']);
  });

  it('no tool after the program phase is enabled; no write before the confirmation phase', () => {
    // Every planned tool is enabled since AI-5: check against an earlier program phase.
    const later = findTool('archive_retention_create')!;
    expect(later.enabled).toBe(true);
    expect(later.phase).toBe('AI-5');
    const issues = registryConsistencyIssues(tools, { programPhase: 'AI-4' });
    expect(issues).toEqual(
      expect.arrayContaining([
        'archive_retention_create: enabled although its phase AI-5 is after the program phase',
        'archive_admin_capture_issue: enabled although its phase AI-5 is after the program phase',
      ]),
    );
    const withoutTemplate = registryConsistencyIssues(
      replace('archive_retention_create', { operationId: 'ArchiveRetentionController_x_v1' }),
    );
    expect(withoutTemplate).toEqual(
      expect.arrayContaining([
        'archive_retention_create: enabled write without a confirmation spec',
        'archive_retention_create: enabled write without an impact template',
      ]),
    );
    expect(registryConsistencyIssues(tools, { programPhase: 'AI-1' })).toEqual(
      expect.arrayContaining([
        'policy_management_create: a write is enabled before the confirmation manager exists',
        'policy_tools_validate: enabled although its phase AI-2 is after the program phase',
      ]),
    );
  });

  it('precondition tools are enabled reads with exactly the mapped path parameters', () => {
    const patch = (operationId: string, change: Partial<ConfirmationSpec>) =>
      CONFIRMATION_SPECS.map((s) => (s.operationId === operationId ? { ...s, ...change } : s));
    const single = spec('PolicyManagementController_disable_v1').precondition as SinglePrecondition;
    expect(
      registryConsistencyIssues(tools, {
        specs: patch('PolicyManagementController_disable_v1', {
          precondition: { ...single, tool: 'policy_management_enable' },
        }),
      }),
    ).toEqual([
      'policy_management_disable: precondition tool policy_management_enable is not an enabled read',
    ]);
    expect(
      registryConsistencyIssues(tools, {
        specs: patch('PolicyManagementController_publish_v1', {
          precondition: { ...single, tool: 'policy_management_get_version' },
        }),
      }),
    ).toEqual([
      'policy_management_publish: precondition params [policyId] must map exactly the path parameters [policyId, versionNo] of policy_management_get_version',
    ]);
    expect(
      registryConsistencyIssues(tools, {
        specs: patch('PolicyManagementController_disable_v1', {
          precondition: { ...single, params: { policyId: 'body.policyId' } },
        }),
      }),
    ).toEqual([
      'policy_management_disable: precondition param policyId maps the missing argument body.policyId',
    ]);
    const each = spec('QuarantineToolsController_bulk_v1').precondition as EachPrecondition;
    expect(
      registryConsistencyIssues(tools, {
        specs: patch('QuarantineToolsController_bulk_v1', {
          precondition: { ...each, paramByAction: { approve: 'entryId', deny: 'approvalId' } },
        }),
      }),
    ).toEqual([
      'quarantine_tools_bulk: approve read quarantine_approvals_get must take exactly the path parameter entryId',
    ]);
  });

  it('injected CAS fields exist in the input schema with the spec minimum', () => {
    const patch = (operationId: string, change: Partial<ConfirmationSpec>) =>
      CONFIRMATION_SPECS.map((s) => (s.operationId === operationId ? { ...s, ...change } : s));
    expect(
      registryConsistencyIssues(tools, {
        specs: patch('QuarantineEntriesController_requestRelease_v1', {
          inject: { in: 'body', field: 'expectedRowVersion', min: 1 },
        }),
      }),
    ).toEqual([
      'quarantine_entries_request_release: injected field body.expectedRowVersion is not in the input schema',
    ]);
    expect(
      registryConsistencyIssues(tools, {
        specs: patch('PolicySettingsController_put_v1', {
          inject: { in: 'body', field: 'expectedRowVersion', min: 1 },
        }),
      }),
    ).toEqual([
      'policy_settings_put: injected field body.expectedRowVersion has minimum 0, spec says 1',
    ]);
    expect(
      registryConsistencyIssues(tools, {
        specs: patch('PolicyManagementController_remove_v1', {
          inject: { in: 'body', field: 'expectedRowVersion', min: 1 },
        }),
      }),
    ).toEqual([
      'policy_management_remove: injected field body.expectedRowVersion is not in the input schema',
    ]);
  });
});

describe('argument helpers', () => {
  it('maps precondition arguments from path parameters and body fields', () => {
    expect(
      preconditionArgs(
        spec('PolicyManagementController_publish_v1').precondition as SinglePrecondition,
        { policyId: POLICY, versionNo: 2, body: { activate: true } },
      ),
    ).toEqual({ policyId: POLICY, versionNo: 2 });
    expect(
      preconditionArgs(
        spec('QuarantineEntriesController_manual_v1').precondition as SinglePrecondition,
        { body: { messageId: POLICY, reason: 'r' } },
      ),
    ).toEqual({ messageId: POLICY });
  });

  it('pre-fills a placeholder CAS value only when omitted, so a required field never blocks', () => {
    const publish = spec('PolicyManagementController_publish_v1');
    const tool = findTool('policy_management_publish')!;
    const args = { policyId: POLICY, versionNo: 1, body: { activate: true } };
    expect(compileValidator(tool)(args).ok).toBe(false);
    const placeholder = withCasPlaceholder(args, publish);
    expect(placeholder).toEqual({ ...args, body: { activate: true, expectedRowVersion: 1 } });
    expect(compileValidator(tool)(placeholder).ok).toBe(true);
    expect(args.body).toEqual({ activate: true }); // never mutated
    const settings = withCasPlaceholder(
      { body: { settings: {} } },
      spec('PolicySettingsController_put_v1'),
    );
    expect(settings).toEqual({ body: { settings: {}, expectedRowVersion: 0 } });
    expect(
      withCasPlaceholder({ policyId: POLICY }, spec('PolicyManagementController_remove_v1')),
    ).toEqual({
      policyId: POLICY,
      expectedRowVersion: 1,
    });
    const kept = withCasPlaceholder(
      { policyId: POLICY, body: { expectedRowVersion: 7 } },
      spec('PolicyManagementController_enable_v1'),
    );
    expect(kept.body).toEqual({ expectedRowVersion: 7 });
  });

  it('injects the read row version over any model value (body, query, created body)', () => {
    const enable = spec('PolicyManagementController_enable_v1');
    expect(
      withInjectedCas({ policyId: POLICY, body: { expectedRowVersion: 99 } }, enable, 4),
    ).toEqual({
      policyId: POLICY,
      body: { expectedRowVersion: 4 },
    });
    expect(withInjectedCas({ policyId: POLICY }, enable, 4)).toEqual({
      policyId: POLICY,
      body: { expectedRowVersion: 4 },
    });
    expect(
      withInjectedCas(
        { policyId: POLICY, expectedRowVersion: 99 },
        spec('PolicyManagementController_remove_v1'),
        5,
      ),
    ).toEqual({ policyId: POLICY, expectedRowVersion: 5 });
    expect(
      withInjectedCas(
        { messageId: POLICY, body: { reason: 'Rescan after the engine fix', expectedVersion: 0 } },
        spec('MessageLifecycleController_rescan_v1'),
        12,
      ),
    ).toEqual({
      messageId: POLICY,
      body: { reason: 'Rescan after the engine fix', expectedVersion: 12 },
    });
    expect(() => withInjectedCas({}, enable, -1)).toThrow();
    const create = spec('PolicyManagementController_create_v1');
    expect(withInjectedCas({ body: { name: 'x' } }, create, 3)).toEqual({ body: { name: 'x' } });
  });

  it('plans bulk reads: first 25 ids, read tool and parameter per action', () => {
    const bulk = spec('QuarantineToolsController_bulk_v1').precondition as EachPrecondition;
    const ids = Array.from(
      { length: 30 },
      (_, i) => `0193aaaa-0000-7000-8000-${String(i).padStart(12, '0')}`,
    );
    const release = eachReads(bulk, { body: { action: 'release', ids, reason: 'r' } });
    expect(release.total).toBe(30);
    expect(release.reads).toHaveLength(25);
    expect(release.reads[0]).toEqual({
      id: ids[0],
      tool: 'quarantine_entries_detail',
      args: { entryId: ids[0] },
    });
    const approve = eachReads(bulk, {
      body: { action: 'approve', ids: ids.slice(0, 2), reason: 'r' },
    });
    expect(approve.reads[1]).toEqual({
      id: ids[1],
      tool: 'quarantine_approvals_get',
      args: { approvalId: ids[1] },
    });
  });
});

describe('snapshots', () => {
  it('keeps state, row version and display fields, sanitized and capped', () => {
    const pre = spec('QuarantineEntriesController_release_v1').precondition as SinglePrecondition;
    const body = {
      id: 'e',
      rowVersion: 3,
      state: 'held',
      subject: `Invoice${String.fromCodePoint(0x202e)}${'x'.repeat(400)}`,
      sender: { envelope: 'a@example.com', headerFrom: null },
      recipient: 'r@example.net',
      explanation: { text: 'not kept' },
    };
    const snapshot = buildSnapshot(body, pre);
    expect(snapshot.rowVersion).toBe(3);
    expect(snapshot.state).toBe('held');
    expect(snapshot['sender.envelope']).toBe('a@example.com');
    expect(snapshot['sender.headerFrom']).toBeNull();
    expect(snapshot.reason).toBeNull();
    expect(String(snapshot.subject)).toHaveLength(300);
    expect(String(snapshot.subject)).not.toContain(String.fromCodePoint(0x202e));
    expect(Object.keys(snapshot)).not.toContain('explanation.text');
    expect(rowVersionOf(body, pre)).toBe(3);
    expect(rowVersionOf({ rowVersion: '3' }, pre)).toBeNull();
    expect(rowVersionOf(body, { rowVersionField: undefined })).toBeNull();
  });

  it('bulk items carry the entry state or the approval status', () => {
    const bulk = spec('QuarantineToolsController_bulk_v1').precondition as EachPrecondition;
    expect(buildEachItem('e1', { state: 'held', rowVersion: 2 }, bulk)).toEqual({
      id: 'e1',
      status: 'held',
      rowVersion: 2,
      stateDigest: stateDigest({ state: 'held', rowVersion: 2 }, bulk.stateFields),
    });
    expect(buildEachItem('a1', { status: 'pending' }, bulk)).toMatchObject({
      status: 'pending',
      rowVersion: null,
    });
  });
});

// ---------------------------------------------------------------------------------------------
// Step AI-3 (design 30 D3–D6)
// ---------------------------------------------------------------------------------------------

const REPO = join(__dirname, '../../../..');
const openapi = JSON.parse(
  readFileSync(join(REPO, 'docs/api/openapi.json'), 'utf8'),
) as OpenApiDocument;
const operationOf = (operationId: string) => {
  for (const item of Object.values(openapi.paths))
    for (const op of Object.values(item)) if (op?.operationId === operationId) return op;
  throw new Error(operationId);
};
const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

/** The schema at a dotted path (`[]` steps into array items), searching anyOf/oneOf variants. */
function schemaAt(schema: unknown, path: string): Record<string, unknown> | null {
  let nodes: Record<string, unknown>[] = isObject(schema) ? [schema] : [];
  const expand = (node: Record<string, unknown>): Record<string, unknown>[] => [
    node,
    ...[...((node.anyOf as unknown[]) ?? []), ...((node.oneOf as unknown[]) ?? [])]
      .filter(isObject)
      .flatMap(expand),
  ];
  for (const raw of path.split('.')) {
    const array = raw.endsWith('[]');
    const key = array ? raw.slice(0, -2) : raw;
    nodes = nodes.flatMap(expand).flatMap((node) => {
      const sub = (node.properties as Record<string, unknown> | undefined)?.[key];
      return isObject(sub) ? [sub] : [];
    });
    if (array)
      nodes = nodes.flatMap(expand).flatMap((node) => (isObject(node.items) ? [node.items] : []));
    if (nodes.length === 0) return null;
  }
  return nodes[0] ?? null;
}

/**
 * Display paths under a free-form object of the read's response (step AI-4): the ATO settings
 * read's `effective` document is typed as an open object, its `mode` is the documented setting.
 */
const FREE_FORM_DISPLAY: Readonly<Record<string, { parent: string; path: string }>> = {
  AtoSettingsController_update_v1: { parent: 'effective', path: 'effective.mode' },
};

describe('AI-3 specs (design 30 D6)', () => {
  const AI3 = CONFIRMATION_SPECS.filter((s) => s.operationId in AI3_WRITES_TESTED_BY);
  const nameOf = (operationId: string) => (findOperation(operationId) as OperationTool).name;

  it('names the design D6 preconditions, selects, state fields and CAS injections', () => {
    expect(AI3).toHaveLength(47);
    const table = Object.fromEntries(
      AI3.map((s) => {
        const pre = s.precondition as SinglePrecondition | null;
        return [
          nameOf(s.operationId),
          [
            pre
              ? `${pre.tool}{${Object.keys(pre.params).join(',')}}${pre.select ? ` ${pre.select.array}[${pre.select.field}=${pre.select.arg}${pre.select.required ? '' : '?'}]` : ''}`
              : null,
            pre?.stateFields.join(',') ?? null,
            s.inject
              ? `${s.inject.in}.${s.inject.field}>=${s.inject.min} from ${pre?.rowVersionField}`
              : null,
          ],
        ];
      }),
    );
    expect(table).toEqual({
      users_invite: [null, null, null],
      users_update: ['users_get{id}', 'email,displayName,status', null],
      users_change_status: ['users_get{id}', 'status,lockedUntil', null],
      users_replace_roles: ['users_get{id}', 'roles,status', null],
      users_reset_mfa: ['users_get{id}', 'mfaEnabled,status', null],
      users_remove: ['users_get{id}', 'status,roles', null],
      users_resend_invitation: ['users_get{id}', 'status', null],
      users_revoke_all_sessions: ['users_get{id}', 'status', null],
      users_revoke_session: [
        'users_list_sessions{id} data[id=sessionId]',
        'authenticatedAt,expiresAt',
        null,
      ],
      roles_create: [null, null, null],
      roles_update: ['roles_get{key}', 'name,description,permissions,system', null],
      roles_remove: ['roles_get{key}', 'permissions,system', null],
      departments_create: [null, null, null],
      departments_update: [
        'departments_get{departmentId}',
        'rowVersion,name,description',
        'body.expectedRowVersion>=1 from rowVersion',
      ],
      departments_remove: [
        'departments_get{departmentId}',
        'rowVersion',
        'query.expectedRowVersion>=1 from rowVersion',
      ],
      departments_add_member: ['departments_get{departmentId}', 'rowVersion', null],
      departments_remove_member: ['departments_get{departmentId}', 'rowVersion', null],
      api_keys_revoke: ['api_keys_get{id}', 'revokedAt,expiresAt', null],
      domains_create: [null, null, null],
      domains_remove: ['domains_get{id}', 'status,inboundEnabled,outboundEnabled', null],
      domains_change_status: ['domains_get{id}', 'status', null],
      domain_dns_verify: ['domain_dns_status{id}', 'status', null],
      domain_dns_rotate: ['domains_get{id}', 'status,dkimKeys', null],
      domain_destinations_replace: ['domain_destinations_get{id}', 'provider,servers', null],
      domain_destinations_remove: ['domain_destinations_get{id}', 'provider,servers', null],
      domain_recipients_set: ['domain_recipients_get{id}', 'mode,enforcement', null],
      domain_recipients_add: ['domain_recipients_get{id}', 'mode', null],
      domain_recipients_remove: ['domain_recipients_get{id}', 'mode', null],
      notifications_put_preferences: [
        'notifications_preferences{}',
        'optOut,quarantineDigestOptOut',
        null,
      ],
      notifications_put_settings: [
        'notifications_settings{}',
        'rowVersion',
        'body.expectedRowVersion>=0 from rowVersion',
      ],
      organizations_create: [null, null, null],
      organizations_update: ['organizations_get{id}', 'name,plan.code,status', null],
      organization_deletion_cancel: [
        'organization_deletion_get{id}',
        'state,cancellable,requestedAt',
        null,
      ],
      organization_configuration_override_feature: [
        'organization_configuration_list_features{id} data[key=featureKey?]',
        'enabled,config,source',
        null,
      ],
      organization_configuration_reset_feature: [
        'organization_configuration_list_features{id} data[key=featureKey?]',
        'enabled,config,source',
        null,
      ],
      organization_configuration_override_limit: [
        'organization_configuration_list_limits{id} data[key=limitKey?]',
        'value,source',
        null,
      ],
      organization_configuration_reset_limit: [
        'organization_configuration_list_limits{id} data[key=limitKey?]',
        'value,source',
        null,
      ],
      organization_configuration_update_settings: [
        'organization_configuration_get_settings{id}',
        'timezone,locale,quarantineRetentionDays,digestEnabled,digestSchedule,notificationEmail,mfaRequired,preferences,updatedAt',
        null,
      ],
      scan_settings_replace: [
        'scan_settings_list{} data[engine=engine]',
        'version,override',
        'body.expectedVersion>=0 from version',
      ],
      scan_settings_reset: [
        'scan_settings_list{} data[engine=engine]',
        'version,override',
        'query.expectedVersion>=0 from version',
      ],
      smtp_connectors_update: ['smtp_connectors_get{id}', 'name,status,networks,requireTls', null],
      smtp_connectors_remove: ['smtp_connectors_get{id}', 'name,status', null],
      webhooks_update: [
        'webhooks_get{webhookId}',
        'rowVersion',
        'body.expectedRowVersion>=1 from rowVersion',
      ],
      webhooks_delete: ['webhooks_get{webhookId}', 'rowVersion,status', null],
      webhooks_test: ['webhooks_get{webhookId}', 'status', null],
      webhook_deliveries_replay: [
        'webhook_deliveries_get{webhookId,deliveryId}',
        'status,attemptCount',
        null,
      ],
      webhook_deliveries_create_replay: ['webhooks_get{webhookId}', 'status', null],
    });
  });

  it('every state, row-version, display and select path exists in the read’s OpenAPI response', () => {
    for (const s of CONFIRMATION_SPECS) {
      const pre = s.precondition;
      if (pre?.kind !== 'single') continue;
      const read = findTool(pre.tool)!;
      let schema: unknown = normalizeSchema(
        successResponseSchema(operationOf(read.operationId)),
        openapi.components?.schemas ?? {},
      );
      if (pre.select) {
        expect(
          schemaAt(schema, `${pre.select.array}[].${pre.select.field}`),
          s.operationId,
        ).not.toBeNull();
        schema = schemaAt(schema, `${pre.select.array}[]`);
      }
      for (const path of [
        ...pre.stateFields,
        ...(pre.rowVersionField ? [pre.rowVersionField] : []),
        ...(pre.displayFields ?? []),
      ]) {
        // A display path under a free-form object of the response (named, display only).
        const freeForm = FREE_FORM_DISPLAY[s.operationId];
        if (freeForm?.path === path && !pre.stateFields.includes(path)) {
          expect(schemaAt(schema, freeForm.parent), `${s.operationId}: ${path}`).not.toBeNull();
          continue;
        }
        // Step AI-5 D5: `preview.<path>` addresses the impact preview's response.
        if (s.impactToken && path.startsWith('preview.')) {
          const preview = normalizeSchema(
            successResponseSchema(operationOf(findTool(s.impactToken.previewTool)!.operationId)),
            openapi.components?.schemas ?? {},
          );
          expect(
            schemaAt(preview, path.slice('preview.'.length)),
            `${s.operationId}: ${path}`,
          ).not.toBeNull();
          continue;
        }
        expect(schemaAt(schema, path), `${s.operationId}: ${path}`).not.toBeNull();
      }
    }
  });

  it('organization writes bind {id} only when customer-reachable', () => {
    expect(findTool('organizations_update')!.bind).toEqual({ id: 'self_organization' });
    expect(findTool('organization_configuration_update_settings')!.bind).toEqual({
      id: 'self_organization',
    });
    for (const name of [
      'organization_deletion_cancel',
      'organization_configuration_override_feature',
      'organization_configuration_reset_feature',
      'organization_configuration_override_limit',
      'organization_configuration_reset_limit',
      'organizations_create',
    ]) {
      expect(findTool(name)!.bind, name).toEqual({});
      expect(findTool(name)!.platformOnly, name).toBe(true);
    }
    expect(
      compileValidator(findTool('organization_deletion_cancel')!)({ body: { reason: 'r' } }).ok,
    ).toBe(false);
  });
});

describe('selected-item preconditions (D5)', () => {
  const sessions = spec('UsersController_revokeSession_v1').precondition as SinglePrecondition;
  const limits = spec('OrganizationConfigurationController_overrideLimit_v1')
    .precondition as SinglePrecondition;
  const scan = spec('ScanSettingsController_replace_v1').precondition as SinglePrecondition;
  const S1 = '0193aaaa-0000-7000-8000-0000000000a1';
  const S2 = '0193aaaa-0000-7000-8000-0000000000a2';
  const body = {
    data: [
      { id: S1, authenticatedAt: 'a1', expiresAt: 'e1', userAgent: 'x' },
      { id: S2, authenticatedAt: 'a2', expiresAt: 'e2', userAgent: 'y' },
    ],
  };

  it('finds the item whose field equals the argument (string compare)', () => {
    expect(selectTarget(body, sessions, { id: 'u', sessionId: S2 })).toEqual({
      found: true,
      item: body.data[1],
    });
    expect(targetOf(body, sessions, { id: 'u', sessionId: S2 })).toBe(body.data[1]);
    expect(stateDigest(targetOf(body, sessions, { sessionId: S2 }), sessions.stateFields)).toBe(
      stateDigest({ authenticatedAt: 'a2', expiresAt: 'e2' }, sessions.stateFields),
    );
    expect(buildSnapshot(targetOf(body, sessions, { sessionId: S1 }), sessions)).toMatchObject({
      authenticatedAt: 'a1',
      userAgent: 'x',
    });
    // Numbers compare as strings; other types never match.
    const numbered = { ...sessions, select: { ...sessions.select!, field: 'n', arg: 'body.n' } };
    expect(selectTarget({ data: [{ n: 7 }] }, numbered, { body: { n: '7' } }).found).toBe(true);
    expect(selectTarget({ data: [{ n: true }] }, numbered, { body: { n: 'true' } }).found).toBe(
      false,
    );
  });

  it('not found: required → found false; optional → the empty target (null fields, digest of {})', () => {
    expect(selectTarget(body, sessions, { sessionId: 'missing' })).toEqual({
      found: false,
      item: null,
    });
    expect(selectTarget({ data: 'x' }, sessions, { sessionId: S1 }).found).toBe(false);
    expect(selectTarget(body, sessions, {}).found).toBe(false);
    const missing = targetOf({ data: [] }, limits, { limitKey: 'max_users' });
    expect(missing).toEqual({});
    expect(buildSnapshot(missing, limits)).toEqual({ value: null, source: null });
    expect(stateDigest(missing, limits.stateFields)).toBe(stateDigest({}, limits.stateFields));
    expect(rowVersionOf(missing, scan)).toBeNull();
  });

  it('nested array paths; row version and CAS from the selected item', () => {
    const nested = { ...scan, select: { ...scan.select!, array: 'result.engines' } };
    const read = {
      result: {
        engines: [
          { engine: 'url', version: 1 },
          { engine: 'rspamd', version: 9 },
        ],
      },
    };
    const item = targetOf(read, nested, { engine: 'rspamd' });
    expect(rowVersionOf(item, nested)).toBe(9);
    expect(
      withInjectedCas(
        { engine: 'rspamd', body: { settings: {}, expectedVersion: 0 } },
        spec('ScanSettingsController_replace_v1'),
        rowVersionOf(item, nested)!,
      ),
    ).toEqual({ engine: 'rspamd', body: { settings: {}, expectedVersion: 9 } });
    // Without select the target is the body itself (AI-2 specs are unchanged).
    const policy = spec('PolicyManagementController_disable_v1').precondition as SinglePrecondition;
    const policyRead = { rowVersion: 3 };
    expect(targetOf(policyRead, policy, {})).toBe(policyRead);
  });

  it('snapshot projections keep lists as JSON and drop credential keys of objects', () => {
    const roles = spec('UsersController_replaceRoles_v1').precondition as SinglePrecondition;
    const snapshot = buildSnapshot(
      {
        email: 'a@example.com',
        displayName: 'A',
        status: 'active',
        roles: [
          { key: 'r1', name: 'One' },
          { key: 'r2', name: 'Two' },
        ],
      },
      roles,
    );
    expect(snapshot['roles[].key']).toBe('["r1","r2"]');
    expect(snapshotList(snapshot['roles[].key'])).toEqual(['r1', 'r2']);
    expect(snapshotList('["cut')).toBeNull();
    expect(snapshotList(3)).toBeNull();
    expect(snapshotPathValue({ a: [{ b: 1 }, 'x', { c: 2 }] }, 'a[].b')).toEqual([1, null, null]);
    expect(snapshotPathValue({ a: 1 }, 'a[].b')).toBeUndefined();
    const long = Array.from({ length: 150 }, (_, i) => `permission:number_${i}`);
    const kept = buildSnapshot(
      { permissions: long },
      {
        kind: 'single',
        tool: 'roles_get',
        params: {},
        stateFields: ['permissions'],
      },
    );
    expect(snapshotList(kept.permissions)).toEqual(long);
    const tooLong = buildSnapshot(
      { permissions: [...long, ...long] },
      {
        kind: 'single',
        tool: 'roles_get',
        params: {},
        stateFields: ['permissions'],
      },
    );
    expect(snapshotList(tooLong.permissions)).toBeNull();
    const scrubbed = buildSnapshot(
      { config: { a: 1, apiToken: 'x', nested: { secret: 'y' } } },
      {
        kind: 'single',
        tool: 't',
        params: {},
        stateFields: ['config'],
      },
    );
    expect(scrubbed.config).toBe('{"a":1,"nested":{}}');
  });
});

describe('AI-3 registry consistency rules (synthetic breaks)', () => {
  const tools = ALL_TOOLS;
  const patch = (operationId: string, change: Partial<ConfirmationSpec>) =>
    CONFIRMATION_SPECS.map((s) => (s.operationId === operationId ? { ...s, ...change } : s));
  const issues = (operationId: string, change: Partial<ConfirmationSpec>) =>
    registryConsistencyIssues(tools, { specs: patch(operationId, change) });

  it('guard and escalation argument paths exist in the write’s input schema', () => {
    expect(
      issues('UsersController_update_v1', { guards: [{ kind: 'not_self_user', arg: 'userId' }] }),
    ).toEqual(['users_update: not_self_user guard reads the missing argument userId']);
    expect(
      issues('WebhooksController_update_v1', {
        escalate: [{ when: { present: 'body.endpoint' }, risk: 'high', warning: 'w' }],
      }),
    ).toEqual(['webhooks_update: escalation reads the missing argument body.endpoint']);
    expect(
      issues('SmtpConnectorsController_update_v1', {
        escalate: [
          { when: { equals: { path: 'body.tls', value: false } }, risk: 'high', warning: 'w' },
        ],
      }),
    ).toEqual(['smtp_connectors_update: escalation reads the missing argument body.tls']);
  });

  it('deny_permission_change with beforeField needs a single precondition', () => {
    const update = spec('RolesController_update_v1');
    expect(issues('RolesController_create_v1', { guards: update.guards })).toEqual([
      'roles_create: deny_permission_change with beforeField needs a single precondition',
    ]);
  });

  it('all guards of a spec share one message (stored denied_guard executions, D12)', () => {
    const update = spec('UsersController_update_v1');
    expect(
      issues('UsersController_update_v1', {
        guards: [
          ...update.guards!,
          {
            kind: 'deny_values',
            arg: 'body.displayName',
            values: ['x'],
            message: 'assistant_feature',
          },
        ],
      }),
    ).toEqual(['users_update: all guards of a spec must share one message']);
  });

  it('select: only on single, non-empty array, an existing argument; CAS needs a row version', () => {
    const pre = spec('ScanSettingsController_replace_v1').precondition as SinglePrecondition;
    expect(
      issues('ScanSettingsController_replace_v1', {
        precondition: { ...pre, select: { ...pre.select!, arg: 'body.engine' } },
      }),
    ).toEqual(['scan_settings_replace: select reads the missing argument body.engine']);
    expect(
      issues('ScanSettingsController_replace_v1', {
        precondition: { ...pre, select: { ...pre.select!, array: '' } },
      }),
    ).toEqual(['scan_settings_replace: select needs a non-empty array and field']);
    expect(
      issues('ScanSettingsController_replace_v1', {
        precondition: { ...pre, rowVersionField: undefined },
      }),
    ).toEqual(['scan_settings_replace: CAS injection needs a precondition with a rowVersionField']);
    const bulk = spec('QuarantineToolsController_bulk_v1').precondition as EachPrecondition;
    expect(
      issues('QuarantineToolsController_bulk_v1', {
        precondition: { ...bulk, select: pre.select } as unknown as EachPrecondition,
      }),
    ).toEqual(['quarantine_tools_bulk: select is only allowed on a single precondition']);
  });

  it('no enabled write has a credential-pattern input key (named exceptions only)', () => {
    const bodyOf = (t: OperationTool) =>
      (t.inputSchema.properties as Record<string, Record<string, unknown>>).body!;
    const withSecret = tools.map((t) =>
      t.name === 'webhooks_update'
        ? {
            ...t,
            inputSchema: {
              ...t.inputSchema,
              properties: {
                ...(t.inputSchema.properties as object),
                body: {
                  ...bodyOf(t),
                  properties: {
                    ...(bodyOf(t).properties as object),
                    signingSecret: { type: 'string' },
                    headers: {
                      type: 'array',
                      items: { anyOf: [{ type: 'object', properties: { authToken: {} } }] },
                    },
                    extra: { type: 'object', additionalProperties: { properties: { apiKey: {} } } },
                  },
                },
              },
            },
          }
        : t,
    );
    expect(registryConsistencyIssues(withSecret)).toEqual([
      'webhooks_update: input property body.signingSecret matches the credential-key pattern',
      'webhooks_update: input property body.headers[].authToken matches the credential-key pattern',
      'webhooks_update: input property body.extra.*.apiKey matches the credential-key pattern',
    ]);
    expect(credentialKeyPaths(findTool('roles_create')!.inputSchema)).toEqual(['body.key']);
    expect(credentialKeyPaths(findTool('roles_update')!.inputSchema)).toEqual(['key']);
    expect(Object.keys(CREDENTIAL_KEY_EXCEPTIONS).sort()).toEqual([
      'AtoProvidersController_create_v1',
      'AtoProvidersController_update_v1',
      'AtoSettingsController_update_v1',
      'BecMessageFeedbackController_record_v1',
      'IncidentsController_update_v1',
      'IntakeSourcesController_attest_v1',
      'ProviderAttestationsController_record_v1',
      'RolesController_create_v1',
      'RolesController_remove_v1',
      'RolesController_update_v1',
    ]);
    // Step AI-4: action names and reason/resolution codes, never credentials.
    expect(credentialKeyPaths(findTool('ato_settings_update')!.inputSchema)).toEqual([
      'body.settings.automation.require_password_reset',
    ]);
    expect(credentialKeyPaths(findTool('bec_message_feedback_record')!.inputSchema)).toEqual([
      'body.reasonCodes',
      'body.suppress.codes',
    ]);
    expect(credentialKeyPaths(findTool('incidents_update')!.inputSchema)).toEqual([
      'body.resolution.code',
    ]);
    for (const [operationId, paths] of Object.entries(CREDENTIAL_KEY_EXCEPTIONS)) {
      const t = findOperation(operationId) as OperationTool;
      expect(credentialKeyPaths(t.inputSchema).sort(), operationId).toEqual(
        Object.keys(paths).sort(),
      );
    }
    // A disabled tool's schema is not checked (secret-returning operations are N/A anyway).
    expect(
      registryConsistencyIssues(
        withSecret.map((t) => (t.name === 'webhooks_update' ? { ...t, enabled: false } : t)),
      ),
    ).toEqual(['WebhooksController_update_v1: confirmation spec without an enabled write tool']);
  });
});

describe('AI-4 specs (design 32 D5)', () => {
  const AI4 = CONFIRMATION_SPECS.filter((s) => s.operationId in AI4_WRITES_TESTED_BY);
  const nameOf = (operationId: string) => (findOperation(operationId) as OperationTool).name;

  it('covers the 64 AI-4 writes; 168 enabled writes have one spec each', () => {
    expect(AI4).toHaveLength(64);
    const enabledWrites = ALL_TOOLS.filter((t) => t.enabled && t.access === 'write');
    expect(enabledWrites).toHaveLength(168);
    for (const write of enabledWrites)
      expect(confirmationSpecOf(write.operationId), write.name).toBeDefined();
  });

  it('names the design D5 preconditions, selects, state fields and CAS injections', () => {
    const table = Object.fromEntries(
      AI4.map((s) => {
        const pre = s.precondition;
        const read =
          pre?.kind === 'single'
            ? `${pre.tool}{${Object.entries(pre.params)
                .map(([k, v]) => (k === v ? k : `${k}=${v}`))
                .join(
                  ',',
                )}}${pre.select ? ` select ${pre.select.array}[${pre.select.field}=${pre.select.arg}]` : ''}`
            : null;
        return [
          nameOf(s.operationId),
          [
            read,
            pre?.stateFields.join(',') ?? null,
            s.inject ? `${s.inject.in}.${s.inject.field}>=${s.inject.min}` : null,
          ],
        ];
      }),
    );
    const account = 'ato_accounts_get{accountId}';
    const response = 'ato_responses_get{responseId}';
    const provider = 'ato_providers_get{integrationId}';
    const v = (tool: string, inject: string | null) => [`${tool}{id}`, 'version', inject];
    expect(table).toEqual({
      ato_accounts_update: [
        account,
        'rowVersion,protection.protected',
        'body.expectedRowVersion>=1',
      ],
      ato_account_mailbox_refresh: [account, 'status', null],
      ato_accounts_set_override: [account, 'overrideDetail.id,overrideDetail.verdict', null],
      ato_accounts_clear_override: [account, 'overrideDetail.id', null],
      ato_accounts_add_trusted_context: [account, 'status', null],
      ato_accounts_remove_trusted_context: [
        `${account} select trustedContexts[id=contextId]`,
        'id,expiresAt',
        null,
      ],
      ato_responses_request: ['incidents_get{incidentId}', 'status', null],
      ato_responses_approve: [response, 'status,approvalExpiresAt', null],
      ato_responses_reject: [response, 'status', null],
      ato_responses_cancel: [response, 'status', null],
      ato_responses_rollback: [response, 'status', null],
      ato_settings_update: ['ato_settings_get{}', 'rowVersion', 'body.expectedRowVersion>=0'],
      ato_providers_create: [
        'ato_providers_connections{} select data[id=body.connectionId]',
        'status',
        null,
      ],
      ato_providers_update: [provider, 'rowVersion,status', 'body.rowVersion>=1'],
      ato_providers_remove: [provider, 'status', null],
      ato_providers_backfill: [provider, 'status', null],
      ato_providers_health_check: [provider, 'status', null],
      ato_providers_pause: [provider, 'status', null],
      ato_providers_resume: [provider, 'status', null],
      incidents_create: ['ato_accounts_get{accountId=body.subject.id}', 'status', null],
      incidents_update: [
        'incidents_get{incidentId}',
        'rowVersion,status',
        'body.expectedRowVersion>=1',
      ],
      incidents_add_note: ['incidents_get{incidentId}', 'status', null],
      bec_executives_create: [null, null, null],
      bec_executives_update: v('bec_executives_get', 'body.version>=1'),
      bec_executives_remove: v('bec_executives_get', 'query.version>=1'),
      bec_trusted_senders_create: [null, null, null],
      bec_trusted_senders_update: v('bec_trusted_senders_get', 'body.version>=1'),
      bec_trusted_senders_remove: v('bec_trusted_senders_get', 'query.version>=1'),
      bec_vendors_create: [null, null, null],
      bec_vendors_update: v('bec_vendors_get', 'body.version>=1'),
      bec_vendors_remove: v('bec_vendors_get', 'query.version>=1'),
      bec_feedback_delete_suppression: ['bec_feedback_get_suppression{id}', 'expiresAt', null],
      bec_message_feedback_record: ['messages_detail{messageId}', 'status', null],
      dlp_compliance_enable: [
        'dlp_compliance_get{}',
        'version,aadhaar.enabled',
        'body.expectedVersion>=0',
      ],
      dlp_compliance_disable: [
        'dlp_compliance_get{}',
        'version,aadhaar.enabled',
        'query.expectedVersion>=0',
      ],
      dlp_dictionaries_create: [null, null, null],
      dlp_dictionaries_update: v('dlp_dictionaries_get', 'body.version>=1'),
      dlp_dictionaries_remove: v('dlp_dictionaries_get', 'query.version>=1'),
      dlp_exceptions_create: [null, null, null],
      dlp_exceptions_update: v('dlp_exceptions_get', 'body.version>=1'),
      dlp_exceptions_remove: v('dlp_exceptions_get', 'query.version>=1'),
      dlp_patterns_create: [null, null, null],
      dlp_patterns_update: v('dlp_patterns_get', 'body.version>=1'),
      dlp_patterns_remove: v('dlp_patterns_get', 'query.version>=1'),
      dlp_policies_create: [null, null, null],
      dlp_policies_update: v('dlp_policies_get', 'body.version>=1'),
      dlp_policies_remove: v('dlp_policies_get', 'query.version>=1'),
      dlp_policies_create_rule: ['dlp_policies_get{id}', 'version', null],
      dlp_policies_update_rule: [
        'dlp_policies_get{id} select rules[id=ruleId]',
        'version',
        'body.version>=1',
      ],
      dlp_policies_remove_rule: [
        'dlp_policies_get{id} select rules[id=ruleId]',
        'version',
        'query.version>=1',
      ],
      risk_profiles_create_draft: [null, null, null],
      risk_profiles_update_draft: [
        'risk_profiles_get_version{versionId}',
        'rowVersion,status',
        'body.expectedRowVersion>=1',
      ],
      risk_profiles_delete_draft: [
        'risk_profiles_get_version{versionId}',
        'rowVersion,status',
        'query.expectedRowVersion>=1',
      ],
      risk_profiles_publish: [
        'risk_profiles_get_version{versionId}',
        'rowVersion,status',
        'body.expectedRowVersion>=1',
      ],
      risk_profiles_activate: [
        'risk_profiles_profile{}',
        'profileVersion',
        'body.expectedProfileVersion>=0',
      ],
      risk_profiles_reset: [
        'risk_profiles_profile{}',
        'profileVersion',
        'body.expectedProfileVersion>=0',
      ],
      attachment_rescans_request: [null, null, null],
      attachment_rescans_cancel: ['attachment_rescans_get{jobId}', 'status', null],
      dead_letters_replay: [null, null, null],
      scan_training_train: [null, null, null],
      threat_hashes_add: [null, null, null],
      threat_hashes_remove: [
        'threat_hashes_list{sha256} select data[sha256=sha256]',
        'severity,expiresAt',
        null,
      ],
      threat_indicators_add: [null, null, null],
      threat_indicators_remove: ['threat_indicators_get{id}', 'severity,expiresAt', null],
    });
  });

  it('state fields are stable: an ATO account rowVersion only where the write CAS-checks it', () => {
    for (const s of CONFIRMATION_SPECS) {
      const pre = s.precondition;
      if (pre?.kind !== 'single' || pre.tool !== 'ato_accounts_get') continue;
      if (pre.stateFields.includes('rowVersion') && !pre.select)
        expect(s.inject?.field, s.operationId).toBe('expectedRowVersion');
    }
    expect(spec('AtoAccountsController_update_v1').inject).toEqual({
      in: 'body',
      field: 'expectedRowVersion',
      min: 1,
    });
    // Moving risk figures are display only.
    for (const operationId of [
      'AtoAccountsController_setOverride_v1',
      'AtoAccountsController_clearOverride_v1',
      'AtoAccountsController_addTrustedContext_v1',
      'IncidentsController_create_v1',
    ]) {
      const pre = spec(operationId).precondition as SinglePrecondition;
      expect(pre.stateFields, operationId).not.toContain('riskScore');
      expect(pre.stateFields, operationId).not.toContain('riskLevel');
      expect(pre.stateFields, operationId).not.toContain('rowVersion');
    }
  });

  it('never shows the DLP pattern text and never binds platform tools to an organization', () => {
    for (const operationId of [
      'DlpPatternsController_update_v1',
      'DlpPatternsController_remove_v1',
    ]) {
      const pre = spec(operationId).precondition as SinglePrecondition;
      expect([...pre.stateFields, ...(pre.displayFields ?? [])], operationId).not.toContain(
        'pattern',
      );
    }
    for (const operationId of Object.keys(AI4_WRITES_TESTED_BY))
      expect((findOperation(operationId) as OperationTool).bind, operationId).toEqual({});
  });

  it('CAS injection with the new field names (body and query)', () => {
    const ID = '0193aaaa-0000-7000-8000-000000000301';
    // body.version
    const exec = spec('BecExecutivesController_update_v1');
    expect(withCasPlaceholder({ id: ID, body: { title: 'CFO' } }, exec)).toEqual({
      id: ID,
      body: { title: 'CFO', version: 1 },
    });
    expect(withInjectedCas({ id: ID, body: { title: 'CFO', version: 99 } }, exec, 4)).toEqual({
      id: ID,
      body: { title: 'CFO', version: 4 },
    });
    // query version
    const remove = spec('DlpPoliciesController_remove_v1');
    expect(withCasPlaceholder({ id: ID }, remove)).toEqual({ id: ID, version: 1 });
    expect(withInjectedCas({ id: ID, version: 7 }, remove, 3)).toEqual({ id: ID, version: 3 });
    // body.rowVersion (IdP integration settings)
    const provider = spec('AtoProvidersController_update_v1');
    expect(
      withInjectedCas({ integrationId: ID, body: { settings: {}, rowVersion: 1 } }, provider, 6),
    ).toEqual({ integrationId: ID, body: { settings: {}, rowVersion: 6 } });
    // body.expectedProfileVersion (the body itself is optional: it is created)
    const activate = spec('RiskProfilesController_activate_v1');
    expect(withCasPlaceholder({ versionId: ID }, activate)).toEqual({
      versionId: ID,
      body: { expectedProfileVersion: 0 },
    });
    expect(withInjectedCas({ versionId: ID }, activate, 5)).toEqual({
      versionId: ID,
      body: { expectedProfileVersion: 5 },
    });
    expect(withInjectedCas({}, spec('RiskProfilesController_reset_v1'), 0)).toEqual({
      body: { expectedProfileVersion: 0 },
    });
    // query expectedVersion (Aadhaar compliance disable); the read's version 0 is valid (min 0)
    const disable = spec('DlpComplianceController_disable_v1');
    expect(withInjectedCas({}, disable, 0)).toEqual({ expectedVersion: 0 });
    expect(
      rowVersionOf(
        { version: 0, aadhaar: { enabled: true } },
        disable.precondition as SinglePrecondition,
      ),
    ).toBe(0);
    // Every injected value passes the write's schema.
    for (const operationId of [
      'BecExecutivesController_update_v1',
      'DlpPoliciesController_remove_v1',
      'RiskProfilesController_activate_v1',
      'DlpComplianceController_disable_v1',
    ]) {
      const s = spec(operationId);
      const t = findOperation(operationId) as OperationTool;
      const base = operationId.startsWith('Risk') ? { versionId: ID } : { id: ID };
      const args = withInjectedCas(
        operationId === 'BecExecutivesController_update_v1' ? { ...base, body: {} } : base,
        s,
        s.inject!.min === 0 ? 0 : 2,
      );
      const cleaned =
        operationId === 'DlpComplianceController_disable_v1' ? { expectedVersion: 0 } : args;
      expect(compileValidator(t)(cleaned), operationId).toEqual({ ok: true });
    }
  });

  it('select: ATO trusted contexts, DLP rules (row version from the rule) and threat hashes', () => {
    const ACCOUNT = '0193aaaa-0000-7000-8000-000000000302';
    const CONTEXT = '0193aaaa-0000-7000-8000-000000000303';
    const contexts = spec('AtoAccountsController_removeTrustedContext_v1')
      .precondition as SinglePrecondition;
    const accountRead = {
      id: ACCOUNT,
      rowVersion: 40,
      trustedContexts: [
        {
          id: 'other',
          kind: 'asn',
          value: '64500',
          reason: 'r',
          source: 'analyst',
          expiresAt: 'x',
        },
        {
          id: CONTEXT,
          kind: 'ip_cidr',
          value: '203.0.113.0/24',
          reason: 'Office VPN',
          source: 'analyst',
          expiresAt: '2027-01-01T00:00:00.000Z',
        },
      ],
    };
    const args = { accountId: ACCOUNT, contextId: CONTEXT };
    expect(preconditionArgs(contexts, args)).toEqual({ accountId: ACCOUNT });
    const item = targetOf(accountRead, contexts, args) as Record<string, unknown>;
    expect(item.value).toBe('203.0.113.0/24');
    expect(stateDigest(item, contexts.stateFields)).toBe(
      stateDigest({ id: CONTEXT, expiresAt: '2027-01-01T00:00:00.000Z' }, contexts.stateFields),
    );
    expect(buildSnapshot(item, contexts)).toMatchObject({ kind: 'ip_cidr', reason: 'Office VPN' });
    expect(selectTarget(accountRead, contexts, { ...args, contextId: 'missing' })).toEqual({
      found: false,
      item: null,
    });
    // A rescoring (account rowVersion) does not change the selected item's digest.
    expect(
      stateDigest(
        targetOf({ ...accountRead, rowVersion: 41 }, contexts, args),
        contexts.stateFields,
      ),
    ).toBe(stateDigest(item, contexts.stateFields));

    const rule = spec('DlpPoliciesController_updateRule_v1').precondition as SinglePrecondition;
    const POLICY_ID = '0193aaaa-0000-7000-8000-000000000304';
    const RULE = '0193aaaa-0000-7000-8000-000000000305';
    const policyRead = {
      id: POLICY_ID,
      version: 9,
      rules: [
        { id: 'r0', name: 'Other', version: 2 },
        {
          id: RULE,
          name: 'Card numbers',
          enabled: true,
          priority: 10,
          action: 'block',
          version: 3,
        },
      ],
    };
    const ruleArgs = { id: POLICY_ID, ruleId: RULE, body: { enabled: false } };
    const ruleItem = targetOf(policyRead, rule, ruleArgs);
    expect(rowVersionOf(ruleItem, rule)).toBe(3);
    expect(withInjectedCas(ruleArgs, spec('DlpPoliciesController_updateRule_v1'), 3).body).toEqual({
      enabled: false,
      version: 3,
    });
    expect(buildSnapshot(ruleItem, rule)).toEqual({
      version: 3,
      name: 'Card numbers',
      enabled: true,
      priority: 10,
      action: 'block',
    });

    const hashes = spec('ThreatHashesController_remove_v1').precondition as SinglePrecondition;
    const SHA = 'a'.repeat(64);
    expect(preconditionArgs(hashes, { sha256: SHA, reason: 'r' })).toEqual({ sha256: SHA });
    const hashRead = {
      data: [{ sha256: SHA, severity: 'high', family: 'Test', source: 'manual', expiresAt: null }],
      nextCursor: null,
    };
    expect(selectTarget(hashRead, hashes, { sha256: SHA }).found).toBe(true);
    expect(selectTarget(hashRead, hashes, { sha256: 'b'.repeat(64) }).found).toBe(false);
    expect(hashes.select?.required).toBe(true);
  });
});

describe('AI-4 registry consistency rules (synthetic breaks)', () => {
  const tools = ALL_TOOLS;
  const patch = (operationId: string, change: Partial<ConfirmationSpec>) =>
    CONFIRMATION_SPECS.map((s) => (s.operationId === operationId ? { ...s, ...change } : s));
  const issues = (operationId: string, change: Partial<ConfirmationSpec>) =>
    registryConsistencyIssues(tools, { specs: patch(operationId, change) });

  it('not_self_field and require_read_value need a single precondition', () => {
    const approve = spec('AtoResponsesController_approve_v1');
    expect(issues('DlpPoliciesController_create_v1', { guards: approve.guards })).toEqual([
      'dlp_policies_create: not_self_field needs a single precondition',
      'dlp_policies_create: require_read_value needs a single precondition',
    ]);
    // On a spec with a single precondition they are fine (no argument is read).
    expect(issues('AtoResponsesController_cancel_v1', { guards: approve.guards })).toEqual([]);
  });

  it('CAS injection fields exist (body or query) with the schema minimum', () => {
    expect(
      issues('BecExecutivesController_update_v1', {
        inject: { in: 'query', field: 'version', min: 1 },
      }),
    ).toEqual([
      'bec_executives_update: injected field version is not in the input schema',
      'bec_executives_update: injected query field version is not a query parameter',
    ]);
    expect(
      issues('RiskProfilesController_activate_v1', {
        inject: { in: 'body', field: 'expectedProfileVersion', min: 1 },
      }),
    ).toEqual([
      'risk_profiles_activate: injected field body.expectedProfileVersion has minimum 0, spec says 1',
    ]);
    expect(
      issues('AtoProvidersController_update_v1', {
        inject: { in: 'body', field: 'expectedRowVersion', min: 1 },
      }),
    ).toEqual([
      'ato_providers_update: injected field body.expectedRowVersion is not in the input schema',
    ]);
  });

  it('query parameters may be mapped in addition to the path parameters, nothing else', () => {
    const hashes = spec('ThreatHashesController_remove_v1').precondition as SinglePrecondition;
    expect(
      issues('ThreatHashesController_remove_v1', {
        precondition: { ...hashes, params: { sha256: 'sha256', family: 'sha256' } },
      }),
    ).toEqual([
      'threat_hashes_remove: precondition params [family] must map exactly the path parameters [] of threat_hashes_list',
    ]);
    const policy = spec('DlpPoliciesController_createRule_v1').precondition as SinglePrecondition;
    expect(
      issues('DlpPoliciesController_createRule_v1', { precondition: { ...policy, params: {} } }),
    ).toEqual([
      'dlp_policies_create_rule: precondition params [] must map exactly the path parameters [id] of dlp_policies_get',
    ]);
  });

  it('redactParams only on read tools and only existing paths (D9)', () => {
    const replace = (name: string, redactParams: string[]) =>
      tools.map((t) => (t.name === name ? { ...t, redactParams } : t));
    expect(findTool('dlp_patterns_test')!.redactParams).toEqual(['body.sample', 'body.pattern']);
    expect(tools.filter((t) => t.redactParams.length > 0).map((t) => t.name)).toEqual([
      'dlp_patterns_test',
    ]);
    expect(registryConsistencyIssues(replace('dlp_patterns_create', ['body.pattern']))).toEqual([
      'dlp_patterns_create: redactParams is only allowed on read tools',
    ]);
    expect(registryConsistencyIssues(replace('dlp_patterns_test', ['body.text']))).toEqual([
      'dlp_patterns_test: redactParams names the missing argument body.text',
    ]);
    expect(registryConsistencyIssues(tools)).toEqual([]);
  });
});
