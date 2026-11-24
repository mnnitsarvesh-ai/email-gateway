import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { normalizeSchema, successResponseSchema, type OpenApiDocument } from '../registry/build';
import { credentialKeyPaths, registryConsistencyIssues } from '../registry/consistency';
import {
  AI2_WRITES_TESTED_BY,
  AI3_WRITES_TESTED_BY,
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
  it('one spec per AI-2, AI-3 and native AI-R write, every one an enabled write of the registry', () => {
    expect(CONFIRMATION_SPECS).toHaveLength(79);
    expect(CONFIRMATION_SPECS.map((s) => s.operationId).sort()).toEqual(
      [
        ...Object.keys(AI2_WRITES_TESTED_BY),
        ...Object.keys(AI3_WRITES_TESTED_BY),
        'AssistantNative_reportSendEmail',
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
    const extra: ConfirmationSpec = {
      operationId: 'AtoAccountsController_update_v1',
      precondition: null,
    };
    expect(registryConsistencyIssues(tools, { specs: [...CONFIRMATION_SPECS, extra] })).toEqual([
      'AtoAccountsController_update_v1: confirmation spec without an enabled write tool',
    ]);
    expect(
      registryConsistencyIssues(tools, { specs: [...CONFIRMATION_SPECS, CONFIRMATION_SPECS[0]!] }),
    ).toEqual(['PolicyManagementController_create_v1: more than one confirmation spec']);
  });

  it('no tool after the program phase is enabled; no write before the confirmation phase', () => {
    const invite = findTool('ato_accounts_update')!;
    expect(invite.enabled).toBe(false);
    expect(invite.phase).toBe('AI-4');
    const issues = registryConsistencyIssues(
      replace('ato_accounts_update', { enabled: true, testedBy: 'x.test.ts' }),
    );
    expect(issues).toEqual(
      expect.arrayContaining([
        'ato_accounts_update: enabled although its phase AI-4 is after the program phase',
        'ato_accounts_update: enabled write without a confirmation spec',
        'ato_accounts_update: enabled write without an impact template',
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
      ])
        expect(schemaAt(schema, path), `${s.operationId}: ${path}`).not.toBeNull();
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
      'RolesController_create_v1',
      'RolesController_remove_v1',
      'RolesController_update_v1',
    ]);
    // A disabled tool's schema is not checked (secret-returning operations are N/A anyway).
    expect(
      registryConsistencyIssues(
        withSecret.map((t) => (t.name === 'webhooks_update' ? { ...t, enabled: false } : t)),
      ),
    ).toEqual(['WebhooksController_update_v1: confirmation spec without an enabled write tool']);
  });
});
