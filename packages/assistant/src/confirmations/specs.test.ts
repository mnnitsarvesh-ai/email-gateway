import { describe, expect, it } from 'vitest';
import { registryConsistencyIssues } from '../registry/consistency';
import { AI2_WRITES_TESTED_BY } from '../registry/manifest';
import { OPERATION_TOOLS, compileValidator, findOperation, findTool } from '../registry/registry';
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
  withCasPlaceholder,
  withInjectedCas,
  type ConfirmationSpec,
  type EachPrecondition,
  type SinglePrecondition,
} from './specs';

const spec = (operationId: string): ConfirmationSpec => confirmationSpecOf(operationId)!;
const POLICY = '0193aaaa-0000-7000-8000-000000000002';

describe('confirmation specs (D4)', () => {
  it('one spec per AI-2 write, every one an enabled write of the registry', () => {
    expect(CONFIRMATION_SPECS).toHaveLength(31);
    expect(CONFIRMATION_SPECS.map((s) => s.operationId).sort()).toEqual(
      Object.keys(AI2_WRITES_TESTED_BY).sort(),
    );
    const enabledWrites = OPERATION_TOOLS.filter((t) => t.enabled && t.access === 'write');
    expect(enabledWrites.map((t) => t.operationId).sort()).toEqual(
      CONFIRMATION_SPECS.map((s) => s.operationId).sort(),
    );
    expect(confirmationSpecOf('PolicyManagementController_list_v1')).toBeUndefined();
  });

  it('the registry consistency rules hold for the generated registry', () => {
    expect(registryConsistencyIssues(OPERATION_TOOLS)).toEqual([]);
  });

  it('names the design D4 preconditions, state fields and CAS injections', () => {
    const table = Object.fromEntries(
      CONFIRMATION_SPECS.map((s) => [
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
  const tools = OPERATION_TOOLS;
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
      operationId: 'UsersController_invite_v1',
      precondition: null,
    };
    expect(registryConsistencyIssues(tools, { specs: [...CONFIRMATION_SPECS, extra] })).toEqual([
      'UsersController_invite_v1: confirmation spec without an enabled write tool',
    ]);
    expect(
      registryConsistencyIssues(tools, { specs: [...CONFIRMATION_SPECS, CONFIRMATION_SPECS[0]!] }),
    ).toEqual(['PolicyManagementController_create_v1: more than one confirmation spec']);
  });

  it('no tool after the program phase is enabled; no write before the confirmation phase', () => {
    const invite = findTool('users_invite')!;
    expect(invite.enabled).toBe(false);
    expect(invite.phase).toBe('AI-3');
    const issues = registryConsistencyIssues(
      replace('users_invite', { enabled: true, testedBy: 'x.test.ts' }),
    );
    expect(issues).toEqual(
      expect.arrayContaining([
        'users_invite: enabled although its phase AI-3 is after the program phase',
        'users_invite: enabled write without a confirmation spec',
        'users_invite: enabled write without an impact template',
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
