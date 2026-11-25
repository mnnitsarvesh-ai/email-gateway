import { describe, expect, it } from 'vitest';
import {
  GUARD_MESSAGES,
  guardArgumentPaths,
  guardMessageOf,
  guardNote,
  guardPhase,
  guardRefusal,
  type ProposalGuard,
} from './guards';
import { EXECUTION_DECISIONS } from '../results/types';
import { CONFIRMATION_SPECS, confirmationSpecOf, type ConfirmationSpec } from './specs';

const SELF = '0193aaaa-0000-7000-8000-00000000abcd';
const OTHER = '0193aaaa-0000-7000-8000-000000000042';
const spec = (operationId: string): ConfirmationSpec => confirmationSpecOf(operationId)!;
const before = (
  s: Pick<ConfirmationSpec, 'guards'>,
  args: Record<string, unknown>,
  read: unknown = null,
) => guardRefusal(s, { args, principalUserPublicId: SELF, read }, 'before_read');
const after = (s: Pick<ConfirmationSpec, 'guards'>, args: Record<string, unknown>, read: unknown) =>
  guardRefusal(s, { args, principalUserPublicId: SELF, read }, 'after_read');

describe('proposal guards (design 30 D3)', () => {
  it('adds the executor decision denied_guard (last, as in the database enum)', () => {
    expect(EXECUTION_DECISIONS).toHaveLength(9);
    expect(EXECUTION_DECISIONS.at(-1)).toBe('denied_guard');
  });

  it('uses the exact server-authored messages', () => {
    expect(GUARD_MESSAGES).toEqual({
      self: 'Changes to your own account, roles, status, MFA or sessions are not available in chat. Ask another administrator, or use your account pages in the portal.',
      assistant_feature:
        'The assistant cannot turn itself on or off for an organization. Use the Organizations page in the portal.',
      assistant_configure:
        'The assistant cannot change who may configure it. Change roles that grant assistant:configure in the portal.',
      ato_four_eyes:
        'This response needs a different person to decide it. The person who requested a response, or who created the API key that requested it, can never approve or reject it, and deciding needs a session signed in with MFA. Ask another responder to decide it in chat or on the Responses page.',
    });
  });

  it('puts the guards of the design on exactly these tools', () => {
    const table = Object.fromEntries(
      CONFIRMATION_SPECS.filter((s) => s.guards).map((s) => [
        s.operationId,
        s.guards!.map(guardNote).join('; '),
      ]),
    );
    expect(table).toEqual({
      UsersController_update_v1: 'guard: not self',
      UsersController_changeStatus_v1: 'guard: not self',
      UsersController_replaceRoles_v1: 'guard: not self',
      UsersController_resetMfa_v1: 'guard: not self',
      UsersController_remove_v1: 'guard: not self',
      UsersController_resendInvitation_v1: 'guard: not self',
      UsersController_revokeAllSessions_v1: 'guard: not self',
      UsersController_revokeSession_v1: 'guard: not self',
      RolesController_create_v1: 'guard: no change of assistant:configure',
      RolesController_update_v1: 'guard: no change of assistant:configure',
      OrganizationConfigurationController_overrideFeature_v1: 'guard: featureKey ≠ ai_assistant',
      OrganizationConfigurationController_resetFeature_v1: 'guard: featureKey ≠ ai_assistant',
      // step AI-4 D3 (I18)
      AtoResponsesController_approve_v1: 'guard: not requester; guard: canDecide = true',
      AtoResponsesController_reject_v1: 'guard: not requester; guard: canDecide = true',
    });
  });

  it('not_self_user: refuses the caller (case-insensitive UUID compare), allows others', () => {
    const roles = spec('UsersController_replaceRoles_v1');
    const args = { id: SELF, body: { roleKeys: ['organization_admin'] } };
    expect(before(roles, args)).toEqual({ guard: 'not_self_user', message: GUARD_MESSAGES.self });
    expect(before(roles, { ...args, id: SELF.toUpperCase() })?.guard).toBe('not_self_user');
    expect(before(roles, { ...args, id: ` ${SELF} ` })?.guard).toBe('not_self_user');
    expect(
      guardRefusal(
        roles,
        { args, principalUserPublicId: SELF.toUpperCase(), read: null },
        'before_read',
      )?.guard,
    ).toBe('not_self_user');
    expect(before(roles, { ...args, id: OTHER })).toBeNull();
    expect(before(roles, { body: {} })).toBeNull(); // the schema check refuses a missing id
    expect(
      guardRefusal(roles, { args, principalUserPublicId: '', read: null }, 'before_read'),
    ).toBeNull();
    // A before-read guard is not evaluated in the after-read phase.
    expect(after(roles, args, {})).toBeNull();
    expect(
      before(spec('UsersController_revokeSession_v1'), { id: SELF, sessionId: OTHER })?.guard,
    ).toBe('not_self_user');
  });

  it('deny_values: the assistant cannot change its own feature', () => {
    const override = spec('OrganizationConfigurationController_overrideFeature_v1');
    const args = { id: OTHER, featureKey: 'ai_assistant', body: { enabled: false } };
    expect(before(override, args)).toEqual({
      guard: 'deny_values',
      message: GUARD_MESSAGES.assistant_feature,
    });
    expect(before(override, { ...args, featureKey: 'AI_Assistant' })?.guard).toBe('deny_values');
    expect(before(override, { ...args, featureKey: 'dlp' })).toBeNull();
    const reset = spec('OrganizationConfigurationController_resetFeature_v1');
    expect(before(reset, { id: OTHER, featureKey: 'ai_assistant' })?.message).toBe(
      GUARD_MESSAGES.assistant_feature,
    );
  });

  it('deny_permission_change without beforeField (roles_create) runs before the read', () => {
    const create = spec('RolesController_create_v1');
    const body = (permissions: string[]) => ({
      body: { key: 'k', name: 'n', permissions },
    });
    expect(before(create, body(['quarantine:read', 'assistant:configure']))).toEqual({
      guard: 'deny_permission_change',
      message: GUARD_MESSAGES.assistant_configure,
    });
    expect(before(create, body(['quarantine:read']))).toBeNull();
    expect(after(create, body(['assistant:configure']), null)).toBeNull();
  });

  it('deny_permission_change with beforeField (roles_update) runs after the read: add and remove', () => {
    const update = spec('RolesController_update_v1');
    const args = (permissions: string[]) => ({ key: 'triage', body: { name: 'T', permissions } });
    const read = (permissions: string[]) => ({ key: 'triage', permissions });
    expect(before(update, args(['assistant:configure']))).toBeNull();
    expect(after(update, args(['a', 'assistant:configure']), read(['a']))?.guard).toBe(
      'deny_permission_change',
    );
    expect(after(update, args(['a']), read(['a', 'assistant:configure']))?.message).toBe(
      GUARD_MESSAGES.assistant_configure,
    );
    // Keeping it (or never having it) is no change.
    expect(
      after(update, args(['b', 'assistant:configure']), read(['assistant:configure', 'a'])),
    ).toBeNull();
    expect(after(update, args(['b']), read(['a']))).toBeNull();
    // Fail closed: no readable old set, or a malformed new set.
    expect(after(update, args(['a']), null)?.guard).toBe('deny_permission_change');
    expect(after(update, args(['a']), { permissions: 'x' })?.guard).toBe('deny_permission_change');
    expect(after(update, { key: 'triage', body: { permissions: [1] } }, read(['a']))?.guard).toBe(
      'deny_permission_change',
    );
    // An omitted list changes nothing.
    expect(after(update, { key: 'triage', body: { name: 'T' } }, read(['a']))).toBeNull();
  });

  it('derives the refusal message of a stored denied_guard execution from the spec (D12)', () => {
    expect(guardMessageOf(spec('UsersController_replaceRoles_v1'))).toBe(GUARD_MESSAGES.self);
    expect(guardMessageOf(spec('UsersController_revokeSession_v1'))).toBe(GUARD_MESSAGES.self);
    expect(guardMessageOf(spec('RolesController_update_v1'))).toBe(
      GUARD_MESSAGES.assistant_configure,
    );
    expect(guardMessageOf(spec('OrganizationConfigurationController_overrideFeature_v1'))).toBe(
      GUARD_MESSAGES.assistant_feature,
    );
    // The derived message is the one the live refusal carried.
    for (const s of CONFIRMATION_SPECS.filter((c) => c.guards)) {
      for (const guard of s.guards!) {
        const key = guard.kind === 'not_self_user' ? 'self' : guard.message;
        expect(guardMessageOf(s)).toBe(GUARD_MESSAGES[key]);
      }
    }
    expect(guardMessageOf(spec('PolicyManagementController_disable_v1'))).toBeNull();
    expect(guardMessageOf(undefined)).toBeNull();
    expect(
      guardMessageOf({
        guards: [
          { kind: 'not_self_user', arg: 'id' },
          { kind: 'deny_values', arg: 'k', values: ['x'], message: 'assistant_feature' },
        ],
      }),
    ).toBeNull();
  });

  it('phases and messages never contain argument values', () => {
    const guards: ProposalGuard[] = CONFIRMATION_SPECS.flatMap((s) => s.guards ?? []);
    // roles_update, plus the two four-eyes guards of ATO approve and reject (step AI-4).
    expect(guards.filter((g) => guardPhase(g) === 'after_read')).toHaveLength(5);
    const marker = 'VALUE-MARKER-1234';
    const refusals = [
      before(spec('UsersController_update_v1'), { id: SELF, body: { displayName: marker } }),
      before(spec('OrganizationConfigurationController_overrideFeature_v1'), {
        id: marker,
        featureKey: 'ai_assistant',
        body: { enabled: true },
      }),
      before(spec('RolesController_create_v1'), {
        body: { key: marker, name: marker, permissions: ['assistant:configure', marker] },
      }),
    ];
    for (const refusal of refusals) {
      expect(refusal).not.toBeNull();
      expect(JSON.stringify(refusal)).not.toContain(marker);
      expect(JSON.stringify(refusal)).not.toContain(SELF);
    }
    expect(
      guardRefusal({}, { args: {}, principalUserPublicId: SELF, read: null }, 'before_read'),
    ).toBeNull();
  });
});

describe('ATO four-eyes guards (design 32 D3, I18)', () => {
  const RESPONSE = '0193aaaa-0000-7000-8000-000000000777';
  const args = { responseId: RESPONSE, body: { reason: 'Looks right' } };
  const response = (patch: Record<string, unknown> = {}) => ({
    id: RESPONSE,
    actionType: 'restrict_smtp_sending',
    status: 'pending_approval',
    requestedBy: { type: 'user', id: OTHER },
    canDecide: true,
    ...patch,
  });
  const FOUR_EYES = GUARD_MESSAGES.ato_four_eyes;

  it('are after-read guards that read no argument', () => {
    for (const name of ['AtoResponsesController_approve_v1', 'AtoResponsesController_reject_v1']) {
      const s = spec(name);
      expect(s.guards!.map(guardPhase)).toEqual(['after_read', 'after_read']);
      expect(s.guards!.flatMap(guardArgumentPaths)).toEqual([]);
      expect(guardMessageOf(s)).toBe(FOUR_EYES);
      // Nothing is refused before the read: the target is needed.
      expect(before(s, args)).toBeNull();
    }
    expect(spec('AtoResponsesController_cancel_v1').guards).toBeUndefined();
    expect(spec('AtoResponsesController_rollback_v1').guards).toBeUndefined();
  });

  it.each(['AtoResponsesController_approve_v1', 'AtoResponsesController_reject_v1'])(
    '%s: requester refused; API-key request without canDecide refused; another responder allowed',
    (operationId) => {
      const s = spec(operationId);
      // The requesting user (any case of the id): refused by the explicit requester check, even
      // if the view's canDecide were wrong.
      expect(after(s, args, response({ requestedBy: { type: 'user', id: SELF } }))).toEqual({
        guard: 'not_self_field',
        message: FOUR_EYES,
      });
      expect(
        after(
          s,
          args,
          response({ requestedBy: { type: 'user', id: SELF.toUpperCase() }, canDecide: true }),
        )?.guard,
      ).toBe('not_self_field');
      // Requested by an API key the caller created: the api's canDecide is false.
      expect(
        after(s, args, response({ requestedBy: { type: 'api_key', id: SELF }, canDecide: false })),
      ).toEqual({ guard: 'require_read_value', message: FOUR_EYES });
      // An API key whose public id happens to equal the user id is not the user (type gate).
      expect(
        after(s, args, response({ requestedBy: { type: 'api_key', id: SELF }, canDecide: true })),
      ).toBeNull();
      // A session without MFA: canDecide false.
      expect(after(s, args, response({ canDecide: false }))?.guard).toBe('require_read_value');
      // Another responder with canDecide true.
      expect(after(s, args, response())).toBeNull();
    },
  );

  it('a response that is not pending passes both guards (the api answers 409)', () => {
    const s = spec('AtoResponsesController_approve_v1');
    for (const status of ['approved', 'succeeded', 'rejected', 'expired'])
      expect(after(s, args, response({ status, canDecide: false })), status).toBeNull();
    // The requester check does not depend on the status.
    expect(
      after(s, args, response({ status: 'approved', requestedBy: { type: 'user', id: SELF } }))
        ?.guard,
    ).toBe('not_self_field');
  });

  it('missing fields: no requester passes the first guard; a missing canDecide fails closed', () => {
    const s = spec('AtoResponsesController_approve_v1');
    expect(after(s, args, response({ requestedBy: { type: 'system', id: null } }))).toBeNull();
    expect(after(s, args, response({ requestedBy: undefined }))).toBeNull();
    const { canDecide: _canDecide, ...withoutCanDecide } = response();
    expect(after(s, args, withoutCanDecide)?.guard).toBe('require_read_value');
    expect(after(s, args, response({ canDecide: 'true' }))?.guard).toBe('require_read_value');
    // No read at all: the status gate does not hold, so nothing is refused (the proposal has
    // already failed when the read failed).
    expect(after(s, args, null)).toBeNull();
    expect(after(s, args, {})).toBeNull();
  });

  it('generic semantics of the two kinds (synthetic specs)', () => {
    const notSelf: ProposalGuard = { kind: 'not_self_field', field: 'owner.id', message: 'self' };
    const required: ProposalGuard = {
      kind: 'require_read_value',
      field: 'state',
      equals: 'open',
      message: 'self',
    };
    const check = (guard: ProposalGuard, read: unknown) => after({ guards: [guard] }, {}, read);
    expect(check(notSelf, { owner: { id: ` ${SELF} ` } })?.guard).toBe('not_self_field');
    expect(check(notSelf, { owner: { id: OTHER } })).toBeNull();
    expect(check(notSelf, { owner: {} })).toBeNull();
    expect(check(notSelf, { owner: { id: 42 } })).toBeNull();
    expect(check(required, { state: 'open' })).toBeNull();
    expect(check(required, { state: 'closed' })?.guard).toBe('require_read_value');
    expect(check(required, {})?.guard).toBe('require_read_value');
    expect(guardNote(notSelf)).toBe('guard: not requester');
    expect(guardNote(required)).toBe('guard: state = open');
    // Never evaluated before the read.
    expect(before({ guards: [notSelf, required] }, {}, { state: 'closed' })).toBeNull();
  });

  it('refusals carry no read or argument value', () => {
    const marker = 'VALUE-MARKER-5678';
    const refusal = after(
      spec('AtoResponsesController_approve_v1'),
      { responseId: marker, body: { reason: marker } },
      response({ requestedBy: { type: 'user', id: SELF }, requestReason: marker }),
    );
    expect(refusal).not.toBeNull();
    expect(JSON.stringify(refusal)).not.toContain(marker);
    expect(JSON.stringify(refusal)).not.toContain(SELF);
  });
});
