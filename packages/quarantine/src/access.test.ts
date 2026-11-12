import { describe, expect, it } from 'vitest';
import {
  allowedActionsFor,
  checkApprover,
  checkSelfService,
  isAccountableRequester,
  type AllowedActionsInput,
  type ApprovalRequester,
  type ApproverCheckInput,
  type SelfServiceInput,
} from './access';
import { resolveQuarantineSettings } from './settings';
import { QUARANTINE_PERMISSIONS as P } from './vocabulary';

const NOW = new Date('2026-11-12T12:00:00.000Z');
const ALL = Object.values(P);

describe('checkApprover (Q14 separation of duties)', () => {
  const base: ApproverCheckInput = {
    approver: {
      type: 'user',
      userId: 'u-approver',
      verifiedEmail: 'boss@corp.example',
      permissions: [P.approve],
    },
    request: {
      status: 'pending',
      kind: 'release_approval',
      expiresAt: new Date(NOW.getTime() + 3_600_000),
      requestedByType: 'user',
      requestedByUserId: 'u-requester',
      requestedByApiKeyCreatorUserId: null,
    },
    entry: { userId: 'u-recipient', recipientAddress: 'Victim@Corp.Example' },
    now: NOW,
  };
  const with_ = (patch: {
    approver?: Partial<ApproverCheckInput['approver']>;
    request?: Partial<ApproverCheckInput['request']>;
    entry?: Partial<ApproverCheckInput['entry']>;
  }): ApproverCheckInput => ({
    ...base,
    approver: { ...base.approver, ...patch.approver },
    request: { ...base.request, ...patch.request },
    entry: { ...base.entry, ...patch.entry },
  });
  it('a different authorized user approves', () => {
    expect(checkApprover(base)).toEqual({ allowed: true });
    expect(
      checkApprover(
        with_({
          request: { requestedByType: 'system', requestedByUserId: null, kind: 'policy_review' },
        }),
      ),
    ).toEqual({ allowed: true });
  });
  it.each([
    [
      'API key',
      with_({ approver: { type: 'api_key', userId: null } }),
      'quarantine_approval_forbidden',
      'api_key',
    ],
    [
      'missing permission',
      with_({ approver: { permissions: [P.read, P.release] } }),
      'quarantine_approval_forbidden',
      'missing_permission',
    ],
    [
      'end user (quarantine:self only)',
      with_({ approver: { permissions: [P.self] } }),
      'quarantine_approval_forbidden',
      'missing_permission',
    ],
    [
      'the requester',
      with_({ approver: { userId: 'u-requester' } }),
      'quarantine_approval_forbidden',
      'requester',
    ],
    [
      'the recipient by user id',
      with_({ approver: { userId: 'u-recipient' } }),
      'quarantine_approval_forbidden',
      'recipient',
    ],
    [
      'the recipient by verified address',
      with_({ approver: { verifiedEmail: ' victim@corp.example' } }),
      'quarantine_approval_forbidden',
      'recipient',
    ],
    [
      'not pending',
      with_({ request: { status: 'approved' } }),
      'quarantine_approval_not_pending',
      'not_pending',
    ],
    [
      'expired',
      with_({ request: { expiresAt: NOW } }),
      'quarantine_approval_not_pending',
      'expired',
    ],
  ] as Array<[string, ApproverCheckInput, string, string]>)(
    '%s → refused',
    (_n, input, code, reason) => {
      expect(checkApprover(input)).toEqual({ allowed: false, code, reason });
    },
  );
  it("an API-key requester is the key creator: the creator never approves the key's requests", () => {
    // The user id column of an API-key request is NULL; the creator of the key is accountable.
    const viaKey = (creator: string | null) =>
      with_({
        request: {
          requestedByType: 'api_key',
          requestedByUserId: null,
          requestedByApiKeyCreatorUserId: creator,
        },
      });
    expect(checkApprover(viaKey('u-approver'))).toEqual({
      allowed: false,
      code: 'quarantine_approval_forbidden',
      reason: 'requester',
    });
    expect(checkApprover(viaKey('u-someone-else'))).toEqual({ allowed: true });
    // A key whose creator was deleted: no live user is accountable, so nobody is barred.
    expect(checkApprover(viaKey(null))).toEqual({ allowed: true });
    // The user id column of an API-key request is never compared.
    expect(
      checkApprover(
        with_({
          request: {
            requestedByType: 'api_key',
            requestedByUserId: 'u-approver',
            requestedByApiKeyCreatorUserId: null,
          },
        }),
      ),
    ).toEqual({ allowed: true });
  });
});

describe('isAccountableRequester (Q14)', () => {
  it.each([
    [
      { requestedByType: 'user', requestedByUserId: 'u1', requestedByApiKeyCreatorUserId: null },
      true,
    ],
    [
      { requestedByType: 'user', requestedByUserId: 'u2', requestedByApiKeyCreatorUserId: 'u1' },
      false,
    ],
    [
      { requestedByType: 'api_key', requestedByUserId: null, requestedByApiKeyCreatorUserId: 'u1' },
      true,
    ],
    [
      { requestedByType: 'api_key', requestedByUserId: null, requestedByApiKeyCreatorUserId: null },
      false,
    ],
    [
      { requestedByType: 'system', requestedByUserId: 'u1', requestedByApiKeyCreatorUserId: 'u1' },
      false,
    ],
  ] as Array<[ApprovalRequester, boolean]>)('%o → %s', (request, expected) => {
    expect(isAccountableRequester(request, 'u1')).toBe(expected);
  });
});

describe('checkSelfService (Q15)', () => {
  const on = resolveQuarantineSettings({
    endUser: {
      selfRelease: true,
      selfReleaseReasons: ['spam', 'bulk'],
      selfReleaseMaxLevel: 'low',
    },
  }).settings;
  const base: SelfServiceInput = {
    action: 'release',
    settings: on,
    caller: { type: 'user', verifiedEmail: 'me@corp.example', permissions: [P.self] },
    entry: {
      recipientAddress: 'ME@corp.example',
      state: 'held',
      reason: 'spam',
      riskLevel: 'low',
      hasHardBlock: false,
    },
  };
  const s = (
    patch: Partial<Omit<SelfServiceInput, 'entry'>> & {
      entry?: Partial<NonNullable<SelfServiceInput['entry']>>;
    },
  ) => checkSelfService({ ...base, ...patch, entry: { ...base.entry!, ...patch.entry } });
  it('own entry, allowed reason and level → allowed', () => {
    expect(checkSelfService(base)).toEqual({ allowed: true });
    expect(s({ action: 'view' })).toEqual({ allowed: true });
    expect(s({ action: 'preview' })).toEqual({ allowed: true });
    expect(s({ action: 'request_release' })).toEqual({ allowed: true });
  });
  it.each([
    [
      'API key',
      { caller: { type: 'api_key', verifiedEmail: null, permissions: [P.self] } },
      'forbidden',
      'not_user',
    ],
    [
      'no quarantine:self',
      { caller: { type: 'user', verifiedEmail: 'me@corp.example', permissions: [P.read] } },
      'forbidden',
      'missing_permission',
    ],
    [
      'no verified email',
      { caller: { type: 'user', verifiedEmail: null, permissions: [P.self] } },
      'forbidden',
      'no_verified_email',
    ],
    [
      'end users disabled',
      { settings: resolveQuarantineSettings({ endUser: { enabled: false } }).settings },
      'quarantine_entry_not_found',
      'end_user_disabled',
    ],
    [
      'another address → 404',
      { entry: { recipientAddress: 'other@corp.example' } },
      'quarantine_entry_not_found',
      'not_own_entry',
    ],
    ['not held', { entry: { state: 'pending_approval' } }, 'quarantine_state_conflict', 'state'],
    [
      'self-release disabled',
      { settings: resolveQuarantineSettings(null).settings },
      'quarantine_self_release_not_allowed',
      'self_release_disabled',
    ],
    [
      'reason not allowed',
      { entry: { reason: 'policy' } },
      'quarantine_self_release_not_allowed',
      'reason_not_allowed',
    ],
    [
      'level too high',
      { entry: { riskLevel: 'medium' } },
      'quarantine_self_release_not_allowed',
      'level_too_high',
    ],
    [
      'unknown level',
      { entry: { riskLevel: null } },
      'quarantine_self_release_not_allowed',
      'level_unknown',
    ],
    [
      'hard block',
      { entry: { hasHardBlock: true } },
      'quarantine_self_release_not_allowed',
      'approval_required',
    ],
    [
      'approval reasons',
      { approvalReasons: ['dlp_quarantine'] },
      'quarantine_self_release_not_allowed',
      'approval_required',
    ],
    ['stale', { stale: true }, 'quarantine_self_release_not_allowed', 'stale'],
  ] as Array<[string, Parameters<typeof s>[0], string, string]>)(
    'release: %s',
    (_n, patch, code, cause) => {
      expect(s(patch)).toEqual({ allowed: false, code, cause });
    },
  );
  it('preview is refused when disabled or for dangerous entries', () => {
    const off = resolveQuarantineSettings({ endUser: { preview: false } }).settings;
    expect(s({ action: 'preview', settings: off })).toMatchObject({ cause: 'preview_disabled' });
    for (const entry of [
      { hasHardBlock: true },
      { reason: 'malware' as const },
      { reason: 'phishing' as const },
    ]) {
      expect(s({ action: 'preview', entry })).toEqual({
        allowed: false,
        code: 'quarantine_preview_not_allowed',
        cause: 'preview_not_allowed',
      });
    }
  });
  it('request-release follows its switch and the state', () => {
    const off = resolveQuarantineSettings({ endUser: { requestRelease: false } }).settings;
    expect(s({ action: 'request_release', settings: off })).toMatchObject({
      cause: 'request_release_disabled',
    });
    expect(s({ action: 'request_release', entry: { state: 'released' } })).toMatchObject({
      cause: 'state',
    });
  });
  it('preferences: opt-out only when allowed', () => {
    const p = (allow: boolean, changes: boolean) =>
      checkSelfService({
        action: 'preferences',
        settings: resolveQuarantineSettings({ digest: { allowOptOut: allow } }).settings,
        caller: base.caller,
        changesDigestOptOut: changes,
      });
    expect(p(true, true)).toEqual({ allowed: true });
    expect(p(false, false)).toEqual({ allowed: true });
    expect(p(false, true)).toMatchObject({ allowed: false, cause: 'opt_out_not_allowed' });
  });
});

describe('allowedActionsFor (Q10)', () => {
  const settings = resolveQuarantineSettings({ download: { enabled: true } }).settings;
  const base: AllowedActionsInput = {
    entry: {
      state: 'held',
      kind: 'quarantine',
      reason: 'spam',
      riskLevel: 'low',
      hasHardBlock: false,
      contentAvailable: true,
    },
    permissions: ALL,
    settings,
    isSelf: false,
  };
  const a = (
    patch: Partial<Omit<AllowedActionsInput, 'entry'>> & {
      entry?: Partial<AllowedActionsInput['entry']>;
    },
  ) => allowedActionsFor({ ...base, ...patch, entry: { ...base.entry, ...patch.entry } });
  it('an admin on a held entry can do everything', () => {
    expect(a({})).toEqual([
      'preview',
      'release',
      'request_release',
      'reject',
      'delete',
      'download',
    ]);
  });
  it('follows permissions', () => {
    expect(a({ permissions: [P.read] })).toEqual([]);
    expect(a({ permissions: [P.read, P.release, P.reject] })).toEqual(['release', 'reject']);
  });
  it('follows the state', () => {
    expect(a({ entry: { state: 'pending_approval' } })).toEqual([
      'preview',
      'reject',
      'delete',
      'download',
    ]);
    expect(a({ entry: { state: 'releasing' } })).toEqual(['preview', 'download']);
    expect(a({ entry: { state: 'rejected' } })).toEqual(['preview', 'delete', 'download']);
    expect(a({ entry: { state: 'deleted', contentAvailable: false } })).toEqual([]);
    expect(a({ entry: { state: 'released' } })).toEqual(['preview', 'download']);
  });
  it('hard blocks: no download; release only when the tenant allows it', () => {
    expect(a({ entry: { hasHardBlock: true } })).toEqual([
      'preview',
      'release',
      'request_release',
      'reject',
      'delete',
    ]);
    const strict = resolveQuarantineSettings({
      release: { allowHardBlocks: false },
      download: { enabled: true },
    }).settings;
    expect(a({ settings: strict, entry: { hasHardBlock: true } })).toEqual([
      'preview',
      'request_release',
      'reject',
      'delete',
    ]);
    expect(a({ entry: { reason: 'malware' } })).not.toContain('download');
  });
  it('download needs the tenant setting', () => {
    expect(a({ settings: resolveQuarantineSettings(null).settings })).not.toContain('download');
  });
  it('self callers: preview, bounded release, request only', () => {
    const on = resolveQuarantineSettings({ endUser: { selfRelease: true } }).settings;
    const self = (
      patch: Partial<AllowedActionsInput['entry']> = {},
      s = on,
      perms: string[] = [P.self],
    ) =>
      allowedActionsFor({
        entry: { ...base.entry, ...patch },
        permissions: perms,
        settings: s,
        isSelf: true,
      });
    expect(self()).toEqual(['preview', 'release', 'request_release']);
    expect(self({ riskLevel: 'high' })).toEqual(['preview', 'request_release']);
    expect(self({ reason: 'policy' })).toEqual(['preview', 'request_release']);
    expect(self({ kind: 'review' })).toEqual(['preview', 'request_release']);
    expect(self({ reason: 'phishing' })).toEqual(['request_release']);
    expect(self({}, resolveQuarantineSettings(null).settings)).toEqual([
      'preview',
      'request_release',
    ]);
    expect(self({}, on, [P.read])).toEqual([]);
    expect(self({}, resolveQuarantineSettings({ endUser: { enabled: false } }).settings)).toEqual(
      [],
    );
    expect(self({ state: 'pending_approval' })).toEqual(['preview']);
  });
});
