import { describe, expect, it } from 'vitest';
import type { Principal } from '../../../auth-contracts/principal';
import type { ClawbackRow, HistoryRow, TargetRow } from '../repositories/api-clawback.repository';
import { ClawbackService, permissionsHash } from './clawback.service';
import { effectiveSettings, OrgSettingsService } from './org-settings.service';
import { originalOf, reopenCountOf } from './reports.service';

/**
 * Unit tests of the step API-3 services' views and helpers (design note 37 C14 #3, #4, #12, #18):
 * the target view's `remediation:purge` gating, the clawback detail hints, the approver
 * permission hash, the triage history's reopen count, the stored original's parse and the
 * settings view. The writes run over HTTP in test/api-mode-clawback.e2e.test.ts and
 * test/api-mode-reports.e2e.test.ts, and on the real writer in integration/api-mode-clawback.test.ts.
 */

const config = {
  API_MODE_HARD_DELETE_ENABLED: false,
  API_MODE_CLAWBACK_MAX_WINDOW_DAYS: 31,
  API_MODE_PURGE_APPROVAL_TTL_HOURS: 72,
  API_MODE_REPORT_MAILBOXES_MAX: 5,
};
const service = new ClawbackService(
  config,
  ...([null, null, null, null, null] as unknown as [never, never, never, never, never]),
);
const NOW = new Date('2026-11-27T10:00:00.000Z');

const user = (permissions: string[], userId = 10n): Principal => ({
  kind: 'user',
  userId,
  userPublicId: '0192f3a0-cccc-7000-8000-00000000000c',
  organizationId: 1n,
  organizationPublicId: '0192f3a0-1111-7000-8000-000000000001',
  organizationKind: 'customer',
  sessionId: 's',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(permissions),
});

const target: TargetRow = {
  id: 1n,
  mailboxPublicId: '0192f3a0-5555-7000-8000-000000000005',
  mailboxAddress: 'alex@contoso.example',
  connectionPublicId: '0192f3a0-3333-7000-8000-000000000003',
  detectionPublicId: '0192f3a0-6666-7000-8000-000000000006',
  receivedAt: NOW,
  headerFrom: 'billing@fabrikam.example',
  subject: 'Invoice overdue',
  matchKeys: ['message_id', 42, 'url'],
  copyRemediationState: 'none',
  status: 'matched',
  plannedAction: null,
  reasonCode: null,
  remediationPublicId: null,
  restoreStatus: 'none',
  restoreReasonCode: null,
};

function clawback(patch: Partial<ClawbackRow> = {}): ClawbackRow {
  return {
    id: 5n,
    publicId: '0192f3a0-eeee-7000-8000-00000000000e',
    trigger: 'admin',
    status: 'pending_approval',
    signal: { v: 1, kind: 'admin', refs: {}, facts: null, signalAt: NOW.toISOString() },
    criteria: {
      v: 1,
      window: { from: '2026-11-26T00:00:00.000Z', to: NOW.toISOString() },
      keys: {
        messageIdHashes: ['a'.repeat(64)],
        senderSubject: { sender: 'a@b.example', subjectKey: 'Hi' },
      },
      directions: ['inbound'],
      includeReportMailboxes: false,
    },
    decisionMode: 'explicit',
    action: 'move_junk',
    signalVerdict: null,
    signalLevel: null,
    signalHardBlocks: null,
    cancelRequestedAt: null,
    restoreStatus: 'none',
    targetsTotal: 2,
    mailboxesTotal: 2,
    targetsEligible: 2,
    mailboxesEligible: 2,
    targetsSkipped: 0,
    targetsSimulated: 0,
    targetsQueued: 0,
    targetsSucceeded: 0,
    targetsFailed: 0,
    targetsCancelled: 0,
    restoresQueued: 0,
    restoresSucceeded: 0,
    restoresFailed: 0,
    restoresSkipped: 0,
    requiresApproval: true,
    approvalReasons: ['mailbox_threshold'],
    approvalStatus: 'pending',
    approvalRequestedAt: NOW,
    approvalExpiresAt: new Date(NOW.getTime() + 3_600_000),
    approvalDecidedAt: null,
    approvedByUserId: null,
    approvalDecisionReason: null,
    requestedByType: 'user',
    requestedByUserId: 77n,
    submittedByUserId: 78n,
    requestReason: 'x',
    submittedAt: NOW,
    reportId: null,
    seedCopyId: null,
    seedCopyReceivedAt: null,
    signalAt: NOW,
    lastErrorCode: null,
    rowVersion: 4,
    startedAt: null,
    completedAt: null,
    createdAt: NOW,
    updatedAt: NOW,
    reportPublicId: null,
    requestedByUserPublicId: null,
    submittedByUserPublicId: null,
    approvedByUserPublicId: null,
    seedCopyPublicId: null,
    ...patch,
  };
}

describe('ClawbackService views (C14 #3, #4)', () => {
  it('targets: masked mailbox and no sender/subject without remediation:purge; unknown match keys dropped', () => {
    expect(service.targetView(target, false)).toMatchObject({
      mailbox: { address: 'a***@contoso.example' },
      headerFrom: null,
      subject: null,
      matchKeys: ['message_id', 'url'],
    });
    expect(service.targetView(target, true)).toMatchObject({
      mailbox: { address: 'alex@contoso.example' },
      headerFrom: 'billing@fabrikam.example',
      subject: 'Invoice overdue',
    });
  });

  it('detail: truncated hashes, the sender + subject key and the caller hints', () => {
    const view = service.detailView(
      clawback(),
      user(['remediation:read', 'remediation:purge']),
      NOW,
    );
    expect(view.criteria.keys.messageIdHashes).toEqual([`${'a'.repeat(12)}…`]);
    expect(view.criteria.keys.senderSubject).toEqual({ sender: 'a@b.example', subjectKey: 'Hi' });
    expect(view.hints).toEqual({
      canSubmit: false,
      canApprove: true,
      canCancel: true,
      canRestore: false,
    });
    expect(
      service.detailView(clawback(), user(['remediation:purge'], 78n), NOW).hints.canApprove,
    ).toBe(false);
    expect(
      service.detailView(
        clawback({ status: 'completed', approvalStatus: 'approved', targetsSucceeded: 2 }),
        user(['remediation:purge', 'quarantine:release']),
        NOW,
      ).hints,
    ).toMatchObject({ canRestore: true, canCancel: false });
  });

  it('a stored criteria document that no longer parses reads as empty (never throws)', () => {
    const view = service.detailView(clawback({ criteria: { v: 9 } }), user([]), NOW);
    expect(view.criteria.keys.messageIdHashes).toEqual([]);
    expect(view.criteria.directions).toEqual([]);
  });

  it('permissionsHash is the SHA-256 of the sorted permission keys', () => {
    expect(permissionsHash(user(['b', 'a']))).toBe(permissionsHash(user(['a', 'b'])));
    expect(permissionsHash(user(['a']))).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('ReportsService helpers (C11, C14 #12)', () => {
  it('reopenCountOf counts the reopen rows of the triage history', () => {
    const row = (metadata: unknown): HistoryRow => ({
      at: NOW,
      actorType: 'user',
      actorId: 'u',
      metadata,
    });
    expect(
      reopenCountOf([
        row({ from: 'pending_triage', to: 'resolved', reopened: false }),
        row({ from: 'resolved', to: 'in_review', reopened: true }),
        row(null),
      ]),
    ).toBe(1);
  });

  it('originalOf parses api-report-original/1 leniently (invalid → null)', () => {
    expect(originalOf({ v: 2 })).toBeNull();
    expect(
      originalOf({
        v: 1,
        messageIdHash: null,
        sender: 'a@b.example',
        subjectKey: 'Hi',
        date: null,
        attachmentSha256: [],
        urlSha256: [],
        extraOriginals: 0,
      }),
    ).toMatchObject({ sender: 'a@b.example' });
  });
});

describe('OrgSettingsService view (C14 #18)', () => {
  const settings = new OrgSettingsService(
    config,
    ...([null, null, null] as unknown as [never, never, never]),
  );

  it('defaults without a row; the row (clamped) with its version otherwise; platform facts', () => {
    expect(settings.view(null)).toMatchObject({
      source: 'defaults',
      rowVersion: null,
      settings: { autoClawback: 'enforce', purgeApprovalMailboxes: 50 },
      platform: { hardDeleteAvailable: false, reportMailboxesMax: 5 },
    });
    const row = {
      internalMailEnabled: false,
      autoClawback: 'review' as const,
      autoMaxMailboxes: 99_999,
      purgeApprovalMailboxes: 20,
      clawbackLookbackDays: 7,
      tiMinConfidence: 90,
      reportAckEnabled: true,
      reportFeedbackEnabled: false,
      rowVersion: 3,
      updatedAt: NOW,
      purgeApprovalRaisedBy: null,
      purgeApprovalBeforeRaise: null,
    };
    expect(settings.view(row)).toMatchObject({
      source: 'row',
      rowVersion: 3,
      settings: { internalMailEnabled: false, autoClawback: 'review', autoMaxMailboxes: 20_000 },
    });
    expect(effectiveSettings(row).autoMaxMailboxes).toBe(20_000);
  });
});
