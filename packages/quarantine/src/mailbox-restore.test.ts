import { describe, expect, it } from 'vitest';
import {
  API_COPY_STATUSES,
  decideMailboxRestore,
  mailboxRestoreApprovalReasons,
  type DecideMailboxRestoreInput,
} from './mailbox-restore';
import { resolveQuarantineSettings } from './settings';
import {
  MAILBOX_CONTAINERS,
  QUARANTINE_LOCATIONS,
  QUARANTINE_ORIGINS,
  QUARANTINE_RELEASE_STATUSES,
} from './vocabulary';
import { quarantineEntryLocationSchema } from './dto';

const defaults = resolveQuarantineSettings(null).settings;
const noHardBlocks = resolveQuarantineSettings({ release: { allowHardBlocks: false } }).settings;
const selfOn = resolveQuarantineSettings({
  endUser: {
    enabled: true,
    selfRelease: true,
    selfReleaseReasons: ['spam', 'bulk'],
    selfReleaseMaxLevel: 'medium',
  },
}).settings;

const base = {
  entry: {
    kind: 'quarantine' as const,
    reason: 'spam' as const,
    state: 'held' as const,
    riskLevel: 'low' as const,
    hasHardBlock: false,
  },
};

function input(overrides: Partial<DecideMailboxRestoreInput> = {}): DecideMailboxRestoreInput {
  return {
    entry: base.entry,
    copyStatus: 'scanned',
    mode: 'operator',
    settings: defaults,
    ...overrides,
  };
}

const notStale = { stale: false, causes: [], verdictAgeHours: null, signatureLagHours: null };

describe('vocabulary appends of step API-2 (mirror the WP1 enum appends)', () => {
  it('pins locations, containers, origins and release statuses', () => {
    expect(QUARANTINE_LOCATIONS).toEqual(['gateway', 'mailbox']);
    expect(MAILBOX_CONTAINERS).toEqual(['quarantine_folder', 'junk', 'deleted_items']);
    expect(QUARANTINE_ORIGINS).toEqual(['policy', 'manual', 'adopted', 'api_remediation']);
    expect(QUARANTINE_RELEASE_STATUSES.slice(-2)).toEqual(['restored', 'restore_failed']);
    expect(API_COPY_STATUSES).toEqual([
      'pending',
      'scanned',
      'scan_failed',
      'parse_failed',
      'too_large',
    ]);
  });

  it('validates the R10.5 location block', () => {
    expect(quarantineEntryLocationSchema.parse({ kind: 'gateway' })).toEqual({ kind: 'gateway' });
    const mailbox = {
      kind: 'mailbox',
      container: 'quarantine_folder',
      mailboxAddress: 'alex@example.test',
      provider: 'microsoft_365',
      connectionId: '0190dddd-0000-7000-8000-000000000001',
      detectionId: '0190dddd-0000-7000-8000-000000000002',
      remediationId: '0190dddd-0000-7000-8000-000000000003',
      remediationStatus: 'succeeded',
    };
    expect(quarantineEntryLocationSchema.parse(mailbox)).toEqual(mailbox);
    const { connectionId: _omitted, ...self } = mailbox;
    expect(quarantineEntryLocationSchema.safeParse(self).success).toBe(true);
    expect(
      quarantineEntryLocationSchema.safeParse({ ...mailbox, container: 'inbox' }).success,
    ).toBe(false);
    expect(quarantineEntryLocationSchema.safeParse({ kind: 'gateway', extra: 1 }).success).toBe(
      false,
    );
  });
});

describe('mailboxRestoreApprovalReasons (R10.1: stored facts only)', () => {
  it.each([
    [{ hasHardBlock: false }, 'scanned', []],
    [{ hasHardBlock: true }, 'scanned', ['hard_block']],
    [{ hasHardBlock: false }, 'scan_failed', ['scan_failed']],
    [{ hasHardBlock: true }, 'too_large', ['hard_block', 'scan_failed']],
    [{ kind: 'review' as const }, 'scanned', ['review']],
    [
      { kind: 'review' as const, hasHardBlock: true },
      'pending',
      ['hard_block', 'scan_failed', 'review'],
    ],
  ] as const)('%o with copy %s → %o', (entry, copyStatus, expected) => {
    expect(
      mailboxRestoreApprovalReasons({ entry: { ...base.entry, ...entry }, copyStatus }),
    ).toEqual(expected);
  });
});

describe('decideMailboxRestore (R10.1)', () => {
  it('operator: clean facts release; never stale, summary null', () => {
    expect(decideMailboxRestore(input())).toEqual({
      outcome: 'release',
      approvalReasons: [],
      staleness: notStale,
      summary: null,
    });
  });

  it('operator: hard block → approval_required (allowed) or refused (tenant disallows)', () => {
    expect(decideMailboxRestore(input({ entry: { ...base.entry, hasHardBlock: true } }))).toEqual({
      outcome: 'approval_required',
      approvalReasons: ['hard_block'],
      staleness: notStale,
      summary: null,
    });
    expect(
      decideMailboxRestore(
        input({ entry: { ...base.entry, hasHardBlock: true }, settings: noHardBlocks }),
      ),
    ).toEqual({
      outcome: 'refused',
      approvalReasons: ['hard_block'],
      refusal: { code: 'quarantine_hard_block_release_disabled', cause: 'hard_block' },
      staleness: notStale,
      summary: null,
    });
    // Without a hard block the tenant setting does not matter.
    expect(decideMailboxRestore(input({ settings: noHardBlocks })).outcome).toBe('release');
  });

  it('operator: a copy that is not scanned needs approval (scan_failed)', () => {
    for (const copyStatus of ['scan_failed', 'pending', 'parse_failed', 'too_large'] as const) {
      expect(decideMailboxRestore(input({ copyStatus }))).toMatchObject({
        outcome: 'approval_required',
        approvalReasons: ['scan_failed'],
      });
    }
  });

  it('approved: covered reasons release; new reasons need a new approval', () => {
    const hb = { ...base.entry, hasHardBlock: true, state: 'pending_approval' as const };
    expect(
      decideMailboxRestore(input({ mode: 'approved', entry: hb, approvedReasons: ['hard_block'] })),
    ).toMatchObject({ outcome: 'release', approvalReasons: [] });
    expect(
      decideMailboxRestore(
        input({
          mode: 'approved',
          entry: hb,
          approvedReasons: ['hard_block'],
          copyStatus: 'scan_failed',
        }),
      ),
    ).toMatchObject({ outcome: 'approval_required', approvalReasons: ['scan_failed'] });
    expect(
      decideMailboxRestore(input({ mode: 'approved', entry: hb, approvedReasons: [] })),
    ).toMatchObject({ outcome: 'approval_required', approvalReasons: ['hard_block'] });
    // The executor's re-check runs while the entry is `releasing`.
    expect(
      decideMailboxRestore(
        input({
          mode: 'approved',
          entry: { ...hb, state: 'releasing' },
          approvedReasons: ['hard_block'],
        }),
      ).outcome,
    ).toBe('release');
    // Approved mode with hard blocks disallowed is still refused.
    expect(
      decideMailboxRestore(
        input({
          mode: 'approved',
          entry: hb,
          approvedReasons: ['hard_block'],
          settings: noHardBlocks,
        }),
      ).refusal?.code,
    ).toBe('quarantine_hard_block_release_disabled');
  });

  it.each([
    ['allowed (spam, low, scanned)', {}, null],
    [
      'end user disabled',
      {
        settings: resolveQuarantineSettings({ endUser: { enabled: false, selfRelease: true } })
          .settings,
      },
      'end_user_disabled',
    ],
    ['self-release disabled', { settings: defaults }, 'self_release_disabled'],
    [
      'reason not allowed',
      { entry: { ...base.entry, reason: 'malware' as const } },
      'reason_not_allowed',
    ],
    ['level unknown', { entry: { ...base.entry, riskLevel: null } }, 'level_unknown'],
    ['level too high', { entry: { ...base.entry, riskLevel: 'high' as const } }, 'level_too_high'],
    ['scan failed → approval', { copyStatus: 'scan_failed' as const }, 'approval_required'],
    [
      'hard block (allowed by tenant) → approval',
      { entry: { ...base.entry, hasHardBlock: true } },
      'approval_required',
    ],
  ] as const)('self: %s', (_label, overrides, cause) => {
    const decision = decideMailboxRestore(
      input({
        settings: selfOn,
        mode: 'self',
        ...(overrides as Partial<DecideMailboxRestoreInput>),
      }),
    );
    if (cause === null) {
      expect(decision).toMatchObject({ outcome: 'release', approvalReasons: [] });
    } else {
      expect(decision.outcome).toBe('refused');
      expect(decision.refusal).toEqual({ code: 'quarantine_self_release_not_allowed', cause });
    }
    expect(decision.staleness.stale).toBe(false);
    expect(decision.summary).toBeNull();
  });

  it('self: a hard block the tenant disallows is refused before the end-user bounds', () => {
    const off = resolveQuarantineSettings({
      release: { allowHardBlocks: false },
      endUser: { enabled: true, selfRelease: true },
    }).settings;
    expect(
      decideMailboxRestore(
        input({ mode: 'self', settings: off, entry: { ...base.entry, hasHardBlock: true } }),
      ).refusal?.code,
    ).toBe('quarantine_hard_block_release_disabled');
  });

  it.each([
    ['operator', 'pending_approval'],
    ['operator', 'released'],
    ['self', 'expired'],
    ['approved', 'held'],
    ['approved', 'deleted'],
  ] as const)('state conflict: %s on a %s entry', (mode, state) => {
    expect(
      decideMailboxRestore(
        input({ mode, settings: selfOn, entry: { ...base.entry, state }, approvedReasons: [] }),
      ),
    ).toEqual({
      outcome: 'refused',
      approvalReasons: [],
      refusal: { code: 'quarantine_state_conflict', cause: `state_${state}` },
      staleness: notStale,
      summary: null,
    });
  });

  it('never answers rescan_required', () => {
    for (const mode of ['operator', 'self', 'approved'] as const) {
      for (const copyStatus of API_COPY_STATUSES) {
        for (const hasHardBlock of [true, false]) {
          const state = mode === 'approved' ? 'pending_approval' : 'held';
          const decision = decideMailboxRestore(
            input({
              mode,
              copyStatus,
              settings: selfOn,
              entry: { ...base.entry, state, hasHardBlock },
            }),
          );
          expect(decision.outcome).not.toBe('rescan_required');
        }
      }
    }
  });
});
