import { describe, expect, it } from 'vitest';
import { MailboxApiError } from '../errors';
import { classifyRemediationError } from './errors';
import {
  containerOf,
  createsQuarantineEntry,
  executedContainerOf,
  executionResultCode,
  gmailLocateCandidates,
  gmailModifyFor,
  gmailTargetReached,
  graphCategoriesWith,
  graphLocateCandidates,
  graphTargetReached,
  hardBlockToPrimaryEngine,
  isReversal,
  isReversible,
  mailboxEntryExplanation,
  providerActionPlan,
  REMEDIATION_PROVIDER_ACTIONS,
  reversalOf,
  verdictToQuarantineReason,
} from './provider-actions';
import { MESSAGE_VERDICTS, REMEDIATION_ACTION_KINDS } from './vocabulary';

const TAG = 'Email Gateway: Suspicious';

describe('the R3 table', () => {
  it.each([
    // action, reversible, reversal, container, entry, google executed container, google code
    [
      'move_quarantine',
      true,
      'restore_inbox',
      'quarantine_folder',
      true,
      'quarantine_folder',
      null,
    ],
    ['move_junk', true, 'restore_inbox', 'junk', true, 'junk', null],
    ['tag', true, 'remove_tag', null, false, null, null],
    ['soft_delete', true, 'restore_inbox', 'deleted_items', true, 'deleted_items', null],
    ['hard_delete', false, null, null, false, 'deleted_items', 'hard_delete_unsupported_provider'],
    ['restore_inbox', false, null, null, false, 'inbox', null],
    ['remove_tag', false, null, null, false, null, null],
  ] as const)(
    '%s',
    (action, reversible, reversal, container, entry, googleContainer, googleCode) => {
      expect(isReversible(action)).toBe(reversible);
      expect(reversalOf(action)).toBe(reversal);
      expect(containerOf(action)).toBe(container);
      expect(createsQuarantineEntry(action)).toBe(entry);
      expect(executedContainerOf(action, 'google_workspace')).toBe(googleContainer);
      expect(executionResultCode(action, 'google_workspace')).toBe(googleCode);
      expect(executionResultCode(action, 'microsoft_365')).toBeNull();
      expect(isReversal(action)).toBe(action === 'restore_inbox' || action === 'remove_tag');
    },
  );

  it('covers every action kind and states the provider steps', () => {
    expect(Object.keys(REMEDIATION_PROVIDER_ACTIONS).sort()).toEqual(
      [...REMEDIATION_ACTION_KINDS].sort(),
    );
    expect(executedContainerOf('hard_delete', 'microsoft_365')).toBeNull();
    expect(providerActionPlan('move_quarantine').graph).toEqual([
      { op: 'ensure_quarantine_folder' },
      { op: 'move', destination: { kind: 'quarantine_folder' } },
    ]);
    expect(providerActionPlan('soft_delete').graph).toEqual([
      { op: 'move', destination: { kind: 'well_known', name: 'recoverableitemsdeletions' } },
    ]);
    expect(providerActionPlan('hard_delete').graph).toEqual([{ op: 'permanent_delete' }]);
    // Gmail never deletes permanently: the hard-delete plan is the Trash plan.
    expect(providerActionPlan('hard_delete').gmail).toEqual([{ op: 'trash' }]);
    expect(providerActionPlan('soft_delete').gmail).toEqual([{ op: 'trash' }]);
    expect(providerActionPlan('restore_inbox').gmail[0]).toEqual({ op: 'untrash_if_trashed' });
    expect(providerActionPlan('restore_inbox').graph).toEqual([
      { op: 'move', destination: { kind: 'well_known', name: 'inbox' } },
      { op: 'remove_tag_category' },
    ]);
    for (const plan of Object.values(REMEDIATION_PROVIDER_ACTIONS)) {
      expect(JSON.stringify(plan.gmail)).not.toContain('delete');
    }
  });
});

describe('already in target (R5.4)', () => {
  const ids = {
    inbox: 'F-inbox',
    junkemail: 'F-junk',
    recoverableitemsdeletions: 'F-del',
    quarantineFolder: 'F-q',
  };
  it.each([
    ['move_quarantine', { parentFolderId: 'F-q', categories: [] }, true],
    ['move_quarantine', { parentFolderId: 'F-inbox', categories: [] }, false],
    ['move_junk', { parentFolderId: 'F-junk', categories: [] }, true],
    ['soft_delete', { parentFolderId: 'F-del', categories: [] }, true],
    ['soft_delete', { parentFolderId: 'F-inbox', categories: [] }, false],
    ['tag', { parentFolderId: 'F-inbox', categories: ['Blue', TAG] }, true],
    ['tag', { parentFolderId: 'F-inbox', categories: ['Blue'] }, false],
    ['remove_tag', { parentFolderId: 'F-inbox', categories: ['Blue'] }, true],
    ['restore_inbox', { parentFolderId: 'F-inbox', categories: [] }, true],
    ['restore_inbox', { parentFolderId: 'F-inbox', categories: [TAG] }, false],
    ['restore_inbox', { parentFolderId: 'F-q', categories: [] }, false],
    ['hard_delete', { parentFolderId: 'F-del', categories: [] }, false],
  ] as const)('Graph %s on %o → %s', (action, state, reached) => {
    expect(graphTargetReached(action, state, ids, TAG)).toBe(reached);
  });

  it('Graph quarantine target is never reached while the folder id is unknown', () => {
    expect(
      graphTargetReached(
        'move_quarantine',
        { parentFolderId: null, categories: [] },
        { ...ids, quarantineFolder: null },
        TAG,
      ),
    ).toBe(false);
  });

  const labels = { quarantineLabelId: 'Label_1', tagLabelId: 'Label_2' };
  it.each([
    ['move_quarantine', ['Label_1'], true],
    ['move_quarantine', ['INBOX', 'Label_1'], false],
    ['move_junk', ['SPAM'], true],
    ['move_junk', ['SPAM', 'INBOX'], false],
    ['soft_delete', ['TRASH'], true],
    ['hard_delete', ['TRASH'], true],
    ['tag', ['INBOX', 'Label_2'], true],
    ['remove_tag', ['INBOX'], true],
    ['restore_inbox', ['INBOX', 'UNREAD'], true],
    ['restore_inbox', ['INBOX', 'Label_1'], false],
    ['restore_inbox', ['INBOX', 'TRASH'], false],
  ] as const)('Gmail %s on %o → %s', (action, labelIds, reached) => {
    expect(gmailTargetReached(action, labelIds, labels)).toBe(reached);
  });

  it('computes only the label changes that still differ', () => {
    const quarantine = providerActionPlan('move_quarantine').gmail[1] as Extract<
      ReturnType<typeof providerActionPlan>['gmail'][number],
      { op: 'modify' }
    >;
    expect(gmailModifyFor(quarantine, ['INBOX', 'UNREAD'], labels)).toEqual({
      add: ['Label_1'],
      remove: ['INBOX'],
    });
    expect(gmailModifyFor(quarantine, ['Label_1'], labels)).toEqual({ add: [], remove: [] });
    const restore = providerActionPlan('restore_inbox').gmail[1] as typeof quarantine;
    expect(gmailModifyFor(restore, ['SPAM', 'Label_1'], labels)).toEqual({
      add: ['INBOX'],
      remove: ['SPAM', 'Label_1'],
    });
    expect(
      gmailModifyFor(restore, ['SPAM'], { quarantineLabelId: null, tagLabelId: null }),
    ).toEqual({ add: ['INBOX'], remove: ['SPAM'] });
  });

  it('adds and removes the Graph tag category without touching others (no-op when so)', () => {
    expect(graphCategoriesWith(['Blue'], TAG, true)).toEqual({
      categories: ['Blue', TAG],
      changed: true,
    });
    expect(graphCategoriesWith(['Blue', TAG], TAG, true)).toEqual({
      categories: ['Blue', TAG],
      changed: false,
    });
    expect(graphCategoriesWith(['Blue', TAG], TAG, false)).toEqual({
      categories: ['Blue'],
      changed: true,
    });
    expect(graphCategoriesWith(['Blue'], TAG, false)).toEqual({
      categories: ['Blue'],
      changed: false,
    });
  });
});

describe('locate filters (R5.3)', () => {
  it('drops Graph drafts and Sent Items matches, keeps at most 5', () => {
    const matches = [
      { id: 'a', parentFolderId: 'F-inbox', isDraft: false },
      { id: 'b', parentFolderId: 'F-sent', isDraft: false },
      { id: 'c', parentFolderId: 'F-inbox', isDraft: true },
      ...Array.from({ length: 6 }, (_, i) => ({
        id: `x${i}`,
        parentFolderId: 'F-q',
        isDraft: false,
      })),
    ];
    expect(graphLocateCandidates(matches, 'F-sent').map((m) => m.id)).toEqual([
      'a',
      'x0',
      'x1',
      'x2',
      'x3',
    ]);
  });

  it('drops Gmail sent-only and draft matches', () => {
    expect(
      gmailLocateCandidates([
        { id: 'sent', labelIds: ['SENT'] },
        { id: 'sent-read', labelIds: ['SENT', 'IMPORTANT', 'CATEGORY_PERSONAL'] },
        { id: 'draft', labelIds: ['DRAFT'] },
        { id: 'self', labelIds: ['SENT', 'INBOX'] },
        { id: 'spam', labelIds: ['SPAM'] },
      ]).map((m) => m.id),
    ).toEqual(['self', 'spam']);
  });
});

describe('mailbox quarantine entry mappings (R9.1)', () => {
  it.each([
    ['malware', 'malware'],
    ['phishing', 'phishing'],
    ['spam', 'spam'],
    ['bulk', 'bulk'],
    ['bec', 'bec'],
    ['dlp_violation', 'dlp'],
    ['suspicious', 'suspicious'],
    ['clean', 'policy'],
    ['unknown', 'policy'],
    [null, 'policy'],
  ] as const)('verdict %s → reason %s', (verdict, reason) => {
    expect(verdictToQuarantineReason(verdict)).toBe(reason);
  });

  it('maps every verdict', () => {
    for (const verdict of MESSAGE_VERDICTS) expect(verdictToQuarantineReason(verdict)).toBeTruthy();
  });

  it.each([
    [['hb.malware_attachment'], 'attachment'],
    [['hb.malware_url'], 'url'],
    [['hb.url_tenant_blocked'], 'url'],
    [['hb.malware_sandbox'], 'sandbox'],
    [['hb.known_phishing'], 'rspamd'],
    [['hb.bec_malicious'], 'bec'],
    [['hb.dlp_block'], 'dlp'],
    [['hb.other', 'hb.malware_url'], 'none'],
    [['constructor'], 'none'],
    [[], 'none'],
  ] as const)('hard blocks %o → engine %s', (hardBlocks, engine) => {
    expect(hardBlockToPrimaryEngine(hardBlocks)).toBe(engine);
  });

  it('explains without content', () => {
    expect(mailboxEntryExplanation('p1-suspicious')).toBe(
      'Removed from the mailbox by the API-mode remediation policy (rule p1-suspicious)',
    );
    expect(mailboxEntryExplanation(null)).toBe(
      'Removed from the mailbox by an API-mode remediation.',
    );
  });
});

describe('classifyRemediationError (R5.6)', () => {
  const e = (
    code: ConstructorParameters<typeof MailboxApiError>[0],
    o: ConstructorParameters<typeof MailboxApiError>[1] = {},
  ) => classifyRemediationError(new MailboxApiError(code, o));
  it.each([
    [e('throttled', { status: 429, retryAfterMs: 2000 }), 'throttled', null, 2000],
    [e('throttle_paused', { retryAfterMs: 500 }), 'throttled', null, 500],
    [e('rate_budget'), 'throttled', null, null],
    [e('quota_exhausted', { status: 403, retryAfterMs: 3_600_000 }), 'throttled', null, 3_600_000],
    [e('provider_unavailable', { status: 503, retryAfterMs: 4000 }), 'throttled', null, 4000],
    [e('provider_unavailable', { status: 503 }), 'retryable', 'provider_unavailable', null],
    [e('provider_unavailable', { status: 500 }), 'retryable', 'provider_unavailable', null],
    [e('aborted'), 'retryable', 'provider_unavailable', null],
    [e('unauthorized', { status: 401 }), 'forbidden', 'provider_forbidden', null],
    [e('forbidden', { status: 403 }), 'forbidden', 'provider_forbidden', null],
    [e('missing_permission', { status: 403 }), 'forbidden', 'provider_forbidden', null],
    [e('not_found', { status: 404 }), 'not_found', 'message_not_found', null],
    [e('bad_request', { status: 400 }), 'rejected', 'provider_rejected', null],
    [e('conflict', { status: 409 }), 'rejected', 'provider_rejected', null],
    [e('unexpected_response'), 'rejected', 'provider_rejected', null],
    [e('grant_missing'), 'access_revoked', 'mailbox_access_revoked', null],
    [e('connection_inactive'), 'access_revoked', 'mailbox_access_revoked', null],
  ])('%o', (outcome, cls, failureCode, retryAfterMs) => {
    expect(outcome).toEqual({ class: cls, failureCode, retryAfterMs });
  });
});
