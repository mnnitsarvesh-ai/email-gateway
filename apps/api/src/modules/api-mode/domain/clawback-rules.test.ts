import { copyMessageIdHash } from '@email-gateway/mailbox-api';
import { normalizeUrl } from '@email-gateway/url-security';
import { describe, expect, it } from 'vitest';
import { normalizeSubjectKey } from '../../messages/domain/search-keys';
import {
  approvalReasonsOf,
  buildAdminCriteria,
  buildReportCriteria,
  decideApproval,
  decideCancel,
  decideClawbackRestore,
  decideReportMailbox,
  decideSubmit,
  decideTriage,
  effectivePurgeThreshold,
  groupResolutionApplies,
  nextPurgeThresholdRaise,
  normalizeAddress,
  originalSearchable,
  type SeedFacts,
  settingsCasOk,
  shouldNotifyReporter,
  submitFacts,
  truncatedHash,
  urlIdentityHash,
} from './clawback-rules';

const ORG = 42n;
const NOW = new Date('2026-11-27T10:00:00.000Z');
const H = 3_600_000;
const D = 24 * H;
const iso = (ms: number) => new Date(ms).toISOString();
const window = { from: iso(NOW.getTime() - D), to: NOW.toISOString() };
const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);

const build = (patch: Partial<Parameters<typeof buildAdminCriteria>[0]> = {}) =>
  buildAdminCriteria({
    organizationId: ORG,
    criteria: null,
    seed: null,
    expand: null,
    directions: null,
    now: NOW,
    maxWindowDays: 31,
    ...patch,
  });

const seed: SeedFacts = {
  receivedAt: new Date(NOW.getTime() - 2 * D),
  messageIdHash: HEX_A,
  attachmentSha256: [HEX_B],
  urlSha256: ['c'.repeat(64)],
  sender: 'billing@fabrikam.example',
  subjectKey: 'Invoice overdue',
};

describe('buildAdminCriteria (C4.4 normalization, C2.4 seeds)', () => {
  it('hashes the Message-ID with the dedupe hash (with or without angle brackets)', () => {
    const a = build({ criteria: { messageId: '<x-1@fabrikam.example>', ...window } });
    const b = build({ criteria: { messageId: ' x-1@fabrikam.example ', ...window } });
    expect(a.ok && a.criteria.keys.messageIdHashes).toEqual([
      copyMessageIdHash(ORG, 'x-1@fabrikam.example'),
    ]);
    expect(b.ok && b.criteria.keys.messageIdHashes).toEqual(
      a.ok ? a.criteria.keys.messageIdHashes : null,
    );
    expect(a.ok && a.trigger).toBe('admin');
    expect(a.ok && a.criteria.directions).toEqual(['inbound', 'internal']);
  });

  it('reduces a URL to its identity hash and lower-cases given hashes', () => {
    const url = 'HTTPS://Example.COM/a?b=1#frag';
    const r = build({ criteria: { url, urlSha256: [HEX_B.toUpperCase()], ...window } });
    expect(r.ok).toBe(true);
    const expected = normalizeUrl(url);
    expect(expected.ok).toBe(true);
    if (r.ok && expected.ok) {
      expect(r.criteria.keys.urlSha256).toEqual([HEX_B, expected.url.sha256]);
    }
    expect(urlIdentityHash('not a url')).toBeNull();
    const bad = build({ criteria: { url: 'ftp://example.com/x', ...window } });
    expect(bad).toEqual({ ok: false, codes: ['url_invalid'] });
  });

  it('normalizes the subject with the explorer subject key and the sender to lower case', () => {
    const subject = 'RE: Fwd:   Invoice overdue ';
    const r = build({
      criteria: { sender: ' Billing@Fabrikam.Example ', subject, ...window },
    });
    expect(r.ok && r.criteria.keys.senderSubject).toEqual({
      sender: 'billing@fabrikam.example',
      subjectKey: normalizeSubjectKey(subject),
    });
    expect(normalizeSubjectKey(subject)).toBe('Invoice overdue');
  });

  it('refuses a sender without a subject, an empty subject key and a bad address (codes only)', () => {
    expect(build({ criteria: { sender: 'a@b.example', ...window } })).toEqual({
      ok: false,
      codes: ['sender_subject_together'],
    });
    expect(build({ criteria: { sender: 'a@b.example', subject: 'RE: FW:', ...window } })).toEqual({
      ok: false,
      codes: ['subject_key_empty'],
    });
    expect(build({ criteria: { sender: 'nobody', subject: 'Hi', ...window } })).toEqual({
      ok: false,
      codes: ['sender_invalid'],
    });
  });

  it('applies the C4.1 window rules: ≤ 31 days, within retention, sender+subject ≤ 7 days', () => {
    const long = build({
      criteria: { messageId: '<a@b>', from: iso(NOW.getTime() - 40 * D), to: NOW.toISOString() },
    });
    expect(long.ok === false && long.codes).toContain('window_too_long');
    const old = build({
      criteria: {
        messageId: '<a@b>',
        from: iso(NOW.getTime() - 200 * D),
        to: iso(NOW.getTime() - 190 * D),
      },
    });
    expect(old.ok === false && old.codes).toContain('window_before_retention');
    const subject = build({
      criteria: {
        sender: 'a@b.example',
        subject: 'Hello',
        from: iso(NOW.getTime() - 10 * D),
        to: NOW.toISOString(),
      },
    });
    expect(subject.ok === false && subject.codes).toContain('sender_subject_window_too_long');
    expect(build({ criteria: { messageId: '<a@b>' } })).toEqual({
      ok: false,
      codes: ['window_required'],
    });
    expect(build({ criteria: { from: window.from, to: window.to } })).toEqual({
      ok: false,
      codes: ['no_keys'],
    });
  });

  it('a seed alone searches its Message-ID around its receipt time', () => {
    const r = build({ seed });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.trigger).toBe('admin');
    expect(r.criteria.keys).toEqual({ messageIdHashes: [HEX_A] });
    expect(r.criteria.window.from).toBe(iso(seed.receivedAt.getTime() - D));
    expect(r.criteria.window.to).toBe(NOW.toISOString());
  });

  it('expand makes a campaign with the seed hashes and sender + subject (7-day limit lifted)', () => {
    const r = build({ seed, expand: { attachments: true, urls: true, senderSubjectHours: 120 } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.trigger).toBe('campaign');
    expect(r.criteria.keys).toEqual({
      messageIdHashes: [HEX_A],
      attachmentSha256: [HEX_B],
      urlSha256: ['c'.repeat(64)],
      senderSubject: { sender: seed.sender, subjectKey: seed.subjectKey },
    });
    expect(r.criteria.window.from).toBe(iso(seed.receivedAt.getTime() - 120 * H));
    expect(r.criteria.window.to).toBe(NOW.toISOString());
  });

  it('expand needs a seed; a seed without sender cannot expand sender + subject', () => {
    expect(build({ criteria: { messageId: '<a@b>', ...window }, expand: { urls: true } })).toEqual({
      ok: false,
      codes: ['expand_needs_seed'],
    });
    expect(build({ seed: { ...seed, sender: null }, expand: { senderSubjectHours: 24 } })).toEqual({
      ok: false,
      codes: ['seed_without_sender_subject'],
    });
  });

  it('honours the directions asked for', () => {
    const r = build({ criteria: { messageId: '<a@b>', ...window }, directions: ['internal'] });
    expect(r.ok && r.criteria.directions).toEqual(['internal']);
  });
});

describe('buildReportCriteria (C11.5)', () => {
  const original = {
    messageIdHash: HEX_A,
    sender: 'billing@fabrikam.example',
    subjectKey: 'Invoice overdue',
    date: iso(NOW.getTime() - 5 * H),
    attachmentSha256: [HEX_B],
    urlSha256: ['c'.repeat(64)],
  };
  const reportedAt = new Date(NOW.getTime() - H);

  it('Message-ID first, ±72 h around the original date', () => {
    const r = buildReportCriteria({
      original,
      reportedAt,
      expand: null,
      now: NOW,
      maxWindowDays: 31,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.trigger).toBe('report');
    expect(r.criteria.keys).toEqual({ messageIdHashes: [HEX_A] });
    expect(r.criteria.window.from).toBe(iso(Date.parse(original.date) - 72 * H));
    expect(r.criteria.window.to).toBe(NOW.toISOString());
  });

  it('without a Message-ID the sender + subject key; expand makes a campaign', () => {
    const noId = buildReportCriteria({
      original: { ...original, messageIdHash: null },
      reportedAt,
      expand: null,
      now: NOW,
      maxWindowDays: 31,
    });
    expect(noId.ok && noId.criteria.keys).toEqual({
      senderSubject: { sender: original.sender, subjectKey: original.subjectKey },
    });
    const campaign = buildReportCriteria({
      original,
      reportedAt,
      expand: { attachments: true, urls: true, senderSubjectHours: 168 },
      now: NOW,
      maxWindowDays: 31,
    });
    expect(campaign.ok && campaign.trigger).toBe('campaign');
    expect(campaign.ok && Object.keys(campaign.criteria.keys).sort()).toEqual([
      'attachmentSha256',
      'messageIdHashes',
      'senderSubject',
      'urlSha256',
    ]);
  });

  it('an unidentified original → original_unknown; an old one → criteria_invalid', () => {
    expect(
      buildReportCriteria({
        original: null,
        reportedAt,
        expand: null,
        now: NOW,
        maxWindowDays: 31,
      }),
    ).toEqual({ ok: false, code: 'original_unknown' });
    const empty = {
      messageIdHash: null,
      sender: null,
      subjectKey: null,
      date: null,
      attachmentSha256: [],
      urlSha256: [],
    };
    expect(originalSearchable(empty)).toBe(false);
    expect(
      buildReportCriteria({
        original: empty,
        reportedAt,
        expand: null,
        now: NOW,
        maxWindowDays: 31,
      }),
    ).toEqual({ ok: false, code: 'original_unknown' });
    const old = buildReportCriteria({
      original: { ...original, date: iso(NOW.getTime() - 300 * D) },
      reportedAt,
      expand: null,
      now: NOW,
      maxWindowDays: 31,
    });
    expect(old.ok === false && old.code).toBe('criteria_invalid');
  });
});

describe('decideSubmit (C5.1, C6)', () => {
  const base = {
    status: 'ready' as const,
    rowVersion: 3,
    expectedRowVersion: 3,
    trigger: 'admin' as const,
    mailboxesEligible: 10,
    storedApprovalReasons: [],
    settings: { purgeApprovalMailboxes: 50, autoMaxMailboxes: 500 },
    action: 'move_junk' as const,
    hardDeleteEnabled: false,
  };

  it('below the threshold → queued; above → pending_approval (mailbox_threshold)', () => {
    expect(decideSubmit(base)).toEqual({
      ok: true,
      status: 'queued',
      requiresApproval: false,
      reasons: [],
    });
    expect(
      decideSubmit({ ...base, mailboxesEligible: 50 }).ok &&
        decideSubmit({ ...base, mailboxesEligible: 50 }),
    ).toMatchObject({ status: 'queued' });
    expect(decideSubmit({ ...base, mailboxesEligible: 51 })).toEqual({
      ok: true,
      status: 'pending_approval',
      requiresApproval: true,
      reasons: ['mailbox_threshold'],
    });
  });

  it('hard delete: refused while the platform setting is off; otherwise always approval', () => {
    expect(decideSubmit({ ...base, action: 'hard_delete' })).toEqual({
      ok: false,
      code: 'hard_delete_disabled',
    });
    expect(decideSubmit({ ...base, action: 'hard_delete', hardDeleteEnabled: true })).toEqual({
      ok: true,
      status: 'pending_approval',
      requiresApproval: true,
      reasons: ['hard_delete'],
    });
  });

  it('an automatic clawback held at its cap needs approval (auto_cap)', () => {
    const auto = { ...base, status: 'review_required' as const, trigger: 'threat_intel' as const };
    expect(decideSubmit({ ...auto, mailboxesEligible: 600, action: null })).toMatchObject({
      reasons: ['mailbox_threshold', 'auto_cap'],
    });
    expect(
      decideSubmit({ ...auto, mailboxesEligible: 3, storedApprovalReasons: ['auto_cap'] }),
    ).toMatchObject({ status: 'pending_approval', reasons: ['auto_cap'] });
    // `review` mode below the cap: no approval needed.
    expect(decideSubmit({ ...auto, mailboxesEligible: 3 })).toMatchObject({ status: 'queued' });
  });

  it('a wrong state or version is a state conflict with the current version', () => {
    expect(decideSubmit({ ...base, expectedRowVersion: 2 })).toEqual({
      ok: false,
      code: 'state_conflict',
      status: 'ready',
      currentRowVersion: 3,
    });
    expect(decideSubmit({ ...base, status: 'queued' })).toMatchObject({ code: 'state_conflict' });
  });

  it('approvalReasonsOf keeps the known reasons in canonical order', () => {
    expect(approvalReasonsOf(['auto_cap', 'x', 'mailbox_threshold'])).toEqual([
      'mailbox_threshold',
      'auto_cap',
    ]);
    expect(approvalReasonsOf(null)).toEqual([]);
  });
});

describe('submitFacts (C3.1)', () => {
  it('a chosen verdict gives the admin row (critical → analyst hard block)', () => {
    expect(
      submitFacts({
        trigger: 'admin',
        chosen: { verdict: 'malware' },
        stored: null,
        reportScanVerdict: null,
      }),
    ).toEqual({ verdict: 'malware', level: 'critical', hardBlocks: ['hb.clawback.analyst'] });
    expect(
      submitFacts({
        trigger: 'campaign',
        chosen: { verdict: 'spam', level: 'medium' },
        stored: null,
        reportScanVerdict: null,
      }),
    ).toEqual({ verdict: 'spam', level: 'medium', hardBlocks: [] });
  });

  it('stored facts (automatic) are kept; a report uses the report row; else phishing', () => {
    const stored = { verdict: 'malware' as const, level: 'high' as const, hardBlocks: [] };
    expect(
      submitFacts({ trigger: 'threat_intel', chosen: {}, stored, reportScanVerdict: null }),
    ).toEqual(stored);
    expect(
      submitFacts({ trigger: 'report', chosen: {}, stored: null, reportScanVerdict: 'bec' }),
    ).toEqual({ verdict: 'bec', level: 'critical', hardBlocks: ['hb.clawback.analyst'] });
    expect(
      submitFacts({ trigger: 'admin', chosen: {}, stored: null, reportScanVerdict: null }),
    ).toMatchObject({ verdict: 'phishing', level: 'critical' });
  });
});

describe('decideApproval (C6, Q14 rules)', () => {
  const base = {
    status: 'pending_approval' as const,
    rowVersion: 4,
    expectedRowVersion: 4,
    approval: {
      status: 'pending' as const,
      expiresAt: new Date(NOW.getTime() + H),
      requestedByUserId: 1n,
      submittedByUserId: 2n,
    },
    approver: { kind: 'user' as const, userId: 3n, permissions: ['remediation:purge'] },
    now: NOW,
  };

  it('another user holding remediation:purge may decide a pending request', () => {
    expect(decideApproval(base)).toEqual({ allowed: true });
  });

  it('api keys, missing permission, the requester and the submitter are forbidden', () => {
    expect(
      decideApproval({ ...base, approver: { ...base.approver, kind: 'api_key', userId: null } }),
    ).toMatchObject({ reason: 'api_key' });
    expect(
      decideApproval({ ...base, approver: { ...base.approver, permissions: [] } }),
    ).toMatchObject({ reason: 'missing_permission' });
    expect(decideApproval({ ...base, approver: { ...base.approver, userId: 1n } })).toMatchObject({
      code: 'api_mode_purge_approval_forbidden',
      reason: 'requester',
    });
    expect(decideApproval({ ...base, approver: { ...base.approver, userId: 2n } })).toMatchObject({
      reason: 'requester',
    });
  });

  it('not pending, expired, and a stale version', () => {
    expect(decideApproval({ ...base, status: 'queued' })).toMatchObject({
      code: 'api_mode_purge_approval_not_pending',
      reason: 'not_pending',
    });
    expect(
      decideApproval({ ...base, approval: { ...base.approval, expiresAt: NOW } }),
    ).toMatchObject({ reason: 'expired' });
    expect(decideApproval({ ...base, expectedRowVersion: 3 })).toEqual({
      allowed: false,
      code: 'state_conflict',
      status: 'pending_approval',
      currentRowVersion: 4,
    });
    // The principal rule comes before the version check.
    expect(
      decideApproval({
        ...base,
        expectedRowVersion: 3,
        approver: { ...base.approver, kind: 'api_key', userId: null },
      }),
    ).toMatchObject({ reason: 'api_key' });
  });
});

describe('decideCancel (C5.6) and decideClawbackRestore (C7)', () => {
  it('nothing queued → immediate; queued/running → requested once; final → refused', () => {
    expect(decideCancel('ready', null)).toEqual({
      ok: true,
      immediate: true,
      alreadyRequested: false,
    });
    expect(decideCancel('pending_approval', null)).toMatchObject({ immediate: true });
    expect(decideCancel('running', null)).toEqual({
      ok: true,
      immediate: false,
      alreadyRequested: false,
    });
    expect(decideCancel('queued', NOW)).toEqual({
      ok: true,
      immediate: false,
      alreadyRequested: true,
    });
    expect(decideCancel('completed', null)).toEqual({ ok: false, status: 'completed' });
    expect(decideCancel('searching', null)).toEqual({ ok: false, status: 'searching' });
  });

  it('restore: final clawbacks with succeeded targets, not while a restore runs', () => {
    expect(
      decideClawbackRestore({ status: 'completed', restoreStatus: 'none', targetsSucceeded: 2 }),
    ).toEqual({ ok: true });
    expect(
      decideClawbackRestore({
        status: 'cancelled',
        restoreStatus: 'completed_with_errors',
        targetsSucceeded: 1,
      }),
    ).toEqual({ ok: true });
    expect(
      decideClawbackRestore({ status: 'running', restoreStatus: 'none', targetsSucceeded: 2 }).ok,
    ).toBe(false);
    expect(
      decideClawbackRestore({
        status: 'completed',
        restoreStatus: 'requested',
        targetsSucceeded: 2,
      }).ok,
    ).toBe(false);
    expect(
      decideClawbackRestore({ status: 'completed', restoreStatus: 'none', targetsSucceeded: 0 }).ok,
    ).toBe(false);
  });
});

describe('report triage (C11.1, C11.3, C11.4)', () => {
  const base = {
    status: 'pending_triage' as const,
    rowVersion: 2,
    expectedRowVersion: 2,
    reopenCount: 0,
    to: 'resolved' as const,
    verdict: 'malicious' as const,
  };

  it('resolve needs a verdict; other statuses refuse one', () => {
    expect(decideTriage(base)).toEqual({
      ok: true,
      to: 'resolved',
      reopened: false,
      rejectReason: null,
    });
    expect(decideTriage({ ...base, verdict: null })).toEqual({
      ok: false,
      code: 'verdict_required',
    });
    expect(decideTriage({ ...base, to: 'in_review' })).toEqual({
      ok: false,
      code: 'verdict_not_allowed',
    });
  });

  it('reject is a dismissal (analyst_rejected); in_review is allowed from open reports', () => {
    expect(decideTriage({ ...base, to: 'rejected', verdict: null })).toMatchObject({
      rejectReason: 'analyst_rejected',
    });
    expect(
      decideTriage({ ...base, status: 'in_review', to: 'in_review', verdict: null }),
    ).toMatchObject({ ok: true });
  });

  it('resolved reopens once; parsing, scanning and rejected reports are conflicts', () => {
    expect(decideTriage({ ...base, status: 'resolved', to: 'in_review', verdict: null })).toEqual({
      ok: true,
      to: 'in_review',
      reopened: true,
      rejectReason: null,
    });
    expect(
      decideTriage({ ...base, status: 'resolved', to: 'in_review', verdict: null, reopenCount: 1 }),
    ).toEqual({ ok: false, code: 'not_reopenable' });
    expect(decideTriage({ ...base, status: 'resolved' })).toMatchObject({ code: 'state_conflict' });
    for (const status of ['received', 'parsing', 'scanning', 'rejected'] as const) {
      expect(decideTriage({ ...base, status })).toMatchObject({ code: 'state_conflict', status });
    }
    expect(decideTriage({ ...base, expectedRowVersion: 1 })).toMatchObject({
      code: 'state_conflict',
      currentRowVersion: 2,
    });
  });

  it('group resolution and reporter feedback defaults', () => {
    expect(groupResolutionApplies({ to: 'resolved', applyToGroup: true, groupKey: 'k' })).toBe(
      true,
    );
    expect(groupResolutionApplies({ to: 'resolved', applyToGroup: false, groupKey: 'k' })).toBe(
      false,
    );
    expect(groupResolutionApplies({ to: 'rejected', applyToGroup: true, groupKey: 'k' })).toBe(
      false,
    );
    expect(groupResolutionApplies({ to: 'resolved', applyToGroup: true, groupKey: null })).toBe(
      false,
    );
    expect(shouldNotifyReporter('resolved', undefined, true)).toBe(true);
    expect(shouldNotifyReporter('resolved', undefined, false)).toBe(false);
    expect(shouldNotifyReporter('resolved', true, false)).toBe(true);
    expect(shouldNotifyReporter('in_review', true, true)).toBe(false);
  });
});

describe('report mailboxes (C9.1) and settings CAS (C14 #19)', () => {
  const base = {
    enabled: true,
    current: false,
    mailboxStatus: 'disabled' as const,
    domainApiSide: true,
    designatedCount: 4,
    max: 5,
  };

  it('designates active, discovered and disabled mailboxes of api/hybrid domains up to the limit', () => {
    expect(decideReportMailbox(base)).toEqual({ ok: true, change: true });
    expect(decideReportMailbox({ ...base, designatedCount: 5 })).toEqual({
      ok: false,
      code: 'limit',
      max: 5,
    });
    expect(decideReportMailbox({ ...base, mailboxStatus: 'deleted' })).toEqual({
      ok: false,
      code: 'not_eligible',
      cause: 'mailbox_deleted',
    });
    expect(decideReportMailbox({ ...base, domainApiSide: false })).toEqual({
      ok: false,
      code: 'not_eligible',
      cause: 'domain_not_api',
    });
  });

  it('an unchanged flag is a no-op; clearing is always allowed', () => {
    expect(decideReportMailbox({ ...base, current: true, designatedCount: 5 })).toEqual({
      ok: true,
      change: false,
    });
    expect(
      decideReportMailbox({ ...base, enabled: false, current: true, domainApiSide: false }),
    ).toEqual({ ok: true, change: true });
    expect(decideReportMailbox({ ...base, enabled: false })).toEqual({ ok: true, change: false });
  });

  it('settings CAS: null creates, otherwise the versions must match', () => {
    expect(settingsCasOk(null, null)).toBe(true);
    expect(settingsCasOk(2, 2)).toBe(true);
    expect(settingsCasOk(2, null)).toBe(false);
    expect(settingsCasOk(null, 1)).toBe(false);
  });
});

describe('helpers', () => {
  it('normalizeAddress and truncatedHash', () => {
    expect(normalizeAddress(' A@B.Example ')).toBe('a@b.example');
    expect(normalizeAddress('a@')).toBeNull();
    expect(normalizeAddress('@b')).toBeNull();
    expect(truncatedHash(HEX_A)).toBe(`${'a'.repeat(12)}…`);
    expect(truncatedHash('abc')).toBe('abc');
  });
});

describe('purge threshold separation of duties (P2 review fix)', () => {
  const none = { raisedBy: null, beforeRaise: null };
  const A = 'user:aaaa';
  const B = 'user:bbbb';

  it('records who raised the threshold and the value before the raise', () => {
    expect(nextPurgeThresholdRaise({ before: 50, next: 10_000, current: none, actor: A })).toEqual({
      raisedBy: A,
      beforeRaise: 50,
    });
    // A second raise by the same principal keeps their earliest value.
    expect(
      nextPurgeThresholdRaise({
        before: 100,
        next: 500,
        current: { raisedBy: A, beforeRaise: 50 },
        actor: A,
      }),
    ).toEqual({ raisedBy: A, beforeRaise: 50 });
    // A raise by someone else starts a new record from the value they saw.
    expect(
      nextPurgeThresholdRaise({
        before: 100,
        next: 500,
        current: { raisedBy: A, beforeRaise: 50 },
        actor: B,
      }),
    ).toEqual({ raisedBy: B, beforeRaise: 100 });
  });

  it('keeps the record on a partial lowering or no change and clears it at or below the value', () => {
    const raised = { raisedBy: A, beforeRaise: 50 };
    expect(nextPurgeThresholdRaise({ before: 1000, next: 500, current: raised, actor: B })).toEqual(
      raised,
    );
    expect(
      nextPurgeThresholdRaise({ before: 1000, next: 1000, current: raised, actor: A }),
    ).toEqual(raised);
    expect(nextPurgeThresholdRaise({ before: 1000, next: 50, current: raised, actor: A })).toEqual(
      none,
    );
    expect(nextPurgeThresholdRaise({ before: 50, next: 20, current: none, actor: A })).toEqual(
      none,
    );
  });

  it('checks the raiser against the earlier value; everyone else against the stored threshold', () => {
    const raise = { raisedBy: A, beforeRaise: 50 };
    expect(effectivePurgeThreshold({ threshold: 10_000, raise, submitter: A })).toEqual({
      threshold: 50,
      selfRaised: true,
    });
    expect(effectivePurgeThreshold({ threshold: 10_000, raise, submitter: B })).toEqual({
      threshold: 10_000,
      selfRaised: false,
    });
    expect(effectivePurgeThreshold({ threshold: 50, raise: none, submitter: A })).toEqual({
      threshold: 50,
      selfRaised: false,
    });
  });

  it('a self-raised threshold still sends a 60-mailbox purge to a second approver', () => {
    const { threshold } = effectivePurgeThreshold({
      threshold: 10_000,
      raise: { raisedBy: A, beforeRaise: 50 },
      submitter: A,
    });
    const decision = decideSubmit({
      status: 'ready',
      rowVersion: 3,
      expectedRowVersion: 3,
      trigger: 'admin',
      mailboxesEligible: 60,
      storedApprovalReasons: [],
      settings: { purgeApprovalMailboxes: threshold, autoMaxMailboxes: 500 },
      action: 'move_junk',
      hardDeleteEnabled: false,
    });
    expect(decision).toMatchObject({
      ok: true,
      status: 'pending_approval',
      reasons: ['mailbox_threshold'],
    });
  });
});
