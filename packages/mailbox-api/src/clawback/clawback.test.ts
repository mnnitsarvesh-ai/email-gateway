import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  decideRemediation,
  DEFAULT_REMEDIATION_POLICY,
  REMEDIATION_PRESETS,
  type RemediationInput,
} from '../remediation/policy';
import { decidePurgeApproval, requiresPurgeApproval } from './approval';
import {
  canonicalCriteriaSha256,
  clawbackCriteriaSchema,
  clawbackSignalSchema,
  parseClawbackCriteria,
  UNSUPPORTED_UNTIL_ATP4,
} from './criteria';
import {
  clawbackSignalKey,
  signalFacts,
  signatureEligible,
  tiEligible,
  type SignalFactsInput,
} from './signal';
import {
  clawbackPolicyOutcome,
  clawbackRemediationInput,
  planClawbackTarget,
  targetEligibility,
  type PlanClawbackTargetInput,
} from './targets';
import {
  actionStrength,
  API_MODE_ACTION_TRIGGERS,
  CLAWBACK_ACTIONS,
  CLAWBACK_APPROVAL_REASONS,
  CLAWBACK_APPROVAL_STATUSES,
  CLAWBACK_HARD_BLOCK_IDS,
  CLAWBACK_MATCH_KEYS,
  CLAWBACK_RESTORE_STATUSES,
  CLAWBACK_SIGNAL_KINDS,
  CLAWBACK_STATUSES,
  CLAWBACK_STRENGTH_ORDER,
  CLAWBACK_TARGET_REASON_CODES,
  CLAWBACK_TARGET_RESTORE_STATUSES,
  CLAWBACK_TARGET_STATUSES,
  CLAWBACK_TRIGGERS,
  entryStateRestoreCode,
} from './vocabulary';

const NOW = new Date('2026-11-27T12:00:00.000Z');
const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);
const DAY = 86_400_000;
const iso = (ms: number) => new Date(ms).toISOString();
const hashes = (seed: string, n: number) =>
  Array.from({ length: n }, (_, i) => createHash('sha256').update(`${seed}${i}`).digest('hex'));

describe('clawback vocabularies (mirror the Prisma enums of §3.1)', () => {
  it('pins every list', () => {
    expect(CLAWBACK_TRIGGERS).toEqual([
      'late_verdict',
      'threat_intel',
      'campaign',
      'report',
      'admin',
    ]);
    expect(CLAWBACK_STATUSES).toEqual([
      'searching',
      'ready',
      'review_required',
      'pending_approval',
      'queued',
      'running',
      'completed',
      'completed_with_errors',
      'no_match',
      'too_broad',
      'denied',
      'expired',
      'cancelled',
      'failed',
    ]);
    expect(CLAWBACK_ACTIONS).toEqual([
      'move_quarantine',
      'move_junk',
      'soft_delete',
      'hard_delete',
    ]);
    expect(CLAWBACK_RESTORE_STATUSES).toEqual([
      'none',
      'requested',
      'running',
      'completed',
      'completed_with_errors',
    ]);
    expect(CLAWBACK_APPROVAL_REASONS).toEqual(['mailbox_threshold', 'hard_delete', 'auto_cap']);
    expect(CLAWBACK_APPROVAL_STATUSES).toEqual([
      'pending',
      'approved',
      'denied',
      'expired',
      'cancelled',
    ]);
    expect(CLAWBACK_TARGET_STATUSES).toEqual([
      'matched',
      'skipped',
      'simulated',
      'queued',
      'succeeded',
      'failed',
      'cancelled',
    ]);
    expect(CLAWBACK_TARGET_RESTORE_STATUSES).toEqual([
      'none',
      'queued',
      'succeeded',
      'failed',
      'skipped',
    ]);
    expect(CLAWBACK_MATCH_KEYS).toEqual([
      'message_id',
      'attachment',
      'url',
      'url_domain',
      'sender_subject',
      'sender',
      'sender_domain',
    ]);
    expect(CLAWBACK_SIGNAL_KINDS).toEqual([
      'sandbox_revision',
      'url_dynamic',
      'threat_indicator',
      'malware_signature',
      'admin',
      'campaign',
      'report',
    ]);
    expect(API_MODE_ACTION_TRIGGERS).toEqual([
      'policy',
      'admin',
      'release',
      'end_user',
      'system',
      'clawback',
      'purge',
    ]);
    expect(CLAWBACK_HARD_BLOCK_IDS).toEqual([
      'hb.clawback.url',
      'hb.clawback.threat_intel',
      'hb.clawback.analyst',
    ]);
  });

  it('lists every §5 target code once, incl. the R5 result codes', () => {
    for (const code of [
      'policy_none',
      'simulated',
      'no_mailbox_access',
      'out_of_scope',
      'mailbox_inactive',
      'report_mailbox',
      'internal_mail_disabled',
      'hard_delete_disabled',
      'remediation_in_progress',
      'already_remediated',
      'restored_after_signal',
      'already_in_target',
      'message_not_found',
      'internal_error',
    ]) {
      expect(CLAWBACK_TARGET_REASON_CODES).toContain(code);
    }
    expect(new Set(CLAWBACK_TARGET_REASON_CODES).size).toBe(CLAWBACK_TARGET_REASON_CODES.length);
    for (const code of CLAWBACK_TARGET_REASON_CODES) expect(code.length).toBeLessThanOrEqual(64);
  });

  it('orders strength tag < move_junk < move_quarantine < soft_delete < hard_delete', () => {
    expect(CLAWBACK_STRENGTH_ORDER).toEqual([
      'tag',
      'move_junk',
      'move_quarantine',
      'soft_delete',
      'hard_delete',
    ]);
    expect(CLAWBACK_STRENGTH_ORDER.map(actionStrength)).toEqual([0, 1, 2, 3, 4]);
  });

  it('builds entry_<state> restore codes', () => {
    expect(entryStateRestoreCode('released')).toBe('entry_released');
    expect(() => entryStateRestoreCode('Held!')).toThrow(RangeError);
  });
});

// ---------------------------------------------------------------------------------------------
// criteria (C4.1)
// ---------------------------------------------------------------------------------------------

const criteria = (overrides: Record<string, unknown> = {}) => ({
  v: 1,
  window: { from: iso(NOW.getTime() - 3 * DAY), to: iso(NOW.getTime()) },
  keys: { messageIdHashes: [HEX_A] },
  directions: ['inbound', 'internal'],
  includeReportMailboxes: false,
  ...overrides,
});
const OPTS = { now: NOW, maxWindowDays: 31 };

describe('api-clawback-criteria/1 (C4.1)', () => {
  it('accepts every key at its limit', () => {
    const value = criteria({
      keys: {
        messageIdHashes: hashes('m', 10),
        attachmentSha256: hashes('a', 20),
        urlSha256: hashes('u', 20),
        urlDomains: ['a.example', 'b.example', 'c.example', 'd.example', 'xn--bcher-kva.example'],
        senders: ['a@example.com', 'b.c+d@example.org'],
        senderDomains: ['example.net'],
        senderSubject: { sender: 'x@example.com', subjectKey: 'Ü'.repeat(128) },
      },
      window: { from: iso(NOW.getTime() - 5 * DAY), to: iso(NOW.getTime()) },
    });
    const result = parseClawbackCriteria(value, OPTS);
    expect(result.ok).toBe(true);
  });

  it.each([
    ['no keys', { keys: {} }, 'no_keys'],
    ['too many Message-ID hashes', { keys: { messageIdHashes: Array(11).fill(HEX_A) } }, 'Too big'],
    ['duplicate hashes', { keys: { attachmentSha256: [HEX_A, HEX_A] } }, 'duplicate_values'],
    ['upper-case hash', { keys: { urlSha256: ['A'.repeat(64)] } }, 'not_hex64'],
    ['empty key array', { keys: { urlSha256: [] } }, 'Too small'],
    [
      '6 url domains',
      { keys: { urlDomains: ['a.ex', 'b.ex', 'c.ex', 'd.ex', 'e.ex', 'f.ex'] } },
      'Too big',
    ],
    ['bad domain', { keys: { senderDomains: ['-bad.example'] } }, 'not_domain'],
    ['upper-case sender', { keys: { senders: ['Alice@example.com'] } }, 'not_lower_case_address'],
    ['no-at sender', { keys: { senders: ['alice.example.com'] } }, 'not_lower_case_address'],
    [
      'subject key 129 code points',
      { keys: { senderSubject: { sender: 'a@example.com', subjectKey: '😀'.repeat(129) } } },
      'subject_key_length',
    ],
    [
      'empty subject key',
      { keys: { senderSubject: { sender: 'a@example.com', subjectKey: '' } } },
      'subject_key_length',
    ],
    ['unknown key', { keys: { messageIdHashes: [HEX_A], body: 'x' } }, 'Unrecognized'],
    ['unknown top-level', { extra: 1 }, 'Unrecognized'],
    ['includeReportMailboxes true', { includeReportMailboxes: true }, 'Invalid input'],
    ['no direction', { directions: [] }, 'Too small'],
    ['duplicate direction', { directions: ['inbound', 'inbound'] }, 'duplicate_values'],
    ['outbound direction', { directions: ['outbound'] }, 'Invalid option'],
    ['version 2', { v: 2 }, 'Invalid input'],
    [
      'inverted window',
      { window: { from: iso(NOW.getTime()), to: iso(NOW.getTime() - DAY) } },
      'window_inverted',
    ],
    ['non-ISO window', { window: { from: 'yesterday', to: iso(NOW.getTime()) } }, 'Invalid'],
  ])('refuses %s', (_name, overrides, code) => {
    const result = parseClawbackCriteria(criteria(overrides), OPTS);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.codes.join('|')).toContain(code);
  });

  it('applies the window rules (max window, retention, sender + subject 7 days)', () => {
    const t = NOW.getTime();
    const long = criteria({ window: { from: iso(t - 32 * DAY), to: iso(t) } });
    expect(parseClawbackCriteria(long, OPTS)).toMatchObject({
      ok: false,
      codes: ['window_too_long'],
    });
    expect(parseClawbackCriteria(long, { ...OPTS, maxWindowDays: 40 }).ok).toBe(true);
    const exactly = criteria({ window: { from: iso(t - 31 * DAY), to: iso(t) } });
    expect(parseClawbackCriteria(exactly, OPTS).ok).toBe(true);
    const old = criteria({ window: { from: iso(t - 187 * DAY), to: iso(t - 180 * DAY) } });
    expect(parseClawbackCriteria(old, OPTS)).toMatchObject({
      ok: false,
      codes: ['window_before_retention'],
    });
    const senderSubject = criteria({
      keys: { senderSubject: { sender: 'a@example.com', subjectKey: 'Invoice' } },
      window: { from: iso(t - 8 * DAY), to: iso(t) },
    });
    expect(parseClawbackCriteria(senderSubject, OPTS)).toMatchObject({
      ok: false,
      codes: ['sender_subject_window_too_long'],
    });
    expect(parseClawbackCriteria(senderSubject, { ...OPTS, fromCampaignSeed: true }).ok).toBe(true);
    const sevenDays = criteria({
      keys: { senderSubject: { sender: 'a@example.com', subjectKey: 'Invoice' } },
      window: { from: iso(t - 7 * DAY), to: iso(t) },
    });
    expect(parseClawbackCriteria(sevenDays, OPTS).ok).toBe(true);
  });

  it('never echoes input values in errors (redaction)', () => {
    const result = parseClawbackCriteria(
      criteria({
        keys: {
          senders: ['Secret.Person@Example.com'],
          senderSubject: { sender: 'x@example.com', subjectKey: '' },
        },
      }),
      OPTS,
    );
    expect(result.ok).toBe(false);
    const text = JSON.stringify(result);
    expect(text).not.toContain('Secret.Person');
    expect(text).not.toContain('x@example.com');
  });

  it('hashes canonically (order of keys and set-like arrays does not matter)', () => {
    const a = clawbackCriteriaSchema.parse(
      criteria({ keys: { attachmentSha256: [HEX_A, HEX_B], messageIdHashes: [HEX_B] } }),
    );
    const b = clawbackCriteriaSchema.parse({
      includeReportMailboxes: false,
      directions: ['internal', 'inbound'],
      keys: { messageIdHashes: [HEX_B], attachmentSha256: [HEX_B, HEX_A] },
      window: a.window,
      v: 1,
    });
    expect(canonicalCriteriaSha256(a)).toBe(canonicalCriteriaSha256(b));
    expect(canonicalCriteriaSha256(a)).toMatch(/^[0-9a-f]{64}$/);
    const c = clawbackCriteriaSchema.parse(criteria({ keys: { attachmentSha256: [HEX_A] } }));
    expect(canonicalCriteriaSha256(c)).not.toBe(canonicalCriteriaSha256(a));
  });
});

// ---------------------------------------------------------------------------------------------
// signal document (§5)
// ---------------------------------------------------------------------------------------------

describe('api-clawback-signal/1 (§5)', () => {
  const signal = (overrides: Record<string, unknown> = {}) => ({
    v: 1,
    kind: 'sandbox_revision',
    refs: {
      messageId: '9001',
      receivedAt: '2026-11-20T10:15:00.000Z',
      scanId: 'scan-1',
      revision: 1,
    },
    facts: {
      verdict: 'malware',
      level: 'critical',
      hardBlocks: ['hb.malware_sandbox'],
      score: 990,
    },
    signalAt: '2026-11-20T10:20:00.000Z',
    ...overrides,
  });

  it('accepts signals with and without facts', () => {
    expect(clawbackSignalSchema.safeParse(signal()).success).toBe(true);
    expect(
      clawbackSignalSchema.safeParse(signal({ kind: 'admin', refs: {}, facts: null })).success,
    ).toBe(true);
  });

  it('refuses refs.campaignRef with unsupported_until_atp4', () => {
    const result = clawbackSignalSchema.safeParse(
      signal({ kind: 'campaign', refs: { campaignRef: 'cmp-1' } }),
    );
    expect(result.success).toBe(false);
    expect(result.error?.issues.map((i) => i.message)).toContain(UNSUPPORTED_UNTIL_ATP4);
  });

  it.each([
    [
      '10 hard blocks',
      { facts: { verdict: 'malware', level: 'high', hardBlocks: Array(10).fill('hb.x') } },
    ],
    ['bad hard block id', { facts: { verdict: 'malware', level: 'high', hardBlocks: ['HB X'] } }],
    ['level none', { facts: { verdict: 'malware', level: 'none', hardBlocks: [] } }],
    ['score 1001', { facts: { verdict: 'malware', level: 'high', hardBlocks: [], score: 1001 } }],
    ['unknown kind', { kind: 'click' }],
    ['unknown ref', { refs: { messageId: '1', subject: 'x' } }],
    ['non-numeric message id', { refs: { messageId: 'abc' } }],
    ['missing signalAt', { signalAt: undefined }],
  ])('refuses %s', (_name, overrides) => {
    expect(clawbackSignalSchema.safeParse(signal(overrides)).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
// signal keys (C2.5) — vectors computed independently (Python hashlib over the same tuple)
// ---------------------------------------------------------------------------------------------

describe('clawbackSignalKey (C2.5)', () => {
  const receivedAt = new Date('2026-11-20T10:15:00.000Z');

  it('matches the fixed vectors', () => {
    expect(
      clawbackSignalKey(42n, {
        source: 'late',
        messageId: 9001n,
        receivedAt,
        kind: 'sandbox_revision',
        revision: 1,
        urlSha256: null,
      }),
    ).toBe('3a5a22479ffcf748d3911170863efaa37bf7906405fef50fb7fe559f1fec7365');
    expect(
      clawbackSignalKey('42', {
        source: 'late',
        messageId: '9001',
        receivedAt,
        kind: 'url_dynamic',
        revision: null,
        urlSha256: 'ab'.repeat(32),
      }),
    ).toBe('fc202280a44c225751959bae8c196b178b1a98d87228d7f9df3cc8db37f9a862');
    expect(clawbackSignalKey(42, { source: 'ti', table: 'threat_indicators', rowId: 77 })).toBe(
      '13c5d2ec19806eab51abb000519cf65c6e6351ea355c0022b1e5f7ebad791f8a',
    );
    expect(clawbackSignalKey(42, { source: 'ti', table: 'malware_signatures', rowId: 77n })).toBe(
      '44625f9a56ae1151cd635989766a9eb3b614624397eb4c46698346327c46cc45',
    );
    // The organization is part of the tuple.
    expect(clawbackSignalKey(43, { source: 'ti', table: 'threat_indicators', rowId: 77 })).toBe(
      '844cd15fd2a37d3869a4c9131c69db82d86a957afbe4bfdb0ef6bdabdc605d61',
    );
  });

  it('refuses malformed inputs', () => {
    const late = {
      source: 'late' as const,
      messageId: 1,
      receivedAt,
      kind: 'sandbox_revision' as const,
      revision: 1,
      urlSha256: null,
    };
    expect(() => clawbackSignalKey(-1, late)).toThrow('signal_key_invalid_organization');
    expect(() => clawbackSignalKey(1, { ...late, messageId: 'x' })).toThrow(
      'signal_key_invalid_message_id',
    );
    expect(() => clawbackSignalKey(1, { ...late, receivedAt: new Date(NaN) })).toThrow(
      'signal_key_invalid_received_at',
    );
    expect(() => clawbackSignalKey(1, { ...late, revision: 256 })).toThrow(
      'signal_key_invalid_revision',
    );
    expect(() => clawbackSignalKey(1, { ...late, kind: 'url_dynamic', revision: null })).toThrow(
      'signal_key_invalid_url_sha256',
    );
  });
});

// ---------------------------------------------------------------------------------------------
// signalFacts (C3.1) — every row
// ---------------------------------------------------------------------------------------------

describe('signalFacts (C3.1)', () => {
  it.each<[string, SignalFactsInput, object]>([
    [
      'sandbox revision: the revision facts',
      {
        kind: 'sandbox_revision',
        verdict: 'malware',
        level: 'critical',
        hardBlocks: ['hb.malware_sandbox'],
        score: 990,
      },
      { verdict: 'malware', level: 'critical', hardBlocks: ['hb.malware_sandbox'], score: 990 },
    ],
    [
      'sandbox revision: none level read as low, hard blocks bounded',
      {
        kind: 'sandbox_revision',
        verdict: 'suspicious',
        level: 'none',
        hardBlocks: [...Array.from({ length: 12 }, (_, i) => `hb.x${i}`), 'BAD ID'],
      },
      {
        verdict: 'suspicious',
        level: 'low',
        hardBlocks: Array.from({ length: 9 }, (_, i) => `hb.x${i}`),
      },
    ],
    [
      'URL dynamic malicious',
      { kind: 'url_dynamic', urlVerdict: 'malicious' },
      { verdict: 'phishing', level: 'critical', hardBlocks: ['hb.clawback.url'] },
    ],
    [
      'URL dynamic suspicious',
      { kind: 'url_dynamic', urlVerdict: 'suspicious' },
      { verdict: 'suspicious', level: 'high', hardBlocks: [] },
    ],
    [
      'TI file hash, high, 80',
      {
        kind: 'threat_indicator',
        indicatorType: 'file_sha256',
        severity: 'high',
        confidence: 80,
        category: null,
      },
      { verdict: 'malware', level: 'high', hardBlocks: [] },
    ],
    [
      'TI file hash, high, 90 → hard block',
      {
        kind: 'threat_indicator',
        indicatorType: 'file_sha256',
        severity: 'high',
        confidence: 90,
        category: 'phishing',
      },
      { verdict: 'malware', level: 'high', hardBlocks: ['hb.clawback.threat_intel'] },
    ],
    [
      'TI url, critical, c2',
      {
        kind: 'threat_indicator',
        indicatorType: 'url',
        severity: 'critical',
        confidence: 50,
        category: 'c2',
      },
      { verdict: 'malware', level: 'critical', hardBlocks: ['hb.clawback.threat_intel'] },
    ],
    [
      'TI domain, malware',
      {
        kind: 'threat_indicator',
        indicatorType: 'domain',
        severity: 'high',
        confidence: 85,
        category: 'malware',
      },
      { verdict: 'malware', level: 'high', hardBlocks: [] },
    ],
    [
      'TI url, phishing',
      {
        kind: 'threat_indicator',
        indicatorType: 'url',
        severity: 'high',
        confidence: 85,
        category: 'phishing',
      },
      { verdict: 'phishing', level: 'high', hardBlocks: [] },
    ],
    [
      'TI domain, scam',
      {
        kind: 'threat_indicator',
        indicatorType: 'domain',
        severity: 'high',
        confidence: 85,
        category: 'scam',
      },
      { verdict: 'phishing', level: 'high', hardBlocks: [] },
    ],
    [
      'TI url, spam',
      {
        kind: 'threat_indicator',
        indicatorType: 'url',
        severity: 'high',
        confidence: 85,
        category: 'spam',
      },
      { verdict: 'spam', level: 'high', hardBlocks: [] },
    ],
    [
      'TI url, no category',
      {
        kind: 'threat_indicator',
        indicatorType: 'url',
        severity: 'high',
        confidence: 85,
        category: null,
      },
      { verdict: 'suspicious', level: 'high', hardBlocks: [] },
    ],
    [
      'TI url, other',
      {
        kind: 'threat_indicator',
        indicatorType: 'url',
        severity: 'medium',
        confidence: 99,
        category: 'other',
      },
      { verdict: 'suspicious', level: 'medium', hardBlocks: ['hb.clawback.threat_intel'] },
    ],
    [
      'TI email (sender), phishing, critical',
      {
        kind: 'threat_indicator',
        indicatorType: 'email',
        severity: 'critical',
        confidence: 80,
        category: 'phishing',
      },
      { verdict: 'phishing', level: 'critical', hardBlocks: ['hb.clawback.threat_intel'] },
    ],
    [
      'malware signature (sandbox, high): confirmed hash',
      { kind: 'malware_signature', severity: 'high' },
      { verdict: 'malware', level: 'high', hardBlocks: ['hb.clawback.threat_intel'] },
    ],
    [
      'report malicious, original phishing',
      { kind: 'report', originalScanVerdict: 'phishing' },
      { verdict: 'phishing', level: 'critical', hardBlocks: ['hb.clawback.analyst'] },
    ],
    [
      'report malicious, original bec',
      { kind: 'report', originalScanVerdict: 'bec' },
      { verdict: 'bec', level: 'critical', hardBlocks: ['hb.clawback.analyst'] },
    ],
    [
      'report malicious, original malware',
      { kind: 'report', originalScanVerdict: 'malware' },
      { verdict: 'malware', level: 'critical', hardBlocks: ['hb.clawback.analyst'] },
    ],
    [
      'report malicious, original clean → phishing',
      { kind: 'report', originalScanVerdict: 'clean' },
      { verdict: 'phishing', level: 'critical', hardBlocks: ['hb.clawback.analyst'] },
    ],
    [
      'report malicious, no scan → phishing',
      { kind: 'report', originalScanVerdict: null },
      { verdict: 'phishing', level: 'critical', hardBlocks: ['hb.clawback.analyst'] },
    ],
    [
      'admin, default critical',
      { kind: 'admin', verdict: 'bec' },
      { verdict: 'bec', level: 'critical', hardBlocks: ['hb.clawback.analyst'] },
    ],
    [
      'campaign, chosen high',
      { kind: 'campaign', verdict: 'spam', level: 'high' },
      { verdict: 'spam', level: 'high', hardBlocks: [] },
    ],
  ])('%s', (_name, input, expected) => {
    expect(signalFacts(input)).toEqual(expected);
  });

  it('feeds P1 as designed (URL malicious → quarantine; TI 80 high → tag)', () => {
    const context: RemediationInput['context'] = {
      provider: 'microsoft_365',
      grantActive: true,
      remediationPaused: false,
      domainEffectiveMode: 'hybrid',
      mailboxStatus: 'active',
    };
    const decide = (input: SignalFactsInput) =>
      decideRemediation(
        clawbackRemediationInput({
          copyRiskScore: 10,
          direction: 'inbound',
          facts: signalFacts(input),
          context,
        }),
        DEFAULT_REMEDIATION_POLICY,
        { hardDeleteEnabled: false },
      );
    expect(decide({ kind: 'url_dynamic', urlVerdict: 'malicious' })).toMatchObject({
      outcome: 'act',
      action: 'move_quarantine',
    });
    expect(
      decide({
        kind: 'threat_indicator',
        indicatorType: 'url',
        severity: 'high',
        confidence: 80,
        category: 'phishing',
      }),
    ).toMatchObject({ outcome: 'act', action: 'tag' });
    expect(decide({ kind: 'campaign', verdict: 'spam', level: 'high' })).toEqual({
      outcome: 'none',
    });
  });
});

describe('threat-intelligence eligibility (C2.2)', () => {
  const ind = (overrides: Partial<Parameters<typeof tiEligible>[0]> = {}) => ({
    indicatorType: 'url' as const,
    severity: 'high' as const,
    confidence: 80,
    expiresAt: null,
    ...overrides,
  });

  it.each([
    ['url high 80', ind(), true],
    [
      'domain critical 100',
      ind({ indicatorType: 'domain', severity: 'critical', confidence: 100 }),
      true,
    ],
    ['file hash', ind({ indicatorType: 'file_sha256' }), true],
    ['email', ind({ indicatorType: 'email' }), true],
    ['ip never', ind({ indicatorType: 'ip', severity: 'critical', confidence: 100 }), false],
    ['medium severity', ind({ severity: 'medium' }), false],
    ['low severity', ind({ severity: 'low' }), false],
    ['confidence 79', ind({ confidence: 79 }), false],
    ['expired', ind({ expiresAt: new Date(NOW.getTime() - 1) }), false],
    ['expires exactly now', ind({ expiresAt: NOW }), false],
    ['expires later', ind({ expiresAt: new Date(NOW.getTime() + 1) }), true],
    ['NaN confidence', ind({ confidence: Number.NaN }), false],
  ])('%s → %s', (_name, indicator, expected) => {
    expect(tiEligible(indicator, 80, NOW)).toBe(expected);
  });

  it('uses the organization floor', () => {
    expect(tiEligible(ind({ confidence: 60 }), 50, NOW)).toBe(true);
    expect(tiEligible(ind({ confidence: 99 }), 100, NOW)).toBe(false);
  });

  it('malware signatures: high/critical and not expired', () => {
    expect(signatureEligible({ severity: 'high', expiresAt: null }, NOW)).toBe(true);
    expect(
      signatureEligible({ severity: 'critical', expiresAt: new Date(NOW.getTime() + DAY) }, NOW),
    ).toBe(true);
    expect(signatureEligible({ severity: 'medium', expiresAt: null }, NOW)).toBe(false);
    expect(
      signatureEligible({ severity: 'high', expiresAt: new Date(NOW.getTime() - DAY) }, NOW),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
// targets (C5.2, C5.3, C3.2)
// ---------------------------------------------------------------------------------------------

describe('targetEligibility (C5.2, C3.4)', () => {
  const base = {
    grantActive: true,
    domainEffectiveMode: 'api' as const,
    mailboxStatus: 'active' as const,
    reportMailbox: false,
  };
  it.each([
    ['eligible', base, { eligible: true }],
    ['hybrid eligible', { ...base, domainEffectiveMode: 'hybrid' as const }, { eligible: true }],
    ['discovered eligible', { ...base, mailboxStatus: 'discovered' as const }, { eligible: true }],
    ['no grant', { ...base, grantActive: false }, { eligible: false, reason: 'no_mailbox_access' }],
    [
      'inline domain',
      { ...base, domainEffectiveMode: 'inline' as const },
      { eligible: false, reason: 'out_of_scope' },
    ],
    [
      'no domain',
      { ...base, domainEffectiveMode: null },
      { eligible: false, reason: 'out_of_scope' },
    ],
    [
      'disabled',
      { ...base, mailboxStatus: 'disabled' as const },
      { eligible: false, reason: 'mailbox_inactive' },
    ],
    [
      'deleted',
      { ...base, mailboxStatus: 'deleted' as const },
      { eligible: false, reason: 'mailbox_inactive' },
    ],
    [
      'report mailbox',
      { ...base, reportMailbox: true },
      { eligible: false, reason: 'report_mailbox' },
    ],
    [
      'order: grant before everything',
      {
        grantActive: false,
        domainEffectiveMode: 'inline' as const,
        mailboxStatus: 'deleted' as const,
        reportMailbox: true,
      },
      { eligible: false, reason: 'no_mailbox_access' },
    ],
    [
      'order: inactive before report mailbox',
      { ...base, mailboxStatus: 'disabled' as const, reportMailbox: true },
      { eligible: false, reason: 'mailbox_inactive' },
    ],
  ])('%s', (_name, input, expected) => {
    expect(targetEligibility(input)).toEqual(expected);
  });
});

describe('planClawbackTarget (C5.3)', () => {
  const signalAt = new Date('2026-11-20T10:00:00.000Z');
  const plan = (overrides: Partial<PlanClawbackTargetInput>) =>
    planClawbackTarget({
      copyState: 'none',
      copyAction: null,
      lastRestoreCompletedAt: null,
      signalAt,
      action: 'move_quarantine',
      mode: 'policy',
      ...overrides,
    });

  it.each<[string, Partial<PlanClawbackTargetInput>, object]>([
    ['untouched copy → act', {}, { kind: 'act', action: 'move_quarantine' }],
    [
      'simulated copy → act',
      { copyState: 'simulated', copyAction: 'tag' },
      { kind: 'act', action: 'move_quarantine' },
    ],
    [
      'failed copy → act',
      { copyState: 'failed', copyAction: 'move_junk' },
      { kind: 'act', action: 'move_quarantine' },
    ],
    ['skipped copy → act', { copyState: 'skipped' }, { kind: 'act', action: 'move_quarantine' }],
    [
      'pending → in progress',
      { copyState: 'pending', copyAction: 'tag' },
      { kind: 'skip', reason: 'remediation_in_progress' },
    ],
    [
      'tagged → escalate',
      { copyState: 'remediated', copyAction: 'tag' },
      { kind: 'act', action: 'move_quarantine' },
    ],
    [
      'junk → escalate to quarantine',
      { copyState: 'remediated', copyAction: 'move_junk' },
      { kind: 'act', action: 'move_quarantine' },
    ],
    [
      'quarantined → equal',
      { copyState: 'remediated', copyAction: 'move_quarantine' },
      { kind: 'skip', reason: 'already_remediated' },
    ],
    [
      'soft deleted → stronger',
      { copyState: 'remediated', copyAction: 'soft_delete' },
      { kind: 'skip', reason: 'already_remediated' },
    ],
    [
      'remediated, unknown action',
      { copyState: 'remediated', copyAction: null },
      { kind: 'skip', reason: 'already_remediated' },
    ],
    [
      'quarantined, explicit soft delete → escalate',
      {
        copyState: 'remediated',
        copyAction: 'move_quarantine',
        action: 'soft_delete',
        mode: 'explicit',
      },
      { kind: 'act', action: 'soft_delete' },
    ],
    [
      'tag never replaces junk',
      { copyState: 'remediated', copyAction: 'move_junk', action: 'tag' },
      { kind: 'skip', reason: 'already_remediated' },
    ],
    [
      'restored after the signal',
      { copyState: 'restored', lastRestoreCompletedAt: new Date(signalAt.getTime() + 1) },
      { kind: 'skip', reason: 'restored_after_signal' },
    ],
    [
      'restored before the signal → act',
      { copyState: 'restored', lastRestoreCompletedAt: new Date(signalAt.getTime() - 1) },
      { kind: 'act', action: 'move_quarantine' },
    ],
    [
      'restored at the signal instant → act',
      { copyState: 'restored', lastRestoreCompletedAt: signalAt },
      { kind: 'act', action: 'move_quarantine' },
    ],
    [
      'restored, unknown time → skip (conservative)',
      { copyState: 'restored', lastRestoreCompletedAt: null },
      { kind: 'skip', reason: 'restored_after_signal' },
    ],
    [
      'hard delete in policy mode',
      { action: 'hard_delete' },
      { kind: 'skip', reason: 'hard_delete_not_allowed' },
    ],
    [
      'hard delete in explicit mode',
      { action: 'hard_delete', mode: 'explicit', hardDeleteEnabled: true },
      { kind: 'act', action: 'hard_delete' },
    ],
    [
      'explicit hard delete with the setting off',
      { action: 'hard_delete', mode: 'explicit', hardDeleteEnabled: false },
      { kind: 'skip', reason: 'hard_delete_disabled' },
    ],
    [
      'hard delete rule precedes in-progress',
      { action: 'hard_delete', copyState: 'pending' },
      { kind: 'skip', reason: 'hard_delete_not_allowed' },
    ],
  ])('%s', (_name, overrides, expected) => {
    expect(plan(overrides)).toEqual(expected);
  });
});

describe('policy mode (C3.2)', () => {
  const context: RemediationInput['context'] = {
    provider: 'google_workspace',
    grantActive: true,
    remediationPaused: false,
    domainEffectiveMode: 'hybrid',
    mailboxStatus: 'active',
    internalMailEnabled: true,
  };

  it('builds the input with copy authority and the higher score', () => {
    const input = clawbackRemediationInput({
      copyRiskScore: 300,
      direction: 'internal',
      facts: {
        verdict: 'phishing',
        level: 'critical',
        hardBlocks: ['hb.clawback.url'],
        score: 900,
      },
      context,
    });
    expect(input).toEqual({
      copy: {
        status: 'scanned',
        verdict: 'phishing',
        riskScore: 900,
        verdictAuthority: 'copy',
        direction: 'internal',
      },
      risk: { level: 'critical', hardBlocks: ['hb.clawback.url'] },
      policyOutcome: null,
      context,
    });
    expect(
      clawbackRemediationInput({
        copyRiskScore: 450,
        direction: 'inbound',
        facts: { verdict: 'malware', level: 'high', hardBlocks: [] },
        context,
      }).copy.riskScore,
    ).toBe(450);
    expect(
      clawbackRemediationInput({
        copyRiskScore: null,
        direction: 'inbound',
        facts: { verdict: 'malware', level: 'high', hardBlocks: [] },
        context,
      }).copy.riskScore,
    ).toBeNull();
  });

  it('maps decisions to target outcomes', () => {
    const facts = signalFacts({ kind: 'url_dynamic', urlVerdict: 'malicious' });
    const build = (
      ctx: Partial<RemediationInput['context']>,
      direction: 'inbound' | 'internal' = 'inbound',
    ) =>
      clawbackRemediationInput({
        copyRiskScore: 0,
        direction,
        facts,
        context: { ...context, ...ctx },
      });
    expect(
      clawbackPolicyOutcome(
        decideRemediation(build({}), DEFAULT_REMEDIATION_POLICY, { hardDeleteEnabled: false }),
      ),
    ).toEqual({
      kind: 'act',
      action: 'move_quarantine',
      ruleId: 'p1-high-confidence-malware-phishing-hb',
    });
    expect(
      clawbackPolicyOutcome(
        decideRemediation(build({}), REMEDIATION_PRESETS.detectOnlyStart, {
          hardDeleteEnabled: false,
        }),
      ),
    ).toMatchObject({ kind: 'simulate', action: 'move_quarantine' });
    expect(
      clawbackPolicyOutcome(
        decideRemediation(build({ remediationPaused: true }), DEFAULT_REMEDIATION_POLICY, {
          hardDeleteEnabled: false,
        }),
      ),
    ).toEqual({ kind: 'skip', reason: 'remediation_paused' });
    expect(
      clawbackPolicyOutcome(
        decideRemediation(
          build({ internalMailEnabled: false }, 'internal'),
          DEFAULT_REMEDIATION_POLICY,
          {
            hardDeleteEnabled: false,
          },
        ),
      ),
    ).toEqual({ kind: 'skip', reason: 'internal_mail_disabled' });
    expect(clawbackPolicyOutcome({ outcome: 'none' })).toEqual({
      kind: 'skip',
      reason: 'policy_none',
    });
  });
});

// ---------------------------------------------------------------------------------------------
// approval (C6)
// ---------------------------------------------------------------------------------------------

describe('requiresPurgeApproval (C6 "When")', () => {
  it.each([
    [50, 50, 'move_junk', false, []],
    [51, 50, 'move_junk', false, ['mailbox_threshold']],
    [1, 50, 'hard_delete', false, ['hard_delete']],
    [10, 50, null, true, ['auto_cap']],
    [600, 50, 'hard_delete', true, ['mailbox_threshold', 'hard_delete', 'auto_cap']],
    [0, 1, 'soft_delete', false, []],
  ] as const)(
    '%i mailboxes, threshold %i, %s, autoCap %s → %j',
    (mailboxesEligible, threshold, action, autoCap, reasons) => {
      expect(requiresPurgeApproval({ mailboxesEligible, threshold, action, autoCap })).toEqual({
        required: reasons.length > 0,
        reasons: [...reasons],
      });
    },
  );
});

describe('decidePurgeApproval (C6 "Rules", mirrors checkApprover)', () => {
  const approver = {
    type: 'user' as const,
    userId: '7',
    permissions: ['remediation:read', 'remediation:purge'],
  };
  const request = {
    status: 'pending' as const,
    expiresAt: new Date(NOW.getTime() + 3600_000),
    requestedByUserId: '5',
    submittedByUserId: '6',
  };
  type Input = Parameters<typeof decidePurgeApproval>[0];
  const decide = (overrides: {
    approver?: Partial<Input['approver']>;
    request?: Partial<Input['request']>;
  }) =>
    decidePurgeApproval({
      approver: { ...approver, ...overrides.approver },
      request: { ...request, ...overrides.request },
      now: NOW,
    });

  it.each<[string, Parameters<typeof decide>[0], object]>([
    ['allowed', {}, { allowed: true }],
    ['allowed for a system clawback', { request: { requestedByUserId: null } }, { allowed: true }],
    [
      'api key',
      { approver: { type: 'api_key' } },
      { allowed: false, code: 'api_mode_purge_approval_forbidden', reason: 'api_key' },
    ],
    [
      'user without id',
      { approver: { userId: null } },
      { allowed: false, code: 'api_mode_purge_approval_forbidden', reason: 'api_key' },
    ],
    [
      'missing permission',
      { approver: { permissions: ['remediation:write'] } },
      { allowed: false, code: 'api_mode_purge_approval_forbidden', reason: 'missing_permission' },
    ],
    [
      'requester',
      { approver: { userId: '5' } },
      { allowed: false, code: 'api_mode_purge_approval_forbidden', reason: 'requester' },
    ],
    [
      'submitter',
      { approver: { userId: '6' } },
      { allowed: false, code: 'api_mode_purge_approval_forbidden', reason: 'requester' },
    ],
    [
      'approved already',
      { request: { status: 'approved' } },
      { allowed: false, code: 'api_mode_purge_approval_not_pending', reason: 'not_pending' },
    ],
    [
      'no approval',
      { request: { status: null } },
      { allowed: false, code: 'api_mode_purge_approval_not_pending', reason: 'not_pending' },
    ],
    [
      'expired',
      { request: { expiresAt: NOW } },
      { allowed: false, code: 'api_mode_purge_approval_not_pending', reason: 'expired' },
    ],
    [
      'no expiry stored',
      { request: { expiresAt: null } },
      { allowed: false, code: 'api_mode_purge_approval_not_pending', reason: 'expired' },
    ],
    [
      'order: permission before pending',
      { approver: { permissions: [] }, request: { status: 'denied' } },
      { allowed: false, code: 'api_mode_purge_approval_forbidden', reason: 'missing_permission' },
    ],
    [
      'order: pending before requester',
      { approver: { userId: '5' }, request: { status: 'expired' } },
      { allowed: false, code: 'api_mode_purge_approval_not_pending', reason: 'not_pending' },
    ],
  ])('%s', (_name, overrides, expected) => {
    expect(decide(overrides)).toEqual(expected);
  });
});
