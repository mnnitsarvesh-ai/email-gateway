import { describe, expect, it } from 'vitest';
import { resolveArchiveSettings } from '../documents/settings';
import type { MessageStatus } from '../vocabulary';
import {
  type CaptureDecisionInput,
  type CaptureMessageFacts,
  categoryOf,
  decideCapture,
  isFinalMessageStatus,
} from './decide';
import { directionEligible, journalEligibility, orgSideParties } from './eligibility';

/** Step 8.6 D6: capture of journal intake messages; gateway behaviour unchanged. */

const NOW = new Date('2026-11-20T12:00:00.000Z');
const HOUR = 3_600_000;

const intake = (status: MessageStatus): CaptureMessageFacts => ({
  status,
  statusReason: status === 'journaled' ? 'intake_unscanned' : null,
  statusChangedAt: new Date(NOW.getTime() - HOUR),
  direction: 'inbound',
  ingestSource: 'journal_intake',
  recipients: [
    { status: 'journaled', direction: 'inbound' },
    { status: 'journaled', direction: null },
  ],
});

const input = (m: CaptureMessageFacts, settings: unknown = null): CaptureDecisionInput => ({
  now: NOW,
  entitled: true,
  enabled: true,
  settings: resolveArchiveSettings(settings),
  sources: { journal: true, policy: false },
  message: m,
  intentCreatedAt: new Date(NOW.getTime() - HOUR),
  waitsSoFar: 0,
  maxAgeDays: 25,
  outcomeWindowDays: 7,
});

describe('decideCapture: journal intake (D6)', () => {
  it('journaled is final and captured as delivered (re-check at +1 h)', () => {
    expect(isFinalMessageStatus('journaled')).toBe(true);
    expect(decideCapture(input(intake('journaled')))).toEqual({
      action: 'capture',
      category: 'delivered',
      final: true,
      sources: { journal: true, policy: false },
      recheckAt: new Date(NOW.getTime() + HOUR),
    });
  });

  it.each(['received', 'persisted', 'scanning', 'scanned', 'scan_failed'] as const)(
    'an intake message in %s waits, even with every category included',
    (status) => {
      const d = decideCapture(
        input(intake(status), { include: { rejected: true, quarantined: true, failed: true } }),
      );
      expect(d).toMatchObject({ action: 'wait', reason: 'not_final' });
      expect(categoryOf(intake(status))).toBeNull();
    },
  );

  it('a delivered recipient does not make a non-final intake message capturable', () => {
    const m: CaptureMessageFacts = {
      ...intake('scanned'),
      recipients: [{ status: 'delivered', direction: 'inbound' }],
    };
    expect(decideCapture(input(m)).action).toBe('wait');
  });

  it('organization gates apply as for gateway mail', () => {
    expect(decideCapture({ ...input(intake('journaled')), entitled: false })).toEqual({
      action: 'skip',
      reason: 'not_entitled',
    });
    expect(decideCapture({ ...input(intake('journaled')), enabled: false })).toEqual({
      action: 'skip',
      reason: 'archiving_disabled',
    });
  });

  it('gateway messages (no ingestSource or gateway) are decided as in 8.1', () => {
    const gateway: CaptureMessageFacts = {
      status: 'scanned',
      statusReason: null,
      direction: 'inbound',
      recipients: [{ status: 'delivered', direction: 'inbound' }],
    };
    const a = decideCapture(input(gateway));
    const b = decideCapture(input({ ...gateway, ingestSource: 'gateway' }));
    expect(a).toEqual(b);
    expect(a).toMatchObject({ action: 'capture', category: 'delivered', final: false });
  });
});

describe('journal eligibility with NULL recipient directions (D3, A4)', () => {
  const settings = resolveArchiveSettings({ directions: { inbound: false, outbound: false } });
  const facts = {
    receivedAt: NOW,
    direction: 'inbound' as const,
    envelopeFrom: 'ext@example.org',
    headerFrom: null,
    recipients: [
      { address: 'x@example.org', direction: null },
      { address: 'a@example.com', direction: 'inbound' as const },
    ],
  };

  it('a NULL direction is not org-side and enables no direction', () => {
    expect(orgSideParties(facts)).toEqual(['a@example.com']);
    expect(directionEligible(settings, facts)).toBe(false);
    expect(
      directionEligible(resolveArchiveSettings({ directions: { inbound: false } }), {
        direction: 'inbound',
        recipients: [{ address: 'x@example.org', direction: null }],
      }),
    ).toBe(false);
    expect(journalEligibility({ settings, journalEnabledAt: new Date(0), message: facts })).toEqual(
      { eligible: false, reason: 'direction_disabled' },
    );
  });

  it('scope include over org-side parties ignores NULL-direction recipients', () => {
    const include = resolveArchiveSettings({
      scope: { mode: 'include', addresses: ['x@example.org'] },
    });
    expect(
      journalEligibility({
        settings: include,
        journalEnabledAt: new Date(0),
        message: facts,
        scope: {
          addresses: ['x@example.org'],
          userEmails: [],
          departmentAddresses: [],
          domains: [],
        },
      }),
    ).toEqual({ eligible: false, reason: 'out_of_scope' });
  });
});
