import { describe, expect, it } from 'vitest';
import { resolveArchiveSettings } from '../documents/settings';
import type { MessageStatus } from '../vocabulary';
import {
  CAPTURE_SKIP_REASONS,
  type CaptureDecisionInput,
  type CaptureMessageFacts,
  categoryOf,
  decideCapture,
} from './decide';

/**
 * Step API-1 D7.6 (ADR-0098, docs/plan/steps/35-api-mode-protection.md): a mailbox API copy is a
 * detection copy, never the compliance record; `decideCapture` skips it (`api_copy`) whatever
 * its state, the organization's archive settings or the intent's sources. Journal intake and
 * gateway messages are decided as before (intake.test.ts, capture.test.ts).
 */

const NOW = new Date('2026-11-26T12:00:00.000Z');
const HOUR = 3_600_000;

const copy = (status: MessageStatus): CaptureMessageFacts => ({
  status,
  statusReason: status === 'journaled' ? 'intake_scan_complete' : null,
  statusChangedAt: new Date(NOW.getTime() - HOUR),
  direction: 'inbound',
  ingestSource: 'mailbox_api',
  recipients: [{ status: 'journaled', direction: 'inbound' }],
});

const input = (m: CaptureMessageFacts | null): CaptureDecisionInput => ({
  now: NOW,
  entitled: true,
  enabled: true,
  settings: resolveArchiveSettings({
    include: { rejected: true, quarantined: true, failed: true },
  }),
  sources: { journal: true, policy: true },
  message: m,
  intentCreatedAt: new Date(NOW.getTime() - HOUR),
  waitsSoFar: 0,
  maxAgeDays: 30,
  outcomeWindowDays: 7,
});

describe('decideCapture: mailbox API copies (step API-1 D7.6)', () => {
  it('api_copy is a capture skip reason', () => {
    expect(CAPTURE_SKIP_REASONS).toContain('api_copy');
  });

  it.each(['persisted', 'scanning', 'scanned', 'scan_failed', 'journaled'] as const)(
    'a copy in %s is skipped (api_copy) with every category and source included',
    (status) => {
      expect(decideCapture(input(copy(status)))).toEqual({ action: 'skip', reason: 'api_copy' });
      expect(categoryOf(copy(status))).toBeNull();
    },
  );

  it('the skip precedes the organization gates and the original check', () => {
    expect(decideCapture({ ...input(copy('journaled')), entitled: false })).toEqual({
      action: 'skip',
      reason: 'api_copy',
    });
    expect(decideCapture({ ...input(copy('journaled')), enabled: false })).toEqual({
      action: 'skip',
      reason: 'api_copy',
    });
    expect(decideCapture(input({ ...copy('journaled'), originalAvailable: false }))).toEqual({
      action: 'skip',
      reason: 'api_copy',
    });
  });

  it('a delivered recipient never makes a copy capturable', () => {
    const m: CaptureMessageFacts = {
      ...copy('journaled'),
      recipients: [{ status: 'delivered', direction: 'inbound' }],
    };
    expect(decideCapture(input(m))).toEqual({ action: 'skip', reason: 'api_copy' });
  });

  it('a missing message row is still lost (message_missing)', () => {
    expect(decideCapture(input(null))).toEqual({ action: 'lost', reason: 'message_missing' });
  });

  it('journal intake and gateway messages are unchanged', () => {
    expect(
      decideCapture(input({ ...copy('journaled'), ingestSource: 'journal_intake' })),
    ).toMatchObject({ action: 'capture', category: 'delivered', final: true });
    expect(
      decideCapture(
        input({
          ...copy('delivered'),
          ingestSource: 'gateway',
          recipients: [{ status: 'delivered', direction: 'inbound' }],
        }),
      ),
    ).toMatchObject({ action: 'capture', category: 'delivered' });
  });
});
