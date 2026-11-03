import { describe, expect, it } from 'vitest';
import { diagnosticText, noticeDeliveryStatus } from './bounce-notice.service';
import type { DsnRecipient } from './dsn-parser';

const recipient = (overrides: Partial<DsnRecipient>): DsnRecipient => ({
  finalRecipient: 'a@b.test',
  originalRecipient: null,
  action: 'failed',
  status: '5.1.1',
  remoteMta: null,
  diagnosticCode: null,
  smtpCode: null,
  ...overrides,
});

describe('bounce notice → delivery signal (step 2.3 R9)', () => {
  it.each([
    [{ action: 'failed', status: '5.1.1' }, 'bounced'],
    [{ action: 'failed', status: null }, 'bounced'],
    [{ action: 'failed', status: '4.4.7' }, 'expired'],
    [{ action: 'delayed', status: '4.2.1' }, 'deferred'],
    [{ action: 'delivered', status: '2.0.0' }, null],
    [{ action: 'relayed', status: '2.0.0' }, null],
  ] as const)('%j → %s', (fields, status) => {
    expect(noticeDeliveryStatus(recipient(fields))).toBe(status);
  });

  it('strips the diagnostic type before classification', () => {
    expect(diagnosticText(recipient({ diagnosticCode: 'smtp; 450 4.2.1 busy' }))).toBe(
      '450 4.2.1 busy',
    );
    expect(diagnosticText(recipient({ diagnosticCode: 'no type' }))).toBe('no type');
    expect(diagnosticText(recipient({ diagnosticCode: null }))).toBe('');
  });
});
