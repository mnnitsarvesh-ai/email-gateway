import { describe, expect, it } from 'vitest';
import { reinjectionDeferralClass } from './reinjector';

const reply = (code: number, enhancedStatus: string | null, text: string) => ({
  code,
  enhancedStatus,
  lines: [text],
  text,
});

describe('reinjectionDeferralClass (R9.2, §9 item 4)', () => {
  it('classifies the 10026 "Destination not configured" RCPT refusal as no_destination', () => {
    // As postfix-outbound 3.7 answers it (docs/deployment/mail-routing.md, V5).
    expect(
      reinjectionDeferralClass(
        reply(
          450,
          '4.4.1',
          '4.4.1 <user@example.test>: Recipient address rejected: Destination not configured',
        ),
      ),
    ).toBe('no_destination');
  });

  it('keeps every other temporary refusal reinjection_4xx', () => {
    expect(reinjectionDeferralClass(reply(451, '4.3.0', '4.3.0 Temporary lookup failure'))).toBe(
      'reinjection_4xx',
    );
    expect(reinjectionDeferralClass(reply(452, null, 'Insufficient system storage'))).toBe(
      'reinjection_4xx',
    );
    expect(reinjectionDeferralClass(undefined)).toBe('reinjection_4xx');
  });
});
