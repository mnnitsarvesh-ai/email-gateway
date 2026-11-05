import { ENGINE_OUTCOME_VALUES, SCAN_VERDICT_VALUES } from '@email-gateway/event-contracts';
import {
  ENGINE_OUTCOMES,
  REASON_CODE_PATTERN,
  SCAN_VERDICTS,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';

/**
 * event-contracts has no dependency on security-contracts; the email-worker depends on both and
 * asserts the mirrored literal lists stay equal (step 4.1 §4).
 */
describe('scan verdict literals', () => {
  it('event-contracts mirrors security-contracts exactly', () => {
    expect([...SCAN_VERDICT_VALUES]).toEqual([...SCAN_VERDICTS]);
    expect([...ENGINE_OUTCOME_VALUES]).toEqual([...ENGINE_OUTCOMES]);
    expect(REASON_CODE_PATTERN.source).toBe('^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)+$');
  });
});
