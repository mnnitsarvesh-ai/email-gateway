import {
  ATTACHMENT_FILE_TYPE_VALUES,
  ENGINE_OUTCOME_VALUES,
  SANDBOX_ATTACHMENT_VERDICT_VALUES,
  SCAN_VERDICT_VALUES,
} from '@email-gateway/event-contracts';
import {
  ATTACHMENT_REASON_CODES,
  ENGINE_OUTCOMES,
  FILE_TYPE_IDS,
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

describe('attachment contract literals (step 4.2 §12 WP1)', () => {
  it('event-contracts mirrors FILE_TYPE_IDS exactly', () => {
    expect([...ATTACHMENT_FILE_TYPE_VALUES]).toEqual([...FILE_TYPE_IDS]);
    expect([...SANDBOX_ATTACHMENT_VERDICT_VALUES]).toEqual(['suspicious', 'unknown']);
    for (const code of ATTACHMENT_REASON_CODES) expect(code).toMatch(REASON_CODE_PATTERN);
  });
});
