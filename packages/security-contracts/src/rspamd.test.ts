import { describe, expect, it } from 'vitest';
import {
  isRspamdReasonCode,
  REASON_CODE_MAX_LENGTH,
  REASON_CODE_PATTERN,
  RSPAMD_MAPPING_VERSION,
  RSPAMD_REASON_CODES,
  rspamdReasonCodeSchema,
} from './index';

describe('rspamd-map/2 contract list (step 5.1 R18)', () => {
  it('names the mapping version', () => {
    expect(RSPAMD_MAPPING_VERSION).toBe('rspamd-map/2');
  });

  it('lists the 27 codes of the mapper and the engine', () => {
    expect(RSPAMD_REASON_CODES).toHaveLength(27);
    expect(new Set(RSPAMD_REASON_CODES).size).toBe(RSPAMD_REASON_CODES.length);
    expect(RSPAMD_REASON_CODES).toContain('engine.too_large');
    expect(RSPAMD_REASON_CODES).toContain('clean.below_threshold');
  });

  it('every code matches the reason-code pattern and length', () => {
    for (const code of RSPAMD_REASON_CODES) {
      expect(code).toMatch(REASON_CODE_PATTERN);
      expect(code.length).toBeLessThanOrEqual(REASON_CODE_MAX_LENGTH);
    }
  });

  it('isRspamdReasonCode and the schema accept only listed codes', () => {
    expect(isRspamdReasonCode('spam.gtube')).toBe(true);
    expect(isRspamdReasonCode('spam.unknown_rule')).toBe(false);
    expect(rspamdReasonCodeSchema.safeParse('auth.dmarc_reject').success).toBe(true);
    expect(rspamdReasonCodeSchema.safeParse('url.none').success).toBe(false);
  });
});
