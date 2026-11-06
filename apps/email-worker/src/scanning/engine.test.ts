import { describe, expect, it } from 'vitest';
import { failureMetricReason, failureReasonCode } from './engine';

describe('failure reason codes (S7 R0, step 4.2 A6, step 4.3 U10)', () => {
  it('maps the url engine attempt failures to their own codes and metric reasons', () => {
    expect(failureReasonCode({ outcome: 'error', errorCode: 'inconsistent_read' })).toBe(
      'engine.inconsistent_read',
    );
    expect(failureReasonCode({ outcome: 'timeout', errorCode: 'extract_timeout' })).toBe(
      'engine.extract_timeout',
    );
    expect(failureMetricReason({ outcome: 'error', errorCode: 'inconsistent_read' })).toBe(
      'inconsistent_read',
    );
    expect(failureMetricReason({ outcome: 'timeout', errorCode: 'extract_timeout' })).toBe(
      'extract_timeout',
    );
    for (const code of [
      'part_unavailable',
      'part_integrity',
      'part_key_mismatch',
      'parse_row_missing',
      'eml_unavailable',
    ]) {
      expect(failureReasonCode({ outcome: 'error', errorCode: code })).toBe(`engine.${code}`);
    }
  });

  it('keeps unknown codes bounded (engine.error / engine.timeout, outcome as metric reason)', () => {
    expect(failureReasonCode({ outcome: 'error', errorCode: 'result_invalid' })).toBe(
      'engine.error',
    );
    expect(failureReasonCode({ outcome: 'timeout', errorCode: 'timeout' })).toBe('engine.timeout');
    expect(failureMetricReason({ outcome: 'error', errorCode: 'something_new' })).toBe('error');
  });
});
