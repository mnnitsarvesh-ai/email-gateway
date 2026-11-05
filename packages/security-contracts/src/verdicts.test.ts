import { describe, expect, it } from 'vitest';
import {
  DEFINITE_VERDICTS,
  ENGINE_OUTCOMES,
  FAILURE_OUTCOMES,
  isDefiniteVerdict,
  isFailureOutcome,
  MAX_REASON_CODES,
  mostSevere,
  REASON_CODE_PATTERN,
  reasonCodeSchema,
  reasonCodesSchema,
  SCAN_VERDICTS,
  VERDICT_SEVERITY,
} from './index';

describe('verdicts (S6, S7)', () => {
  it('has the seven standardized verdicts, lower-case, in the design order', () => {
    expect([...SCAN_VERDICTS]).toEqual([
      'clean',
      'spam',
      'suspicious',
      'malicious',
      'unknown',
      'timeout',
      'error',
    ]);
    expect([...ENGINE_OUTCOMES]).toEqual([...SCAN_VERDICTS, 'skipped']);
  });

  it('splits the verdicts into definite verdicts and failures', () => {
    expect([...DEFINITE_VERDICTS, ...FAILURE_OUTCOMES].sort()).toEqual([...SCAN_VERDICTS].sort());
    for (const v of DEFINITE_VERDICTS) expect(isDefiniteVerdict(v)).toBe(true);
    for (const v of FAILURE_OUTCOMES) {
      expect(isDefiniteVerdict(v)).toBe(false);
      expect(isFailureOutcome(v)).toBe(true);
    }
    expect(isDefiniteVerdict('skipped')).toBe(false);
    expect(isFailureOutcome('skipped')).toBe(false);
    expect(isDefiniteVerdict('toString')).toBe(false);
  });

  it('orders severity malicious > spam > suspicious > unknown > clean; failures have none', () => {
    expect(VERDICT_SEVERITY).toEqual({
      clean: 1,
      unknown: 2,
      suspicious: 3,
      spam: 4,
      malicious: 5,
    });
    expect(Object.keys(VERDICT_SEVERITY)).not.toContain('timeout');
    expect(Object.keys(VERDICT_SEVERITY)).not.toContain('error');
  });

  it('mostSevere picks the most severe definite verdict and ignores failures and skipped', () => {
    expect(mostSevere(['clean', 'spam', 'suspicious'])).toBe('spam');
    expect(mostSevere(['unknown', 'clean'])).toBe('unknown');
    expect(mostSevere(['malicious', 'spam'])).toBe('malicious');
    expect(mostSevere(['timeout', 'clean', 'error'])).toBe('clean');
    expect(mostSevere(new Set(['suspicious', 'skipped']))).toBe('suspicious');
  });

  it('mostSevere never invents clean: no definite verdict is null', () => {
    expect(mostSevere([])).toBeNull();
    expect(mostSevere(['timeout', 'error', 'skipped'])).toBeNull();
  });
});

describe('reason codes', () => {
  it('accepts dotted lower-case codes of at most 64 characters', () => {
    for (const code of [
      'spam.score',
      'auth.dmarc_reject',
      'engine.circuit_open',
      'phishing.link_mismatch_auth_failure',
      'a.b.c',
      'x1.y_2',
    ]) {
      expect(REASON_CODE_PATTERN.test(code), code).toBe(true);
      expect(reasonCodeSchema.safeParse(code).success, code).toBe(true);
    }
    expect(reasonCodeSchema.safeParse(`a.${'b'.repeat(62)}`).success).toBe(true);
    expect(reasonCodeSchema.safeParse(`a.${'b'.repeat(63)}`).success).toBe(false);
  });

  it('refuses single segments, upper case, leading digits and other characters', () => {
    for (const code of [
      'spam',
      'Spam.score',
      '1spam.score',
      'spam.',
      '.spam',
      'spam..x',
      'spam.sco-re',
      'spam score.x',
    ]) {
      expect(reasonCodeSchema.safeParse(code).success, code).toBe(false);
    }
  });

  it('caps a list at 32 unique codes', () => {
    const codes = Array.from({ length: MAX_REASON_CODES }, (_, i) => `rule.r${i}`);
    expect(reasonCodesSchema.safeParse(codes).success).toBe(true);
    expect(reasonCodesSchema.safeParse([...codes, 'rule.extra']).success).toBe(false);
    expect(reasonCodesSchema.safeParse(['spam.score', 'spam.score']).success).toBe(false);
  });
});
