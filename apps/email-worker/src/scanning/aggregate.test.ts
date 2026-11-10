import { describe, expect, it } from 'vitest';
import { aggregateRound, type FinalEngineResult } from './aggregate';

const final = (
  engine: string,
  outcome: FinalEngineResult['outcome'],
  reasonCodes: string[] = [],
  errorCode: string | null = null,
): FinalEngineResult => ({ engine, outcome, reasonCodes, errorCode, attempts: 1 });

describe('aggregateRound (S6)', () => {
  it('a clean required engine gives scanned/completed/clean', () => {
    expect(
      aggregateRound(['rspamd'], [final('rspamd', 'clean', ['clean.below_threshold'])]),
    ).toEqual({
      outcome: 'scanned',
      lifecycleReason: 'scan_complete',
      scanStatus: 'completed',
      verdict: 'clean',
      reasonCodes: ['clean.below_threshold'],
      failedRequired: [],
    });
  });

  it('takes the most severe definite verdict of all finals; unknown when none is definite', () => {
    const r = aggregateRound(
      ['rspamd'],
      [final('rspamd', 'suspicious', ['auth.dmarc_reject']), final('url', 'spam', ['spam.score'])],
    );
    expect(r.verdict).toBe('spam');
    expect(r.reasonCodes).toEqual(['spam.score', 'auth.dmarc_reject']);
    expect(aggregateRound(['rspamd'], [final('rspamd', 'skipped')]).verdict).toBe('unknown');
    expect(
      aggregateRound(['rspamd'], [final('rspamd', 'unknown', ['engine.too_large'])]).verdict,
    ).toBe('unknown');
  });

  it('a required timeout or error fails the round, never clean', () => {
    const timeout = aggregateRound(['rspamd'], [final('rspamd', 'timeout', ['engine.timeout'])]);
    expect(timeout).toMatchObject({
      outcome: 'scan_failed',
      lifecycleReason: 'scan_timeout',
      scanStatus: 'timed_out',
      verdict: 'timeout',
      failedRequired: ['rspamd'],
    });
    const error = aggregateRound(['rspamd'], [final('rspamd', 'error', ['engine.error'])]);
    expect(error).toMatchObject({
      outcome: 'scan_failed',
      lifecycleReason: 'scan_error',
      scanStatus: 'failed',
      verdict: 'error',
    });
    const both = aggregateRound(
      ['rspamd', 'clamav'],
      [final('rspamd', 'timeout'), final('clamav', 'error')],
    );
    expect(both).toMatchObject({ lifecycleReason: 'scan_error', verdict: 'error' });
  });

  it('eml_unavailable takes precedence as the failure reason', () => {
    const r = aggregateRound(
      ['rspamd'],
      [final('rspamd', 'error', ['engine.eml_unavailable'], 'eml_unavailable')],
    );
    expect(r).toMatchObject({ lifecycleReason: 'eml_unavailable', scanStatus: 'failed' });
  });

  it('malicious beats a failure in the verdict, but the round still fails', () => {
    const r = aggregateRound(
      ['rspamd', 'clamav'],
      [final('rspamd', 'timeout'), final('clamav', 'malicious', ['malware.signature'])],
    );
    expect(r).toMatchObject({ outcome: 'scan_failed', verdict: 'malicious' });
  });

  it('non-required failures never fail the round; a required engine without a final does', () => {
    const r = aggregateRound(['rspamd'], [final('rspamd', 'clean'), final('url', 'error')]);
    expect(r).toMatchObject({ outcome: 'scanned', verdict: 'clean' });
    expect(aggregateRound(['rspamd'], [])).toMatchObject({
      outcome: 'scan_failed',
      verdict: 'error',
      failedRequired: ['rspamd'],
    });
  });

  it('unions reason codes, failures first, then by severity and name, at most 32', () => {
    const many = Array.from({ length: 40 }, (_, i) => `info.code_${String(i).padStart(2, '0')}`);
    const r = aggregateRound(
      ['rspamd', 'b'],
      [final('rspamd', 'clean', many), final('b', 'error', ['engine.error', 'info.code_00'])],
    );
    expect(r.reasonCodes).toHaveLength(32);
    expect(r.reasonCodes.slice(0, 2)).toEqual(['engine.error', 'info.code_00']);
    expect(new Set(r.reasonCodes).size).toBe(32);
  });

  describe('asynchronous engines are excluded (step 4.6 X10)', () => {
    const required = ['rspamd', 'attachment'];
    const base = [
      final('rspamd', 'clean', ['clean.below_threshold']),
      final('attachment', 'suspicious', ['archive.encrypted']),
    ];
    const without = aggregateRound(required, base);

    it.each([
      ['malicious', ['sandbox.static.eicar_test']],
      ['unknown', ['sandbox.static_only', 'sandbox.no_findings']],
      ['error', ['sandbox.error', 'sandbox.error.internal']],
      ['timeout', ['sandbox.timeout']],
      ['skipped', ['sandbox.tenant_disabled']],
    ] as const)(
      'a sandbox %s final changes neither the verdict, the codes nor the outcome',
      (outcome, sandboxCodes) => {
        const sandbox = final('sandbox', outcome, [...sandboxCodes]);
        // Before completion (written first) and after (written last): same aggregate.
        expect(aggregateRound(required, [sandbox, ...base])).toEqual(without);
        expect(aggregateRound(required, [...base, sandbox])).toEqual(without);
      },
    );

    it('a sandbox final never satisfies or fails a required engine, even if listed as required', () => {
      const missing = aggregateRound(required, [base[0]!, final('sandbox', 'malicious')]);
      expect(missing).toMatchObject({
        outcome: 'scan_failed',
        verdict: 'error',
        failedRequired: ['attachment'],
      });
      expect(missing.reasonCodes).toEqual(['clean.below_threshold']);
      // A (misconfigured) snapshot naming the sandbox: its final is still not counted.
      expect(
        aggregateRound(['rspamd', 'sandbox'], [base[0]!, final('sandbox', 'clean')]),
      ).toMatchObject({ outcome: 'scan_failed', failedRequired: ['sandbox'] });
    });

    it('a malicious sandbox final alone leaves a clean round clean', () => {
      expect(
        aggregateRound(
          ['rspamd'],
          [final('sandbox', 'malicious', ['sandbox.static.eicar_test']), base[0]!],
        ),
      ).toEqual(aggregateRound(['rspamd'], [base[0]!]));
    });
  });
});
