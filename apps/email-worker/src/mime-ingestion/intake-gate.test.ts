import { describe, expect, it } from 'vitest';
import { INTAKE_PARSE_ACTOR, intakeGate } from './mime-repository';

/**
 * The parse commit's gate (step 8.6 D4, docs/plan/steps/27-journal-intake-and-archive-split.md):
 * gateway messages keep the 3.1 behaviour; a journal intake message never gets
 * `parse_failed.v1` (the policy-engine's E5 fail-safe) and gets `parsed.v1` only when its scan
 * was requested.
 */
describe('intakeGate', () => {
  it.each([
    // [ingestSource, scanRequested, parseFailed, expected]
    [undefined, false, false, { kind: 'outbox' }],
    [undefined, false, true, { kind: 'outbox' }],
    ['gateway', true, false, { kind: 'outbox' }],
    ['gateway', false, true, { kind: 'outbox' }],
    ['journal_intake', false, false, { kind: 'journal', reason: 'intake_unscanned' }],
    ['journal_intake', false, true, { kind: 'journal', reason: 'intake_parse_failed' }],
    ['journal_intake', true, false, { kind: 'outbox' }],
    ['journal_intake', true, true, { kind: 'journal', reason: 'intake_parse_failed' }],
  ] as const)('%s scan=%s failed=%s', (source, scan, failed, expected) => {
    expect(intakeGate(source, scan, failed)).toEqual(expected);
  });

  it('applies E30 as the scanner role of the email-worker', () => {
    expect(INTAKE_PARSE_ACTOR).toEqual({
      role: 'scanner',
      service: 'email-worker',
      type: 'system',
    });
  });
});
