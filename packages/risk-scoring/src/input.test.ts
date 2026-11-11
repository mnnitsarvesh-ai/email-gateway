import { describe, expect, it } from 'vitest';
import { buildScoringInput, RiskInputError, scoringInputSchema } from './index';
import type { RoundRows } from './input';
import {
  cleanRows,
  final,
  removeFinal,
  rule,
  setFinal,
  withBec,
  withCodes,
} from './rows.test-support';

const build = (rows: RoundRows, revision: 0 | 1 = 0) => buildScoringInput(rows, revision);

describe('buildScoringInput (R2, R12)', () => {
  it('assembles a sorted, schema-valid risk-input/1', () => {
    const input = build(cleanRows());
    expect(scoringInputSchema.parse(input)).toEqual(input);
    expect(input.version).toBe('risk-input/1');
    expect(input.round).toEqual({
      scanKind: 'initial',
      lifecycleRound: 1,
      outcome: 'scanned',
      requiredEngines: ['attachment', 'bec', 'dlp', 'rspamd', 'url'],
    });
    expect(input.engines.map((e) => e.engine)).toEqual([
      'attachment',
      'bec',
      'dlp',
      'rspamd',
      'url',
    ]);
    expect(input.engines.every((e) => e.status === 'definite' && e.required)).toBe(true);
    expect(input.engines[0]!.completedAt).toBe('2026-11-10T10:00:00.000Z');
    expect(input.auth).toEqual({
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'pass',
      dmarcPolicy: 'reject',
      arc: 'none',
    });
    expect(input.sandbox).toBeNull();
  });

  it('maps statuses: definite, failed, skipped, missing; scan status → outcome', () => {
    let rows = setFinal(cleanRows(), final('url', 'timeout', []));
    rows = setFinal(rows, final('attachment', 'skipped', ['attachment.none']));
    rows = removeFinal(rows, 'rspamd');
    rows = { ...rows, scan: { ...rows.scan, status: 'timed_out' } };
    const input = build(rows);
    const status = Object.fromEntries(input.engines.map((e) => [e.engine, e.status]));
    expect(status).toEqual({
      attachment: 'skipped',
      bec: 'definite',
      dlp: 'definite',
      rspamd: 'missing',
      url: 'failed',
    });
    expect(input.round.outcome).toBe('scan_failed');
    expect(input.engines.find((e) => e.engine === 'rspamd')).toMatchObject({
      outcome: null,
      attempts: 0,
      completedAt: null,
    });
  });

  it('bec: active rule codes exclude suppressed rules; trusted sender from codes; AI raise', () => {
    let rows = withBec(cleanRows(), 'clean', ['bec.trusted_sender', 'bec.content.urgency'], {
      suppressed: ['bec.history.first_contact'],
    });
    let input = build(rows);
    expect(input.bec).toEqual({
      deterministicVerdict: 'clean',
      verdict: 'clean',
      activeRuleCodes: ['bec.content.urgency', 'bec.trusted_sender'],
      trustedSender: 'authenticated',
      aiRaised: false,
    });
    rows = withBec(cleanRows(), 'clean', [], {
      finalCodes: ['bec.trusted_sender_unauthenticated'],
    });
    expect(build(rows).bec?.trustedSender).toBe('unauthenticated');
    rows = withBec(cleanRows(), 'clean', [], {
      verdict: 'suspicious',
      finalCodes: ['bec.ai.flagged'],
    });
    input = build(rows);
    expect(input.bec?.aiRaised).toBe(true);
    rows = withBec(cleanRows(), 'clean', [], {
      verdict: 'suspicious',
      finalCodes: ['clean.below_threshold'],
    });
    expect(build(rows).bec?.aiRaised).toBe(false);
  });

  it('dlp: maxSeverity is the maximum over categories', () => {
    const rows: RoundRows = {
      ...cleanRows(),
      dlp: {
        action: 'alert',
        verdict: 'suspicious',
        coverage: 'partial',
        categories: [
          { category: 'personal_info', count: 2, maxSeverity: 'low', maxConfidence: 'high' },
          { category: 'payment_card', count: 1, maxSeverity: 'high', maxConfidence: 'high' },
          { category: 'confidential', count: 1, maxSeverity: 'medium', maxConfidence: 'low' },
        ],
      },
    };
    expect(build(rows).dlp).toEqual({
      action: 'alert',
      verdict: 'suspicious',
      coverage: 'partial',
      maxSeverity: 'high',
    });
  });

  it('missing child rows add risk.input.<engine>_row_missing to that engine', () => {
    const input = build({ ...cleanRows(), auth: null, bec: null, dlp: null });
    const codes = (e: string) => input.engines.find((x) => x.engine === e)!.reasonCodes;
    expect(codes('rspamd')).toContain('risk.input.auth_row_missing');
    expect(codes('bec')).toContain('risk.input.bec_row_missing');
    expect(codes('dlp')).toContain('risk.input.dlp_row_missing');
    // not expected for unknown rspamd, skipped or failed engines
    let rows = withCodes(cleanRows(), 'rspamd', 'unknown', ['engine.too_large']);
    rows = setFinal(rows, final('bec', 'skipped', ['bec.not_inbound']));
    rows = setFinal(rows, final('dlp', 'error', []));
    const other = build({ ...rows, auth: null, bec: null, dlp: null });
    expect(
      other.engines.flatMap((e) => e.reasonCodes).filter((c) => c.startsWith('risk.input.')),
    ).toEqual([]);
  });

  it('revision 1 requires a non-skipped sandbox final; revision 0 ignores it', () => {
    const rows = setFinal(
      cleanRows(),
      final('sandbox', 'suspicious', ['sandbox.static.pe_packed']),
    );
    expect(build(rows, 0).sandbox).toBeNull();
    expect(build(rows, 0).engines.some((e) => e.engine === 'sandbox')).toBe(false);
    expect(build(rows, 1).sandbox).toEqual({
      outcome: 'suspicious',
      reasonCodes: ['sandbox.static.pe_packed'],
    });
    expect(() => build(cleanRows(), 1)).toThrow(RiskInputError);
    expect(() =>
      build(setFinal(cleanRows(), final('sandbox', 'skipped', ['sandbox.feature_disabled'])), 1),
    ).toThrow(RiskInputError);
  });

  it.each<[string, (rows: RoundRows) => RoundRows]>([
    ['unknown engine in finals', (r) => setFinal(r, final('antivirus', 'clean', []))],
    [
      'unknown required engine',
      (r) => ({ ...r, scan: { ...r.scan, requiredEngines: ['rspamd', 'nope'] } }),
    ],
    [
      'required engines not an array',
      (r) => ({ ...r, scan: { ...r.scan, requiredEngines: 'rspamd' } }),
    ],
    [
      'duplicate required engine',
      (r) => ({ ...r, scan: { ...r.scan, requiredEngines: ['rspamd', 'rspamd'] } }),
    ],
    [
      'sandbox required',
      (r) => ({ ...r, scan: { ...r.scan, requiredEngines: ['rspamd', 'sandbox'] } }),
    ],
    [
      'two finals of one engine',
      (r) => ({ ...r, finals: [...r.finals, final('url', 'clean', [])] }),
    ],
    ['malformed reason codes', (r) => withCodes(r, 'url', 'clean', ['Not A Code'])],
    [
      'reason codes not an array',
      (r) => setFinal(r, { ...final('url', 'clean', []), reasonCodes: { a: 1 } }),
    ],
    [
      'malformed bec rules',
      (r) => ({ ...r, bec: { ...r.bec!, rules: [{ code: 'bec.x.y', suppressed: 'maybe' }] } }),
    ],
    ['unknown bec verdict', (r) => ({ ...r, bec: { ...r.bec!, verdict: 'evil' } })],
    ['unknown dlp action', (r) => ({ ...r, dlp: { ...r.dlp!, action: 'shred' } })],
    [
      'malformed dlp categories',
      (r) => ({ ...r, dlp: { ...r.dlp!, categories: [{ maxSeverity: 'extreme' }] } }),
    ],
    ['negative attempt', (r) => setFinal(r, { ...final('url', 'clean', []), attempt: -1 })],
    [
      'invalid date',
      (r) => setFinal(r, { ...final('url', 'clean', []), completedAt: new Date('nope') }),
    ],
    ['negative recipient count', (r) => ({ ...r, message: { ...r.message, recipientCount: -1 } })],
    [
      'unknown scan status',
      (r) => ({ ...r, scan: { ...r.scan, status: 'running' as 'completed' } }),
    ],
  ])('throws RiskInputError on %s', (_name, mutate) => {
    expect(() => build(mutate(cleanRows()))).toThrow(RiskInputError);
  });

  it('rules with non-null suppression never count as active', () => {
    const rows = {
      ...cleanRows(),
      bec: { ...cleanRows().bec!, rules: [rule('bec.content.urgency', 'feedback')] },
    };
    expect(build(rows).bec?.activeRuleCodes).toEqual([]);
  });
});
