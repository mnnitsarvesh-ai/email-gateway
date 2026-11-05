import { BadRequestException } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import type {
  AuthResultRow,
  EngineResultRow,
  ScanRoundRow,
} from '../repositories/message-scans-read.repository';
import {
  decodeScanCursor,
  encodeScanCursor,
  engineOf,
  roundOf,
  stringArray,
  symbolsOf,
} from './message-scans';

const at = (s: number) => new Date(Date.UTC(2026, 10, 5, 8, 0, s));

const scan = (id: bigint, round: number, overrides: Partial<ScanRoundRow> = {}): ScanRoundRow => ({
  id,
  lifecycleRound: round,
  scanKind: round === 0 ? 'initial' : 'rescan',
  status: 'running',
  scanVerdict: null,
  reasonCodes: null,
  requiredEngines: ['rspamd'],
  startedAt: at(0),
  completedAt: null,
  deadlineAt: at(59),
  ...overrides,
});

const row = (overrides: Partial<EngineResultRow>): EngineResultRow => ({
  scanId: 1n,
  engine: 'rspamd',
  engineVersion: '3.12.1',
  outcome: 'error',
  score: null,
  requiredScore: null,
  action: null,
  reasonCodes: ['engine.error'],
  errorCode: 'unavailable',
  settingsVersion: null,
  durationMs: 10,
  evidence: null,
  attempt: 1,
  isFinal: false,
  completedAt: at(1),
  ...overrides,
});

describe('message scans mapping (step 4.1 S16)', () => {
  it('parses stored JSON defensively', () => {
    expect(stringArray(['a.b', 'c.d'])).toEqual(['a.b', 'c.d']);
    expect(stringArray(null)).toEqual([]);
    expect(stringArray([1, 'x'])).toEqual([]);
    expect(symbolsOf(null)).toEqual([]);
    expect(symbolsOf({ signals: 'x' })).toEqual([]);
    expect(
      symbolsOf({
        signals: [
          { name: 'R_SPF_FAIL', score: 1, options: ['-all'] },
          { name: '', score: 1 },
          { name: 'NO_OPTIONS', score: -0.5 },
          { name: 'BAD', score: 'x' },
        ],
      }),
    ).toEqual([
      { name: 'R_SPF_FAIL', score: 1, options: ['-all'] },
      { name: 'NO_OPTIONS', score: -0.5, options: [] },
    ]);
    const many = { signals: Array.from({ length: 250 }, (_, i) => ({ name: `S${i}`, score: 0 })) };
    expect(symbolsOf(many)).toHaveLength(200);
  });

  it('shows an engine without a final row as not final, with its attempts', () => {
    const view = engineOf('rspamd', [row({ attempt: 2, completedAt: at(3) }), row({})]);
    expect(view).toMatchObject({
      engine: 'rspamd',
      final: false,
      outcome: null,
      score: null,
      reasonCodes: [],
      symbols: [],
      completedAt: null,
      engineVersion: '3.12.1',
    });
    expect(view.attempts.map((a) => a.attempt)).toEqual([1, 2]);
  });

  it('uses the final row as the result and converts decimals', () => {
    const final = row({
      attempt: 2,
      isFinal: true,
      outcome: 'suspicious',
      score: new Prisma.Decimal('4.25'),
      requiredScore: new Prisma.Decimal('15'),
      action: 'no action',
      reasonCodes: ['spam.suspicious_score'],
      errorCode: null,
      settingsVersion: 'rspamd-map/1;p=0123456789ab;t=2',
      evidence: { signals: [{ name: 'BAYES_SPAM', score: 3, options: ['99%'] }] },
      completedAt: at(4),
    });
    const view = engineOf('rspamd', [row({}), final]);
    expect(view).toMatchObject({
      final: true,
      outcome: 'suspicious',
      score: 4.25,
      requiredScore: 15,
      reasonCodes: ['spam.suspicious_score'],
      symbols: [{ name: 'BAYES_SPAM', score: 3, options: ['99%'] }],
      settingsVersion: 'rspamd-map/1;p=0123456789ab;t=2',
      completedAt: at(4).toISOString(),
    });
    expect(view.attempts.map((a) => [a.attempt, a.outcome, a.errorCode])).toEqual([
      [1, 'error', 'unavailable'],
      [2, 'suspicious', null],
    ]);
  });

  it('builds a round from its own rows only, engines in catalog order, auth of the first engine', () => {
    const auth: AuthResultRow = {
      scanId: 2n,
      engine: 'rspamd',
      spf: 'pass',
      spfDomain: 'clean.scan.test',
      dkim: 'pass',
      dkimSignatures: [
        { domain: 'clean.scan.test', result: 'pass', selector: 'eg2026' },
        { garbage: true },
      ],
      dmarc: 'pass',
      dmarcPolicy: 'reject',
      dmarcDomain: 'clean.scan.test',
      arc: 'none',
    };
    const view = roundOf(
      scan(2n, 1, {
        status: 'completed',
        scanVerdict: 'clean',
        reasonCodes: ['clean.below_threshold'],
      }),
      [
        row({ scanId: 2n, engine: 'zzz_future', isFinal: true, outcome: 'clean' }),
        row({ scanId: 2n, isFinal: true, outcome: 'clean' }),
        row({ scanId: 1n, isFinal: true, outcome: 'spam' }),
      ],
      [auth, { ...auth, scanId: 1n, spf: 'fail' }],
    );
    expect(view).toMatchObject({
      round: 1,
      scanKind: 'rescan',
      status: 'completed',
      verdict: 'clean',
      reasonCodes: ['clean.below_threshold'],
      requiredEngines: ['rspamd'],
      auth: {
        spf: 'pass',
        dkimSignatures: [{ domain: 'clean.scan.test', result: 'pass', selector: 'eg2026' }],
      },
    });
    expect(view.engines.map((e) => [e.engine, e.outcome])).toEqual([
      ['rspamd', 'clean'],
      ['zzz_future', 'clean'],
    ]);
    expect(roundOf(scan(3n, 2), [], []).auth).toBeNull();
  });

  it('round-trips the cursor and refuses anything else', () => {
    for (const round of [0, 1, 42, 65_535]) {
      expect(decodeScanCursor(encodeScanCursor(round))).toBe(round);
    }
    for (const bad of ['bogus', Buffer.from('r65536').toString('base64url'), 'cjAx', '']) {
      expect(() => decodeScanCursor(bad)).toThrow(BadRequestException);
    }
  });
});
