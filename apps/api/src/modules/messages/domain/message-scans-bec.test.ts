import { Prisma } from '@email-gateway/database';
import { BecScanViewSchema, ScanRoundSchema } from '../dto/message-scans.schemas';
import { describe, expect, it } from 'vitest';
import type {
  BecResultRow,
  EngineResultRow,
  ScanRoundRow,
} from '../repositories/message-scans-read.repository';
import { becOf, NO_BEC, roundOf } from './message-scans';

const at = (ms: number) => new Date(Date.UTC(2026, 10, 6, 8, 0, 0, ms));
const PROFILE = '0190f0f0-0000-7000-8000-0000000000e1';
const FEEDBACK = '0190f0f0-0000-7000-8000-0000000000fb';

const scan: ScanRoundRow = {
  id: 9n,
  lifecycleRound: 0,
  scanKind: 'initial',
  status: 'completed',
  scanVerdict: 'malicious',
  reasonCodes: ['bec.impersonation.executive_name'],
  requiredEngines: ['rspamd', 'url', 'bec'],
  startedAt: at(0),
  completedAt: at(900),
  deadlineAt: at(1000),
};

const final: EngineResultRow = {
  scanId: 9n,
  engine: 'bec',
  engineVersion: 'bec/1;lex=2876a3ab;fm=35f13669;br=fb362bf9',
  outcome: 'malicious',
  score: new Prisma.Decimal('100'),
  requiredScore: new Prisma.Decimal('40'),
  action: null,
  reasonCodes: ['bec.impersonation.executive_name', 'bec.content.gift_card'],
  errorCode: null,
  settingsVersion: 'bec-map/1;p=abcdefabcdef;t=none',
  durationMs: 187,
  evidence: { signals: [{ name: 'bec:X1', score: 40, options: ['impersonation'] }] },
  attempt: 1,
  isFinal: true,
  completedAt: at(777),
};

const result: BecResultRow = {
  scanId: 9n,
  engineVersion: 'bec/1;lex=2876a3ab;fm=35f13669;br=fb362bf9',
  rulesVersion: 'bec-map/1',
  settingsVersion: 'bec-map/1;p=abcdefabcdef;t=none',
  lexiconVersion: '2876a3ab',
  deterministicScore: 100,
  score: 100,
  deterministicVerdict: 'malicious',
  verdict: 'malicious',
  inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' },
  rules: [
    {
      id: 'X1',
      code: 'bec.impersonation.executive_name',
      category: 'impersonation',
      severity: 'high',
      weight: 40,
      suppressed: null,
      evidence: [
        {
          header: 'From',
          displayName: 'Anita Sharma',
          address: 'anita.ceo@gmail.com',
          domain: 'gmail.com',
          profile: { kind: 'executive', id: PROFILE, match: 'exact' },
        },
      ],
    },
    {
      id: 'C3',
      code: 'bec.content.gift_card',
      category: 'intent',
      severity: 'high',
      weight: 30,
      suppressed: null,
      evidence: [
        {
          keywords: {
            category: 'gift_card',
            language: 'en',
            lexiconIds: ['en.gift_card.001'],
            spans: [{ source: 'text', start: 4, end: 14 }],
          },
        },
      ],
    },
  ],
  ai: [],
  aiShadow: [
    {
      layer: 'local',
      mode: 'shadow',
      provider: 'local',
      modelId: 'bec-lr',
      modelVersion: 'bec-lr/1@0a0f071f7a91',
      promptTemplateVersion: null,
      status: 'ok',
      labels: [{ label: 'bec', confidence: 0.97 }],
      confidence: 0.97,
      indicators: [],
      citedFeatures: [{ feature: 'rule_x1', contribution: 2.1 }],
      spans: [],
      responseSha256: 'f'.repeat(64),
      durationMs: 3,
    },
  ],
};

describe('bec section of the scans read API (step 4.4 B15)', () => {
  const inputs = {
    results: [result],
    feedback: [
      { scanId: 9n, publicId: FEEDBACK, kind: 'false_positive' as const, createdAt: at(1234) },
      { scanId: 8n, publicId: FEEDBACK, kind: 'false_negative' as const, createdAt: at(1) },
    ],
    ids: NO_BEC.ids,
  };

  it('maps the stored result: versions, scores, thresholds, inputs, rules, AI, feedback', () => {
    const view = becOf(9n, final, inputs)!;
    expect(BecScanViewSchema.parse(view)).toEqual(view);
    expect(view).toMatchObject({
      verdict: 'malicious',
      deterministicVerdict: 'malicious',
      score: 100,
      thresholds: { suspicious: 40, malicious: null },
      inputs: { auth: 'available', history: 'disabled' },
      rules: [
        { id: 'X1', evidence: [{ profile: { id: PROFILE } }] },
        { id: 'C3', evidence: [{ keywords: { spans: [{ start: 4, end: 14 }] } }] },
      ],
      ai: [],
      aiShadow: [{ layer: 'local', mode: 'shadow', confidence: 0.97 }],
      feedback: [{ id: FEEDBACK, kind: 'false_positive', createdAt: '2026-11-06T08:00:01.000Z' }],
    });
    const text = JSON.stringify(view);
    expect(text).not.toContain('responseSha256');
    expect(text).not.toContain('durationMs');
    expect(becOf(10n, final, inputs)).toBeNull();
  });

  it('puts the section on the bec engine entry: no duration, time rounded to the second, scanId', () => {
    const round = roundOf(scan, [final], [], undefined, undefined, inputs);
    expect(ScanRoundSchema.parse(round)).toBeTruthy();
    expect(round.scanId).toBe('9');
    const bec = round.engines.find((e) => e.engine === 'bec')!;
    expect(bec.durationMs).toBeNull();
    expect(bec.completedAt).toBe('2026-11-06T08:00:00.000Z');
    expect(bec.attempts[0]).toMatchObject({ durationMs: null, at: '2026-11-06T08:00:00.000Z' });
    expect(bec.bec?.rules).toHaveLength(2);
    // Before the result row exists (or for a failure) the section is null.
    const pending = roundOf(scan, [final], [], undefined, undefined, NO_BEC);
    expect(pending.engines[0]!.bec).toBeNull();
  });
});
