import { describe, expect, it } from 'vitest';
import { mulberry32 } from '../training/generator';
import type { BecVerdict } from '../rules/codes';
import {
  combineVerdict,
  effectiveMode,
  type CombineAssessment,
  type CombineSettings,
} from './combine';
import { AI_STATUSES, type AiAssessment, type AiLabel, type AiMode, type AiStatus } from './types';

const SEVERITY: Record<BecVerdict, number> = {
  skipped: -1,
  clean: 0,
  unknown: 1,
  suspicious: 2,
  malicious: 3,
};

const assessment = (status: AiStatus, label: AiLabel, confidence: number): AiAssessment => ({
  status,
  labels: status === 'ok' ? [{ label, confidence }] : [],
  confidence: status === 'ok' ? confidence : null,
  citedFeatures: [],
  spans: [],
  indicators: [],
  modelId: 'm',
  modelVersion: 'm/1',
  promptTemplateVersion: null,
  responseSha256: null,
  durationMs: 1,
});

interface Case {
  d: BecVerdict;
  score: number;
  identity: boolean;
  intent: boolean;
  anyRule: boolean;
  entries: CombineAssessment[];
  settings: CombineSettings;
}

/** Asserts P1–P6 for one case. */
function checkInvariant(c: Case): void {
  const r = combineVerdict(
    c.d,
    c.score,
    { identity: c.identity, intent: c.intent },
    c.entries,
    c.settings,
  );
  const label = JSON.stringify({
    ...c,
    entries: c.entries.map((e) => [e.mode, e.assessment.status, e.assessment.labels]),
  });
  // P1: final clean ⇒ D clean
  if (r.verdict === 'clean') expect(c.d, label).toBe('clean');
  // P2: final malicious ⇒ D ∈ {suspicious, malicious} and evidence and band (unless D was malicious)
  if (r.verdict === 'malicious' && c.d !== 'malicious') {
    expect(c.d, label).toBe('suspicious');
    expect(c.identity && c.intent, label).toBe(true);
    expect(c.score, label).toBeGreaterThanOrEqual(
      c.settings.maliciousScore - c.settings.aiMaliciousBand,
    );
    expect(c.settings.aiMaliciousBand, label).toBeGreaterThan(0);
  }
  // P3: never lowers
  expect(SEVERITY[r.verdict], label).toBeGreaterThanOrEqual(SEVERITY[c.d]);
  expect(r.score, label).toBeGreaterThanOrEqual(Math.min(100, c.score));
  // P4: with no deterministic rule fired the final verdict is never malicious
  if (!c.anyRule) expect(['clean', 'unknown', 'suspicious', 'skipped'], label).toContain(r.verdict);
  // P5: shadow assessments never change anything
  const activeOnly = c.entries.filter((e) => e.mode === 'active');
  const without = combineVerdict(
    c.d,
    c.score,
    { identity: c.identity, intent: c.intent },
    activeOnly,
    c.settings,
  );
  expect({ v: r.verdict, s: r.score, c: r.codes }, label).toEqual({
    v: without.verdict,
    s: without.score,
    c: without.codes,
  });
  c.entries.forEach((e, i) => {
    if (e.mode !== 'active') expect(r.effects[i], label).toBe('none');
  });
  // P6: no ok assessment applied → verdict and score equal D
  if (!activeOnly.some((e) => e.assessment.status === 'ok')) {
    expect(r.verdict, label).toBe(c.d);
    expect(r.score, label).toBe(c.score);
  }
}

const settings = (band: number, raise = 0.8, corroborate = 0.9): CombineSettings => ({
  suspiciousScore: 40,
  maliciousScore: 80,
  aiMaliciousBand: band,
  corroborateConfidence: corroborate,
  raiseConfidence: raise,
});

/** A deterministic verdict consistent with its score and evidence (bec-map/1 rules). */
const consistent = (
  d: BecVerdict,
  score: number,
  identity: boolean,
  intent: boolean,
  anyRule: boolean,
): boolean => {
  if (!anyRule && (score > 0 || identity || intent)) return false;
  if (d === 'malicious') return score >= 80 && identity && intent;
  if (d === 'suspicious') return score >= 40 && !(score >= 80 && identity && intent);
  if (d === 'clean' || d === 'unknown') return score < 40;
  return true;
};

describe('combineVerdict rules 1–5', () => {
  const s = settings(10);
  const ok = (label: AiLabel, c: number, mode: AiMode = 'active'): CombineAssessment => ({
    layer: 'llm',
    mode,
    assessment: assessment('ok', label, c),
  });
  it('1: malicious stays malicious', () => {
    expect(
      combineVerdict('malicious', 90, { identity: true, intent: true }, [ok('benign', 0.99)], s),
    ).toMatchObject({ verdict: 'malicious', codes: ['bec.ai.disagrees'] });
  });
  it('2: corroboration within the band with identity + intent', () => {
    const r = combineVerdict(
      'suspicious',
      72,
      { identity: true, intent: true },
      [ok('bec', 0.95)],
      s,
    );
    expect(r).toMatchObject({
      verdict: 'malicious',
      score: 80,
      codes: ['bec.ai.corroborated'],
      effects: ['corroborated_malicious'],
    });
    expect(
      combineVerdict('suspicious', 69, { identity: true, intent: true }, [ok('bec', 0.95)], s)
        .verdict,
    ).toBe('suspicious');
    expect(
      combineVerdict('suspicious', 75, { identity: true, intent: false }, [ok('bec', 0.95)], s)
        .verdict,
    ).toBe('suspicious');
    expect(
      combineVerdict('suspicious', 75, { identity: true, intent: true }, [ok('bec', 0.89)], s)
        .verdict,
    ).toBe('suspicious');
    expect(
      combineVerdict(
        'suspicious',
        79,
        { identity: true, intent: true },
        [ok('bec', 0.99)],
        settings(0),
      ).verdict,
    ).toBe('suspicious');
  });
  it('4: raise clean/unknown to suspicious at the raise confidence', () => {
    expect(
      combineVerdict('clean', 10, { identity: false, intent: false }, [ok('phishing', 0.8)], s),
    ).toMatchObject({
      verdict: 'suspicious',
      score: 40,
      codes: ['bec.ai.flagged'],
      effects: ['raised_to_suspicious'],
    });
    expect(
      combineVerdict('unknown', 0, { identity: false, intent: false }, [ok('bec', 0.79)], s)
        .verdict,
    ).toBe('unknown');
    expect(
      combineVerdict(
        'clean',
        0,
        { identity: false, intent: false },
        [ok('bec', 0.7)],
        settings(10, 0.6),
      ).verdict,
    ).toBe('suspicious');
  });
  it('5: disagrees / unavailable are informational', () => {
    expect(
      combineVerdict('suspicious', 50, { identity: true, intent: false }, [ok('benign', 0.99)], s),
    ).toMatchObject({ verdict: 'suspicious', codes: ['bec.ai.disagrees'] });
    const failed: CombineAssessment = {
      layer: 'llm',
      mode: 'active',
      assessment: assessment('timeout', 'bec', 0),
    };
    expect(
      combineVerdict('clean', 0, { identity: false, intent: false }, [failed], s),
    ).toMatchObject({ verdict: 'clean', codes: ['bec.ai.unavailable'] });
    expect(
      combineVerdict('clean', 0, { identity: false, intent: false }, [ok('benign', 0.9)], s),
    ).toMatchObject({ verdict: 'clean', codes: [] });
  });
  it('shadow never applies; the strongest applied assessment wins', () => {
    expect(
      combineVerdict(
        'clean',
        0,
        { identity: false, intent: false },
        [ok('bec', 0.99, 'shadow')],
        s,
      ),
    ).toMatchObject({ verdict: 'clean', codes: [], effects: ['none'] });
    const r = combineVerdict(
      'clean',
      0,
      { identity: false, intent: false },
      [ok('bec', 0.85), ok('phishing', 0.97)],
      s,
    );
    expect(r.effects).toEqual(['none', 'raised_to_suspicious']);
  });
  it('effectiveMode caps the tenant choice by the platform mode', () => {
    expect(effectiveMode('shadow', 'active', 'shadow')).toBe('shadow');
    expect(effectiveMode('active', undefined, 'off')).toBe('off');
    expect(effectiveMode('active', 'active', 'off')).toBe('active');
    expect(effectiveMode('off', 'shadow', 'shadow')).toBe('off');
  });
});

describe('aggregation invariant P1–P6', () => {
  it('holds on the exhaustive grid', () => {
    const verdicts: BecVerdict[] = ['clean', 'unknown', 'suspicious', 'malicious', 'skipped'];
    const scores = [0, 15, 39, 40, 55, 69, 70, 75, 79, 80, 95, 100];
    const labels: AiLabel[] = ['bec', 'phishing', 'benign', 'spam'];
    const confidences = [0, 0.5, 0.6, 0.79, 0.8, 0.89, 0.9, 0.95, 1];
    const modes: AiMode[] = ['active', 'shadow'];
    const bands = [0, 10, 15];
    let cases = 0;
    for (const d of verdicts)
      for (const score of scores)
        for (const identity of [false, true])
          for (const intent of [false, true])
            for (const anyRule of [false, true]) {
              if (!consistent(d, score, identity, intent, anyRule)) continue;
              for (const band of bands)
                for (const status of AI_STATUSES)
                  for (const label of labels)
                    for (const confidence of confidences)
                      for (const mode of modes) {
                        checkInvariant({
                          d,
                          score,
                          identity,
                          intent,
                          anyRule,
                          entries: [
                            {
                              layer: 'local',
                              mode,
                              assessment: assessment(status, label, confidence),
                            },
                          ],
                          settings: settings(band),
                        });
                        cases += 1;
                      }
            }
    expect(cases).toBeGreaterThan(50_000);
  });

  it('holds on 10 000 seeded random cases with several providers', () => {
    const random = mulberry32(20261106);
    const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
    let checked = 0;
    while (checked < 10_000) {
      const d = pick<BecVerdict>(['clean', 'unknown', 'suspicious', 'malicious', 'skipped']);
      const score = Math.floor(random() * 101);
      const identity = random() < 0.5;
      const intent = random() < 0.5;
      const anyRule = random() < 0.8;
      if (!consistent(d, score, identity, intent, anyRule)) continue;
      const entries: CombineAssessment[] = Array.from({ length: Math.floor(random() * 4) }, () => ({
        layer: pick(['local', 'llm'] as const),
        mode: pick(['active', 'shadow'] as const),
        assessment: assessment(
          pick(AI_STATUSES),
          pick(['bec', 'phishing', 'benign', 'spam'] as const),
          Math.round(random() * 100) / 100,
        ),
      }));
      checkInvariant({
        d,
        score,
        identity,
        intent,
        anyRule,
        entries,
        settings: settings(
          Math.floor(random() * 16),
          0.6 + Math.round(random() * 39) / 100,
          0.8 + Math.round(random() * 19) / 100,
        ),
      });
      checked += 1;
    }
    expect(checked).toBe(10_000);
  });
});
