import { describe, expect, it } from 'vitest';
import { loadCorpus } from '../corpus';
import { BEC_DEFAULT_RULE_SETTINGS } from '../rules/defaults';
import { evaluateBecRules } from '../rules/evaluate';
import { AI_FEATURE_NAMES } from '../rules/codes';
import { loadBecStaticData } from '../static-data';
import { checkModel } from '../training/model-files';
import { buildAiInput } from './input';
import { loadLocalModel, loadModelManifest, LocalBecModel } from './local-model';

const data = loadBecStaticData();
const model = loadLocalModel('bec-lr/1');
const signal = new AbortController().signal;

describe('model:check (B9)', () => {
  it('retraining reproduces the committed weights, the manifest hash matches, held-out metrics ≥ 0.9', () => {
    const result = checkModel();
    expect(result.problems).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.records).toBeGreaterThanOrEqual(200);
    expect(result.maxWeightDelta).toBeLessThanOrEqual(1e-9);
    expect(result.metrics.precision).toBeGreaterThanOrEqual(0.9);
    expect(result.metrics.recall).toBeGreaterThanOrEqual(0.9);
  });
});

describe('local model bec-lr/1', () => {
  it('is listed in the manifest and versioned by its file hash', () => {
    const entry = loadModelManifest().find((m) => m.version === 'bec-lr/1')!;
    expect(model.modelVersion).toBe(`bec-lr/1@${entry.sha256.slice(0, 12)}`);
    expect(model.model.features).toEqual(AI_FEATURE_NAMES);
    expect(() => loadLocalModel('bec-lr/9')).toThrow(/not in models\/manifest.json/);
    expect(() =>
      loadLocalModel('bec-lr/1', [
        {
          id: 'bec-lr',
          version: 'bec-lr/1',
          file: 'bec-lr-1.json',
          sha256: '0'.repeat(64),
          status: 'available',
        },
      ]),
    ).toThrow(/hash differs/);
    expect(
      () => new LocalBecModel({ ...model.model, features: ['x'], weights: [1] }, 'a'.repeat(64)),
    ).toThrow();
  });

  it('scores corpus BEC templates above benign ones; cites ≤ 5 features and lexicon spans', async () => {
    for (const { fixture, input } of loadCorpus()) {
      if (fixture.label === null) continue;
      const result = evaluateBecRules(input, BEC_DEFAULT_RULE_SETTINGS, data, {
        now: new Date('2026-11-03T00:00:00Z'),
      });
      const assessment = await model.assess(buildAiInput(result, input.tenant), signal);
      expect(assessment.status).toBe('ok');
      expect(assessment.labels[0]!.label, fixture.id).toBe(
        fixture.label === 'bec' ? 'bec' : 'benign',
      );
      expect(assessment.confidence).toBeGreaterThanOrEqual(0.5);
      expect(assessment.citedFeatures.length).toBeLessThanOrEqual(5);
      for (const cited of assessment.citedFeatures)
        expect(AI_FEATURE_NAMES).toContain(cited.feature);
      expect(assessment.spans.length).toBeLessThanOrEqual(8);
      for (const span of assessment.spans) expect(span.end).toBeGreaterThan(span.start);
      expect(assessment).toMatchObject({
        modelId: 'bec-lr',
        promptTemplateVersion: null,
        responseSha256: null,
        indicators: [],
      });
    }
  });

  it('probability is the logistic of the weighted sum (booleans as 1/0, missing as 0)', () => {
    const p0 = model.probability({});
    expect(p0).toBeCloseTo(1 / (1 + Math.exp(-model.model.bias)), 12);
    const i = AI_FEATURE_NAMES.indexOf('rule_x1');
    const p1 = model.probability({ rule_x1: true });
    expect(p1).toBeCloseTo(1 / (1 + Math.exp(-(model.model.bias + model.model.weights[i]!))), 12);
  });

  it('returns timeout when already aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    expect((await model.assess({ features: {}, excerpt: null }, controller.signal)).status).toBe(
      'timeout',
    );
  });
});
