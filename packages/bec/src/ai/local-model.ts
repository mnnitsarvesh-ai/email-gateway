import { z } from 'zod';
import { readPackageFile, sha256Hex } from '../data';
import { AI_FEATURE_NAMES } from '../rules/codes';
import { featureVector } from '../rules/features';
import {
  failedAssessment,
  type AiAssessment,
  type AiInput,
  type AiSpan,
  type BecAiProvider,
} from './types';

/**
 * Local model `bec-lr/1` (B9, B16): binary logistic regression over `AI_FEATURE_NAMES`
 * (label bec_or_phishing vs benign). Weights in `models/bec-lr-1.json`, listed with their
 * SHA-256 in `models/manifest.json`; the worker refuses to start when the configured model is
 * not in the manifest or its file hash differs (`loadLocalModel` throws).
 */

export const LOCAL_MODEL_ID = 'bec-lr';
export const MAX_CITED_FEATURES = 5;
export const MAX_AI_SPANS = 8;

export const localModelFileSchema = z.strictObject({
  id: z.literal(LOCAL_MODEL_ID),
  version: z.string().regex(/^bec-lr\/\d+$/),
  features: z.array(z.string()).min(1).max(256),
  weights: z.array(z.number()).min(1).max(256),
  bias: z.number(),
  trainedOn: z.strictObject({ fixtureSet: z.string(), sha256: z.string().regex(/^[0-9a-f]{64}$/) }),
  metrics: z.strictObject({ accuracy: z.number(), precision: z.number(), recall: z.number() }),
});
export type LocalModelFile = z.infer<typeof localModelFileSchema>;

export const manifestEntrySchema = z.strictObject({
  id: z.string(),
  version: z.string(),
  file: z.string().regex(/^[a-z0-9-]+\.json$/),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  status: z.literal('available'),
});
export const manifestSchema = z.array(manifestEntrySchema).min(1).max(32);
export type ModelManifestEntry = z.infer<typeof manifestEntrySchema>;

export function loadModelManifest(
  text: string = readPackageFile('models', 'manifest.json'),
): ModelManifestEntry[] {
  return manifestSchema.parse(JSON.parse(text));
}

export const sigmoid = (z: number): number =>
  z >= 0 ? 1 / (1 + Math.exp(-z)) : Math.exp(z) / (1 + Math.exp(z));

export class LocalBecModel implements BecAiProvider {
  readonly kind = 'local' as const;
  readonly modelId = LOCAL_MODEL_ID;
  readonly modelVersion: string;

  constructor(
    readonly model: LocalModelFile,
    readonly fileSha256: string,
  ) {
    if (model.features.length !== model.weights.length)
      throw new Error('bec-lr: features/weights length mismatch');
    if (model.features.join('\n') !== AI_FEATURE_NAMES.join('\n')) {
      throw new Error(`${model.version}: feature list differs from AI_FEATURE_NAMES`);
    }
    this.modelVersion = `${model.version}@${fileSha256.slice(0, 12)}`;
  }

  /** P(bec_or_phishing) of a feature record. */
  probability(features: Readonly<Record<string, number | boolean>>): number {
    const x = featureVector(features);
    let z = this.model.bias;
    for (let i = 0; i < x.length; i += 1) z += this.model.weights[i]! * x[i]!;
    return sigmoid(z);
  }

  assess(input: AiInput, signal: AbortSignal): Promise<AiAssessment> {
    const started = performance.now();
    if (signal.aborted) return Promise.resolve(failedAssessment('timeout', this, 0));
    const x = featureVector(input.features);
    const p = this.probability(input.features);
    const contributions = x
      .map((value, i) => ({
        feature: AI_FEATURE_NAMES[i]!,
        contribution: this.model.weights[i]! * value,
      }))
      .filter((c) => c.contribution !== 0)
      .sort(
        (a, b) =>
          Math.abs(b.contribution) - Math.abs(a.contribution) || (a.feature < b.feature ? -1 : 1),
      )
      .slice(0, MAX_CITED_FEATURES)
      .map((c) => ({ feature: c.feature, contribution: Math.round(c.contribution * 1e6) / 1e6 }));
    const spans: AiSpan[] = [];
    for (const cited of contributions) {
      if (!cited.feature.startsWith('lex_') || cited.contribution <= 0) continue;
      const category = cited.feature.slice(4);
      for (const span of input.lexiconSpans?.[category] ?? []) {
        if (spans.length >= MAX_AI_SPANS) break;
        spans.push({ ...span, label: category });
      }
    }
    const round = (v: number): number => Math.round(v * 1e6) / 1e6;
    const bec = p >= 0.5;
    const labels: AiAssessment['labels'] = bec
      ? [
          { label: 'bec', confidence: round(p) },
          { label: 'benign', confidence: round(1 - p) },
        ]
      : [
          { label: 'benign', confidence: round(1 - p) },
          { label: 'bec', confidence: round(p) },
        ];
    return Promise.resolve({
      status: 'ok',
      labels,
      confidence: round(Math.max(p, 1 - p)),
      citedFeatures: contributions,
      spans,
      indicators: [],
      modelId: this.modelId,
      modelVersion: this.modelVersion,
      promptTemplateVersion: null,
      responseSha256: null,
      durationMs: Math.round(performance.now() - started),
    });
  }
}

/** Loads a model by version (`BEC_LOCAL_MODEL`, e.g. `bec-lr/1`), verifying the manifest hash. */
export function loadLocalModel(
  version: string,
  manifest: ModelManifestEntry[] = loadModelManifest(),
): LocalBecModel {
  const entry = manifest.find((m) => m.version === version);
  if (!entry) throw new Error(`local model ${version} is not in models/manifest.json`);
  const text = readPackageFile('models', entry.file);
  const sha = sha256Hex(text);
  if (sha !== entry.sha256)
    throw new Error(`local model ${version}: file hash differs from the manifest`);
  const model = localModelFileSchema.parse(JSON.parse(text));
  if (model.version !== version || model.id !== entry.id)
    throw new Error(`local model ${version}: manifest mismatch`);
  return new LocalBecModel(model, sha);
}
