import { AI_FEATURE_NAMES } from '../rules/codes';
import { featureVector } from '../rules/features';
import { sigmoid, type LocalModelFile } from '../ai/local-model';
import type { TrainingRecord } from './generator';

/**
 * Deterministic trainer of `bec-lr/1` (B9): batch gradient descent on the logistic loss with
 * L2, zero initialization, features in AI_FEATURE_NAMES order, a fixed learning rate and
 * iteration count. Every 5th record (index % 5 === 4) is held out for the metrics.
 */

export const TRAINING_HYPERPARAMETERS = Object.freeze({
  learningRate: 0.5,
  iterations: 3000,
  l2: 0.001,
});

export interface TrainResult {
  weights: number[];
  bias: number;
}

export const isHeldOut = (index: number): boolean => index % 5 === 4;

export function trainLogistic(
  records: readonly TrainingRecord[],
  params: { learningRate: number; iterations: number; l2: number } = TRAINING_HYPERPARAMETERS,
): TrainResult {
  const xs = records.map((r) => featureVector(r.features));
  const ys = records.map((r) => r.label);
  const d = AI_FEATURE_NAMES.length;
  const n = xs.length;
  const weights = new Array<number>(d).fill(0);
  let bias = 0;
  const grad = new Array<number>(d).fill(0);
  for (let it = 0; it < params.iterations; it += 1) {
    grad.fill(0);
    let gradBias = 0;
    for (let i = 0; i < n; i += 1) {
      const x = xs[i]!;
      let z = bias;
      for (let j = 0; j < d; j += 1) z += weights[j]! * x[j]!;
      const error = sigmoid(z) - ys[i]!;
      gradBias += error;
      for (let j = 0; j < d; j += 1) grad[j]! += error * x[j]!;
    }
    for (let j = 0; j < d; j += 1) {
      weights[j] = weights[j]! - params.learningRate * (grad[j]! / n + params.l2 * weights[j]!);
    }
    bias -= params.learningRate * (gradBias / n);
  }
  return { weights, bias };
}

export interface Metrics {
  accuracy: number;
  precision: number;
  recall: number;
}

export function evaluateModel(model: TrainResult, records: readonly TrainingRecord[]): Metrics {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const record of records) {
    const x = featureVector(record.features);
    let z = model.bias;
    for (let j = 0; j < x.length; j += 1) z += model.weights[j]! * x[j]!;
    const predicted = sigmoid(z) >= 0.5 ? 1 : 0;
    if (predicted === 1 && record.label === 1) tp += 1;
    else if (predicted === 1) fp += 1;
    else if (record.label === 0) tn += 1;
    else fn += 1;
  }
  const round = (v: number): number => Math.round(v * 1e6) / 1e6;
  return {
    accuracy: round((tp + tn) / Math.max(1, records.length)),
    precision: round(tp / Math.max(1, tp + fp)),
    recall: round(tp / Math.max(1, tp + fn)),
  };
}

export function buildModelFile(
  records: readonly TrainingRecord[],
  datasetSha256: string,
  fixtureSet: string,
): LocalModelFile {
  const train = records.filter((_, i) => !isHeldOut(i));
  const heldOut = records.filter((_, i) => isHeldOut(i));
  const result = trainLogistic(train);
  return {
    id: 'bec-lr',
    version: 'bec-lr/1',
    features: [...AI_FEATURE_NAMES],
    weights: result.weights,
    bias: result.bias,
    trainedOn: { fixtureSet, sha256: datasetSha256 },
    metrics: evaluateModel(result, heldOut),
  };
}
