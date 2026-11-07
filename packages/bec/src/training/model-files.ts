import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PACKAGE_DIR, sha256Hex } from '../data';
import {
  loadLocalModel,
  loadModelManifest,
  localModelFileSchema,
  type LocalModelFile,
} from '../ai/local-model';
import { loadBecStaticData } from '../static-data';
import { generateTrainingRecords, parseJsonl, recordsToJsonl, TRAINING_SET_ID } from './generator';
import { buildModelFile, isHeldOut } from './trainer';

/**
 * `model:generate` / `model:train` / `model:check` (B9, B16). Paths are inside the package:
 * training/bec-train-1.jsonl, models/bec-lr-1.json, models/manifest.json.
 */

export const TRAINING_FILE = join(PACKAGE_DIR, 'training', 'bec-train-1.jsonl');
export const MODEL_FILE = join(PACKAGE_DIR, 'models', 'bec-lr-1.json');
export const MANIFEST_FILE = join(PACKAGE_DIR, 'models', 'manifest.json');
export const MIN_HELD_OUT_PRECISION = 0.9;
export const MIN_HELD_OUT_RECALL = 0.9;
export const WEIGHT_TOLERANCE = 1e-9;

/**
 * Serializes a JSON artefact exactly as the repository's Prettier config formats it, so the
 * committed bytes, the manifest SHA-256 and `pnpm format` agree (number arrays are filled).
 */
export async function formatJson(value: unknown, filepath: string): Promise<string> {
  const prettier = await import('prettier');
  const options = (await prettier.resolveConfig(filepath)) ?? {};
  return prettier.format(JSON.stringify(value), { ...options, filepath });
}

export function generateTrainingFile(): string {
  const text = recordsToJsonl(generateTrainingRecords(loadBecStaticData()));
  writeFileSync(TRAINING_FILE, text);
  return text;
}

export async function trainAndWrite(): Promise<LocalModelFile> {
  const text = readFileSync(TRAINING_FILE, 'utf8');
  const model = buildModelFile(parseJsonl(text), sha256Hex(text), TRAINING_SET_ID);
  const serialized = await formatJson(model, MODEL_FILE);
  writeFileSync(MODEL_FILE, serialized);
  const manifest = [
    {
      id: model.id,
      version: model.version,
      file: 'bec-lr-1.json',
      sha256: sha256Hex(serialized),
      status: 'available',
    },
  ];
  writeFileSync(MANIFEST_FILE, await formatJson(manifest, MANIFEST_FILE));
  return model;
}

export interface ModelCheckResult {
  ok: boolean;
  problems: string[];
  records: number;
  heldOut: number;
  maxWeightDelta: number;
  metrics: LocalModelFile['metrics'];
}

/** Regenerates and retrains in memory and compares with the committed artefacts. */
export function checkModel(): ModelCheckResult {
  const problems: string[] = [];
  const committedText = readFileSync(TRAINING_FILE, 'utf8');
  const regenerated = recordsToJsonl(generateTrainingRecords(loadBecStaticData()));
  if (regenerated !== committedText)
    problems.push('training/bec-train-1.jsonl differs from the seeded generator output');
  const records = parseJsonl(committedText);
  if (records.length < 200) problems.push(`training set has ${records.length} records (< 200)`);

  const committedModelText = readFileSync(MODEL_FILE, 'utf8');
  const committed = localModelFileSchema.parse(JSON.parse(committedModelText));
  const retrained = buildModelFile(records, sha256Hex(committedText), TRAINING_SET_ID);
  let maxWeightDelta = Math.abs(retrained.bias - committed.bias);
  if (retrained.weights.length !== committed.weights.length) problems.push('weight count differs');
  retrained.weights.forEach((w, i) => {
    maxWeightDelta = Math.max(maxWeightDelta, Math.abs(w - (committed.weights[i] ?? Number.NaN)));
  });
  if (!(maxWeightDelta <= WEIGHT_TOLERANCE))
    problems.push(`retrained weights differ by ${maxWeightDelta} (> ${WEIGHT_TOLERANCE})`);
  if (committed.trainedOn.sha256 !== sha256Hex(committedText))
    problems.push('model trainedOn.sha256 does not match the training file');

  const manifest = loadModelManifest(readFileSync(MANIFEST_FILE, 'utf8'));
  const entry = manifest.find((m) => m.version === committed.version);
  if (!entry) problems.push(`${committed.version} missing from models/manifest.json`);
  else if (entry.sha256 !== sha256Hex(committedModelText))
    problems.push('manifest sha256 does not match models/bec-lr-1.json');
  try {
    loadLocalModel(committed.version);
  } catch (error) {
    problems.push(`loadLocalModel failed: ${(error as Error).message}`);
  }
  const metrics = retrained.metrics;
  if (metrics.precision < MIN_HELD_OUT_PRECISION)
    problems.push(`held-out precision ${metrics.precision} < ${MIN_HELD_OUT_PRECISION}`);
  if (metrics.recall < MIN_HELD_OUT_RECALL)
    problems.push(`held-out recall ${metrics.recall} < ${MIN_HELD_OUT_RECALL}`);
  return {
    ok: problems.length === 0,
    problems,
    records: records.length,
    heldOut: records.filter((_, i) => isHeldOut(i)).length,
    maxWeightDelta,
    metrics,
  };
}
