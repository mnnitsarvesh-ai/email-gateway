import { loadCorpus } from '../corpus';
import { BEC_DEFAULT_RULE_SETTINGS } from '../rules/defaults';
import { evaluateBecRules } from '../rules/evaluate';
import { AI_FEATURE_NAMES } from '../rules/codes';
import type { BecStaticData } from '../static-data';

/**
 * Seeded generator of the synthetic training set `bec-train/1` (B9): every labelled corpus
 * template (fixtures/corpus, no real mail) is evaluated by bec-map/1 to obtain its feature
 * vector; each template then yields `VARIANTS_PER_TEMPLATE` variants by seeded perturbations
 * that keep the template's meaning (benign templates gain benign-compatible noise such as
 * urgency words, amounts, a reply thread or an unauthenticated forwarder; BEC templates lose
 * at most one non-core cue and gain the same noise). Deterministic: same code + same corpus +
 * same seed → byte-identical JSONL.
 */

export const TRAINING_SET_ID = 'bec-train/1';
export const TRAINING_SEED = 0x6265631;
export const VARIANTS_PER_TEMPLATE = 11;
export const TRAINING_NOW = new Date('2026-11-03T00:00:00.000Z');

export interface TrainingRecord {
  id: string;
  template: string;
  label: 0 | 1;
  /** Non-zero features only (AI_FEATURE_NAMES subset). */
  features: Record<string, number>;
}

/** mulberry32: small, fast, seedable PRNG (deterministic across platforms). */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const LOG1P = (n: number): number => Math.round(Math.log1p(n) * 1e6) / 1e6;

/** Noise compatible with legitimate mail (never identity impersonation or payment redirection). */
const BENIGN_NOISE: ReadonlyArray<(f: Record<string, number>, r: () => number) => void> = [
  (f) => {
    f.rule_c7 = 1;
    f.lex_urgency = LOG1P(1);
  },
  (f, r) => {
    f.rule_c10 = 1;
    f.pat_amount = LOG1P(1 + Math.floor(r() * 2));
  },
  (f) => {
    f.isReply = 1;
  },
  (f) => {
    f.rule_p1 = 1;
  },
  (f) => {
    f.lex_authority = LOG1P(1);
  },
  (f, r) => {
    f.urlCountLog = LOG1P(1 + Math.floor(r() * 4));
  },
  (f, r) => {
    f.textLengthBucket = Math.floor(r() * 4);
  },
  (f) => {
    f.rule_a5 = 1;
  },
];

/** Cues a BEC variant may lose (one at most): never the identity or the core intent rule. */
const DROPPABLE = [
  'rule_c7',
  'lex_urgency',
  'rule_c8',
  'lex_secrecy',
  'rule_c10',
  'pat_amount',
  'pat_iban',
  'rule_x2',
];

export function generateTrainingRecords(
  data: BecStaticData,
  seed: number = TRAINING_SEED,
): TrainingRecord[] {
  const random = mulberry32(seed);
  const records: TrainingRecord[] = [];
  for (const { fixture, input } of loadCorpus()) {
    if (fixture.label === null) continue;
    const label: 0 | 1 = fixture.label === 'bec' ? 1 : 0;
    const base = evaluateBecRules(input, BEC_DEFAULT_RULE_SETTINGS, data, {
      now: TRAINING_NOW,
    }).features;
    for (let k = 0; k <= VARIANTS_PER_TEMPLATE; k += 1) {
      const features: Record<string, number> = { ...base };
      if (k > 0) {
        const noise = Math.floor(random() * 3);
        for (let n = 0; n < noise; n += 1) {
          BENIGN_NOISE[Math.floor(random() * BENIGN_NOISE.length)]!(features, random);
        }
        if (label === 1 && random() < 0.5) {
          const present = DROPPABLE.filter((name) => (features[name] ?? 0) !== 0);
          if (present.length > 0) features[present[Math.floor(random() * present.length)]!] = 0;
        }
      }
      const nonZero: Record<string, number> = {};
      for (const name of AI_FEATURE_NAMES)
        if ((features[name] ?? 0) !== 0) nonZero[name] = features[name]!;
      records.push({ id: `${fixture.id}#${k}`, template: fixture.id, label, features: nonZero });
    }
  }
  return records;
}

export const recordsToJsonl = (records: readonly TrainingRecord[]): string =>
  records.map((r) => JSON.stringify(r)).join('\n') + '\n';

export function parseJsonl(text: string): TrainingRecord[] {
  return text
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as TrainingRecord);
}
