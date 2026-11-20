import { z } from 'zod';
import type { LlmUsage } from './types';

/**
 * Advisory token prices (design D6, §7 Q1/Q7) in micro-USD per million tokens, as of 2026-11:
 * Claude Opus 5.5 $4 input / $20 output / $0.20 cache read; Claude Sonnet 5.5 $2 / $10 / $0.10;
 * cache writes (5-minute) at 1.25× input. Other models (OpenAI, Azure deployments) are priced
 * only through `ASSISTANT_MODEL_PRICES` (JSON); an unknown model's cost is `null`. Tokens are
 * always recorded; cost is advisory.
 */

export interface ModelPrice {
  inputMicrosPerMTok: number;
  outputMicrosPerMTok: number;
  cacheReadMicrosPerMTok: number;
  cacheWriteMicrosPerMTok: number;
}

const USD = 1_000_000;

export const DEFAULT_MODEL_PRICES: Readonly<Record<string, ModelPrice>> = {
  'claude-opus-5-5': {
    inputMicrosPerMTok: 4 * USD,
    outputMicrosPerMTok: 20 * USD,
    cacheReadMicrosPerMTok: 0.2 * USD,
    cacheWriteMicrosPerMTok: 5 * USD,
  },
  'claude-sonnet-5-5': {
    inputMicrosPerMTok: 2 * USD,
    outputMicrosPerMTok: 10 * USD,
    cacheReadMicrosPerMTok: 0.1 * USD,
    cacheWriteMicrosPerMTok: 2.5 * USD,
  },
};

const price = z.number().int().min(0).max(1_000_000_000);
const modelPricesSchema = z.record(
  z.string().min(1).max(128),
  z.strictObject({
    inputMicrosPerMTok: price,
    outputMicrosPerMTok: price,
    cacheReadMicrosPerMTok: price.optional(),
    cacheWriteMicrosPerMTok: price.optional(),
  }),
);

/**
 * Parses `ASSISTANT_MODEL_PRICES` (`{ "<model>": { inputMicrosPerMTok, outputMicrosPerMTok,
 * cacheReadMicrosPerMTok?, cacheWriteMicrosPerMTok? } }`); cache prices default to the input price
 * (read) and 1.25× input (write). Throws on invalid input (config validation fails closed).
 */
export function parseModelPrices(json: string | undefined): Record<string, ModelPrice> {
  if (!json || json.trim() === '') return {};
  const parsed = modelPricesSchema.parse(JSON.parse(json));
  return Object.fromEntries(
    Object.entries(parsed).map(([model, value]) => [
      model,
      {
        inputMicrosPerMTok: value.inputMicrosPerMTok,
        outputMicrosPerMTok: value.outputMicrosPerMTok,
        cacheReadMicrosPerMTok: value.cacheReadMicrosPerMTok ?? value.inputMicrosPerMTok,
        cacheWriteMicrosPerMTok:
          value.cacheWriteMicrosPerMTok ?? Math.round(value.inputMicrosPerMTok * 1.25),
      },
    ]),
  );
}

/** Cost of one call or turn in micro-USD, or null when the model has no price. */
export function costMicros(
  model: string,
  usage: LlmUsage,
  overrides: Readonly<Record<string, ModelPrice>> = {},
): number | null {
  const prices = overrides[model] ?? DEFAULT_MODEL_PRICES[model];
  if (!prices) return null;
  const total =
    usage.inputTokens * prices.inputMicrosPerMTok +
    usage.outputTokens * prices.outputMicrosPerMTok +
    usage.cacheReadTokens * prices.cacheReadMicrosPerMTok +
    usage.cacheWriteTokens * prices.cacheWriteMicrosPerMTok;
  return Math.round(total / 1_000_000);
}
