import { z } from 'zod';
import { AI_FEATURE_NAMES, AI_INDICATORS } from '../rules/codes';

/**
 * Structured output of the LLM provider (B10): no free-text field. The JSON Schema sent as
 * `output_config.format` is hand-written: every object `additionalProperties: false` with every
 * property required, enums for labels/indicators/features. Numeric ranges and array lengths are
 * not expressible in structured-output schemas (unsupported keywords), so they are enforced by
 * the zod schema below after `JSON.parse` (any failure → `invalid_output`).
 */

export const LLM_LABELS = ['bec', 'phishing', 'benign', 'spam'] as const;

export const BEC_LLM_OUTPUT_JSON_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['labels', 'indicators', 'citedFeatures', 'spans'],
  properties: {
    labels: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['label', 'confidence'],
        properties: {
          label: { type: 'string', enum: [...LLM_LABELS] },
          confidence: { type: 'number' },
        },
      },
    },
    indicators: { type: 'array', items: { type: 'string', enum: [...AI_INDICATORS] } },
    citedFeatures: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['feature', 'weight'],
        properties: {
          feature: { type: 'string', enum: [...AI_FEATURE_NAMES] },
          weight: { type: 'number' },
        },
      },
    },
    spans: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['start', 'end', 'indicator'],
        properties: {
          start: { type: 'integer' },
          end: { type: 'integer' },
          indicator: { type: 'string', enum: [...AI_INDICATORS] },
        },
      },
    },
  },
} as const;

export const llmOutputSchema = z.strictObject({
  labels: z
    .array(z.strictObject({ label: z.enum(LLM_LABELS), confidence: z.number().min(0).max(1) }))
    .min(1)
    .max(4),
  indicators: z.array(z.enum(AI_INDICATORS)).max(8),
  citedFeatures: z
    .array(
      z.strictObject({
        feature: z.string().refine((f) => AI_FEATURE_NAMES.includes(f), 'unknown feature'),
        weight: z.number().min(-1000).max(1000),
      }),
    )
    .max(8),
  spans: z
    .array(
      z
        .strictObject({
          start: z.number().int().min(0),
          end: z.number().int().min(0),
          indicator: z.enum(AI_INDICATORS),
        })
        .refine((s) => s.start < s.end, 'start must be < end'),
    )
    .max(8),
});
export type LlmOutput = z.infer<typeof llmOutputSchema>;

/** Canonical JSON (keys sorted recursively) for `responseSha256`. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
