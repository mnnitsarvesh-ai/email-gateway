import Anthropic, {
  APIConnectionError,
  APIConnectionTimeoutError,
  APIError,
  APIUserAbortError,
} from '@anthropic-ai/sdk';
import { sha256Hex } from '../data';
import { mapExcerptSpan, type RedactedExcerpt } from '../text/excerpt';
import {
  BEC_LLM_OUTPUT_JSON_SCHEMA,
  canonicalJson,
  llmOutputSchema,
  type LlmOutput,
} from './llm-schema';
import { loadPromptTemplate, type PromptTemplate } from './prompt';
import {
  failedAssessment,
  type AiAssessment,
  type AiInput,
  type AiSpan,
  type AiStatus,
  type BecAiProvider,
} from './types';

/**
 * The LLM provider (B10): Anthropic Claude through the official `@anthropic-ai/sdk` (1.1.0).
 *
 * Request (shapes verified against the installed SDK's type definitions, §12 WP2):
 * `client.beta.messages.create({ model, max_tokens, system, messages, output_config: { effort:
 * 'low', format: { type: 'json_schema', schema } }, betas: ['server-side-fallback-2026-07-01'],
 * fallbacks: 'default' }, { timeout, maxRetries: 0, signal })`; with
 * `BEC_LLM_REFUSAL_FALLBACK=off` the plain `client.messages.create` without betas/fallbacks.
 * No `thinking`, `temperature` or `top_p` (adaptive thinking is always on for this model; depth
 * is set by `effort`). Errors are classified with the SDK's typed error classes, never message
 * text. The raw response text is never stored or logged: only the validated output's hash.
 * The client is built with `openTelemetry: false` and `logLevel: 'off'` so no request content
 * can reach traces or logs through the SDK.
 */

export const LLM_PROVIDER = 'anthropic';
export const SERVER_SIDE_FALLBACK_BETA = 'server-side-fallback-2026-07-01';

export type RefusalFallback = 'default' | 'off';

export interface AnthropicProviderOptions {
  apiKey: string;
  /** BEC_LLM_MODEL (default claude-opus-5-5). */
  model: string;
  /** BEC_LLM_MAX_OUTPUT_TOKENS (4 096). */
  maxOutputTokens: number;
  /** BEC_LLM_TIMEOUT_MS (20 000). */
  timeoutMs: number;
  /** BEC_LLM_REFUSAL_FALLBACK. */
  refusalFallback: RefusalFallback;
  /** Injected transport (tests; never a real call in CI). */
  fetch?: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
  baseURL?: string;
  /** Metrics hook (token counts, status); never receives content. */
  onResult?: (info: LlmCallInfo) => void;
  prompt?: PromptTemplate;
}

export interface LlmCallInfo {
  status: AiStatus;
  /** HTTP status of an API error, null otherwise. */
  httpStatus: number | null;
  /** Typed SDK error class name or a fixed reason; never message text. */
  reason:
    | 'ok'
    | 'refusal'
    | 'max_tokens'
    | 'schema'
    | 'json'
    | 'timeout'
    | 'aborted'
    | 'rate_limited'
    | 'server_error'
    | 'client_error'
    | 'connection'
    | 'unexpected';
  inputTokens: number | null;
  outputTokens: number | null;
  /** Model that answered (`response.model`; a server-side fallback may differ). */
  respondedModel: string | null;
  durationMs: number;
}

interface ResponseLike {
  model: string;
  stop_reason: string | null;
  content: ReadonlyArray<{ type: string; text?: string }>;
  usage?: { input_tokens?: number | null; output_tokens?: number | null } | null;
}

/** The user message: features, categorical facts and the redacted excerpt only (B10). */
export function buildUserContent(input: AiInput): string {
  return JSON.stringify({
    features: input.features,
    facts: input.facts ?? null,
    excerpt: input.excerpt ? { subject: input.excerpt.subject, text: input.excerpt.text } : null,
  });
}

/** Validates a parsed model output against the zod schema and the excerpt bounds. */
export function validateLlmOutput(
  value: unknown,
  excerpt: RedactedExcerpt | null,
): { ok: true; output: LlmOutput } | { ok: false } {
  const parsed = llmOutputSchema.safeParse(value);
  if (!parsed.success) return { ok: false };
  const length = excerpt?.text.length ?? 0;
  if (parsed.data.spans.some((s) => s.end > length)) return { ok: false };
  return { ok: true, output: parsed.data };
}

export class AnthropicBecProvider implements BecAiProvider {
  readonly kind = 'llm' as const;
  readonly modelId: string;
  readonly modelVersion: string;
  private readonly client: Anthropic;
  private readonly prompt: PromptTemplate;

  constructor(private readonly options: AnthropicProviderOptions) {
    if (!options.apiKey) throw new Error('BEC_LLM_API_KEY is required for the anthropic provider');
    this.modelId = options.model;
    this.modelVersion = options.model;
    this.prompt = options.prompt ?? loadPromptTemplate();
    this.client = new Anthropic({
      apiKey: options.apiKey,
      maxRetries: 0,
      timeout: options.timeoutMs,
      openTelemetry: false,
      logLevel: 'off',
      ...(options.fetch ? { fetch: options.fetch } : {}),
      ...(options.baseURL ? { baseURL: options.baseURL } : {}),
    });
  }

  get promptSha256(): string {
    return this.prompt.sha256;
  }

  async assess(input: AiInput, signal: AbortSignal): Promise<AiAssessment> {
    const started = performance.now();
    const elapsed = (): number => Math.round(performance.now() - started);
    const report = (info: Omit<LlmCallInfo, 'durationMs'>): void =>
      this.options.onResult?.({ ...info, durationMs: elapsed() });
    const fail = (
      status: Exclude<AiStatus, 'ok'>,
      info: Omit<LlmCallInfo, 'status' | 'durationMs'>,
    ): AiAssessment => {
      report({ status, ...info });
      return failedAssessment(status, this, elapsed(), this.prompt.version);
    };
    const base = {
      model: this.options.model,
      max_tokens: this.options.maxOutputTokens,
      system: this.prompt.text,
      messages: [{ role: 'user' as const, content: buildUserContent(input) }],
      output_config: {
        effort: 'low' as const,
        format: {
          type: 'json_schema' as const,
          schema: BEC_LLM_OUTPUT_JSON_SCHEMA as unknown as Record<string, unknown>,
        },
      },
    };
    const requestOptions = { timeout: this.options.timeoutMs, maxRetries: 0, signal };

    let response: ResponseLike;
    try {
      response =
        this.options.refusalFallback === 'default'
          ? await this.client.beta.messages.create(
              { ...base, betas: [SERVER_SIDE_FALLBACK_BETA], fallbacks: 'default' },
              requestOptions,
            )
          : await this.client.messages.create(base, requestOptions);
    } catch (error: unknown) {
      const none = { inputTokens: null, outputTokens: null, respondedModel: null };
      if (error instanceof APIConnectionTimeoutError)
        return fail('timeout', { httpStatus: null, reason: 'timeout', ...none });
      if (error instanceof APIUserAbortError)
        return fail('timeout', { httpStatus: null, reason: 'aborted', ...none });
      if (error instanceof APIConnectionError)
        return fail('error', { httpStatus: null, reason: 'connection', ...none });
      if (error instanceof APIError) {
        const status = typeof error.status === 'number' ? error.status : null;
        const reason =
          status === 429
            ? 'rate_limited'
            : status !== null && status >= 500
              ? 'server_error'
              : 'client_error';
        return fail('error', { httpStatus: status, reason, ...none });
      }
      return fail('error', { httpStatus: null, reason: 'unexpected', ...none });
    }

    const usage = {
      inputTokens: response.usage?.input_tokens ?? null,
      outputTokens: response.usage?.output_tokens ?? null,
      respondedModel: response.model,
      httpStatus: null,
    };
    if (response.stop_reason === 'refusal') return fail('refused', { reason: 'refusal', ...usage });
    if (response.stop_reason === 'max_tokens')
      return fail('invalid_output', { reason: 'max_tokens', ...usage });
    const text = response.content
      .filter((block) => block.type === 'text' && typeof block.text === 'string')
      .map((block) => block.text!)
      .join('');
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      return fail('invalid_output', { reason: 'json', ...usage });
    }
    const validated = validateLlmOutput(json, input.excerpt);
    if (!validated.ok) return fail('invalid_output', { reason: 'schema', ...usage });
    const output = validated.output;

    const labels = [...output.labels].sort((a, b) => b.confidence - a.confidence);
    const spans: AiSpan[] = [];
    for (const span of output.spans) {
      const mapped = input.excerpt ? mapExcerptSpan(input.excerpt, span.start, span.end) : null;
      if (mapped) spans.push({ ...mapped, label: span.indicator });
    }
    report({ status: 'ok', reason: 'ok', ...usage });
    return {
      status: 'ok',
      labels,
      confidence: labels[0]!.confidence,
      citedFeatures: output.citedFeatures.map((c) => ({
        feature: c.feature,
        contribution: c.weight,
      })),
      spans,
      indicators: [...new Set(output.indicators)],
      modelId: this.modelId,
      modelVersion: response.model,
      promptTemplateVersion: this.prompt.version,
      responseSha256: sha256Hex(canonicalJson(output)),
      durationMs: elapsed(),
    };
  }
}
