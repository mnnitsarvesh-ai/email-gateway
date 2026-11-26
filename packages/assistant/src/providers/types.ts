/**
 * The LLM provider contract of the assistant (design D6, ADR-0092). One interface for Anthropic
 * Claude, OpenAI, Azure OpenAI and the deterministic fake. The model is an untrusted client: a
 * provider only transports text and tool calls; validation happens in the executor.
 *
 * Providers never put provider message text into errors or logs: `LlmError` carries a fixed
 * reason code, the HTTP status and (for refusals) the policy category only.
 */

export const LLM_PROVIDER_IDS = ['anthropic', 'openai', 'azure_openai', 'fake'] as const;
export type LlmProviderId = (typeof LLM_PROVIDER_IDS)[number];

export const META_TOOL_NAMES = ['describe_tool', 'call_tool'] as const;
export type MetaToolName = (typeof META_TOOL_NAMES)[number];

export type LlmEffort = 'low' | 'medium' | 'high' | 'xhigh' | 'max';

/** A provider-level tool: one of the two meta tools (D4), with a strict JSON schema. */
export interface MetaToolDef {
  name: MetaToolName;
  description: string;
  /** JSON Schema object (`additionalProperties: false`, every property required: strict mode). */
  inputSchema: Record<string, unknown>;
}

/**
 * Provider-native, append-only transcript (D7): the entries a provider produced
 * (`appendToTranscript`) and the entries built by `userEntry` / `toolResultEntries`, replayed
 * verbatim on every later request of the same segment (preserved thinking).
 */
export type ProviderTranscript = readonly unknown[];

export interface LlmRequest {
  /** Versioned prompt + catalogue index + context block (cacheable prefix first). */
  system: string;
  transcript: ProviderTranscript;
  tools: readonly MetaToolDef[];
  maxOutputTokens: number;
}

export type LlmStop = 'end_turn' | 'tool_use' | 'max_tokens' | 'refusal' | 'pause_turn';

export interface LlmToolCall {
  /** Provider-assigned call id (echoed in the tool result). */
  id: string;
  /**
   * Normally a `MetaToolName`; kept as the raw string the model emitted because every call id
   * needs a tool result, so an unknown name is answered with a coded error, never dropped.
   */
  name: MetaToolName | (string & {});
  /** Raw model-supplied input; validated by `parseMetaToolInput` and the executor. */
  input: unknown;
}

export interface LlmUsage {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}

export interface LlmResponse {
  stop: LlmStop;
  text: string;
  toolCalls: LlmToolCall[];
  /** Native entries to append verbatim (the assistant message incl. thinking blocks). */
  appendToTranscript: unknown[];
  usage: LlmUsage;
  /** Model id reported by the provider (a server-side fallback may differ from the request). */
  responseModel: string;
  /** Refusal policy category (`stop_details.category`) when `stop === 'refusal'`. */
  refusalCategory?: string | null;
}

/** A tool result to hand back to the model (the serialized `assistant-tool-result/1` envelope). */
export interface LlmToolResult {
  toolCallId: string;
  content: string;
  isError: boolean;
}

export interface LlmProvider {
  readonly id: LlmProviderId;
  readonly model: string;
  /** One model call; streams text deltas; returns the final assistant message, tool calls and usage. */
  complete(
    request: LlmRequest,
    signal: AbortSignal,
    onDelta: (text: string) => void,
  ): Promise<LlmResponse>;
  /** The native transcript entry of a user message. */
  userEntry(text: string): unknown[];
  /** The native transcript entries that return tool results (in call order). */
  toolResultEntries(results: readonly LlmToolResult[]): unknown[];
  /**
   * Checks the credentials and the model without generating tokens (step AI-6 D7: tenant-key
   * validation): Anthropic retrieves the model, OpenAI `GET {base}/models/{model}`; the fake
   * resolves. Absent where no probe exists (Azure OpenAI). Throws a classified `LlmError`
   * (`auth` for 401/403, `rate_limited`, `server_error`, `connection`, `timeout`, …).
   */
  probe?(signal: AbortSignal): Promise<void>;
}

export const LLM_ERROR_REASONS = [
  'timeout',
  'aborted',
  'rate_limited',
  'server_error',
  'client_error',
  'connection',
  'refusal',
  'schema',
  'unexpected',
  // step AI-6 D6/D7: 401/403 of the provider (a rejected key); never counts toward the breaker
  'auth',
] as const;
export type LlmErrorReason = (typeof LLM_ERROR_REASONS)[number];

/**
 * A classified provider failure. The message is a fixed text built from the reason code, never
 * the provider's own message (which may echo request content).
 */
export class LlmError extends Error {
  readonly reason: LlmErrorReason;
  readonly httpStatus: number | null;
  /** `retry-after` of a 429/5xx in milliseconds, when the provider sent one. */
  readonly retryAfterMs: number | null;
  /** Whether text had already been streamed to the caller before the failure (no retry then). */
  readonly afterDelta: boolean;
  /** Refusal category (reason `refusal` only). */
  readonly category: string | null;

  constructor(
    reason: LlmErrorReason,
    options: {
      httpStatus?: number | null;
      retryAfterMs?: number | null;
      afterDelta?: boolean;
      category?: string | null;
    } = {},
  ) {
    super(`LLM provider error: ${reason}${options.httpStatus ? ` (${options.httpStatus})` : ''}`);
    this.name = 'LlmError';
    this.reason = reason;
    this.httpStatus = options.httpStatus ?? null;
    this.retryAfterMs = options.retryAfterMs ?? null;
    this.afterDelta = options.afterDelta ?? false;
    this.category = options.category ?? null;
  }

  /** Connection errors, 429 and 5xx are retryable once, and only before any delta was streamed. */
  get retryable(): boolean {
    return (
      !this.afterDelta &&
      (this.reason === 'connection' ||
        this.reason === 'rate_limited' ||
        this.reason === 'server_error')
    );
  }
}

/** Reason code of an HTTP error status (shared by the providers; 401/403 → `auth`, step AI-6). */
export function reasonOfStatus(status: number): LlmErrorReason {
  if (status === 401 || status === 403) return 'auth';
  if (status === 429) return 'rate_limited';
  if (status >= 500) return 'server_error';
  return 'client_error';
}

/** Parses a `retry-after` header value (seconds or HTTP date) into milliseconds. */
export function parseRetryAfter(value: string | null | undefined, now: number): number | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (/^\d+(\.\d+)?$/.test(trimmed)) return Math.round(Number(trimmed) * 1000);
  const at = Date.parse(trimmed);
  return Number.isNaN(at) ? null : Math.max(0, at - now);
}

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
