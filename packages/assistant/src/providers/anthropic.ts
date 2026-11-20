import Anthropic, {
  APIConnectionError,
  APIConnectionTimeoutError,
  APIError,
  APIUserAbortError,
} from '@anthropic-ai/sdk';
import {
  LlmError,
  parseRetryAfter,
  reasonOfStatus,
  type FetchLike,
  type LlmEffort,
  type LlmProvider,
  type LlmRequest,
  type LlmResponse,
  type LlmStop,
  type LlmToolCall,
  type LlmToolResult,
} from './types';

/**
 * Anthropic Claude through the official `@anthropic-ai/sdk` 1.1.0 (design D6, ADR-0092), the same
 * pinned SDK and conventions as the BEC layer (packages/bec/src/ai/anthropic.ts).
 *
 * Request shapes verified against the installed SDK's type definitions
 * (`resources/beta/messages/messages.d.ts`, `resources/messages/messages.d.ts`,
 * `lib/BetaMessageStream.d.ts`, `client.d.ts`, `core/error.d.ts`):
 *
 * - `client.beta.messages.stream(body: BetaMessageStreamParams = MessageCreateParamsBase, options)`
 *   with `model`, `max_tokens`, `system: Array<BetaTextBlockParam>` (one `{ type: 'text', text,
 *   cache_control: { type: 'ephemeral' } }` block), `tools: Array<BetaTool>` (`{ name,
 *   description, input_schema: { type: 'object', ... }, strict: true }`), `tool_choice:
 *   BetaToolChoiceAuto` (`{ type: 'auto' }`), `messages: Array<BetaMessageParam>`, `output_config:
 *   BetaOutputConfig` (`{ effort: 'low' | 'medium' | 'high' | 'xhigh' | 'max' }`), `betas:
 *   Array<AnthropicBeta>` (`['server-side-fallback-2026-07-01']`) and `fallbacks:
 *   BetaFallbacksParam` (`'default'`);
 * - with the refusal fallback off: `client.messages.stream(...)` with the same fields minus `betas`
 *   and `fallbacks` (`TextBlockParam.cache_control`, `Tool.strict`, `OutputConfig.effort` exist on
 *   the GA types too);
 * - never `thinking` (always on for claude-opus-5-5; `effort` is the control), `temperature`,
 *   `top_p`, `top_k` (rejected) or a forced `tool_choice` (`any` / `tool`: rejected);
 * - the stream: `on('text', (delta, snapshot) => …)`, `finalMessage(): Promise<BetaMessage>`;
 *   `BetaMessage.stop_reason: BetaStopReason` (`end_turn | max_tokens | stop_sequence | tool_use |
 *   pause_turn | compaction | refusal | model_context_window_exceeded`), `stop_details:
 *   BetaRefusalStopDetails | null` (`category`), `usage: BetaUsage` (`input_tokens`,
 *   `output_tokens`, `cache_read_input_tokens`, `cache_creation_input_tokens`), `model`;
 * - client options `{ apiKey, baseURL, fetch, maxRetries: 0, timeout, logLevel: 'off',
 *   openTelemetry: false }`; request options `{ signal, timeout, maxRetries: 0 }`;
 * - errors: `APIUserAbortError`, `APIConnectionTimeoutError`, `APIConnectionError` (no status),
 *   `APIError` (`status`, `headers`); classified by class and status, never by message text.
 *
 * The assistant content blocks of the final message are appended to the transcript **verbatim**
 * (thinking blocks, fallback blocks and signatures unmodified: preserved thinking, D7).
 */

export const SERVER_SIDE_FALLBACK_BETA = 'server-side-fallback-2026-07-01';
export type RefusalFallback = 'default' | 'off';

export interface AnthropicProviderOptions {
  apiKey: string;
  /** ASSISTANT_MODEL (default claude-opus-5-5). */
  model: string;
  /** ASSISTANT_EFFORT (default low). */
  effort: LlmEffort;
  /** ASSISTANT_REFUSAL_FALLBACK (default `default`). */
  refusalFallback: RefusalFallback;
  /** Per model call timeout in milliseconds. */
  timeoutMs: number;
  baseURL?: string;
  /** Injected transport (tests never reach the network). */
  fetch?: FetchLike;
  /** Clock for `retry-after` dates (tests). */
  now?: () => number;
}

interface ContentBlockLike {
  type: string;
  text?: string;
  id?: string;
  name?: string;
  input?: unknown;
}

interface FinalMessageLike {
  model: string;
  stop_reason: string | null;
  stop_details?: { category?: string | null } | null;
  content: readonly ContentBlockLike[];
  usage?: {
    input_tokens?: number | null;
    output_tokens?: number | null;
    cache_read_input_tokens?: number | null;
    cache_creation_input_tokens?: number | null;
  } | null;
}

interface StreamLike {
  on(event: 'text', listener: (delta: string) => void): unknown;
  finalMessage(): Promise<FinalMessageLike>;
}

const STOPS: Readonly<Record<string, LlmStop>> = {
  end_turn: 'end_turn',
  stop_sequence: 'end_turn',
  tool_use: 'tool_use',
  max_tokens: 'max_tokens',
  model_context_window_exceeded: 'max_tokens',
  pause_turn: 'pause_turn',
};

export class AnthropicProvider implements LlmProvider {
  readonly id = 'anthropic' as const;
  readonly model: string;
  private readonly client: Anthropic;

  constructor(private readonly options: AnthropicProviderOptions) {
    if (!options.apiKey)
      throw new Error('ASSISTANT_ANTHROPIC_API_KEY is required for the anthropic provider');
    this.model = options.model;
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

  userEntry(text: string): unknown[] {
    return [{ role: 'user', content: [{ type: 'text', text }] }];
  }

  toolResultEntries(results: readonly LlmToolResult[]): unknown[] {
    if (results.length === 0) return [];
    return [
      {
        role: 'user',
        content: results.map((result) => ({
          type: 'tool_result',
          tool_use_id: result.toolCallId,
          content: result.content,
          ...(result.isError ? { is_error: true } : {}),
        })),
      },
    ];
  }

  /** The request body (exported for request-shape tests through `buildRequest`). */
  buildRequest(request: LlmRequest) {
    return {
      model: this.options.model,
      max_tokens: request.maxOutputTokens,
      system: [
        {
          type: 'text' as const,
          text: request.system,
          cache_control: { type: 'ephemeral' as const },
        },
      ],
      tools: request.tools.map((tool) => ({
        name: tool.name,
        description: tool.description,
        input_schema: { ...tool.inputSchema, type: 'object' as const },
        strict: true,
      })),
      tool_choice: { type: 'auto' as const },
      messages: request.transcript as Anthropic.Beta.Messages.BetaMessageParam[],
      output_config: { effort: this.options.effort },
    };
  }

  async complete(
    request: LlmRequest,
    signal: AbortSignal,
    onDelta: (text: string) => void,
  ): Promise<LlmResponse> {
    const body = this.buildRequest(request);
    const requestOptions = { signal, timeout: this.options.timeoutMs, maxRetries: 0 };
    let streamed = false;
    let final: FinalMessageLike;
    try {
      const stream: StreamLike =
        this.options.refusalFallback === 'default'
          ? this.client.beta.messages.stream(
              { ...body, betas: [SERVER_SIDE_FALLBACK_BETA], fallbacks: 'default' },
              requestOptions,
            )
          : this.client.messages.stream(
              { ...body, messages: body.messages as Anthropic.Messages.MessageParam[] },
              requestOptions,
            );
      stream.on('text', (delta: string) => {
        if (delta.length === 0) return;
        streamed = true;
        onDelta(delta);
      });
      final = await stream.finalMessage();
    } catch (error: unknown) {
      throw this.classify(error, streamed);
    }
    return this.toResponse(final);
  }

  private classify(error: unknown, afterDelta: boolean): LlmError {
    if (error instanceof LlmError) return error;
    if (error instanceof APIConnectionTimeoutError) return new LlmError('timeout', { afterDelta });
    if (error instanceof APIUserAbortError) return new LlmError('aborted', { afterDelta });
    if (error instanceof APIConnectionError) return new LlmError('connection', { afterDelta });
    if (error instanceof APIError) {
      const status = typeof error.status === 'number' ? error.status : null;
      if (status === null) return new LlmError('unexpected', { afterDelta });
      const headers = error.headers as Headers | undefined;
      return new LlmError(reasonOfStatus(status), {
        httpStatus: status,
        afterDelta,
        retryAfterMs: parseRetryAfter(
          headers?.get('retry-after'),
          (this.options.now ?? Date.now)(),
        ),
      });
    }
    return new LlmError('unexpected', { afterDelta });
  }

  private toResponse(final: FinalMessageLike): LlmResponse {
    // stop_reason first, before any content is used.
    if (final.stop_reason === 'refusal')
      throw new LlmError('refusal', { category: final.stop_details?.category ?? null });
    const stop = final.stop_reason ? STOPS[final.stop_reason] : undefined;
    if (!stop) throw new LlmError('unexpected');
    const usage = {
      inputTokens: final.usage?.input_tokens ?? 0,
      outputTokens: final.usage?.output_tokens ?? 0,
      cacheReadTokens: final.usage?.cache_read_input_tokens ?? 0,
      cacheWriteTokens: final.usage?.cache_creation_input_tokens ?? 0,
    };
    const text = final.content
      .filter((block) => block.type === 'text' && typeof block.text === 'string')
      .map((block) => block.text!)
      .join('');
    // A truncated (max_tokens) message may end in an incomplete tool_use block: no tool runs.
    const toolCalls: LlmToolCall[] =
      stop === 'tool_use'
        ? final.content
            .filter((block) => block.type === 'tool_use' && typeof block.id === 'string')
            .map((block) => ({ id: block.id!, name: String(block.name ?? ''), input: block.input }))
        : [];
    if (stop === 'tool_use' && toolCalls.length === 0) throw new LlmError('schema');
    return {
      stop,
      text,
      toolCalls,
      appendToTranscript: [{ role: 'assistant', content: final.content }],
      usage,
      responseModel: final.model,
    };
  }
}
