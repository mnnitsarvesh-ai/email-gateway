import { z } from 'zod';
import {
  LlmError,
  parseRetryAfter,
  reasonOfStatus,
  type FetchLike,
  type LlmProvider,
  type LlmProviderId,
  type LlmRequest,
  type LlmResponse,
  type LlmStop,
  type LlmToolCall,
  type LlmToolResult,
} from './types';

/**
 * OpenAI and Azure OpenAI Chat Completions over plain HTTPS (design D6, ADR-0092; no SDK, like
 * ADR-0082). Streaming (`stream: true`, `stream_options: { include_usage: true }`), the two meta
 * tools as strict functions, `tool_choice: 'auto'`, `max_completion_tokens`. The SSE body is read
 * with a bounded line parser (1 MiB per line, a configurable total) and every chunk is validated
 * with zod; tool-call argument fragments are concatenated by `index`.
 *
 * Transcript entries are OpenAI chat messages: `{ role: 'user', content }`, the assistant message
 * `{ role: 'assistant', content, tool_calls? }` and one `{ role: 'tool', tool_call_id, content }` per
 * tool result. The system prompt is sent as the first message of every request.
 *
 * Errors are classified by HTTP status and transport failure, never by the response text, which
 * is read (bounded) and discarded.
 */

export const SSE_MAX_LINE_BYTES = 1024 * 1024;
export const SSE_DEFAULT_MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const ERROR_BODY_MAX_BYTES = 64 * 1024;

const toolCallDelta = z.looseObject({
  index: z.number().int().min(0).max(127),
  id: z.string().max(256).optional().nullable(),
  type: z.string().optional().nullable(),
  function: z
    .looseObject({
      name: z.string().max(128).optional().nullable(),
      arguments: z.string().optional().nullable(),
    })
    .optional()
    .nullable(),
});

export const chatCompletionChunkSchema = z.looseObject({
  model: z.string().max(256).optional().nullable(),
  choices: z
    .array(
      z.looseObject({
        index: z.number().int().min(0).optional(),
        delta: z
          .looseObject({
            role: z.string().optional().nullable(),
            content: z.string().optional().nullable(),
            refusal: z.string().optional().nullable(),
            tool_calls: z.array(toolCallDelta).max(128).optional().nullable(),
          })
          .optional()
          .nullable(),
        finish_reason: z.string().optional().nullable(),
      }),
    )
    .max(8),
  usage: z
    .looseObject({
      prompt_tokens: z.number().int().min(0),
      completion_tokens: z.number().int().min(0),
      prompt_tokens_details: z
        .looseObject({ cached_tokens: z.number().int().min(0).optional().nullable() })
        .optional()
        .nullable(),
    })
    .optional()
    .nullable(),
});
export type ChatCompletionChunk = z.infer<typeof chatCompletionChunkSchema>;

const FINISH: Readonly<Record<string, LlmStop | 'refusal'>> = {
  stop: 'end_turn',
  tool_calls: 'tool_use',
  function_call: 'tool_use',
  length: 'max_tokens',
  content_filter: 'refusal',
};

/**
 * Bounded SSE reader: yields the `data:` payload of every event. Throws `LlmError('schema')` when
 * a line exceeds `SSE_MAX_LINE_BYTES` or the body exceeds `maxTotalBytes`.
 */
export async function* readSseData(
  body: ReadableStream<Uint8Array>,
  maxTotalBytes: number,
): AsyncGenerator<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder('utf-8');
  let buffer = '';
  let total = 0;
  let data: string[] = [];
  const flush = function* (): Generator<string> {
    if (data.length > 0) yield data.join('\n');
    data = [];
  };
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxTotalBytes) throw new LlmError('schema');
      buffer += decoder.decode(value, { stream: true });
      let newline = buffer.search(/\r\n|\r|\n/);
      while (newline >= 0) {
        const line = buffer.slice(0, newline);
        const sepLength = buffer.startsWith('\r\n', newline) ? 2 : 1;
        buffer = buffer.slice(newline + sepLength);
        if (Buffer.byteLength(line, 'utf8') > SSE_MAX_LINE_BYTES) throw new LlmError('schema');
        if (line === '') yield* flush();
        else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
        // comments (":"), event, id and retry fields carry nothing the client needs
        newline = buffer.search(/\r\n|\r|\n/);
      }
      if (Buffer.byteLength(buffer, 'utf8') > SSE_MAX_LINE_BYTES) throw new LlmError('schema');
    }
    buffer += decoder.decode();
    if (buffer.startsWith('data:')) data.push(buffer.slice(5).replace(/^ /, ''));
    yield* flush();
  } finally {
    reader.releaseLock();
  }
}

export interface OpenAiCompatibleOptions {
  apiKey: string;
  /** Model id (OpenAI) or deployment name (Azure; also reported as the model). */
  model: string;
  timeoutMs: number;
  fetch?: FetchLike;
  /** Max SSE body size per call (default 8 MiB). */
  maxStreamBytes?: number;
  now?: () => number;
}

interface PartialToolCall {
  id: string;
  name: string;
  arguments: string;
}

abstract class ChatCompletionsProvider implements LlmProvider {
  abstract readonly id: LlmProviderId;
  readonly model: string;

  protected constructor(protected readonly base: OpenAiCompatibleOptions) {
    this.model = base.model;
  }

  protected abstract url(): string;
  protected abstract authHeaders(): Record<string, string>;
  /** Whether the body names the model (OpenAI) or the deployment URL does (Azure). */
  protected abstract readonly sendsModel: boolean;

  userEntry(text: string): unknown[] {
    return [{ role: 'user', content: text }];
  }

  toolResultEntries(results: readonly LlmToolResult[]): unknown[] {
    return results.map((result) => ({
      role: 'tool',
      tool_call_id: result.toolCallId,
      content: result.content,
    }));
  }

  buildBody(request: LlmRequest): Record<string, unknown> {
    return {
      ...(this.sendsModel ? { model: this.base.model } : {}),
      messages: [{ role: 'system', content: request.system }, ...request.transcript],
      tools: request.tools.map((tool) => ({
        type: 'function',
        function: {
          name: tool.name,
          description: tool.description,
          parameters: tool.inputSchema,
          strict: true,
        },
      })),
      tool_choice: 'auto',
      stream: true,
      stream_options: { include_usage: true },
      max_completion_tokens: request.maxOutputTokens,
    };
  }

  async complete(
    request: LlmRequest,
    signal: AbortSignal,
    onDelta: (text: string) => void,
  ): Promise<LlmResponse> {
    const fetchImpl = this.base.fetch ?? fetch;
    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), this.base.timeoutMs);
    const combined = AbortSignal.any([signal, timeout.signal]);
    let streamed = false;
    const abortReason = (): LlmError =>
      new LlmError(signal.aborted ? 'aborted' : 'timeout', { afterDelta: streamed });
    try {
      let response: Response;
      try {
        response = await fetchImpl(this.url(), {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            accept: 'text/event-stream',
            ...this.authHeaders(),
          },
          body: JSON.stringify(this.buildBody(request)),
          signal: combined,
        });
      } catch {
        if (combined.aborted) throw abortReason();
        throw new LlmError('connection');
      }
      if (!response.ok) {
        await discardBody(response);
        throw new LlmError(reasonOfStatus(response.status), {
          httpStatus: response.status,
          retryAfterMs: parseRetryAfter(
            response.headers.get('retry-after'),
            (this.base.now ?? Date.now)(),
          ),
        });
      }
      if (!response.body) throw new LlmError('schema');

      let text = '';
      let finish: string | null = null;
      let responseModel: string | null = null;
      let usage = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };
      const calls = new Map<number, PartialToolCall>();
      try {
        for await (const data of readSseData(
          response.body,
          this.base.maxStreamBytes ?? SSE_DEFAULT_MAX_TOTAL_BYTES,
        )) {
          if (data.trim() === '[DONE]') break;
          let json: unknown;
          try {
            json = JSON.parse(data);
          } catch {
            throw new LlmError('schema', { afterDelta: streamed });
          }
          const parsed = chatCompletionChunkSchema.safeParse(json);
          if (!parsed.success) throw new LlmError('schema', { afterDelta: streamed });
          const chunk = parsed.data;
          if (!responseModel && chunk.model) responseModel = chunk.model;
          if (chunk.usage) {
            const cached = chunk.usage.prompt_tokens_details?.cached_tokens ?? 0;
            usage = {
              inputTokens: Math.max(0, chunk.usage.prompt_tokens - cached),
              outputTokens: chunk.usage.completion_tokens,
              cacheReadTokens: cached,
              cacheWriteTokens: 0,
            };
          }
          const choice = chunk.choices.find((c) => (c.index ?? 0) === 0);
          if (!choice) continue;
          const delta = choice.delta;
          if (delta?.content) {
            text += delta.content;
            streamed = true;
            onDelta(delta.content);
          }
          for (const call of delta?.tool_calls ?? []) {
            const current = calls.get(call.index) ?? { id: '', name: '', arguments: '' };
            if (call.id) current.id = call.id;
            if (call.function?.name) current.name += call.function.name;
            if (call.function?.arguments) current.arguments += call.function.arguments;
            if (current.arguments.length > SSE_MAX_LINE_BYTES)
              throw new LlmError('schema', { afterDelta: streamed });
            calls.set(call.index, current);
          }
          if (choice.finish_reason) finish = choice.finish_reason;
        }
      } catch (error: unknown) {
        if (error instanceof LlmError) throw error;
        if (combined.aborted) throw abortReason();
        throw new LlmError('connection', { afterDelta: streamed });
      }

      const mapped = finish ? FINISH[finish] : undefined;
      if (!mapped) throw new LlmError('schema', { afterDelta: streamed });
      if (mapped === 'refusal')
        throw new LlmError('refusal', { category: finish, afterDelta: streamed });
      const ordered = [...calls.entries()].sort((a, b) => a[0] - b[0]).map(([, call]) => call);
      if (mapped === 'tool_use' && (ordered.length === 0 || ordered.some((c) => !c.id)))
        throw new LlmError('schema', { afterDelta: streamed });
      const toolCalls: LlmToolCall[] =
        mapped === 'tool_use'
          ? ordered.map((call) => ({ id: call.id, name: call.name, input: parseArguments(call) }))
          : [];
      const assistant: Record<string, unknown> = {
        role: 'assistant',
        content: text.length > 0 ? text : null,
      };
      if (toolCalls.length > 0)
        assistant.tool_calls = ordered.map((call) => ({
          id: call.id,
          type: 'function',
          function: { name: call.name, arguments: call.arguments },
        }));
      return {
        stop: mapped,
        text,
        toolCalls,
        appendToTranscript: [assistant],
        usage,
        responseModel: responseModel ?? this.base.model,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

/** The function arguments string parsed as JSON; the raw string when it is not JSON (rejected later). */
function parseArguments(call: PartialToolCall): unknown {
  try {
    return JSON.parse(call.arguments === '' ? '{}' : call.arguments);
  } catch {
    return call.arguments;
  }
}

async function discardBody(response: Response): Promise<void> {
  if (!response.body) return;
  const reader: ReadableStreamDefaultReader<Uint8Array> = response.body.getReader();
  let read = 0;
  try {
    while (read < ERROR_BODY_MAX_BYTES) {
      const { value, done } = await reader.read();
      if (done) break;
      read += value.byteLength;
    }
    await reader.cancel();
  } catch {
    // the body is never used
  }
}

function requireKey<T extends OpenAiCompatibleOptions>(options: T, message: string): T {
  if (!options.apiKey) throw new Error(message);
  return options;
}

function azureDeployment(options: AzureOpenAiProviderOptions): string {
  if (!options.deployment || !options.apiVersion || !options.endpoint)
    throw new Error('Azure OpenAI needs an endpoint, a deployment and an API version');
  return options.deployment;
}

export interface OpenAiProviderOptions extends OpenAiCompatibleOptions {
  /** ASSISTANT_OPENAI_BASE_URL (default https://api.openai.com/v1). */
  baseURL: string;
}

export class OpenAiProvider extends ChatCompletionsProvider {
  readonly id = 'openai' as const;
  protected readonly sendsModel = true;

  constructor(private readonly options: OpenAiProviderOptions) {
    super(requireKey(options, 'ASSISTANT_OPENAI_API_KEY is required for the openai provider'));
  }

  protected url(): string {
    return `${this.options.baseURL.replace(/\/+$/, '')}/chat/completions`;
  }

  protected authHeaders(): Record<string, string> {
    return { authorization: `Bearer ${this.options.apiKey}` };
  }
}

export interface AzureOpenAiProviderOptions extends Omit<OpenAiCompatibleOptions, 'model'> {
  /** ASSISTANT_AZURE_OPENAI_ENDPOINT, e.g. https://<resource>.openai.azure.com */
  endpoint: string;
  /** ASSISTANT_AZURE_OPENAI_DEPLOYMENT. */
  deployment: string;
  /** ASSISTANT_AZURE_OPENAI_API_VERSION. */
  apiVersion: string;
}

export class AzureOpenAiProvider extends ChatCompletionsProvider {
  readonly id = 'azure_openai' as const;
  protected readonly sendsModel = false;

  constructor(private readonly options: AzureOpenAiProviderOptions) {
    super(
      requireKey(
        { ...options, model: azureDeployment(options) },
        'ASSISTANT_AZURE_OPENAI_API_KEY is required for the azure_openai provider',
      ),
    );
  }

  protected url(): string {
    const endpoint = this.options.endpoint.replace(/\/+$/, '');
    return `${endpoint}/openai/deployments/${encodeURIComponent(this.options.deployment)}/chat/completions?api-version=${encodeURIComponent(this.options.apiVersion)}`;
  }

  protected authHeaders(): Record<string, string> {
    return { 'api-key': this.options.apiKey };
  }
}
