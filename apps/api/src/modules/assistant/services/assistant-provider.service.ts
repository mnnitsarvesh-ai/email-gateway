import { Inject, Injectable } from '@nestjs/common';
import {
  completeWithRetry,
  countsTowardBreaker,
  createLlmProvider,
  LlmError,
  type LlmProvider,
  type LlmRequest,
  type LlmResponse,
  type ModelPrice,
  ProviderBreaker,
} from '@email-gateway/assistant';
import { API_CONFIG } from '../../../api-config.token';
import { KeyValueStore } from '../../../kv/key-value-store';
import { type AssistantConfig, BREAKER_KEY_PREFIX } from '../assistant.constants';
import { AssistantMetrics } from './assistant-metrics';

/** Builds the configured LLM provider (tests inject a factory returning a `FakeProvider`). */
export type LlmProviderFactory = (config: AssistantConfig) => LlmProvider;
export const LLM_PROVIDER_FACTORY = Symbol('LLM_PROVIDER_FACTORY');

/** The production factory: the package's `createLlmProvider` mapped from the zod config. */
export const defaultLlmProviderFactory: LlmProviderFactory = (config) =>
  createLlmProvider({
    provider: config.ASSISTANT_PROVIDER,
    model:
      config.ASSISTANT_PROVIDER === 'fake'
        ? 'fake'
        : config.ASSISTANT_PROVIDER === 'azure_openai'
          ? (config.ASSISTANT_AZURE_OPENAI_DEPLOYMENT ?? config.ASSISTANT_MODEL)
          : config.ASSISTANT_MODEL,
    effort: config.ASSISTANT_EFFORT,
    refusalFallback: config.ASSISTANT_REFUSAL_FALLBACK,
    timeoutMs: config.ASSISTANT_TIMEOUT_MS,
    nodeEnv: config.NODE_ENV,
    anthropicApiKey: config.ASSISTANT_ANTHROPIC_API_KEY,
    anthropicBaseUrl: config.ASSISTANT_ANTHROPIC_BASE_URL,
    openaiApiKey: config.ASSISTANT_OPENAI_API_KEY,
    openaiBaseUrl: config.ASSISTANT_OPENAI_BASE_URL,
    azureApiKey: config.ASSISTANT_AZURE_OPENAI_API_KEY,
    azureEndpoint: config.ASSISTANT_AZURE_OPENAI_ENDPOINT,
    azureDeployment: config.ASSISTANT_AZURE_OPENAI_DEPLOYMENT,
    azureApiVersion: config.ASSISTANT_AZURE_OPENAI_API_VERSION,
  });

/**
 * The provider of the assistant (design D6, ADR-0092): built lazily from the config (never when
 * the assistant is off), one retry policy (`completeWithRetry`), a Redis-backed breaker shared
 * by every api pod (`as:brk:<provider>`), token and error metrics. Errors carry reason codes
 * only, never provider text.
 */
@Injectable()
export class AssistantProviderService {
  private built: LlmProvider | null = null;
  private readonly breaker: ProviderBreaker;
  readonly prices: Readonly<Record<string, ModelPrice>>;

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    @Inject(LLM_PROVIDER_FACTORY) private readonly factory: LlmProviderFactory,
    kv: KeyValueStore,
    private readonly metrics: AssistantMetrics,
  ) {
    this.breaker = new ProviderBreaker(kv, {
      threshold: config.ASSISTANT_BREAKER_THRESHOLD,
      resetMs: config.ASSISTANT_BREAKER_RESET_MS,
      keyPrefix: BREAKER_KEY_PREFIX,
    });
    this.prices = Object.fromEntries(
      Object.entries(config.ASSISTANT_MODEL_PRICES ?? {}).map(([model, p]) => [
        model,
        {
          inputMicrosPerMTok: p.inputPerMTokMicros,
          outputMicrosPerMTok: p.outputPerMTokMicros,
          cacheReadMicrosPerMTok: p.cacheReadPerMTokMicros ?? p.inputPerMTokMicros,
          cacheWriteMicrosPerMTok:
            p.cacheWritePerMTokMicros ?? Math.round(p.inputPerMTokMicros * 1.25),
        },
      ]),
    );
  }

  /** The configured provider id (status, turns, usage rows). */
  get providerId(): string {
    return this.config.ASSISTANT_PROVIDER;
  }

  /** The configured model label (`fake` for the fake, the deployment for Azure). */
  get model(): string {
    if (this.config.ASSISTANT_PROVIDER === 'fake') return 'fake';
    if (this.config.ASSISTANT_PROVIDER === 'azure_openai') {
      return this.config.ASSISTANT_AZURE_OPENAI_DEPLOYMENT ?? this.config.ASSISTANT_MODEL;
    }
    return this.config.ASSISTANT_MODEL;
  }

  provider(): LlmProvider {
    this.built ??= this.factory(this.config);
    return this.built;
  }

  /** Breaker state (`503 assistant_provider_unavailable` at turn start when open). */
  isOpen(): Promise<boolean> {
    return this.breaker.isOpen(this.providerId);
  }

  async complete(
    request: LlmRequest,
    signal: AbortSignal,
    onDelta: (text: string) => void,
  ): Promise<LlmResponse> {
    const provider = this.provider();
    try {
      const response = await completeWithRetry(provider, request, signal, onDelta);
      await this.breaker.recordSuccess(this.providerId).catch(() => undefined);
      const labels = { provider: this.providerId, model: provider.model };
      this.metrics.llmTokens.inc({ ...labels, kind: 'input' }, response.usage.inputTokens);
      this.metrics.llmTokens.inc({ ...labels, kind: 'output' }, response.usage.outputTokens);
      this.metrics.llmTokens.inc({ ...labels, kind: 'cache_read' }, response.usage.cacheReadTokens);
      this.metrics.llmTokens.inc(
        { ...labels, kind: 'cache_write' },
        response.usage.cacheWriteTokens,
      );
      return response;
    } catch (error: unknown) {
      const reason = error instanceof LlmError ? error.reason : 'unexpected';
      this.metrics.llmErrors.inc({ provider: this.providerId, reason });
      if (countsTowardBreaker(error) && !signal.aborted) {
        await this.breaker.recordFailure(this.providerId).catch(() => undefined);
      }
      throw error;
    }
  }
}
