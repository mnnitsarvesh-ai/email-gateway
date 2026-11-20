import { AnthropicProvider, type RefusalFallback } from './anthropic';
import { FakeProvider } from './fake';
import { AzureOpenAiProvider, OpenAiProvider } from './openai-compatible';
import type { FetchLike, LlmEffort, LlmProvider, LlmProviderId } from './types';

/**
 * Builds the configured provider from a plain options object (the api maps its zod config onto
 * it). Keys and URLs are passed in; nothing is read from the environment here.
 */

export const DEFAULT_OPENAI_BASE_URL = 'https://api.openai.com/v1';

export interface ProviderFactoryOptions {
  provider: LlmProviderId;
  /** Model id (Anthropic/OpenAI) or the fake's label; Azure uses `azureDeployment`. */
  model: string;
  effort: LlmEffort;
  refusalFallback: RefusalFallback;
  timeoutMs: number;
  nodeEnv: string | undefined;
  anthropicApiKey?: string;
  anthropicBaseUrl?: string;
  openaiApiKey?: string;
  openaiBaseUrl?: string;
  azureApiKey?: string;
  azureEndpoint?: string;
  azureDeployment?: string;
  azureApiVersion?: string;
  fetch?: FetchLike;
  /** Fake only (tests): follow instruction-shaped text in tool results. */
  fakeObedient?: boolean;
  now?: () => Date;
}

export function createLlmProvider(options: ProviderFactoryOptions): LlmProvider {
  switch (options.provider) {
    case 'anthropic':
      return new AnthropicProvider({
        apiKey: options.anthropicApiKey ?? '',
        model: options.model,
        effort: options.effort,
        refusalFallback: options.refusalFallback,
        timeoutMs: options.timeoutMs,
        ...(options.anthropicBaseUrl ? { baseURL: options.anthropicBaseUrl } : {}),
        ...(options.fetch ? { fetch: options.fetch } : {}),
      });
    case 'openai':
      return new OpenAiProvider({
        apiKey: options.openaiApiKey ?? '',
        model: options.model,
        baseURL: options.openaiBaseUrl || DEFAULT_OPENAI_BASE_URL,
        timeoutMs: options.timeoutMs,
        ...(options.fetch ? { fetch: options.fetch } : {}),
      });
    case 'azure_openai':
      return new AzureOpenAiProvider({
        apiKey: options.azureApiKey ?? '',
        endpoint: options.azureEndpoint ?? '',
        deployment: options.azureDeployment ?? '',
        apiVersion: options.azureApiVersion ?? '',
        timeoutMs: options.timeoutMs,
        ...(options.fetch ? { fetch: options.fetch } : {}),
      });
    case 'fake':
      return new FakeProvider({
        nodeEnv: options.nodeEnv,
        model: options.model || 'fake',
        obedient: options.fakeObedient ?? false,
        ...(options.now ? { now: options.now } : {}),
      });
    default: {
      const never: never = options.provider;
      throw new Error(`unknown assistant provider ${String(never)}`);
    }
  }
}
