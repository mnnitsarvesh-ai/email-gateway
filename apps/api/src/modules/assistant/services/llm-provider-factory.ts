import {
  createProviderFromSpec,
  type LlmProvider,
  type LlmProviderId,
  type ProviderCommonOptions,
  type ProviderRole,
  type ProviderSpec,
} from '@email-gateway/assistant';
import type { AssistantConfig } from '../assistant.constants';

/**
 * What `LLM_PROVIDER_FACTORY` receives (step AI-6 D6, D7): the candidate's `ProviderSpec` (role,
 * provider, model, credentials, the platform endpoints). `ASSISTANT_PROVIDER` and `NODE_ENV` mirror
 * the platform configuration for factories written before AI-6 (transitional; a factory typed
 * `(spec: ProviderSpec) => LlmProvider` is assignable).
 */
export type ProviderFactorySpec = ProviderSpec &
  Readonly<Pick<AssistantConfig, 'ASSISTANT_PROVIDER' | 'NODE_ENV'>>;

/**
 * The test seam of the provider layer: builds the `LlmProvider` of one candidate. Production uses
 * `defaultLlmProviderFactory(config)` (the package's `createProviderFromSpec` with the platform
 * effort, refusal fallback, timeout and environment); tests inject a factory that returns a fake
 * or an Anthropic/OpenAI provider over an injected local `fetch`.
 */
export type LlmProviderFactory = (spec: ProviderFactorySpec) => LlmProvider;
export const LLM_PROVIDER_FACTORY = Symbol('LLM_PROVIDER_FACTORY');

/** The options shared by every candidate, from the zod config. */
export function commonProviderOptions(config: AssistantConfig): ProviderCommonOptions {
  return {
    effort: config.ASSISTANT_EFFORT,
    refusalFallback: config.ASSISTANT_REFUSAL_FALLBACK,
    timeoutMs: config.ASSISTANT_TIMEOUT_MS,
    nodeEnv: config.NODE_ENV,
  };
}

/** The production factory: `createProviderFromSpec` over the platform's common options. */
export const defaultLlmProviderFactory =
  (config: AssistantConfig): LlmProviderFactory =>
  (spec) =>
    createProviderFromSpec(spec, commonProviderOptions(config));

/**
 * The spec of a platform candidate (`primary` = ASSISTANT_PROVIDER/ASSISTANT_MODEL, `fallback` =
 * ASSISTANT_FALLBACK_PROVIDER/ASSISTANT_FALLBACK_MODEL) with the platform's credentials and
 * endpoints of that provider; null for `fallback` when ASSISTANT_FALLBACK_PROVIDER is `none`.
 */
export function platformSpec(
  config: AssistantConfig,
  role: Exclude<ProviderRole, 'tenant'>,
): ProviderFactorySpec | null {
  const provider: LlmProviderId | 'none' =
    role === 'primary' ? config.ASSISTANT_PROVIDER : config.ASSISTANT_FALLBACK_PROVIDER;
  if (provider === 'none') return null;
  const requested =
    role === 'primary' ? config.ASSISTANT_MODEL : (config.ASSISTANT_FALLBACK_MODEL ?? '');
  const base = {
    role,
    provider,
    ASSISTANT_PROVIDER: config.ASSISTANT_PROVIDER,
    NODE_ENV: config.NODE_ENV,
  } as const;
  switch (provider) {
    case 'fake':
      // The fake's label stays `fake` unless a fallback names a distinct model (two fakes).
      return { ...base, model: role === 'fallback' && requested ? requested : 'fake' };
    case 'anthropic':
      return {
        ...base,
        model: requested,
        ...(config.ASSISTANT_ANTHROPIC_API_KEY !== undefined && {
          apiKey: config.ASSISTANT_ANTHROPIC_API_KEY,
        }),
        ...(config.ASSISTANT_ANTHROPIC_BASE_URL !== undefined && {
          baseURL: config.ASSISTANT_ANTHROPIC_BASE_URL,
        }),
      };
    case 'openai':
      return {
        ...base,
        model: requested,
        ...(config.ASSISTANT_OPENAI_API_KEY !== undefined && {
          apiKey: config.ASSISTANT_OPENAI_API_KEY,
        }),
        ...(config.ASSISTANT_OPENAI_BASE_URL !== undefined && {
          baseURL: config.ASSISTANT_OPENAI_BASE_URL,
        }),
      };
    case 'azure_openai': {
      const deployment = config.ASSISTANT_AZURE_OPENAI_DEPLOYMENT ?? requested;
      return {
        ...base,
        // The deployment is the model label of an Azure candidate (as AI-1).
        model: role === 'fallback' && requested ? requested : deployment,
        ...(config.ASSISTANT_AZURE_OPENAI_API_KEY !== undefined && {
          apiKey: config.ASSISTANT_AZURE_OPENAI_API_KEY,
        }),
        ...(config.ASSISTANT_AZURE_OPENAI_ENDPOINT !== undefined && {
          azureEndpoint: config.ASSISTANT_AZURE_OPENAI_ENDPOINT,
        }),
        azureDeployment: role === 'fallback' && requested ? requested : deployment,
        ...(config.ASSISTANT_AZURE_OPENAI_API_VERSION !== undefined && {
          azureApiVersion: config.ASSISTANT_AZURE_OPENAI_API_VERSION,
        }),
      };
    }
  }
}

/** The spec of a tenant candidate: the platform endpoint of its provider, never a tenant URL. */
export function tenantSpec(
  config: AssistantConfig,
  key: { provider: 'anthropic' | 'openai'; model: string; apiKey: string },
  organizationPublicId: string,
): ProviderFactorySpec {
  const baseURL =
    key.provider === 'anthropic'
      ? config.ASSISTANT_ANTHROPIC_BASE_URL
      : config.ASSISTANT_OPENAI_BASE_URL;
  return {
    role: 'tenant',
    provider: key.provider,
    model: key.model,
    apiKey: key.apiKey,
    organizationPublicId,
    ASSISTANT_PROVIDER: config.ASSISTANT_PROVIDER,
    NODE_ENV: config.NODE_ENV,
    ...(baseURL !== undefined && { baseURL }),
  };
}
