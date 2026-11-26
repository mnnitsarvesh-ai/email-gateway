import type { RefusalFallback } from './anthropic';
import { countsTowardBreaker } from './breaker';
import { createLlmProvider, type ProviderFactoryOptions } from './factory';
import {
  LlmError,
  type FetchLike,
  type LlmEffort,
  type LlmErrorReason,
  type LlmProvider,
  type LlmProviderId,
} from './types';

/**
 * Provider routing helpers of step AI-6 (design D6/D7, ADR-0097). The api's `ProviderRouterService`
 * orders the candidates of a turn (tenant key → platform primary → platform secondary) and keeps
 * one Redis breaker per candidate; these pure helpers give the breaker key of a candidate, decide
 * whether a failure allows the same-turn switch, and build a provider from a candidate spec.
 * Nothing here reads the environment.
 */

export const PROVIDER_ROLES = ['primary', 'fallback', 'tenant'] as const;
export type ProviderRole = (typeof PROVIDER_ROLES)[number];

/** Providers a tenant may bring a key for (design D7: Azure needs a tenant endpoint; refused). */
export const TENANT_KEY_PROVIDERS: readonly LlmProviderId[] = ['anthropic', 'openai'];

const KEY_PART = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * The breaker key of a candidate, without the `ProviderBreaker` prefix (`as:brk:`): the provider
 * id for the primary (unchanged from AI-1), `<provider>:fb` for the secondary (both may be the
 * same provider family with different models) and `t:<organizationPublicId>` for a tenant key
 * (a tenant's bad key never opens a platform breaker).
 */
export function breakerKeyFor(
  role: ProviderRole,
  providerId: string,
  organizationPublicId?: string,
): string {
  if (!KEY_PART.test(providerId)) throw new Error('breaker key: invalid provider id');
  switch (role) {
    case 'primary':
      return providerId;
    case 'fallback':
      return `${providerId}:fb`;
    case 'tenant':
      if (!organizationPublicId || !KEY_PART.test(organizationPublicId))
        throw new Error('breaker key: a tenant candidate needs the organization public id');
      return `t:${organizationPublicId}`;
    default: {
      const never: never = role;
      throw new Error(`breaker key: unknown role ${String(never)}`);
    }
  }
}

/**
 * Whether a failed model call allows the same-turn switch to the next healthy candidate (D6): a
 * breaker-qualifying `LlmError` (`connection`, `timeout`, `rate_limited`, `server_error`) raised
 * before any text delta was streamed. The caller also checks that no tool ran in the turn and that
 * it has not switched yet. `auth` (a rejected tenant key) is handled separately by the router.
 */
export function isSwitchableFailure(error: unknown): boolean {
  return countsTowardBreaker(error) && error instanceof LlmError && !error.afterDelta;
}

/** One candidate of a turn: which provider, which model and which credentials. */
export interface ProviderSpec {
  role: ProviderRole;
  provider: LlmProviderId;
  /** Model id (Anthropic/OpenAI) or the fake's label; Azure uses `azureDeployment`. */
  model: string;
  /** The platform key of the provider, or the decrypted tenant key (lives only in the client). */
  apiKey?: string;
  /** Anthropic / OpenAI base URL (always the platform's configured endpoint). */
  baseURL?: string;
  azureEndpoint?: string;
  azureDeployment?: string;
  azureApiVersion?: string;
  /** Tenant candidates: the organization whose key it is. */
  organizationPublicId?: string;
}

/** Options shared by every candidate (the api maps its zod config onto them). */
export interface ProviderCommonOptions {
  effort: LlmEffort;
  refusalFallback: RefusalFallback;
  timeoutMs: number;
  nodeEnv: string | undefined;
  fetch?: FetchLike;
  now?: () => Date;
  fakeObedient?: boolean;
  fakeLatencyMs?: number;
  fakeFailure?: LlmErrorReason | null;
}

/** Builds the provider of a candidate through `createLlmProvider` (no environment reads). */
export function createProviderFromSpec(
  spec: ProviderSpec,
  common: ProviderCommonOptions,
): LlmProvider {
  if (spec.role === 'tenant') {
    if (!TENANT_KEY_PROVIDERS.includes(spec.provider))
      throw new Error(`a tenant key is not offered for the ${spec.provider} provider`);
    if (!spec.organizationPublicId)
      throw new Error('a tenant candidate needs the organization public id');
  }
  const options: ProviderFactoryOptions = {
    provider: spec.provider,
    model: spec.model,
    effort: common.effort,
    refusalFallback: common.refusalFallback,
    timeoutMs: common.timeoutMs,
    nodeEnv: common.nodeEnv,
    ...(common.fetch ? { fetch: common.fetch } : {}),
    ...(common.now ? { now: common.now } : {}),
  };
  switch (spec.provider) {
    case 'anthropic':
      return createLlmProvider({
        ...options,
        ...(spec.apiKey !== undefined ? { anthropicApiKey: spec.apiKey } : {}),
        ...(spec.baseURL ? { anthropicBaseUrl: spec.baseURL } : {}),
      });
    case 'openai':
      return createLlmProvider({
        ...options,
        ...(spec.apiKey !== undefined ? { openaiApiKey: spec.apiKey } : {}),
        ...(spec.baseURL ? { openaiBaseUrl: spec.baseURL } : {}),
      });
    case 'azure_openai':
      return createLlmProvider({
        ...options,
        ...(spec.apiKey !== undefined ? { azureApiKey: spec.apiKey } : {}),
        ...(spec.azureEndpoint !== undefined ? { azureEndpoint: spec.azureEndpoint } : {}),
        ...(spec.azureDeployment !== undefined ? { azureDeployment: spec.azureDeployment } : {}),
        ...(spec.azureApiVersion !== undefined ? { azureApiVersion: spec.azureApiVersion } : {}),
      });
    case 'fake':
      return createLlmProvider({
        ...options,
        ...(common.fakeObedient !== undefined ? { fakeObedient: common.fakeObedient } : {}),
        ...(common.fakeLatencyMs !== undefined ? { fakeLatencyMs: common.fakeLatencyMs } : {}),
        ...(common.fakeFailure !== undefined ? { fakeFailure: common.fakeFailure } : {}),
      });
    default: {
      const never: never = spec.provider;
      throw new Error(`unknown assistant provider ${String(never)}`);
    }
  }
}
