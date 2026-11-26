import { performance } from 'node:perf_hooks';
import { Inject, Injectable, Optional } from '@nestjs/common';
import {
  breakerKeyFor,
  completeWithRetry,
  countsTowardBreaker,
  isSwitchableFailure,
  LlmError,
  type LlmProvider,
  type LlmRequest,
  type LlmResponse,
  type ModelPrice,
  ProviderBreaker,
  type ProviderRole,
} from '@email-gateway/assistant';
import { API_CONFIG } from '../../../api-config.token';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { KeyValueStore } from '../../../kv/key-value-store';
import { type AssistantConfig, BREAKER_KEY_PREFIX } from '../assistant.constants';
import type { SettingsRow } from '../repositories/assistant-settings.repository';
import { AssistantMetrics } from './assistant-metrics';
import {
  LLM_PROVIDER_FACTORY,
  type LlmProviderFactory,
  platformSpec,
  type ProviderFactorySpec,
} from './llm-provider-factory';
import { TenantKeyService } from './tenant-key.service';

export {
  defaultLlmProviderFactory,
  LLM_PROVIDER_FACTORY,
  type LlmProviderFactory,
  type ProviderFactorySpec,
} from './llm-provider-factory';

/** Whose key pays for a turn (`ai_chat_turns.key_source`, D6/D7). */
export type KeySource = 'platform' | 'tenant';

/** One candidate of a turn (D6): which provider, model, breaker and credentials. */
export interface RouteCandidate {
  role: ProviderRole;
  providerId: string;
  model: string;
  /** Breaker key without the `as:brk:` prefix (`breakerKeyFor`). */
  breakerKey: string;
  keySource: KeySource;
  /** The built provider (platform: cached per role; tenant: cached per key version). */
  provider: LlmProvider;
  /** Tenant candidates: the key version the client was built from. */
  keyVersion?: number;
}

/** The candidates of a turn and the one in use (D6). */
export interface TurnRoute {
  /** Every eligible candidate in order (tenant → primary → fallback). */
  candidates: readonly RouteCandidate[];
  current: RouteCandidate;
  /** Provider id of the skipped or failed first candidate (`ai_chat_turns.fallback_from`). */
  fallbackFrom: string | null;
  /** The same-turn switch happened (at most one per turn). */
  switched: boolean;
}

/** The selection at turn start. */
export type RouteSelection =
  | { kind: 'route'; route: TurnRoute }
  /** Every candidate's breaker is open (`503 assistant_provider_unavailable`). */
  | { kind: 'unavailable' }
  /** `useTenantKey` without a valid key and no platform fallback (`503 assistant_tenant_key_invalid`). */
  | { kind: 'tenant_key_invalid' };

/** What a failed model call leads to (D6). */
export type FailureDecision =
  { kind: 'switch'; route: TurnRoute } | { kind: 'tenant_key_invalid' } | { kind: 'fail' };

/**
 * The provider router of the assistant (step AI-6 D6, D7; ADR-0097; replaces the single provider
 * of AI-1, D6/ADR-0092, and keeps its name `AssistantProviderService`).
 *
 * - **Candidates per turn** (`select`, at turn start): the organization's own key when the
 *   platform offers tenant keys, the settings say `useTenantKey` and the key is `valid`; then the
 *   platform primary (ASSISTANT_PROVIDER/ASSISTANT_MODEL) and the platform secondary
 *   (ASSISTANT_FALLBACK_PROVIDER/ASSISTANT_FALLBACK_MODEL unless `none`) — after a tenant key
 *   only when `tenantKeyFallbackToPlatform`. The first candidate whose Redis breaker is closed is
 *   used; none → `unavailable` (`503 assistant_provider_unavailable`); `useTenantKey` without a
 *   usable key and without the platform fallback → `tenant_key_invalid`.
 * - **Breakers**: one per candidate (`breakerKeyFor`: `as:brk:<provider>` for the primary as in
 *   AI-1, `as:brk:<provider>:fb` for the secondary, `as:brk:t:<organizationPublicId>` for a tenant
 *   key), passive half-open (the window expires).
 * - **Same-turn switch** (`onFailure`): the caller allows it only for the first model call of a
 *   turn before any text delta and before any tool ran; a breaker-qualifying failure
 *   (`isSwitchableFailure`) moves to the next closed candidate (at most once). A tenant key
 *   answered `auth` (401/403) is marked `invalid` and audited; the turn continues on the platform
 *   only when the tenant allowed it, else `tenant_key_invalid`.
 * - **Metrics**: `assistant_llm_requests_total{provider,role,outcome}`,
 *   `assistant_llm_seconds{provider,role}`, `assistant_provider_switches_total{from,to,reason}`
 *   (roles), `assistant_provider_fallback_active`, `assistant_provider_breaker_open{provider,role}`
 *   (platform candidates; refreshed at turn start and status), plus the AI-1 token and error
 *   series. Labels never carry an organization or user.
 *
 * **Test seam** `LLM_PROVIDER_FACTORY`: `(spec: ProviderFactorySpec) => LlmProvider`, called once
 * per platform role (cached) and once per tenant key version (`TenantKeyService` cache);
 * `ProviderFactorySpec` = the package's `ProviderSpec` (role, provider, model, credentials,
 * platform endpoints) plus `ASSISTANT_PROVIDER`/`NODE_ENV` of the platform config. Production uses
 * `defaultLlmProviderFactory(config)` (`createProviderFromSpec`). Errors carry reason codes
 * only, never provider text or a key.
 */
@Injectable()
export class ProviderRouterService {
  private readonly platform = new Map<'primary' | 'fallback', LlmProvider>();
  private readonly breaker: ProviderBreaker;
  readonly prices: Readonly<Record<string, ModelPrice>>;

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    @Inject(LLM_PROVIDER_FACTORY) private readonly factory: LlmProviderFactory,
    private readonly kv: KeyValueStore,
    private readonly metrics: AssistantMetrics,
    @Optional() private readonly tenantKeys?: TenantKeyService,
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

  /** The platform primary's provider id (status, AI-1 callers). */
  get providerId(): string {
    return this.config.ASSISTANT_PROVIDER;
  }

  /** The platform primary's model label (`fake` for the fake, the deployment for Azure). */
  get model(): string {
    return this.spec('primary')!.model;
  }

  /** The platform primary's provider (built once). */
  provider(): LlmProvider {
    return this.platformProvider('primary');
  }

  /** The platform primary's breaker (AI-1). */
  isOpen(): Promise<boolean> {
    return this.breaker.isOpen(breakerKeyFor('primary', this.providerId));
  }

  /** The platform candidates in order (primary, then the secondary when configured). */
  platformCandidates(): RouteCandidate[] {
    const out: RouteCandidate[] = [];
    for (const role of ['primary', 'fallback'] as const) {
      const spec = this.spec(role);
      if (!spec) continue;
      out.push({
        role,
        providerId: spec.provider,
        model: spec.model,
        breakerKey: breakerKeyFor(role, spec.provider),
        keySource: 'platform',
        provider: this.platformProvider(role),
      });
    }
    return out;
  }

  /**
   * D6 turn-start selection (also the status view's `keySource`/`fallbackActive`). `who` gives the
   * organization public id of the tenant breaker; without it no tenant candidate is considered.
   */
  async select(
    scope: TenantScope,
    settings: Pick<SettingsRow, 'useTenantKey' | 'tenantKeyFallbackToPlatform'> | null,
    who: { organizationPublicId: string } | null,
  ): Promise<RouteSelection> {
    const tenantMode =
      who !== null &&
      this.tenantKeys !== undefined &&
      this.tenantKeys.enabled &&
      settings?.useTenantKey === true;
    const candidates: RouteCandidate[] = [];
    if (tenantMode) {
      const client = await this.tenantKeys.client(scope.organizationId, who.organizationPublicId);
      if (client) {
        candidates.push({
          role: 'tenant',
          providerId: client.providerId,
          model: client.model,
          breakerKey: breakerKeyFor('tenant', client.providerId, who.organizationPublicId),
          keySource: 'tenant',
          provider: client.provider,
          keyVersion: client.keyVersion,
        });
      }
    }
    if (!tenantMode || settings?.tenantKeyFallbackToPlatform === true) {
      candidates.push(...this.platformCandidates());
    }
    if (candidates.length === 0) return { kind: 'tenant_key_invalid' };
    const open = await Promise.all(candidates.map((c) => this.breaker.isOpen(c.breakerKey)));
    this.observeBreakers(candidates, open);
    const index = open.findIndex((isOpen) => !isOpen);
    if (index < 0) {
      this.metrics.providerFallbackActive.set(0);
      return { kind: 'unavailable' };
    }
    const current = candidates[index]!;
    this.metrics.providerFallbackActive.set(current.role === 'fallback' ? 1 : 0);
    if (index > 0) {
      this.metrics.providerSwitches.inc({
        from: candidates[0]!.role,
        to: current.role,
        reason: 'breaker_open',
      });
    }
    return {
      kind: 'route',
      route: {
        candidates,
        current,
        fallbackFrom: index > 0 ? candidates[0]!.providerId : null,
        switched: false,
      },
    };
  }

  /** Refreshes `assistant_provider_breaker_open` of the platform candidates (status route). */
  async refreshBreakerGauges(): Promise<void> {
    const candidates = this.platformCandidates();
    const open = await Promise.all(candidates.map((c) => this.breaker.isOpen(c.breakerKey)));
    this.observeBreakers(candidates, open);
  }

  /** One model call on the route's current candidate (retry policy, breaker, metrics). */
  async complete(
    route: TurnRoute,
    request: LlmRequest,
    signal: AbortSignal,
    onDelta: (text: string) => void,
  ): Promise<LlmResponse> {
    const candidate = route.current;
    const provider = candidate.provider;
    const labels = { provider: candidate.providerId, role: candidate.role };
    const started = performance.now();
    try {
      const response = await completeWithRetry(provider, request, signal, onDelta);
      await this.breaker.recordSuccess(candidate.breakerKey).catch(() => undefined);
      this.metrics.llmRequests.inc({ ...labels, outcome: 'ok' });
      const tokens = { provider: candidate.providerId, model: provider.model };
      this.metrics.llmTokens.inc({ ...tokens, kind: 'input' }, response.usage.inputTokens);
      this.metrics.llmTokens.inc({ ...tokens, kind: 'output' }, response.usage.outputTokens);
      this.metrics.llmTokens.inc({ ...tokens, kind: 'cache_read' }, response.usage.cacheReadTokens);
      this.metrics.llmTokens.inc(
        { ...tokens, kind: 'cache_write' },
        response.usage.cacheWriteTokens,
      );
      return response;
    } catch (error: unknown) {
      const reason = error instanceof LlmError ? error.reason : 'unexpected';
      this.metrics.llmErrors.inc({ provider: candidate.providerId, reason });
      this.metrics.llmRequests.inc({ ...labels, outcome: reason });
      if (countsTowardBreaker(error) && !signal.aborted) {
        await this.breaker.recordFailure(candidate.breakerKey).catch(() => undefined);
      }
      throw error;
    } finally {
      this.metrics.llmSeconds.observe(labels, (performance.now() - started) / 1000);
    }
  }

  /**
   * A model call of the route failed (D6). A tenant key answered `auth` is invalidated (always);
   * then, when `maySwitch` (first call of the turn, no delta, no tool, no earlier switch), the next
   * closed candidate takes over: after a switchable failure, or after the tenant key's refusal
   * when the platform fallback is allowed (else `tenant_key_invalid`).
   */
  async onFailure(
    route: TurnRoute,
    error: unknown,
    who: { principal: UserPrincipal; scope: TenantScope },
    maySwitch: boolean,
  ): Promise<FailureDecision> {
    const current = route.current;
    const tenantRefused =
      current.keySource === 'tenant' && error instanceof LlmError && error.reason === 'auth';
    if (tenantRefused && this.tenantKeys && current.keyVersion !== undefined) {
      await this.tenantKeys.invalidate(who.principal, who.scope, current.keyVersion);
    }
    if (!tenantRefused && !isSwitchableFailure(error)) return { kind: 'fail' };
    const at = route.candidates.indexOf(current);
    const rest = route.candidates.slice(at + 1).filter((c) => c.keySource === 'platform');
    if (!maySwitch || route.switched || rest.length === 0) {
      return tenantRefused ? { kind: 'tenant_key_invalid' } : { kind: 'fail' };
    }
    for (const next of rest) {
      if (await this.breaker.isOpen(next.breakerKey)) continue;
      const reason = tenantRefused
        ? 'tenant_key_invalid'
        : error instanceof LlmError
          ? error.reason
          : 'unexpected';
      this.metrics.providerSwitches.inc({ from: current.role, to: next.role, reason });
      if (next.role === 'fallback') this.metrics.providerFallbackActive.set(1);
      return {
        kind: 'switch',
        route: {
          candidates: route.candidates,
          current: next,
          fallbackFrom: route.fallbackFrom ?? current.providerId,
          switched: true,
        },
      };
    }
    return tenantRefused ? { kind: 'tenant_key_invalid' } : { kind: 'fail' };
  }

  private spec(role: 'primary' | 'fallback'): ProviderFactorySpec | null {
    return platformSpec(this.config, role);
  }

  private platformProvider(role: 'primary' | 'fallback'): LlmProvider {
    let built = this.platform.get(role);
    if (!built) {
      const spec = this.spec(role);
      if (!spec) throw new Error(`no ${role} assistant provider is configured`);
      built = this.factory(spec);
      this.platform.set(role, built);
    }
    return built;
  }

  private observeBreakers(candidates: readonly RouteCandidate[], open: readonly boolean[]): void {
    candidates.forEach((candidate, i) => {
      if (candidate.keySource !== 'platform') return;
      this.metrics.providerBreakerOpen.set(
        { provider: candidate.providerId, role: candidate.role },
        open[i] ? 1 : 0,
      );
    });
  }
}

/**
 * The router under its AI-1 name: the DI token the assistant services, the unit harness and the
 * integration support use (same constructor and behaviour as `ProviderRouterService`).
 */
@Injectable()
export class AssistantProviderService extends ProviderRouterService {}
