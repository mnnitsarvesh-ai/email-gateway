import {
  AnthropicBecProvider,
  type BecAiProvider,
  type BecStaticData,
  FakeBecLlmProvider,
  loadBecStaticData,
  loadLocalModel,
  loadModelManifest,
  type LocalBecModel,
} from '@email-gateway/bec';
import {
  BEC_MAPPING_VERSION,
  engineCatalogEntry,
  type EngineCatalogEntry,
  resolveBecSettings,
  settingsVersion,
} from '@email-gateway/security-contracts';
import type { WorkerConfig } from '../../../config';
import { becPlatformFromConfig } from '../../bec-config';
import { CircuitBreaker } from '../../circuit-breaker';
import { S3PartReader } from '../../parts/part-reader';
import type { EngineDeps, EngineSettingsResolution, ScanEngineRegistration } from '../../registry';
import { urlSettingsFor } from '../url/registration';
import { BecAiLayer } from './ai-layer';
import { BecMetrics } from './bec-metrics';
import { type BecStore, PrismaBecStore } from './bec-store';
import { BecEngine, type BecEngineLimits } from './bec.engine';
import { type LlmBudgetCheck, RedisLlmBudget } from './llm-budget';

/** Ledger consumer of `scan.bec` (topology v6 `ledgerName`). */
export const BEC_CONSUMER = 'email-worker.scan.bec';

const catalog = engineCatalogEntry('bec') as EngineCatalogEntry;

/** B13 / S8: tenant row → effective settings (an invalid row falls back to the platform). */
export function becSettingsFor(
  config: Readonly<WorkerConfig>,
  row: { settings: unknown; version: number } | null,
): EngineSettingsResolution {
  const platform = becPlatformFromConfig(config);
  const resolved = resolveBecSettings(platform, row?.settings ?? null);
  if (resolved.ok) {
    return {
      settings: resolved.settings,
      settingsVersion: settingsVersion(BEC_MAPPING_VERSION, platform, row ? row.version : null),
      invalidRow: false,
      violations: [],
    };
  }
  const fallback = resolveBecSettings(platform, null);
  if (!fallback.ok) throw new Error('the platform BEC settings are invalid');
  return {
    settings: fallback.settings,
    settingsVersion: settingsVersion(BEC_MAPPING_VERSION, platform, null),
    invalidRow: true,
    violations: [...new Set(resolved.violations.map((v) => v.code))],
  };
}

export function becLimitsFromConfig(config: Readonly<WorkerConfig>): BecEngineLimits {
  return {
    textMaxBytes: config.BEC_TEXT_MAX_BYTES,
    textMaxChars: config.BEC_TEXT_MAX_CHARS,
    textTimeoutMs: config.BEC_TEXT_TIMEOUT_MS,
    historyMaxRecipients: config.BEC_HISTORY_MAX_RECIPIENTS,
    historyMinMessages: config.BEC_HISTORY_MIN_MESSAGES,
    suppressionMaxWeight: config.BEC_SUPPRESSION_MAX_WEIGHT,
  };
}

/** The local models of B16: the active one and the optional shadow one (manifest + hash). */
export function loadLocalModels(config: Readonly<WorkerConfig>): {
  active: LocalBecModel;
  shadow: LocalBecModel | null;
} {
  const manifest = loadModelManifest();
  return {
    active: loadLocalModel(config.BEC_LOCAL_MODEL, manifest),
    shadow:
      config.BEC_LOCAL_MODEL_SHADOW === ''
        ? null
        : loadLocalModel(config.BEC_LOCAL_MODEL_SHADOW, manifest),
  };
}

/**
 * The LLM providers of B10, or nulls when the platform mode is off. `anthropic` needs
 * BEC_LLM_API_KEY (the config refuses a mode other than off without it); `fake` is refused when
 * NODE_ENV=production (config and the provider's constructor).
 */
export function createLlmProviders(
  config: Readonly<WorkerConfig>,
  metrics: BecMetrics,
  fetchImpl?: (input: string | URL | Request, init?: RequestInit) => Promise<Response>,
): { active: BecAiProvider | null; shadow: BecAiProvider | null } {
  if (config.BEC_LLM_MODE === 'off') return { active: null, shadow: null };
  const build = (model: string): BecAiProvider => {
    if (config.BEC_LLM_PROVIDER === 'fake') {
      return new FakeBecLlmProvider({ nodeEnv: config.NODE_ENV });
    }
    if (!config.BEC_LLM_API_KEY) {
      throw new Error('BEC_LLM_API_KEY is required when BEC_LLM_MODE is not off');
    }
    return new AnthropicBecProvider({
      apiKey: config.BEC_LLM_API_KEY,
      model,
      maxOutputTokens: config.BEC_LLM_MAX_OUTPUT_TOKENS,
      timeoutMs: config.BEC_LLM_TIMEOUT_MS,
      refusalFallback: config.BEC_LLM_REFUSAL_FALLBACK,
      onResult: (info) => metrics.tokens(info.inputTokens, info.outputTokens),
      ...(fetchImpl ? { fetch: fetchImpl } : {}),
    });
  };
  return {
    active: build(config.BEC_LLM_MODEL),
    shadow: config.BEC_LLM_SHADOW_MODEL === '' ? null : build(config.BEC_LLM_SHADOW_MODEL),
  };
}

/** Test seams and replacements of the bec engine's dependencies (integration tests). */
export interface BecEngineOverrides {
  store?: BecStore;
  budget?: LlmBudgetCheck;
  data?: BecStaticData;
  now?: () => Date;
}

/** Everything the bec engine is built from (also used by the integration tests). */
export function createBecEngine(deps: EngineDeps, overrides: BecEngineOverrides = {}): BecEngine {
  const { config, logger } = deps;
  const metrics = BecMetrics.for(deps.registry);
  if (!config.BEC_CONTEXT_HMAC_KEY) {
    throw new Error('BEC_CONTEXT_HMAC_KEY is required where the bec engine consumes');
  }
  const data =
    overrides.data ?? loadBecStaticData({ brandsFile: config.URL_PROTECTED_BRANDS_FILE });
  const local = loadLocalModels(config);
  const llm = createLlmProviders(config, metrics);
  const breaker = new CircuitBreaker({
    failureThreshold: config.BEC_LLM_BREAKER_THRESHOLD,
    failureRatio: 1,
    window: Math.max(10, config.BEC_LLM_BREAKER_THRESHOLD),
    openMs: config.BEC_LLM_BREAKER_RESET_MS,
    halfOpenProbes: 1,
    onTransition: (from, to) => {
      metrics.breaker(to);
      const log = { from, to };
      if (to === 'open') logger.warn(log, 'bec llm circuit opened');
      else logger.info(log, 'bec llm circuit changed state');
    },
  });
  const ai = new BecAiLayer({
    local,
    llm: { provider: config.BEC_LLM_PROVIDER, ...llm },
    budget:
      overrides.budget ??
      new RedisLlmBudget(deps.redis?.client ?? null, config.BEC_LLM_MAX_CALLS_PER_MINUTE),
    breaker,
    concurrency: config.BEC_LLM_CONCURRENCY,
    timeoutMs: config.BEC_LLM_TIMEOUT_MS,
    minScore: config.BEC_LLM_MIN_SCORE,
    maxExcerptChars: config.BEC_LLM_MAX_EXCERPT_CHARS,
    metrics,
    logger,
  });

  // B16: scan_engine_info at start (the round service refreshes it per result) and the models.
  deps.metrics.engineVersion(catalog.name, data.engineVersion);
  metrics.model(
    'local',
    local.active.modelId,
    local.active.modelVersion,
    config.BEC_LOCAL_MODEL_MODE,
  );
  if (local.shadow) {
    metrics.model('local', local.shadow.modelId, local.shadow.modelVersion, 'shadow');
  }
  if (llm.active)
    metrics.model('llm', llm.active.modelId, llm.active.modelVersion, config.BEC_LLM_MODE);
  if (llm.shadow) metrics.model('llm', llm.shadow.modelId, config.BEC_LLM_SHADOW_MODEL, 'shadow');

  const dependsOn = catalog.dependsOn ?? [];
  if (!dependsOn.includes('rspamd') || !dependsOn.includes('url')) {
    throw new Error('the bec catalog entry must depend on rspamd and url');
  }
  return new BecEngine({
    store:
      overrides.store ??
      new PrismaBecStore(
        deps.prisma,
        {
          executives: config.BEC_MAX_EXECUTIVES,
          vendors: config.BEC_MAX_VENDORS,
          trustedSenders: config.BEC_MAX_TRUSTED_SENDERS,
          suppressions: config.BEC_SUPPRESSIONS_MAX_PER_TENANT,
        },
        {
          ttlMs: config.BEC_TENANT_DATA_CACHE_TTL_MS,
          ...(overrides.now ? { now: overrides.now } : {}),
        },
      ),
    parts: new S3PartReader(deps.s3.client, deps.s3.mailBucket, config.SCAN_S3_TIMEOUT_MS),
    data,
    ai,
    dependencies: { auth: 'rspamd', url: 'url' },
    historyKey: config.BEC_CONTEXT_HMAC_KEY,
    limits: becLimitsFromConfig(config),
    lookalike: {
      minLabel: config.URL_LOOKALIKE_MIN_LABEL,
      longLabel: config.URL_LOOKALIKE_LONG_LABEL,
      maxDistanceShort: config.URL_LOOKALIKE_MAX_DISTANCE_SHORT,
      maxDistanceLong: config.URL_LOOKALIKE_MAX_DISTANCE_LONG,
      highScore: config.URL_LOOKALIKE_HIGH_SCORE,
    },
    platformExtraDomains: config.URL_PROTECTED_EXTRA_DOMAINS,
    urlSettings: (row) => urlSettingsFor(config, row).settings as never,
    readiness: {
      localModel: local.active.modelVersion,
      localModelMode: config.BEC_LOCAL_MODEL_MODE,
      localShadowModel: local.shadow?.modelVersion ?? 'none',
      llmMode: config.BEC_LLM_MODE,
      llmProvider: llm.active ? config.BEC_LLM_PROVIDER : 'none',
    },
    metrics,
    logger,
    ...(overrides.now ? { now: overrides.now } : {}),
  });
}

export const becRegistration: ScanEngineRegistration = {
  catalog,
  consumerName: BEC_CONSUMER,
  budget: (config) => ({
    concurrency: config.SCAN_BEC_CONCURRENCY,
    timeoutMs: config.SCAN_BEC_TIMEOUT_MS,
    maxAttempts: config.SCAN_BEC_MAX_ATTEMPTS,
  }),
  create: (deps) => createBecEngine(deps),
  settingsFor: becSettingsFor,
};
