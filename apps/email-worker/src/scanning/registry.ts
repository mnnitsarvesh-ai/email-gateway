import type { MetricsService, RedisService, S3Service } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { type EngineCatalogEntry, engineCatalogEntry } from '@email-gateway/security-contracts';
import type { WorkerConfig } from '../config';
import type { ScanEngineAdapter } from './engine';
import { attachmentRegistration } from './engines/attachment/registration';
import { becRegistration } from './engines/bec/registration';
import { dlpRegistration } from './engines/dlp/registration';
import { rspamdRegistration } from './engines/rspamd/registration';
import { urlRegistration } from './engines/url/registration';
import type { ScanMetrics } from './scan-metrics';

/** A tenant override row of `scan_engine_settings` (S8). */
export interface EngineSettingsRow {
  settings: unknown;
  version: number;
}

/** The effective settings of one engine for one tenant (S8). */
export interface EngineSettingsResolution {
  settings: unknown;
  /** `scan_engine_results.settings_version`. */
  settingsVersion: string;
  /** The row existed but failed validation at use: the platform settings were applied. */
  invalidRow: boolean;
  /** Violation codes of an invalid row (codes only, never values). */
  violations: string[];
}

/** Per-engine budgets (S5, S10): `SCAN_<ENGINE>_CONCURRENCY`, `_TIMEOUT_MS`, `_MAX_ATTEMPTS`. */
export interface EngineBudget {
  concurrency: number;
  timeoutMs: number;
  maxAttempts: number;
}

/**
 * What a registration may use to build its adapter (step 4.2 A12). `rspamdRegistration` uses the
 * config and the logger only.
 */
export interface EngineDeps {
  config: Readonly<WorkerConfig>;
  logger: Logger;
  /** The writer client (§2.0: the scan stage reads and writes the writer only). */
  prisma: PrismaClient;
  /** S3 mail bucket (part objects). */
  s3: Pick<S3Service, 'client' | 'mailBucket'>;
  /** The shared app Redis, or null when the worker has none configured for the engine. */
  redis: Pick<RedisService, 'client'> | null;
  metrics: ScanMetrics;
  /** The worker's Prometheus registry (engine-specific series). */
  registry: MetricsService;
}

/**
 * The email-worker side of an engine (step 4.1 S4): its catalog entry, ledger consumer name, the
 * adapter factory and its settings. The orchestrator iterates `ENGINE_REGISTRY` and never names
 * an engine.
 */
export interface ScanEngineRegistration {
  readonly catalog: EngineCatalogEntry;
  /** `message_idempotency.consumer` of the engine's queue consumer (topology ledgerName). */
  readonly consumerName: string;
  budget(config: Readonly<WorkerConfig>): EngineBudget;
  create(deps: EngineDeps): ScanEngineAdapter;
  /** Merges a tenant row (or none) into the platform settings, re-validating it (S8). */
  settingsFor(
    config: Readonly<WorkerConfig>,
    row: EngineSettingsRow | null,
  ): EngineSettingsResolution;
}

/**
 * Every engine with an adapter in this worker (4.1: Rspamd; 4.2: attachment; 4.3: url; 4.4: bec,
 * a stage-2 engine triggered by its dependencies' finals, B2; 4.5: dlp, stage 1, D1).
 */
export const ENGINE_REGISTRY: readonly ScanEngineRegistration[] = Object.freeze([
  rspamdRegistration,
  attachmentRegistration,
  urlRegistration,
  becRegistration,
  dlpRegistration,
]);

/** The registrations of the platform-enabled engines (`SCAN_ENGINES`), in catalog order. */
export function enabledRegistrations(
  enabled: readonly string[],
  registry: readonly ScanEngineRegistration[] = ENGINE_REGISTRY,
): ScanEngineRegistration[] {
  for (const name of enabled) {
    if (!engineCatalogEntry(name)) throw new Error(`scan engine not in the catalog: ${name}`);
    if (!registry.some((r) => r.catalog.name === name)) {
      throw new Error(`scan engine ${name} has no adapter in this worker`);
    }
  }
  return registry.filter((r) => enabled.includes(r.catalog.name));
}
