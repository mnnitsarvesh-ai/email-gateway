import { RspamdClient } from '@email-gateway/rspamd';
import {
  engineCatalogEntry,
  type EngineCatalogEntry,
  resolveRspamdSettings,
  settingsVersion,
} from '@email-gateway/security-contracts';
import type { WorkerConfig } from '../../../config';
import { rspamdPlatformFromConfig } from '../../config';
import type { EngineSettingsResolution, ScanEngineRegistration } from '../../registry';
import { RspamdEngine } from './rspamd.engine';
import { RSPAMD_MAPPING_VERSION } from './verdict-mapper';

/** Ledger consumer of `scan.spam` (topology v3 `ledgerName`). */
export const RSPAMD_CONSUMER = 'email-worker.scan.rspamd';

const catalog = engineCatalogEntry('rspamd') as EngineCatalogEntry;

/** The Rspamd client of the scan role (normal worker; controller read password optional). */
export function createRspamdClient(config: Readonly<WorkerConfig>): RspamdClient {
  if (!config.SCAN_RSPAMD_URL) throw new Error('SCAN_RSPAMD_URL is not configured');
  return new RspamdClient({
    baseUrl: config.SCAN_RSPAMD_URL,
    ...(config.RSPAMD_CONTROLLER_URL ? { controllerUrl: config.RSPAMD_CONTROLLER_URL } : {}),
    ...(config.RSPAMD_CONTROLLER_PASSWORD
      ? { controllerPassword: config.RSPAMD_CONTROLLER_PASSWORD }
      : {}),
    timeoutMs: config.SCAN_RSPAMD_TIMEOUT_MS,
    // In-flight HTTP calls = handler concurrency (S10).
    maxInFlight: config.SCAN_RSPAMD_CONCURRENCY,
  });
}

/** S8: tenant row → effective settings (an invalid row falls back to the platform settings). */
export function rspamdSettingsFor(
  config: Readonly<WorkerConfig>,
  row: { settings: unknown; version: number } | null,
): EngineSettingsResolution {
  const platform = rspamdPlatformFromConfig(config);
  const resolved = resolveRspamdSettings(platform, row?.settings ?? null);
  if (resolved.ok) {
    return {
      settings: resolved.settings,
      settingsVersion: settingsVersion(RSPAMD_MAPPING_VERSION, platform, row ? row.version : null),
      invalidRow: false,
      violations: [],
    };
  }
  const fallback = resolveRspamdSettings(platform, null);
  if (!fallback.ok) throw new Error('the platform Rspamd settings are invalid');
  return {
    settings: fallback.settings,
    settingsVersion: settingsVersion(RSPAMD_MAPPING_VERSION, platform, null),
    invalidRow: true,
    violations: [...new Set(resolved.violations.map((v) => v.code))],
  };
}

export const rspamdRegistration: ScanEngineRegistration = {
  catalog,
  consumerName: RSPAMD_CONSUMER,
  budget: (config) => ({
    concurrency: config.SCAN_RSPAMD_CONCURRENCY,
    timeoutMs: config.SCAN_RSPAMD_TIMEOUT_MS,
    maxAttempts: config.SCAN_RSPAMD_MAX_ATTEMPTS,
  }),
  create: ({ config }) =>
    new RspamdEngine({
      client: createRspamdClient(config),
      maxBytes: config.SCAN_RSPAMD_MAX_BYTES,
      versionTtlMs: config.SCAN_ENGINE_VERSION_TTL_MS,
      controllerConfigured: Boolean(
        config.RSPAMD_CONTROLLER_URL && config.RSPAMD_CONTROLLER_PASSWORD,
      ),
    }),
  settingsFor: rspamdSettingsFor,
};
