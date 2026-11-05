import type { Logger } from '@email-gateway/logger';
import type { WorkerConfig } from '../config';
import type {
  EngineSettingsResolution,
  EngineSettingsRow,
  ScanEngineRegistration,
} from './registry';
import type { ScanMetrics } from './scan-metrics';

/** Reads a tenant's override row of one engine from the writer (`scan_engine_settings`). */
export interface EngineSettingsSource {
  loadEngineSettings(organizationId: bigint, engine: string): Promise<EngineSettingsRow | null>;
}

export interface SettingsResolverOptions {
  source: EngineSettingsSource;
  config: Readonly<WorkerConfig>;
  metrics: Pick<ScanMetrics, 'settingsCache' | 'settingsInvalid'>;
  logger: Logger;
  /** SCAN_SETTINGS_CACHE_TTL_MS (0 = no cache). */
  ttlMs: number;
  /** Bounded size (S8: 10 000 entries, LRU). */
  maxEntries?: number;
  now?: () => number;
}

interface Entry {
  value: EngineSettingsResolution;
  at: number;
}

/** Remembered invalid (organization, engine, version) triples: logged once each. */
const MAX_LOGGED_INVALID = 10_000;

/**
 * Effective engine settings per tenant (step 4.1 S8): the tenant's `scan_engine_settings` row
 * (writer), re-validated at use by the engine's registration (`settingsFor`, e.g.
 * `resolveRspamdSettings`). An invalid row (for example after the platform bounds were
 * tightened) is ignored in favour of the platform settings, logged once per row version and
 * counted (`scan_settings_invalid_total{engine}`). Results are cached in process per
 * (organization, engine) for SCAN_SETTINGS_CACHE_TTL_MS, at most 10 000 entries (LRU), so a
 * changed setting takes effect within the TTL.
 */
export class SettingsResolver {
  private readonly cache = new Map<string, Entry>();
  private readonly loggedInvalid = new Set<string>();
  private readonly now: () => number;
  private readonly maxEntries: number;

  constructor(private readonly options: SettingsResolverOptions) {
    this.now = options.now ?? Date.now;
    this.maxEntries = options.maxEntries ?? 10_000;
  }

  get size(): number {
    return this.cache.size;
  }

  async resolve(
    registration: ScanEngineRegistration,
    organizationId: bigint,
  ): Promise<EngineSettingsResolution> {
    const engine = registration.catalog.name;
    const key = `${organizationId.toString()}:${engine}`;
    const now = this.now();
    const cached = this.cache.get(key);
    if (cached && this.options.ttlMs > 0 && now - cached.at < this.options.ttlMs) {
      // LRU: move to the most recently used end.
      this.cache.delete(key);
      this.cache.set(key, cached);
      this.options.metrics.settingsCache.inc({ result: 'hit' });
      return cached.value;
    }
    this.options.metrics.settingsCache.inc({ result: 'miss' });
    const row = await this.options.source.loadEngineSettings(organizationId, engine);
    const value = registration.settingsFor(this.options.config, row);
    if (value.invalidRow) {
      this.options.metrics.settingsInvalid.inc({ engine });
      const logKey = `${key}:${String(row?.version ?? 0)}`;
      if (!this.loggedInvalid.has(logKey)) {
        if (this.loggedInvalid.size >= MAX_LOGGED_INVALID) this.loggedInvalid.clear();
        this.loggedInvalid.add(logKey);
        this.options.logger.warn(
          {
            organizationId: organizationId.toString(),
            engine,
            settingsRowVersion: row?.version ?? null,
            violations: value.violations,
          },
          'tenant scan settings are invalid; the platform settings are applied',
        );
      }
    }
    if (this.options.ttlMs > 0) {
      this.cache.delete(key);
      this.cache.set(key, { value, at: now });
      while (this.cache.size > this.maxEntries) {
        const oldest = this.cache.keys().next().value;
        if (oldest === undefined) break;
        this.cache.delete(oldest);
      }
    }
    return value;
  }
}
