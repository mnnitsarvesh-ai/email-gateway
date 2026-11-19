import {
  GEOIP_DATABASES,
  GeoIpService,
  type GeoIpDatabase,
  type GeoIpDatabaseStatus,
  type GeoView,
} from '@email-gateway/ato-detection';
import type { AtoMetrics } from '../metrics/ato-metrics';

export interface GeoIpConfig {
  ATO_GEOIP_CITY_DB_PATH?: string | undefined;
  ATO_GEOIP_ASN_DB_PATH?: string | undefined;
  ATO_GEOIP_ANONYMOUS_DB_PATH?: string | undefined;
  ATO_GEOIP_MAX_AGE_DAYS: number;
  ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES: boolean;
}

/**
 * The worker's view of the operator-provided MaxMind databases (D7, ADR-0074): lookups with
 * metrics, reload on modification time (`ATO_GEOIP_RELOAD_SECONDS`, maintenance of every
 * replica), age and loaded gauges. Without the City database every lookup is `unavailable` and the
 * geographic rules say so (capabilities); nothing is guessed.
 */
export class AtoGeoIp {
  private constructor(
    private readonly service: GeoIpService,
    private readonly metrics: AtoMetrics | null,
  ) {}

  static async open(
    config: GeoIpConfig,
    metrics: AtoMetrics | null,
    now?: () => Date,
  ): Promise<AtoGeoIp> {
    const service = await GeoIpService.open(
      {
        city: config.ATO_GEOIP_CITY_DB_PATH ?? null,
        asn: config.ATO_GEOIP_ASN_DB_PATH ?? null,
        anonymous: config.ATO_GEOIP_ANONYMOUS_DB_PATH ?? null,
      },
      {
        maxAgeDays: config.ATO_GEOIP_MAX_AGE_DAYS,
        allowDocumentationRanges: config.ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES,
        ...(now ? { now } : {}),
      },
    );
    const geo = new AtoGeoIp(service, metrics);
    geo.exportGauges();
    return geo;
  }

  lookup(ip: string): GeoView {
    const result = this.service.lookup(ip);
    if (this.metrics) {
      for (const db of GEOIP_DATABASES) {
        this.metrics.geoipLookups.inc({ database: db, result: result.results[db] });
      }
    }
    const { results: _results, ...view } = result;
    void _results;
    return view;
  }

  status(): Record<GeoIpDatabase, GeoIpDatabaseStatus> {
    return this.service.status();
  }

  loaded(db: GeoIpDatabase): boolean {
    return this.service.status()[db].loaded;
  }

  async reload(): Promise<GeoIpDatabase[]> {
    const changed = await this.service.reloadIfChanged();
    this.exportGauges();
    return changed;
  }

  exportGauges(): void {
    if (!this.metrics) return;
    const status = this.service.status();
    for (const db of GEOIP_DATABASES) {
      const s = status[db];
      this.metrics.geoipLoaded.set({ database: db }, s.loaded ? 1 : 0);
      if (s.ageSeconds !== null) this.metrics.geoipAge.set({ database: db }, s.ageSeconds);
      else this.metrics.geoipAge.remove({ database: db });
    }
  }
}
