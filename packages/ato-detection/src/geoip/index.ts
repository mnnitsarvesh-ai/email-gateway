/**
 * `GeoIpService` (step 8.4 D7, ADR-0074): reads operator-provided MaxMind databases (City, ASN and
 * the optional Anonymous IP) with the official reader `@maxmind/geoip2-node`. Each database is
 * optional; a missing City database makes every geographic lookup honestly `unavailable` (no
 * guessing). Files are reloaded when their modification time changes (the reader is swapped
 * atomically; a broken new file keeps the previous reader). A database older than
 * `maxAgeDays` marks located lookups `stale`. Only geolocatable addresses are looked up
 * (documentation ranges only when explicitly allowed, for tests).
 */
import { readFile, stat } from 'node:fs/promises';
import { ReaderModel } from '@maxmind/geoip2-node';
import { Reader as MmdbReader } from 'maxmind';
import { classifyIp } from '../net';
import type { GeoView } from '../rules/types';
import { ANONYMIZER_FLAGS } from '../taxonomy';

export const GEOIP_DATABASES = ['city', 'asn', 'anonymous'] as const;
export type GeoIpDatabase = (typeof GEOIP_DATABASES)[number];

export type GeoIpPaths = Partial<Record<GeoIpDatabase, string | null>>;

export interface GeoIpOptions {
  /** `ATO_GEOIP_MAX_AGE_DAYS`. */
  maxAgeDays: number;
  /** `ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES` (tests only; refused outside local/ci by the worker). */
  allowDocumentationRanges: boolean;
  now?: () => Date;
}

/** Per-database outcome of one lookup (metric `ato_geoip_lookups_total{database,result}`). */
export type GeoIpLookupResult = 'hit' | 'miss' | 'unavailable' | 'skipped' | 'error';

export interface GeoResult extends GeoView {
  results: Record<GeoIpDatabase, GeoIpLookupResult>;
}

export interface GeoIpDatabaseStatus {
  configured: boolean;
  loaded: boolean;
  databaseType: string | null;
  buildEpoch: number | null;
  ageSeconds: number | null;
  stale: boolean;
  /** Error code of the last failed (re)load, if any. */
  error: string | null;
}

interface Loaded {
  model: ReaderModel;
  databaseType: string;
  buildEpoch: number;
  mtimeMs: number;
}

const EXPECTED_TYPE: Readonly<Record<GeoIpDatabase, string>> = {
  city: 'City',
  asn: 'ASN',
  anonymous: 'Anonymous-IP',
};

const round4 = (n: number): number => Math.round(n * 10_000) / 10_000;
const clip = (s: string | undefined | null, max: number): string | null =>
  s === undefined || s === null || s.length === 0 ? null : s.slice(0, max);

const isNotFound = (error: unknown): boolean =>
  error instanceof Error && error.constructor.name === 'AddressNotFoundError';

export class GeoIpService {
  private readonly loaded: Partial<Record<GeoIpDatabase, Loaded>> = {};
  private readonly errors: Partial<Record<GeoIpDatabase, string>> = {};
  private readonly clock: () => Date;

  private constructor(
    private readonly paths: GeoIpPaths,
    private readonly options: GeoIpOptions,
  ) {
    this.clock = options.now ?? (() => new Date());
  }

  /** Opens the configured databases (a failing file is reported in `status()`, never thrown). */
  static async open(paths: GeoIpPaths, options: GeoIpOptions): Promise<GeoIpService> {
    const service = new GeoIpService(paths, options);
    for (const db of GEOIP_DATABASES) await service.load(db, true);
    return service;
  }

  private async load(db: GeoIpDatabase, force: boolean): Promise<boolean> {
    const path = this.paths[db];
    if (!path) return false;
    try {
      const info = await stat(path);
      const current = this.loaded[db];
      if (!force && current && current.mtimeMs === info.mtimeMs) return false;
      const buffer = await readFile(path);
      const reader = new MmdbReader(buffer);
      const databaseType = reader.metadata.databaseType;
      if (!databaseType.includes(EXPECTED_TYPE[db])) {
        this.errors[db] = 'unexpected_database_type';
        return false;
      }
      // Atomic swap: lookups see the old or the new reader, never a partial one.
      this.loaded[db] = {
        model: new ReaderModel(reader),
        databaseType,
        buildEpoch: Number(reader.metadata.buildEpoch.getTime() / 1000),
        mtimeMs: info.mtimeMs,
      };
      delete this.errors[db];
      return true;
    } catch (error) {
      this.errors[db] =
        (error as NodeJS.ErrnoException).code === 'ENOENT'
          ? 'file_not_found'
          : 'unreadable_database';
      return false;
    }
  }

  /** Reloads every database whose file modification time changed; returns the reloaded ones. */
  async reloadIfChanged(): Promise<GeoIpDatabase[]> {
    const out: GeoIpDatabase[] = [];
    for (const db of GEOIP_DATABASES) if (await this.load(db, false)) out.push(db);
    return out;
  }

  private stale(db: GeoIpDatabase): boolean {
    const l = this.loaded[db];
    if (!l) return false;
    return this.clock().getTime() / 1000 - l.buildEpoch > this.options.maxAgeDays * 86_400;
  }

  /** Status per database (D17 capabilities, D19 metrics). */
  status(): Record<GeoIpDatabase, GeoIpDatabaseStatus> {
    const now = this.clock().getTime() / 1000;
    const out = {} as Record<GeoIpDatabase, GeoIpDatabaseStatus>;
    for (const db of GEOIP_DATABASES) {
      const l = this.loaded[db];
      out[db] = {
        configured: Boolean(this.paths[db]),
        loaded: l !== undefined,
        databaseType: l?.databaseType ?? null,
        buildEpoch: l?.buildEpoch ?? null,
        ageSeconds: l ? Math.max(0, Math.floor(now - l.buildEpoch)) : null,
        stale: this.stale(db),
        error: this.errors[db] ?? null,
      };
    }
    return out;
  }

  /** Looks an IP up in every loaded database. Never throws. */
  lookup(ip: string): GeoResult {
    const result: GeoResult = {
      status: 'unavailable',
      country: null,
      region: null,
      city: null,
      latitude: null,
      longitude: null,
      accuracyKm: null,
      asn: null,
      asnOrg: null,
      anonymizerFlags: null,
      results: { city: 'unavailable', asn: 'unavailable', anonymous: 'unavailable' },
    };
    const cls = classifyIp(ip, { allowDocumentationRanges: this.options.allowDocumentationRanges });
    if (!cls.geolocatable) {
      result.status = cls.valid ? 'private' : 'not_found';
      result.results = { city: 'skipped', asn: 'skipped', anonymous: 'skipped' };
      return result;
    }
    const city = this.loaded.city;
    if (city) {
      try {
        const r = city.model.city(ip);
        result.country = clip(r.country?.isoCode, 2);
        result.city = clip(r.city?.names.en, 64);
        result.region = clip(r.subdivisions?.[0]?.names.en, 64);
        if (r.location) {
          result.latitude = round4(r.location.latitude);
          result.longitude = round4(r.location.longitude);
          result.accuracyKm = Math.min(65535, Math.max(0, Math.round(r.location.accuracyRadius)));
        }
        result.status = this.stale('city') ? 'stale' : 'located';
        result.results.city = 'hit';
      } catch (error) {
        result.status = 'not_found';
        result.results.city = isNotFound(error) ? 'miss' : 'error';
      }
    }
    const asn = this.loaded.asn;
    if (asn) {
      try {
        const r = asn.model.asn(ip);
        result.asn = r.autonomousSystemNumber ?? null;
        result.asnOrg = clip(r.autonomousSystemOrganization, 128);
        result.results.asn = 'hit';
      } catch (error) {
        result.results.asn = isNotFound(error) ? 'miss' : 'error';
      }
    }
    const anon = this.loaded.anonymous;
    if (anon) {
      try {
        const r = anon.model.anonymousIP(ip);
        let flags = 0;
        if (r.isAnonymousVpn) flags |= ANONYMIZER_FLAGS.anonymousVpn;
        if (r.isPublicProxy) flags |= ANONYMIZER_FLAGS.publicProxy;
        if (r.isTorExitNode) flags |= ANONYMIZER_FLAGS.torExitNode;
        if (r.isHostingProvider) flags |= ANONYMIZER_FLAGS.hostingProvider;
        if (r.isResidentialProxy) flags |= ANONYMIZER_FLAGS.residentialProxy;
        if (r.isAnonymous) flags |= ANONYMIZER_FLAGS.anonymous;
        result.anonymizerFlags = flags;
        result.results.anonymous = 'hit';
      } catch (error) {
        const notFound = isNotFound(error);
        result.anonymizerFlags = notFound ? 0 : null;
        result.results.anonymous = notFound ? 'miss' : 'error';
      }
    }
    return result;
  }
}
