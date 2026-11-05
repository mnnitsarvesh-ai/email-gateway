import type { ClamdVersion } from '@email-gateway/clamav';

/** The parts of `ClamdClient` the version provider uses. */
export interface ClamdVersionSource {
  version(signal?: AbortSignal): Promise<ClamdVersion>;
}

/**
 * The ClamAV version the worker believes is current (step 4.2 A10, A13): the last version a scan
 * or a `VERSION` call reported, refreshed by `VERSION` after SCAN_ENGINE_VERSION_TTL_MS. Used for
 * the cache lookup key (the result is stored under the version that actually scanned) and by the
 * signature watcher. A failed refresh keeps the last known version; none known → null (the
 * lookup is skipped, never `clean`).
 */
export class ClamavVersionProvider {
  private known: { version: ClamdVersion; at: number } | null = null;
  private refreshing: Promise<ClamdVersion | null> | null = null;

  constructor(
    private readonly source: ClamdVersionSource,
    private readonly ttlMs: number,
    private readonly now: () => number = () => performance.now(),
  ) {}

  get current(): ClamdVersion | null {
    return this.known?.version ?? null;
  }

  /** Records the version a scan reported (same IDSESSION as the scan, A7). */
  observe(version: ClamdVersion): void {
    this.known = { version, at: this.now() };
  }

  /** The known version within the TTL, else a bounded `VERSION` call (best effort). */
  async get(signal?: AbortSignal): Promise<ClamdVersion | null> {
    if (this.known && this.now() - this.known.at < this.ttlMs) return this.known.version;
    this.refreshing ??= this.source
      .version(signal)
      .then((version) => {
        this.observe(version);
        return version;
      })
      .catch(() => this.current)
      .finally(() => {
        this.refreshing = null;
      });
    return this.refreshing;
  }

  /** Always asks clamd (the watcher's poll); throws on failure. */
  async fetch(signal?: AbortSignal): Promise<ClamdVersion> {
    const version = await this.source.version(signal);
    this.observe(version);
    return version;
  }
}
