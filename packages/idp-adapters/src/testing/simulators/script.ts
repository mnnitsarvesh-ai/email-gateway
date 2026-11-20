/**
 * Script API of the simulators (design note D12): failure injection, delayed read-back,
 * permission revocation, licences and the call log used by the tests' assertions.
 */
import type { SimDataset, SimLicense } from './types';
import type { SimTokenRegistry } from './tokens';

export interface SimInjection {
  /** Simulator name (`graph`, `o365`, …); any simulator when omitted. */
  simulator?: string;
  method?: string;
  /** Path (after the simulator prefix) prefix, or a pattern. */
  path: string | RegExp;
  status: number;
  /** `Retry-After` header value (seconds or HTTP date). */
  retryAfter?: string;
  /** Provider error code in the error body (Graph/O365 `error.code`). */
  code?: string;
  /** Google error reason (`errors[0].reason`). */
  reason?: string;
  /** How many matching requests are answered (default 1; Infinity for all). */
  times?: number;
  /** Answer with a 302 redirect to this location instead of an error. */
  redirectTo?: string;
  /** Raw body to answer with (bypasses the error shape), e.g. a malformed payload. */
  rawBody?: string;
}

export interface SimCall {
  simulator: string;
  method: string;
  /** Path after the simulator prefix, without the query string. */
  path: string;
  /** Query string (`?…`, empty when none) for assertions on windows and paging. */
  query?: string;
  status: number;
  /** Request subject (token subject) when known. */
  subject?: string;
}

export interface StaleView {
  value: unknown;
  remaining: number;
}

export class SimScript {
  private injections: (SimInjection & { remaining: number })[] = [];
  private readonly log: SimCall[] = [];
  private pendingReadBackDelay = 0;
  /** Stale read-back views per resource key (set by writes after `delayReadBack`). */
  readonly staleViews = new Map<string, StaleView>();

  constructor(
    public dataset: SimDataset,
    readonly tokens: SimTokenRegistry,
    readonly now: () => number = Date.now,
  ) {}

  inject(injection: SimInjection): void {
    this.injections.push({ ...injection, remaining: injection.times ?? 1 });
  }

  /** The next state-changing write keeps the old state visible for `reads` read-backs. */
  delayReadBack(reads: number): void {
    this.pendingReadBackDelay = reads;
  }

  revokePermission(name: string, directoryId?: string): void {
    this.tokens.revokePermission(name, directoryId);
  }

  setLicense(directoryId: string, license: SimLicense, value: boolean): void {
    const directory = this.dataset.microsoft?.directories.find((d) => d.tenantId === directoryId);
    if (!directory) throw new Error('sim_directory_not_found');
    directory.licenses[license] = value;
  }

  calls(filter: { simulator?: string; method?: string; path?: string | RegExp } = {}): SimCall[] {
    return this.log.filter(
      (call) =>
        (filter.simulator === undefined || call.simulator === filter.simulator) &&
        (filter.method === undefined || call.method === filter.method) &&
        (filter.path === undefined ||
          (typeof filter.path === 'string'
            ? call.path.startsWith(filter.path)
            : filter.path.test(call.path))),
    );
  }

  /** Calls that change provider state (anything but GET). */
  writes(simulator?: string): SimCall[] {
    return this.log.filter(
      (call) => call.method !== 'GET' && (simulator === undefined || call.simulator === simulator),
    );
  }

  clearCalls(): void {
    this.log.length = 0;
  }

  reset(dataset?: SimDataset): void {
    this.injections = [];
    this.log.length = 0;
    this.pendingReadBackDelay = 0;
    this.staleViews.clear();
    if (dataset) this.dataset = dataset;
  }

  record(call: SimCall): void {
    this.log.push(call);
  }

  /** The injection answering this request, if any (consumes one use). */
  take(simulator: string, method: string, path: string): SimInjection | null {
    for (const injection of this.injections) {
      if (injection.remaining <= 0) continue;
      if (injection.simulator !== undefined && injection.simulator !== simulator) continue;
      if (injection.method !== undefined && injection.method !== method) continue;
      const matches =
        typeof injection.path === 'string'
          ? path.startsWith(injection.path)
          : injection.path.test(path);
      if (!matches) continue;
      injection.remaining -= 1;
      return injection;
    }
    return null;
  }

  /**
   * Called by a simulator before a state-changing write; keeps each `[key, before]` view visible
   * for the delayed number of read-backs (one `delayReadBack` covers one write).
   */
  beforeWrite(entries: readonly (readonly [string, unknown])[]): void {
    if (this.pendingReadBackDelay <= 0) return;
    for (const [key, before] of entries) {
      this.staleViews.set(key, {
        value: before === undefined ? undefined : structuredClone(before),
        remaining: this.pendingReadBackDelay,
      });
    }
    this.pendingReadBackDelay = 0;
  }

  /** Called by a simulator when reading `key` back; returns the stale view while it lasts. */
  readBack<T>(key: string, current: T): T {
    const stale = this.staleViews.get(key);
    if (!stale) return current;
    if (stale.remaining <= 0) {
      this.staleViews.delete(key);
      return current;
    }
    stale.remaining -= 1;
    return stale.value as T;
  }
}
