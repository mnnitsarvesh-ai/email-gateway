import { COUNT_SCRIPT, type CounterRedis, RELEASE_SCRIPT, RESERVE_SCRIPT } from './inflight';

/**
 * An in-memory stand-in of the three Lua scripts of `InflightCounters` (unit tests only; the real
 * scripts run against Redis in the integration suite). Slot keys are sorted sets (member → expiry
 * score), rate keys plain counters.
 */
export class FakeCounterRedis implements CounterRedis {
  /** Plain counters (rate keys). */
  readonly store = new Map<string, number>();
  /** Sorted sets (slot keys): member → score (lease expiry, ms). */
  readonly zsets = new Map<string, Map<string, number>>();
  readonly ttl = new Map<string, number>();
  down = false;

  /** Members of a slot key, expired ones included (what a crashed process leaves behind). */
  size(key: string): number {
    return this.zsets.get(key)?.size ?? 0;
  }

  ping(): Promise<string> {
    return this.down ? Promise.reject(new Error('Connection is closed.')) : Promise.resolve('PONG');
  }

  private zset(key: string): Map<string, number> {
    let z = this.zsets.get(key);
    if (!z) {
      z = new Map();
      this.zsets.set(key, z);
    }
    return z;
  }

  private expire(key: string, now: number): void {
    const z = this.zsets.get(key);
    if (!z) return;
    for (const [member, score] of z) if (score <= now) z.delete(member);
  }

  eval(script: string, numKeys: number, ...args: Array<string | number>): Promise<unknown> {
    if (this.down) return Promise.reject(new Error('Connection is closed.'));
    const keys = args.slice(0, numKeys).map(String);
    const argv = args.slice(numKeys).map(String);
    if (script === RESERVE_SCRIPT) {
      const [org, sub, rate] = keys as [string, string, string];
      const [orgCap, subCap, rateCap, now, expiry, rateTtl, token, lease] = argv as [
        string,
        string,
        string,
        string,
        string,
        string,
        string,
        string,
      ];
      this.expire(org, Number(now));
      this.expire(sub, Number(now));
      if (this.size(org) >= Number(orgCap)) return Promise.resolve(1);
      if (this.size(sub) >= Number(subCap)) return Promise.resolve(2);
      if ((this.store.get(rate) ?? 0) >= Number(rateCap)) return Promise.resolve(3);
      this.zset(org).set(token, Number(expiry));
      this.zset(sub).set(token, Number(expiry));
      this.ttl.set(org, Number(lease));
      this.ttl.set(sub, Number(lease));
      this.store.set(rate, (this.store.get(rate) ?? 0) + 1);
      this.ttl.set(rate, Number(rateTtl));
      return Promise.resolve(0);
    }
    if (script === COUNT_SCRIPT) {
      const now = Number(argv[0]);
      let n = 0;
      for (const score of this.zsets.get(keys[0]!)?.values() ?? []) if (score > now) n += 1;
      return Promise.resolve(n);
    }
    if (script === RELEASE_SCRIPT) {
      const token = argv[0]!;
      this.zsets.get(keys[0]!)?.delete(token);
      this.zsets.get(keys[1]!)?.delete(token);
      if (keys[2] !== undefined) {
        const v = this.store.get(keys[2]) ?? 0;
        if (v > 0) this.store.set(keys[2], v - 1);
      }
      return Promise.resolve(0);
    }
    return Promise.reject(new Error('unknown script'));
  }
}
