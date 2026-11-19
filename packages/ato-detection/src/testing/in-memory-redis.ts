/**
 * `InMemoryRedis` (test kit): the `RedisLike` subset the ATO windows use, with TTLs on an injected
 * clock. `eval` recognizes the exact Lua texts of `windows/scripts.ts` and runs equivalent
 * JavaScript, so unit tests exercise the windows without a Redis server; the package integration
 * test runs the real Lua against Redis.
 */
import type { RedisLike } from '../windows';
import {
  IP_FAILURE_SCRIPT,
  MEMBERS_SCRIPT,
  RECORD_SCRIPT,
  SEEN_ADD_SCRIPT,
  UNION_COUNT_SCRIPT,
} from '../windows/scripts';

type Value = { kind: 'string'; value: string } | { kind: 'set'; value: Set<string> };

export class InMemoryRedis implements RedisLike {
  private readonly data = new Map<string, Value>();
  private readonly expiry = new Map<string, number>();
  /** Every eval'd script text (tests assert the Lua path was used). */
  readonly evals: string[] = [];

  constructor(private readonly clock: () => number = () => Date.now()) {}

  private alive(key: string): Value | undefined {
    const at = this.expiry.get(key);
    if (at !== undefined && at <= this.clock()) {
      this.data.delete(key);
      this.expiry.delete(key);
    }
    return this.data.get(key);
  }

  private str(key: string): string | null {
    const v = this.alive(key);
    if (!v) return null;
    if (v.kind !== 'string') throw new Error('WRONGTYPE');
    return v.value;
  }

  private set_(key: string, create: boolean): Set<string> | null {
    const v = this.alive(key);
    if (v) {
      if (v.kind !== 'set') throw new Error('WRONGTYPE');
      return v.value;
    }
    if (!create) return null;
    const s = new Set<string>();
    this.data.set(key, { kind: 'set', value: s });
    return s;
  }

  /** Remaining TTL in seconds (-2 missing, -1 no TTL), like Redis TTL. */
  ttl(key: string): number {
    if (!this.alive(key)) return -2;
    const at = this.expiry.get(key);
    return at === undefined ? -1 : Math.ceil((at - this.clock()) / 1000);
  }

  keys(): string[] {
    return [...this.data.keys()].filter((k) => this.alive(k) !== undefined);
  }

  members(key: string): string[] {
    return [...(this.set_(key, false) ?? [])];
  }

  private setNxEx(key: string, value: string, seconds: number): boolean {
    if (this.alive(key)) return false;
    this.data.set(key, { kind: 'string', value });
    this.expiry.set(key, this.clock() + seconds * 1000);
    return true;
  }

  private expireSync(key: string, seconds: number): number {
    if (!this.alive(key)) return 0;
    this.expiry.set(key, this.clock() + seconds * 1000);
    return 1;
  }

  private incrBy(key: string, n: number): number {
    const next = Number(this.str(key) ?? 0) + n;
    const at = this.expiry.get(key);
    this.data.set(key, { kind: 'string', value: String(next) });
    if (at !== undefined) this.expiry.set(key, at);
    return next;
  }

  private sadd(key: string, member: string): void {
    this.set_(key, true)!.add(member);
  }

  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown> {
    this.evals.push(script);
    const keys = args.slice(0, numKeys).map(String);
    const argv = args.slice(numKeys).map(String);
    const union = (ks: string[]) => {
      const out = new Set<string>();
      for (const k of ks) for (const m of this.set_(k, false) ?? []) out.add(m);
      return out;
    };
    if (script === RECORD_SCRIPT) {
      if (!this.setNxEx(keys[0]!, '1', Number(argv[0]))) return Promise.resolve(0);
      for (let i = 1; i < keys.length; i++) {
        const base = 1 + (i - 1) * 4;
        const op = argv[base]!;
        const ttl = Number(argv[base + 1]);
        const arg = argv[base + 2]!;
        const cap = Number(argv[base + 3]);
        const key = keys[i]!;
        if (op === 'incr' || op === 'incr_nx') {
          this.incrBy(key, Number(arg));
          if (op === 'incr' || this.ttl(key) < 0) this.expireSync(key, ttl);
        } else {
          const s = this.set_(key, false);
          if (!(s?.has(arg) ?? false) && (s?.size ?? 0) < cap) this.sadd(key, arg);
          if (op === 'sadd' || this.ttl(key) < 0) this.expireSync(key, ttl);
        }
      }
      return Promise.resolve(1);
    }
    if (script === UNION_COUNT_SCRIPT) return Promise.resolve(union(keys).size);
    if (script === MEMBERS_SCRIPT) return Promise.resolve([...(this.set_(keys[0]!, false) ?? [])]);
    if (script === SEEN_ADD_SCRIPT) {
      const s = this.set_(keys[0]!, false);
      if (s?.has(argv[0]!)) return Promise.resolve(0);
      if ((s?.size ?? 0) >= Number(argv[1])) return Promise.resolve(0);
      this.sadd(keys[0]!, argv[0]!);
      if (this.ttl(keys[0]!) < 0) this.expireSync(keys[0]!, Number(argv[2]));
      return Promise.resolve(1);
    }
    if (script === IP_FAILURE_SCRIPT) {
      let applied = 0;
      if (this.setNxEx(keys[0]!, '1', Number(argv[0]))) {
        applied = 1;
        this.incrBy(keys[1]!, 1);
        this.expireSync(keys[1]!, Number(argv[1]));
        const s = this.set_(keys[2]!, false);
        if (!(s?.has(argv[2]!) ?? false) && (s?.size ?? 0) < Number(argv[3]))
          this.sadd(keys[2]!, argv[2]!);
        this.expireSync(keys[2]!, Number(argv[1]));
      }
      const distinct = union(keys.slice(4)).size;
      let flagged = 0;
      let newly = 0;
      if (distinct >= Number(argv[4])) {
        if (!this.alive(keys[3]!)) {
          newly = 1;
          this.data.set(keys[3]!, { kind: 'string', value: `campaign|${distinct}` });
          this.expiry.set(keys[3]!, this.clock() + Number(argv[5]) * 1000);
        } else {
          this.data.set(keys[3]!, { kind: 'string', value: `campaign|${distinct}` });
        }
        flagged = 1;
      } else if (this.alive(keys[3]!)) {
        flagged = 1;
      }
      return Promise.resolve([applied, distinct, flagged, newly]);
    }
    return Promise.reject(new Error('InMemoryRedis: unknown script'));
  }

  mget(...keys: string[]): Promise<(string | null)[]> {
    return Promise.resolve(keys.map((k) => this.str(k)));
  }

  get(key: string): Promise<string | null> {
    return Promise.resolve(this.str(key));
  }

  set(key: string, value: string, ...args: (string | number)[]): Promise<unknown> {
    let ex: number | null = null;
    let nx = false;
    let keepTtl = false;
    for (let i = 0; i < args.length; i++) {
      const a = String(args[i]).toUpperCase();
      if (a === 'EX') ex = Number(args[++i]);
      else if (a === 'NX') nx = true;
      else if (a === 'KEEPTTL') keepTtl = true;
    }
    if (nx && this.alive(key)) return Promise.resolve(null);
    const previous = this.expiry.get(key);
    this.data.set(key, { kind: 'string', value });
    if (ex !== null) this.expiry.set(key, this.clock() + ex * 1000);
    else if (keepTtl && previous !== undefined) this.expiry.set(key, previous);
    else this.expiry.delete(key);
    return Promise.resolve('OK');
  }

  scard(key: string): Promise<number> {
    return Promise.resolve(this.set_(key, false)?.size ?? 0);
  }

  del(...keys: string[]): Promise<number> {
    let n = 0;
    for (const k of keys) {
      if (this.alive(k)) n++;
      this.data.delete(k);
      this.expiry.delete(k);
    }
    return Promise.resolve(n);
  }

  expire(key: string, seconds: number): Promise<number> {
    return Promise.resolve(this.expireSync(key, seconds));
  }
}
