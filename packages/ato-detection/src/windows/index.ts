/**
 * Short-term ATO state in Redis (step 8.4 D8, ADR-0071): per-account one-minute and one-hour
 * counters, capped sets in 10-minute buckets, attachment spread, seen-today novelty sets, the last
 * successful location, platform-wide IP campaign windows and flags, connector attribution of
 * submissions and the fast-path signal dedupe marker. Every key has a TTL and every update is
 * idempotent per source event (Lua, `ato:dd:*` markers). Redis is never the source of truth:
 * losing it loses at most in-window counts.
 */
import { hmacKey } from '../keys';
import { DATA_ACCESS_ACTIONS } from '../rules/evaluate';
import {
  MINUTE_METRICS,
  type MinuteMetric,
  type Observation,
  type SeenToday,
  type WindowSnapshot,
} from '../rules/types';
import {
  IP_FAILURE_SCRIPT,
  MEMBERS_SCRIPT,
  RECORD_SCRIPT,
  SEEN_ADD_SCRIPT,
  UNION_COUNT_SCRIPT,
} from './scripts';

export * from './scripts';

/** The minimal Redis interface the windows need (ioredis-compatible). */
export interface RedisLike {
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  mget(...keys: string[]): Promise<(string | null)[]>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: (string | number)[]): Promise<unknown>;
  scard(key: string): Promise<number>;
  del(...keys: string[]): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
}

/** TTLs and caps of D8 (seconds / members). */
export const WINDOW_TTLS = Object.freeze({
  minute: 2 * 3600,
  hour: 50 * 3600,
  set: 2 * 3600,
  attachment: 2 * 3600,
  seen: 48 * 3600,
  last: 30 * 86400,
  ip: 2 * 3600,
  submission: 2 * 3600,
  dedupe: 2 * 3600,
});
export const WINDOW_CAPS = Object.freeze({ set: 200, attachment: 200, seen: 200, ipAccounts: 500 });

const SET_NAMES = {
  failureIps: 'fip',
  successPrefixes: 'sp',
  externalDomains: 'xd',
  senders: 'snd',
};
const SEEN_KEYS: Readonly<Record<keyof SeenToday, string>> = {
  prefixes: 'pfx',
  countries: 'cc',
  asns: 'asn',
  devices: 'dev',
  domains: 'dom',
  clientPrefixes: 'cpfx',
};

export interface WindowAccount {
  organizationId: bigint;
  accountId: bigint;
}

export interface LastSuccess {
  at: string;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
  accuracyKm: number | null;
  anonymizerFlags: number | null;
  trusted: boolean;
}

export interface SubmissionAttribution {
  connectorId: string;
  clientIp: string | null;
  helo: string | null;
  tls: string | null;
}

export interface IpFailureResult {
  applied: boolean;
  distinctAccounts: number;
  flagged: boolean;
  newlyFlagged: boolean;
}

export interface AtoWindowsOptions {
  /** `ATO_HMAC_KEY`: members that must not be kept in clear (recipient domains, subject keys). */
  hmacKey: string;
  /** Key prefix (default `ato:`). */
  prefix?: string;
}

const minuteOf = (at: Date): number => Math.floor(at.getTime() / 60_000);
const hourOf = (at: Date): number => Math.floor(at.getTime() / 3_600_000);
const tenMinuteOf = (at: Date): number => Math.floor(at.getTime() / 600_000);

interface Op {
  key: string;
  op: 'incr' | 'incr_nx' | 'sadd' | 'sadd_nx';
  ttl: number;
  arg: string | number;
  cap: number;
}

export class AtoWindows {
  private readonly prefix: string;
  private readonly key: string;

  constructor(
    private readonly redis: RedisLike,
    options: AtoWindowsOptions,
  ) {
    if (!options.hmacKey || options.hmacKey.length < 16) {
      throw new Error('AtoWindows needs an HMAC key of at least 16 characters');
    }
    this.prefix = options.prefix ?? 'ato:';
    this.key = options.hmacKey;
  }

  // ---------------------------------------------------------------- key builders

  minuteKey(a: WindowAccount, metric: string, minute: number): string {
    return `${this.prefix}w:${a.organizationId}:${a.accountId}:${metric}:m${minute}`;
  }

  hourKey(a: WindowAccount, metric: string, hour: number): string {
    return `${this.prefix}w:${a.organizationId}:${a.accountId}:${metric}:h${hour}`;
  }

  setKey(a: WindowAccount, set: string, bucket: number): string {
    return `${this.prefix}s:${a.organizationId}:${a.accountId}:${set}:m${bucket}`;
  }

  attachmentKey(a: WindowAccount, sha256: string): string {
    return `${this.prefix}att:${a.organizationId}:${a.accountId}:${sha256}`;
  }

  seenKey(a: WindowAccount, kind: keyof SeenToday): string {
    return `${this.prefix}seen:${a.organizationId}:${a.accountId}:${SEEN_KEYS[kind]}`;
  }

  lastKey(a: WindowAccount): string {
    return `${this.prefix}last:${a.organizationId}:${a.accountId}`;
  }

  ipFailureKey(ip: string, minute: number): string {
    return `${this.prefix}ip:${ip}:f:m${minute}`;
  }

  ipAccountsKey(ip: string, bucket: number): string {
    return `${this.prefix}ip:${ip}:a:m${bucket}`;
  }

  ipFlagKey(ip: string): string {
    return `${this.prefix}ipflag:${ip}`;
  }

  submissionKey(organizationId: bigint, queueId: string): string {
    return `${this.prefix}sub:${organizationId}:${queueId}`;
  }

  dedupeKey(eventKey: string, metric: string): string {
    return `${this.prefix}dd:${eventKey}:${metric}`;
  }

  signalKey(organizationId: bigint, dedupeKey: string): string {
    return `${this.prefix}sigdd:${organizationId}:${dedupeKey}`;
  }

  private hmac(purpose: string, value: string): string {
    return hmacKey(this.key, purpose, value);
  }

  /** Short per-subject metric name of O5 (16 hex of the subject-key HMAC). */
  subjectMetric(subjectKey: string): string {
    return `sj${this.hmac('subject', subjectKey).slice(0, 16)}`;
  }

  // ---------------------------------------------------------------- updates

  /** The window updates an observation implies (pure; exposed for tests). */
  opsFor(account: WindowAccount, observation: Observation): Op[] {
    const at = observation.occurredAt;
    const m = minuteOf(at);
    const b = tenMinuteOf(at);
    const ops: Op[] = [];
    const incr = (metric: string, n = 1) => {
      if (n > 0)
        ops.push({
          key: this.minuteKey(account, metric, m),
          op: 'incr',
          ttl: WINDOW_TTLS.minute,
          arg: n,
          cap: 0,
        });
    };
    const sadd = (set: string, member: string) =>
      ops.push({
        key: this.setKey(account, set, b),
        op: 'sadd',
        ttl: WINDOW_TTLS.set,
        arg: member,
        cap: WINDOW_CAPS.set,
      });
    switch (observation.type) {
      case 'auth': {
        const o = observation.outcome;
        if (o === 'success') {
          incr('as');
          if (observation.ipPrefix) sadd(SET_NAMES.successPrefixes, observation.ipPrefix);
        } else if (o === 'mfa_failure') {
          incr('mf');
        } else if (
          o === 'failure' ||
          o === 'locked' ||
          o === 'rate_limited' ||
          o === 'throttled' ||
          o === 'blocked'
        ) {
          incr('af');
          if (observation.ip) sadd(SET_NAMES.failureIps, observation.ip);
        }
        break;
      }
      case 'account_change':
        if (DATA_ACCESS_ACTIONS.includes(observation.action)) incr('data');
        break;
      case 'outbound_message': {
        incr('msg');
        ops.push({
          key: this.hourKey(account, 'msg', hourOf(at)),
          op: 'incr',
          ttl: WINDOW_TTLS.hour,
          arg: 1,
          cap: 0,
        });
        incr('rcpt', observation.externalRecipients + observation.internalRecipients);
        incr('ext', observation.externalRecipients);
        incr('newdom', observation.newDomainRecipients);
        if (observation.findings.spam) incr('spam');
        if (observation.replyWithoutParent) incr('rnp');
        if (!observation.headerFromMatches) incr('hfm');
        if (observation.subjectKey) incr(this.subjectMetric(observation.subjectKey));
        const domains = [...new Set(observation.externalDomains)].slice(0, WINDOW_CAPS.set);
        for (const d of domains) sadd(SET_NAMES.externalDomains, this.hmac('domain', d));
        if (observation.externalRecipients > 0) {
          for (const att of observation.attachments.slice(0, 20)) {
            const key = this.attachmentKey(account, att.sha256);
            for (const d of domains) {
              ops.push({
                key,
                op: 'sadd_nx',
                ttl: WINDOW_TTLS.attachment,
                arg: this.hmac('domain', d),
                cap: WINDOW_CAPS.attachment,
              });
            }
            ops.push({
              key: `${key}:n`,
              op: 'incr_nx',
              ttl: WINDOW_TTLS.attachment,
              arg: observation.externalRecipients,
              cap: 0,
            });
          }
        }
        break;
      }
      case 'smtp_submission':
        sadd(SET_NAMES.senders, observation.senderHash);
        break;
      case 'provider':
        break;
    }
    return ops;
  }

  /**
   * Records an observation's window updates once per `observationKey` and account (Lua, `ato:dd:*`).
   * Returns false for a duplicate (nothing changed).
   */
  async record(
    observationKey: string,
    account: WindowAccount,
    observation: Observation,
    _now: Date,
  ): Promise<boolean> {
    const ops = this.opsFor(account, observation);
    if (ops.length === 0) return true;
    const keys = [
      this.dedupeKey(observationKey, `a${account.accountId}`),
      ...ops.map((o) => o.key),
    ];
    const args: (string | number)[] = [WINDOW_TTLS.dedupe];
    for (const o of ops) args.push(o.op, o.ttl, o.arg, o.cap);
    const result = await this.redis.eval(RECORD_SCRIPT, keys.length, ...keys, ...args);
    return Number(result) === 1;
  }

  // ---------------------------------------------------------------- reads

  private async unionCount(keys: string[]): Promise<number> {
    if (keys.length === 0) return 0;
    return Number(await this.redis.eval(UNION_COUNT_SCRIPT, keys.length, ...keys));
  }

  private async minuteSeries(account: WindowAccount, metric: string, now: Date): Promise<number[]> {
    const m = minuteOf(now);
    const keys = Array.from({ length: 60 }, (_, i) => this.minuteKey(account, metric, m - i));
    const values = await this.redis.mget(...keys);
    return values.map((v) => Number(v ?? 0));
  }

  private setWindow(account: WindowAccount, set: string, now: Date, minutes: number): string[] {
    const b = tenMinuteOf(now);
    return Array.from({ length: Math.ceil(minutes / 10) }, (_, i) =>
      this.setKey(account, set, b - i),
    );
  }

  /**
   * The window snapshot rules read after the observation was recorded (D8: MGET of the needed
   * buckets, set cardinalities through SUNION). Metrics an observation type never uses are zero.
   */
  async snapshot(
    account: WindowAccount,
    observation: Observation,
    now: Date,
  ): Promise<WindowSnapshot> {
    const zeros = Array<number>(60).fill(0);
    const minutes = Object.fromEntries(MINUTE_METRICS.map((m) => [m, zeros])) as Record<
      MinuteMetric,
      number[]
    >;
    let hourlyMessages = Array<number>(24).fill(0);
    const snap: WindowSnapshot = {
      minutes,
      hourlyMessages,
      distinctFailureIps30m: 0,
      distinctSuccessPrefixes60m: 0,
      distinctExternalDomains60m: 0,
      distinctSenders60m: 0,
      subjectMessages60m: 0,
      attachmentSpread: null,
    };
    const read = async (metrics: MinuteMetric[]) => {
      for (const metric of metrics) minutes[metric] = await this.minuteSeries(account, metric, now);
    };
    switch (observation.type) {
      case 'auth':
        await read(['af', 'as', 'mf']);
        snap.distinctFailureIps30m = await this.unionCount(
          this.setWindow(account, SET_NAMES.failureIps, now, 30),
        );
        snap.distinctSuccessPrefixes60m = await this.unionCount(
          this.setWindow(account, SET_NAMES.successPrefixes, now, 60),
        );
        break;
      case 'account_change':
        await read(['data']);
        break;
      case 'outbound_message': {
        await read(['msg', 'rcpt', 'ext', 'newdom', 'spam', 'rnp', 'hfm']);
        const h = hourOf(now);
        const values = await this.redis.mget(
          ...Array.from({ length: 24 }, (_, i) => this.hourKey(account, 'msg', h - i)),
        );
        hourlyMessages = values.map((v) => Number(v ?? 0));
        snap.hourlyMessages = hourlyMessages;
        snap.distinctExternalDomains60m = await this.unionCount(
          this.setWindow(account, SET_NAMES.externalDomains, now, 60),
        );
        if (observation.subjectKey) {
          const series = await this.minuteSeries(
            account,
            this.subjectMetric(observation.subjectKey),
            now,
          );
          snap.subjectMessages60m = series.reduce((s, n) => s + n, 0);
        }
        for (const att of observation.attachments.slice(0, 20)) {
          const key = this.attachmentKey(account, att.sha256);
          const domains = await this.redis.scard(key);
          const recipients = Number((await this.redis.get(`${key}:n`)) ?? 0);
          if (!snap.attachmentSpread || recipients > snap.attachmentSpread.recipients) {
            snap.attachmentSpread = { sha256: att.sha256, type: att.type, recipients, domains };
          }
        }
        break;
      }
      case 'smtp_submission':
        snap.distinctSenders60m = await this.unionCount(
          this.setWindow(account, SET_NAMES.senders, now, 60),
        );
        break;
      case 'provider':
        break;
    }
    return snap;
  }

  // ---------------------------------------------------------------- platform IP windows

  /**
   * Platform-wide failure window of an IP (D8): every portal and SMTP authentication failure of
   * every organization counts; the IP is flagged when it failed against ≥ `minAccounts` distinct
   * accounts (account HMACs, no tenant identity) within `windowMinutes`.
   */
  async recordAuthFailure(
    eventKey: string,
    ip: string,
    accountHmac: string,
    now: Date,
    options: { windowMinutes: number; minAccounts: number; flagHours: number },
  ): Promise<IpFailureResult> {
    const b = tenMinuteOf(now);
    const windowSets = Array.from(
      { length: Math.max(1, Math.ceil(options.windowMinutes / 10)) },
      (_, i) => this.ipAccountsKey(ip, b - i),
    );
    const keys = [
      this.dedupeKey(eventKey, 'ip'),
      this.ipFailureKey(ip, minuteOf(now)),
      this.ipAccountsKey(ip, b),
      this.ipFlagKey(ip),
      ...windowSets,
    ];
    const raw = (await this.redis.eval(
      IP_FAILURE_SCRIPT,
      keys.length,
      ...keys,
      WINDOW_TTLS.dedupe,
      WINDOW_TTLS.ip,
      accountHmac,
      WINDOW_CAPS.ipAccounts,
      options.minAccounts,
      options.flagHours * 3600,
    )) as unknown[];
    return {
      applied: Number(raw[0]) === 1,
      distinctAccounts: Number(raw[1]),
      flagged: Number(raw[2]) === 1,
      newlyFlagged: Number(raw[3]) === 1,
    };
  }

  /** The campaign flag of an IP (null when not flagged). */
  async ipFlag(ip: string): Promise<{ flagged: true; distinctAccounts: number } | null> {
    const value = await this.redis.get(this.ipFlagKey(ip));
    if (value === null) return null;
    const n = Number(value.split('|')[1] ?? 0);
    return { flagged: true, distinctAccounts: Number.isFinite(n) ? n : 0 };
  }

  // ---------------------------------------------------------------- novelty

  /** Adds a value to today's seen set; true when it was new (D9 same-day novelty). */
  async rememberSeen(
    account: WindowAccount,
    kind: keyof SeenToday,
    value: string,
  ): Promise<boolean> {
    const result = await this.redis.eval(
      SEEN_ADD_SCRIPT,
      1,
      this.seenKey(account, kind),
      value,
      WINDOW_CAPS.seen,
      WINDOW_TTLS.seen,
    );
    return Number(result) === 1;
  }

  /** Values seen today per kind. */
  async seenToday(account: WindowAccount): Promise<SeenToday> {
    const out: Record<string, Set<string>> = {};
    for (const kind of Object.keys(SEEN_KEYS) as (keyof SeenToday)[]) {
      const members = (await this.redis.eval(MEMBERS_SCRIPT, 1, this.seenKey(account, kind))) as
        string[] | null;
      out[kind] = new Set(members ?? []);
    }
    return out as unknown as SeenToday;
  }

  // ---------------------------------------------------------------- last success, attribution

  async setLastSuccess(account: WindowAccount, value: LastSuccess): Promise<void> {
    await this.redis.set(this.lastKey(account), JSON.stringify(value), 'EX', WINDOW_TTLS.last);
  }

  async lastSuccess(account: WindowAccount): Promise<LastSuccess | null> {
    const raw = await this.redis.get(this.lastKey(account));
    if (!raw) return null;
    try {
      return JSON.parse(raw) as LastSuccess;
    } catch {
      return null;
    }
  }

  async setSubmissionAttribution(
    organizationId: bigint,
    queueId: string,
    value: SubmissionAttribution,
  ): Promise<void> {
    await this.redis.set(
      this.submissionKey(organizationId, queueId),
      JSON.stringify(value),
      'EX',
      WINDOW_TTLS.submission,
    );
  }

  async submissionAttribution(
    organizationId: bigint,
    queueId: string,
  ): Promise<SubmissionAttribution | null> {
    const raw = await this.redis.get(this.submissionKey(organizationId, queueId));
    if (!raw) return null;
    try {
      return JSON.parse(raw) as SubmissionAttribution;
    } catch {
      return null;
    }
  }

  // ---------------------------------------------------------------- signal fast path

  /**
   * Fast-path signal dedupe (D8 `ato:sigdd:*`): true the first time within the window. Only skips
   * work early; the store's dedupe under the account lock is authoritative.
   */
  async markSignal(
    organizationId: bigint,
    dedupeKey: string,
    windowMinutes: number,
  ): Promise<boolean> {
    const result = await this.redis.set(
      this.signalKey(organizationId, dedupeKey),
      '1',
      'EX',
      Math.max(60, windowMinutes * 60),
      'NX',
    );
    return result === 'OK';
  }

  /** Clears a fast-path marker (when the transaction that set it rolled back). */
  async clearSignal(organizationId: bigint, dedupeKey: string): Promise<void> {
    await this.redis.del(this.signalKey(organizationId, dedupeKey));
  }
}
