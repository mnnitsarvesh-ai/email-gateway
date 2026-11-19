/**
 * Behavioural baselines `ato-baseline/1` (step 8.4 D9, ADR-0071): daily activity rows
 * (`ato_account_activity_daily`) are merged per detect transaction with bounded sets; the
 * maintenance role rebuilds each account's baseline from the last `baselines.windowDays` of daily
 * rows and its auth events. Statistics are integer: median and MAD (scaled by 1483/1000) and the
 * robust threshold `max(absMin, median + k × max(MAD, max(1, median/10)))`.
 */
import type { ResolvedAtoSettings } from './settings';
import type { BaselineView } from './rules/types';
import { ATO_BASELINE_VERSION } from './versions';

export const BASELINE_LIMITS = Object.freeze({
  prefixes: 50,
  asns: 20,
  countries: 20,
  devices: 20,
  externalDomains: 200,
  attachmentTypes: 30,
  peers: 200,
  clientPrefixes: 50,
  maxBytes: 32 * 1024,
});

/** Bounds of the daily row's JSON lists (§3.2). */
export const ACTIVITY_LIMITS = Object.freeze({
  ipPrefixes: 20,
  recipientDomains: 100,
  attachmentTypes: 20,
  peers: 50,
  clientPrefixes: 20,
});

export interface HourCount {
  m: number;
  a: number;
}

export interface ActivityContent {
  bec?: Record<string, number>;
  financial?: number;
  phishing?: number;
  spam?: number;
  fromMismatch?: number;
  massSubject?: number;
  maxHourExternalDomains?: number;
  maxHourPrefixes?: number;
  maxHourSenders?: number;
  clientPrefixes?: string[];
}

/** In-memory form of one `ato_account_activity_daily` row. */
export interface ActivityDayRow {
  dayStart: Date;
  authSuccess: number;
  authFailure: number;
  messages: number;
  recipients: number;
  externalRecipients: number;
  internalRecipients: number;
  attachments: number;
  findings: number;
  maxHourMessages: number;
  hourCounts: HourCount[];
  ipPrefixes: Array<{ p: string; n: number; cc?: string; asn?: number }>;
  recipientDomains: Array<{ d: string; n: number }>;
  attachmentTypes: Array<{ t: string; n: number }>;
  peers: Array<{ k: string; n: number }>;
  content: ActivityContent;
}

/** One change of a day row from one observation. */
export interface ActivityDelta {
  at: Date;
  authSuccess?: number;
  authFailure?: number;
  messages?: number;
  recipients?: number;
  externalRecipients?: number;
  internalRecipients?: number;
  attachments?: number;
  findings?: number;
  ipPrefix?: { p: string; cc?: string | null; asn?: number | null } | null;
  recipientDomains?: readonly string[];
  attachmentTypes?: readonly string[];
  peer?: string | null;
  becCategories?: readonly string[];
  financial?: boolean;
  phishing?: boolean;
  spam?: boolean;
  fromMismatch?: boolean;
  massSubject?: boolean;
  clientPrefix?: string | null;
  /** Hourly maxima seen in the windows at this observation. */
  hourExternalDomains?: number;
  hourPrefixes?: number;
  hourSenders?: number;
}

/** UTC midnight of a time. */
export function utcDayStart(at: Date): Date {
  return new Date(Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate()));
}

/** An empty day row. */
export function emptyActivityDay(dayStart: Date): ActivityDayRow {
  return {
    dayStart,
    authSuccess: 0,
    authFailure: 0,
    messages: 0,
    recipients: 0,
    externalRecipients: 0,
    internalRecipients: 0,
    attachments: 0,
    findings: 0,
    maxHourMessages: 0,
    hourCounts: Array.from({ length: 24 }, () => ({ m: 0, a: 0 })),
    ipPrefixes: [],
    recipientDomains: [],
    attachmentTypes: [],
    peers: [],
    content: {},
  };
}

function bump<T extends { n: number }>(
  list: T[],
  match: (item: T) => boolean,
  create: () => T,
  limit: number,
): T[] {
  const found = list.find(match);
  if (found) {
    found.n += 1;
    return list;
  }
  if (list.length < limit) list.push(create());
  return list;
}

/**
 * Applies a delta to a day row (pure; returns a new row). Lists are bounded (§3.2): a value beyond
 * the bound is not added (its counts still go into the totals).
 */
export function applyActivityDelta(row: ActivityDayRow, delta: ActivityDelta): ActivityDayRow {
  const next: ActivityDayRow = JSON.parse(JSON.stringify(row)) as ActivityDayRow;
  next.dayStart = row.dayStart;
  const add = (
    k: keyof ActivityDayRow &
      (
        | 'authSuccess'
        | 'authFailure'
        | 'messages'
        | 'recipients'
        | 'externalRecipients'
        | 'internalRecipients'
        | 'attachments'
        | 'findings'
      ),
    v?: number,
  ) => {
    if (v) next[k] += v;
  };
  add('authSuccess', delta.authSuccess);
  add('authFailure', delta.authFailure);
  add('messages', delta.messages);
  add('recipients', delta.recipients);
  add('externalRecipients', delta.externalRecipients);
  add('internalRecipients', delta.internalRecipients);
  add('attachments', delta.attachments);
  add('findings', delta.findings);
  if (next.hourCounts.length !== 24) next.hourCounts = emptyActivityDay(row.dayStart).hourCounts;
  const hour = delta.at.getUTCHours();
  next.hourCounts[hour]!.m += delta.messages ?? 0;
  next.hourCounts[hour]!.a += delta.authSuccess ?? 0;
  next.maxHourMessages = Math.max(next.maxHourMessages, ...next.hourCounts.map((h) => h.m));
  if (delta.ipPrefix) {
    const ip = delta.ipPrefix;
    bump(
      next.ipPrefixes,
      (x) => x.p === ip.p,
      () => ({
        p: ip.p,
        n: 1,
        ...(ip.cc ? { cc: ip.cc } : {}),
        ...(ip.asn !== null && ip.asn !== undefined ? { asn: ip.asn } : {}),
      }),
      ACTIVITY_LIMITS.ipPrefixes,
    );
  }
  for (const d of delta.recipientDomains ?? []) {
    bump(
      next.recipientDomains,
      (x) => x.d === d,
      () => ({ d, n: 1 }),
      ACTIVITY_LIMITS.recipientDomains,
    );
  }
  for (const t of delta.attachmentTypes ?? []) {
    bump(
      next.attachmentTypes,
      (x) => x.t === t,
      () => ({ t, n: 1 }),
      ACTIVITY_LIMITS.attachmentTypes,
    );
  }
  if (delta.peer) {
    const k = delta.peer;
    bump(
      next.peers,
      (x) => x.k === k,
      () => ({ k, n: 1 }),
      ACTIVITY_LIMITS.peers,
    );
  }
  const c = next.content;
  for (const cat of delta.becCategories ?? []) {
    c.bec = c.bec ?? {};
    c.bec[cat] = (c.bec[cat] ?? 0) + 1;
  }
  if (delta.financial) c.financial = (c.financial ?? 0) + 1;
  if (delta.phishing) c.phishing = (c.phishing ?? 0) + 1;
  if (delta.spam) c.spam = (c.spam ?? 0) + 1;
  if (delta.fromMismatch) c.fromMismatch = (c.fromMismatch ?? 0) + 1;
  if (delta.massSubject) c.massSubject = (c.massSubject ?? 0) + 1;
  if (delta.clientPrefix) {
    c.clientPrefixes = c.clientPrefixes ?? [];
    if (
      !c.clientPrefixes.includes(delta.clientPrefix) &&
      c.clientPrefixes.length < ACTIVITY_LIMITS.clientPrefixes
    ) {
      c.clientPrefixes.push(delta.clientPrefix);
    }
  }
  if (delta.hourExternalDomains) {
    c.maxHourExternalDomains = Math.max(c.maxHourExternalDomains ?? 0, delta.hourExternalDomains);
  }
  if (delta.hourPrefixes) c.maxHourPrefixes = Math.max(c.maxHourPrefixes ?? 0, delta.hourPrefixes);
  if (delta.hourSenders) c.maxHourSenders = Math.max(c.maxHourSenders ?? 0, delta.hourSenders);
  return next;
}

// ------------------------------------------------------------------ statistics

/** Integer median: the middle value, or the floor of the mean of the two middle values. */
export function median(series: readonly number[]): number {
  if (series.length === 0) return 0;
  const s = [...series].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 1 ? s[mid]! : Math.floor((s[mid - 1]! + s[mid]!) / 2);
}

/** Median and MAD; `mad` is scaled by 1483/1000 (consistency with a normal distribution). */
export function medianMad(series: readonly number[]): { median: number; mad: number } {
  const med = median(series);
  const deviations = series.map((x) => Math.abs(x - med));
  return { median: med, mad: Math.floor((median(deviations) * 1483) / 1000) };
}

/** `max(absMin, median + k × max(MAD, max(1, ⌊median / 10⌋)))` (D9). */
export function robustThreshold(series: readonly number[], k: number, absMin: number): number {
  const { median: med, mad } = medianMad(series);
  return Math.max(absMin, med + k * Math.max(mad, Math.max(1, Math.floor(med / 10))));
}

/** `mature` when active days ≥ `minActiveDays` and events ≥ `minEvents` (D9). */
export function isMature(
  activeDays: number,
  events: number,
  baselines: Pick<ResolvedAtoSettings['baselines'], 'minActiveDays' | 'minEvents'>,
): boolean {
  return activeDays >= baselines.minActiveDays && events >= baselines.minEvents;
}

// ------------------------------------------------------------------ baseline

export interface BaselineAuthRow {
  occurredAt: Date;
  outcome: string;
  channel: string;
  ipPrefix: string | null;
  countryCode: string | null;
  asn: number | null;
  deviceHash: string | null;
}

export interface Baseline {
  version: typeof ATO_BASELINE_VERSION;
  windowStart: string;
  windowEnd: string;
  timeZone: string;
  eventCount: number;
  activeDays: number;
  mature: boolean;
  prefixes: Array<{ p: string; n: number }>;
  asns: Array<{ a: number; n: number }>;
  countries: Array<{ c: string; n: number }>;
  devices: Array<{ d: string; n: number }>;
  channels: string[];
  hourHistogram: number[];
  weekdayHistogram: number[];
  messageHourHistogram: number[];
  dailyMessages: number[];
  dailyRecipients: number[];
  dailyExternalRecipients: number[];
  maxHourlyMessages: number[];
  maxHourlyExternalDomains: number;
  maxHourlyPrefixes: number;
  maxHourlySenders: number;
  externalDomains: Array<{ d: string; n: number }>;
  attachmentTypes: Array<{ t: string; n: number }>;
  peers: Array<{ k: string; n: number }>;
  clientPrefixes: string[];
  content: {
    becCategories: string[];
    financial: number;
    phishing: number;
    spam: number;
    fromMismatch: number;
    massSubject: number;
  };
}

const formatters = new Map<string, Intl.DateTimeFormat>();
function localParts(at: Date, timeZone: string): { hour: number; weekday: number } {
  let f = formatters.get(timeZone);
  if (!f) {
    try {
      f = new Intl.DateTimeFormat('en-US', {
        timeZone,
        hour: 'numeric',
        hourCycle: 'h23',
        weekday: 'short',
      });
    } catch {
      f = new Intl.DateTimeFormat('en-US', {
        timeZone: 'UTC',
        hour: 'numeric',
        hourCycle: 'h23',
        weekday: 'short',
      });
    }
    formatters.set(timeZone, f);
  }
  const parts = f.formatToParts(at);
  const hour = Number(parts.find((p) => p.type === 'hour')?.value ?? '0') % 24;
  const wd = parts.find((p) => p.type === 'weekday')?.value ?? 'Mon';
  return { hour, weekday: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].indexOf(wd) };
}

/** Local hour (0–23) of a time in an IANA zone (UTC for an unknown zone). */
export function localHour(at: Date, timeZone: string): number {
  return localParts(at, timeZone).hour;
}

function topCounts<K>(entries: Map<K, number>, limit: number): Array<[K, number]> {
  return [...entries.entries()]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .slice(0, limit);
}

/**
 * `buildBaseline(days, authEvents, settings, now)` (D9): the last `windowDays` of daily rows and
 * the auth events of the same window, in the organization's time zone. Deterministic; bounded to
 * 32 KiB (external domains are trimmed first).
 */
export function buildBaseline(
  days: readonly ActivityDayRow[],
  authEvents: readonly BaselineAuthRow[],
  settings: Pick<ResolvedAtoSettings, 'baselines'>,
  now: Date,
  timeZone = 'UTC',
): Baseline {
  const windowDays = settings.baselines.windowDays;
  const windowEnd = utcDayStart(now);
  const windowStart = new Date(windowEnd.getTime() - windowDays * 86_400_000);
  const inWindow = days
    .filter((d) => d.dayStart >= windowStart && d.dayStart < windowEnd)
    .sort((a, b) => a.dayStart.getTime() - b.dayStart.getTime());
  const byDay = new Map(inWindow.map((d) => [utcDayStart(d.dayStart).getTime(), d]));
  const series = (pick: (d: ActivityDayRow) => number): number[] =>
    Array.from({ length: windowDays }, (_, i) => {
      const d = byDay.get(windowStart.getTime() + i * 86_400_000);
      return d ? pick(d) : 0;
    });
  const activeDays = inWindow.filter((d) => d.authSuccess + d.authFailure + d.messages > 0).length;
  const eventCount = inWindow.reduce((s, d) => s + d.authSuccess + d.authFailure + d.messages, 0);

  const prefixes = new Map<string, number>();
  const asns = new Map<number, number>();
  const countries = new Map<string, number>();
  const devices = new Map<string, number>();
  const channels = new Set<string>();
  const hourHistogram = Array<number>(24).fill(0);
  const weekdayHistogram = Array<number>(7).fill(0);
  const events = authEvents.filter(
    (e) => e.occurredAt >= windowStart && e.occurredAt < now && e.outcome === 'success',
  );
  for (const e of events) {
    if (e.ipPrefix) prefixes.set(e.ipPrefix, (prefixes.get(e.ipPrefix) ?? 0) + 1);
    if (e.asn !== null) asns.set(e.asn, (asns.get(e.asn) ?? 0) + 1);
    if (e.countryCode) countries.set(e.countryCode, (countries.get(e.countryCode) ?? 0) + 1);
    if (e.deviceHash) devices.set(e.deviceHash, (devices.get(e.deviceHash) ?? 0) + 1);
    channels.add(e.channel);
    const { hour, weekday } = localParts(e.occurredAt, timeZone);
    hourHistogram[hour]! += 1;
    if (weekday >= 0) weekdayHistogram[weekday]! += 1;
  }
  // Daily rows add prefixes and countries of aggregated successes (SMTP) not in auth events.
  const messageHourHistogram = Array<number>(24).fill(0);
  const domains = new Map<string, number>();
  const types = new Map<string, number>();
  const peers = new Map<string, number>();
  const clientPrefixes = new Set<string>();
  const bec = new Set<string>();
  const content = { financial: 0, phishing: 0, spam: 0, fromMismatch: 0, massSubject: 0 };
  let maxHourlyExternalDomains = 0;
  let maxHourlyPrefixes = 0;
  let maxHourlySenders = 0;
  for (const d of inWindow) {
    for (const ip of d.ipPrefixes) {
      if (!prefixes.has(ip.p)) prefixes.set(ip.p, ip.n);
      if (ip.cc && !countries.has(ip.cc)) countries.set(ip.cc, ip.n);
      if (ip.asn !== undefined && !asns.has(ip.asn)) asns.set(ip.asn, ip.n);
    }
    d.hourCounts.forEach((h, utcHour) => {
      if (h.m > 0) {
        const local = localHour(new Date(d.dayStart.getTime() + utcHour * 3_600_000), timeZone);
        messageHourHistogram[local]! += h.m;
      }
    });
    for (const r of d.recipientDomains) domains.set(r.d, (domains.get(r.d) ?? 0) + r.n);
    for (const t of d.attachmentTypes) types.set(t.t, (types.get(t.t) ?? 0) + t.n);
    for (const p of d.peers) peers.set(p.k, (peers.get(p.k) ?? 0) + p.n);
    for (const cp of d.content.clientPrefixes ?? []) clientPrefixes.add(cp);
    for (const [cat, n] of Object.entries(d.content.bec ?? {})) if (n > 0) bec.add(cat);
    content.financial += d.content.financial ?? 0;
    content.phishing += d.content.phishing ?? 0;
    content.spam += d.content.spam ?? 0;
    content.fromMismatch += d.content.fromMismatch ?? 0;
    content.massSubject += d.content.massSubject ?? 0;
    maxHourlyExternalDomains = Math.max(
      maxHourlyExternalDomains,
      d.content.maxHourExternalDomains ?? 0,
    );
    maxHourlyPrefixes = Math.max(maxHourlyPrefixes, d.content.maxHourPrefixes ?? 0);
    maxHourlySenders = Math.max(maxHourlySenders, d.content.maxHourSenders ?? 0);
  }

  const baseline: Baseline = {
    version: ATO_BASELINE_VERSION,
    windowStart: windowStart.toISOString(),
    windowEnd: windowEnd.toISOString(),
    timeZone,
    eventCount,
    activeDays,
    mature: isMature(activeDays, eventCount, settings.baselines),
    prefixes: topCounts(prefixes, BASELINE_LIMITS.prefixes).map(([p, n]) => ({ p, n })),
    asns: topCounts(asns, BASELINE_LIMITS.asns).map(([a, n]) => ({ a, n })),
    countries: topCounts(countries, BASELINE_LIMITS.countries).map(([c, n]) => ({ c, n })),
    devices: topCounts(devices, BASELINE_LIMITS.devices).map(([d, n]) => ({ d, n })),
    channels: [...channels].sort(),
    hourHistogram,
    weekdayHistogram,
    messageHourHistogram,
    dailyMessages: series((d) => d.messages),
    dailyRecipients: series((d) => d.recipients),
    dailyExternalRecipients: series((d) => d.externalRecipients),
    maxHourlyMessages: series((d) => d.maxHourMessages),
    maxHourlyExternalDomains,
    maxHourlyPrefixes,
    maxHourlySenders,
    externalDomains: topCounts(domains, BASELINE_LIMITS.externalDomains).map(([d, n]) => ({
      d,
      n,
    })),
    attachmentTypes: topCounts(types, BASELINE_LIMITS.attachmentTypes).map(([t, n]) => ({ t, n })),
    peers: topCounts(peers, BASELINE_LIMITS.peers).map(([k, n]) => ({ k, n })),
    clientPrefixes: [...clientPrefixes].sort().slice(0, BASELINE_LIMITS.clientPrefixes),
    content: { becCategories: [...bec].sort(), ...content },
  };
  while (
    Buffer.byteLength(JSON.stringify(baseline), 'utf8') > BASELINE_LIMITS.maxBytes &&
    baseline.externalDomains.length > 0
  ) {
    baseline.externalDomains = baseline.externalDomains.slice(
      0,
      Math.floor(baseline.externalDomains.length / 2),
    );
  }
  return baseline;
}

/** Read view of a baseline for rule evaluation (null baseline → an empty, immature view). */
export function baselineView(b: Baseline | null): BaselineView {
  if (!b) {
    return {
      mature: false,
      eventCount: 0,
      activeDays: 0,
      prefixes: new Set(),
      asns: new Set(),
      countries: new Set(),
      devices: new Set(),
      channels: new Set(),
      hourHistogram: Array<number>(24).fill(0),
      messageHourHistogram: Array<number>(24).fill(0),
      dailyMessages: [],
      maxHourlyMessages: [],
      maxHourlyExternalDomains: 0,
      maxHourlyPrefixes: 0,
      maxHourlySenders: 0,
      externalDomains: new Set(),
      attachmentTypes: new Set(),
      peers: new Set(),
      clientPrefixes: new Set(),
      becCategories: new Set(),
      financialSeen: false,
      fromMismatchSeen: false,
      massSubjectSeen: false,
    };
  }
  return {
    mature: b.mature,
    eventCount: b.eventCount,
    activeDays: b.activeDays,
    prefixes: new Set(b.prefixes.map((x) => x.p)),
    asns: new Set(b.asns.map((x) => x.a)),
    countries: new Set(b.countries.map((x) => x.c)),
    devices: new Set(b.devices.map((x) => x.d)),
    channels: new Set(b.channels),
    hourHistogram: b.hourHistogram,
    messageHourHistogram: b.messageHourHistogram,
    dailyMessages: b.dailyMessages,
    maxHourlyMessages: b.maxHourlyMessages,
    maxHourlyExternalDomains: b.maxHourlyExternalDomains,
    maxHourlyPrefixes: b.maxHourlyPrefixes,
    maxHourlySenders: b.maxHourlySenders,
    externalDomains: new Set(b.externalDomains.map((x) => x.d)),
    attachmentTypes: new Set(b.attachmentTypes.map((x) => x.t)),
    peers: new Set(b.peers.map((x) => x.k)),
    clientPrefixes: new Set(b.clientPrefixes),
    becCategories: new Set(b.content.becCategories),
    financialSeen: b.content.financial > 0,
    fromMismatchSeen: b.content.fromMismatch > 0,
    massSubjectSeen: b.content.massSubject > 0,
  };
}

/** Parses a stored baseline (`ato_account_baselines.baseline`); null when not `ato-baseline/1`. */
export function parseBaseline(value: unknown): Baseline | null {
  if (!value || typeof value !== 'object') return null;
  const b = value as Partial<Baseline>;
  if (b.version !== ATO_BASELINE_VERSION || !Array.isArray(b.prefixes)) return null;
  return b as Baseline;
}
