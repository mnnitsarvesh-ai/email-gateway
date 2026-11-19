/**
 * Observation, snapshot and row builders (test kit). Defaults are synthetic (documentation IPs,
 * `example.test` style values); every builder takes overrides.
 */
import { baselineView, type Baseline } from '../baseline';
import { mergeAtoSettings, type AtoSettingsInput, type ResolvedAtoSettings } from '../settings';
import type {
  AccountChangeObservation,
  AccountSnapshot,
  AuthObservation,
  BaselineView,
  GeoView,
  OutboundMessageObservation,
  ProviderObservation,
  RuleContext,
  RuleInput,
  SeenToday,
  SubmissionObservation,
  WindowSnapshot,
} from '../rules/types';
import { MINUTE_METRICS, type MinuteMetric } from '../rules/types';
import type { ScoreSignal } from '../scoring';
import { ATO_BASELINE_VERSION } from '../versions';

export const T0 = new Date('2026-11-18T10:00:00.000Z');

export function geoView(overrides: Partial<GeoView> = {}): GeoView {
  return {
    status: 'located',
    country: 'IN',
    region: 'Maharashtra',
    city: 'Mumbai',
    latitude: 19.076,
    longitude: 72.8777,
    accuracyKm: 20,
    asn: 64500,
    asnOrg: 'Synthetic Documentation AS64500',
    anonymizerFlags: 0,
    ...overrides,
  };
}

export function authObservation(overrides: Partial<AuthObservation> = {}): AuthObservation {
  return {
    type: 'auth',
    key: 'evt-auth-1',
    source: 'portal_login',
    channel: 'portal',
    outcome: 'success',
    failureCode: null,
    occurredAt: T0,
    ip: '192.0.2.10',
    ipPrefix: '192.0.2.0/24',
    geo: geoView(),
    device: { hash: '0123456789abcdef', label: 'Chrome 120 · Windows · desktop' },
    reputation: null,
    dnsblListed: null,
    ipFlag: null,
    blockedNetwork: false,
    trustedNetwork: false,
    authEventRef: null,
    ...overrides,
  };
}

export function accountChangeObservation(
  overrides: Partial<AccountChangeObservation> = {},
): AccountChangeObservation {
  return {
    type: 'account_change',
    key: 'evt-change-1',
    action: 'auth.mfa_disabled',
    occurredAt: T0,
    auditRef: null,
    ...overrides,
  };
}

export function outboundObservation(
  overrides: Partial<OutboundMessageObservation> = {},
): OutboundMessageObservation {
  return {
    type: 'outbound_message',
    key: 'evt-mail-1',
    occurredAt: T0,
    message: { id: 101n, receivedAt: T0 },
    clientIpPrefix: '198.51.100.0/24',
    connectorAttributed: false,
    headerFromMatches: true,
    replyWithoutParent: false,
    externalRecipients: 1,
    internalRecipients: 0,
    externalDomains: ['partner.example'],
    newDomainRecipients: 0,
    attachments: [],
    subjectKey: 'subject-key-1',
    findings: {
      phishing: false,
      phishingCodes: [],
      malware: false,
      spam: false,
      becCategories: [],
      financial: false,
    },
    ...overrides,
  };
}

export function submissionObservation(
  overrides: Partial<SubmissionObservation> = {},
): SubmissionObservation {
  return {
    type: 'smtp_submission',
    key: 'evt-sub-1:0',
    occurredAt: T0,
    clientIpPrefix: '198.51.100.0/24',
    senderHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    ...overrides,
  };
}

export function providerObservation(
  overrides: Partial<ProviderObservation> = {},
): ProviderObservation {
  return {
    type: 'provider',
    key: 'prov:1',
    occurredAt: T0,
    stream: 'mailbox_audit',
    provider: 'fake',
    eventId: 'fake-evt-1',
    riskLevel: null,
    mailbox: null,
    oauth: null,
    tokenAnomaly: false,
    ...overrides,
  };
}

export function accountSnapshot(overrides: Partial<AccountSnapshot> = {}): AccountSnapshot {
  return {
    id: 42n,
    publicId: '01900000-0000-7000-8000-000000000042',
    kind: 'gateway_user',
    lastSuccess: null,
    ...overrides,
  };
}

/** A window snapshot with all counts zero; `minutes` sets per-metric totals in the current minute. */
export function windowSnapshot(
  overrides: Partial<Omit<WindowSnapshot, 'minutes'>> & {
    minutes?: Partial<Record<MinuteMetric, number | readonly number[]>>;
  } = {},
): WindowSnapshot {
  const minutes = Object.fromEntries(
    MINUTE_METRICS.map((m) => {
      const v = overrides.minutes?.[m];
      if (Array.isArray(v))
        return [m, [...(v as number[]), ...Array<number>(60).fill(0)].slice(0, 60)];
      const series = Array<number>(60).fill(0);
      if (typeof v === 'number') series[0] = v;
      return [m, series];
    }),
  ) as Record<MinuteMetric, number[]>;
  const { minutes: _m, ...rest } = overrides;
  return {
    minutes,
    hourlyMessages: Array<number>(24).fill(0),
    distinctFailureIps30m: 0,
    distinctSuccessPrefixes60m: 0,
    distinctExternalDomains60m: 0,
    distinctSenders60m: 0,
    subjectMessages60m: 0,
    attachmentSpread: null,
    ...rest,
  };
}

export function seenToday(overrides: Partial<Record<keyof SeenToday, string[]>> = {}): SeenToday {
  return {
    prefixes: new Set(overrides.prefixes ?? []),
    countries: new Set(overrides.countries ?? []),
    asns: new Set(overrides.asns ?? []),
    devices: new Set(overrides.devices ?? []),
    domains: new Set(overrides.domains ?? []),
    clientPrefixes: new Set(overrides.clientPrefixes ?? []),
  };
}

export function ruleContext(overrides: Partial<RuleContext> = {}): RuleContext {
  return {
    now: T0,
    learning: false,
    timeZone: 'UTC',
    trustedNetworks: [],
    trustedContexts: [],
    ...overrides,
  };
}

/** A mature baseline (28 active days, 100 events) with optional overrides of the stored form. */
export function matureBaseline(overrides: Partial<Baseline> = {}): Baseline {
  const hourHistogram = Array<number>(24).fill(0);
  for (let h = 8; h <= 18; h++) hourHistogram[h] = 10;
  const messageHourHistogram = [...hourHistogram];
  return {
    version: ATO_BASELINE_VERSION,
    windowStart: '2026-10-21T00:00:00.000Z',
    windowEnd: '2026-11-18T00:00:00.000Z',
    timeZone: 'UTC',
    eventCount: 100,
    activeDays: 28,
    mature: true,
    prefixes: [{ p: '192.0.2.0/24', n: 50 }],
    asns: [{ a: 64500, n: 50 }],
    countries: [{ c: 'IN', n: 50 }],
    devices: [{ d: '0123456789abcdef', n: 50 }],
    channels: ['portal'],
    hourHistogram,
    weekdayHistogram: [20, 20, 20, 20, 20, 0, 0],
    messageHourHistogram,
    dailyMessages: Array<number>(28).fill(20),
    dailyRecipients: Array<number>(28).fill(30),
    dailyExternalRecipients: Array<number>(28).fill(10),
    maxHourlyMessages: Array<number>(28).fill(5),
    maxHourlyExternalDomains: 3,
    maxHourlyPrefixes: 1,
    maxHourlySenders: 2,
    externalDomains: [{ d: 'partner.example', n: 40 }],
    attachmentTypes: [{ t: 'application/pdf', n: 5 }],
    peers: [],
    clientPrefixes: ['198.51.100.0/24'],
    content: {
      becCategories: [],
      financial: 0,
      phishing: 0,
      spam: 0,
      fromMismatch: 0,
      massSubject: 0,
    },
    ...overrides,
  };
}

export function matureBaselineView(overrides: Partial<Baseline> = {}): BaselineView {
  return baselineView(matureBaseline(overrides));
}

/** Resolved settings from an input (defaults when omitted). */
export function resolvedSettings(input: AtoSettingsInput = {}): ResolvedAtoSettings {
  return mergeAtoSettings(input);
}

/** A rule input with defaults (gateway user, success login, no baseline). */
export function ruleInput(overrides: Partial<RuleInput> = {}): RuleInput {
  return {
    observation: authObservation(),
    account: accountSnapshot(),
    baseline: null,
    windows: windowSnapshot(),
    seen: seenToday(),
    context: ruleContext(),
    ...overrides,
  };
}

/** A fresh active score signal. */
export function scoreSignal(
  overrides: Partial<ScoreSignal> & Pick<ScoreSignal, 'code'>,
): ScoreSignal {
  return {
    category: 'access_context',
    strength: 'weak',
    weight: 10,
    status: 'active',
    lastOccurredAt: T0,
    ...overrides,
  };
}
