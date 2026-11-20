/**
 * Inputs and outputs of the pure rule evaluation (step 8.4 D10, §4.4 `rules/evaluate.ts`). The
 * worker builds an `Observation` from a source event (portal login, account change, SMTP AUTH or
 * submission, outbound message, provider event), reads the account snapshot, the baseline view and
 * the window snapshot, and calls `evaluateRules`; correlation runs inside the transaction after the
 * account lock (`evaluateCorrelation`).
 */
import type { AtoAccountKind, SecurityIncidentSeverity } from '@email-gateway/security-contracts';
import type {
  AuthChannel,
  AuthOutcome,
  AuthSource,
  GeoStatus,
  SignalCategory,
  SignalSourceKind,
  SignalStatus,
  SignalStrength,
} from '../taxonomy';

/** Normalized IP reputation of D7 (stored in `ato_auth_events.reputation`). */
export interface AtoIpReputation {
  status: 'listed' | 'clear' | 'error';
  severity: SecurityIncidentSeverity | null;
  category: 'phishing' | 'malware' | 'spam' | 'scam' | 'c2' | 'other' | null;
  /** Null today (the platform feed has no trust model); set by ATP-1 through the adapter. */
  confidence: 'high' | 'medium' | 'low' | null;
  providers: string[];
}

/** Enrichment of an address (GeoIP City/ASN/Anonymous; D7). */
export interface GeoView {
  status: GeoStatus;
  country: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  accuracyKm: number | null;
  asn: number | null;
  asnOrg: string | null;
  /** `ANONYMIZER_FLAGS` bitmask; null when the Anonymous IP database is not configured. */
  anonymizerFlags: number | null;
}

export interface AuthObservation {
  type: 'auth';
  /** Source event key (`eventId` or `eventId:seq`), used for idempotency and dedupe. */
  key: string;
  source: AuthSource;
  channel: AuthChannel;
  outcome: AuthOutcome;
  failureCode: string | null;
  occurredAt: Date;
  ip: string | null;
  /** /24 or /48 prefix of `ip`. */
  ipPrefix: string | null;
  geo: GeoView | null;
  device: { hash: string; label: string } | null;
  reputation: AtoIpReputation | null;
  /** Listed by an ATO DNSBL zone (null when DNSBL is not configured or not checked). */
  dnsblListed: boolean | null;
  /** Platform campaign flag of the IP (D8). */
  ipFlag: { flagged: boolean; distinctAccounts: number } | null;
  /** In a tenant blocked network (treated as listed, high). */
  blockedNetwork: boolean;
  /** In a tenant trusted network. */
  trustedNetwork: boolean;
  /** `ato_auth_events` row of this observation (link target). */
  authEventRef: { id: bigint; occurredAt: Date } | null;
  /** Account address is a platform `email` indicator (T4; checked on the first event of the day). */
  breachListed?: boolean | null;
  /** Throttle lock (A4): the login throttle locked the account with this attempt. */
  lockedByThrottle?: boolean;
  /** Other active sessions or recent successes within G3's window, located (G3). */
  concurrentLocations?: readonly {
    country: string;
    latitude: number;
    longitude: number;
    accuracyKm: number;
    at: Date;
  }[];
}

export interface AccountChangeObservation {
  type: 'account_change';
  key: string;
  action: string;
  occurredAt: Date;
  auditRef: { id: bigint; createdAt: Date } | null;
}

export interface OutboundMessageObservation {
  type: 'outbound_message';
  key: string;
  occurredAt: Date;
  message: { id: bigint; receivedAt: Date };
  /** Client IP prefix of the submission (O7); null when unknown. */
  clientIpPrefix: string | null;
  /** Message attributed to the connector account (D4) — correlation X3 for connectors. */
  connectorAttributed: boolean;
  /** Header From address equals the envelope sender. */
  headerFromMatches: boolean;
  /** Has In-Reply-To and its parent is not known to the organization. */
  replyWithoutParent: boolean;
  externalRecipients: number;
  internalRecipients: number;
  /** Registrable domains of the external recipients (≤ 1000, no addresses). */
  externalDomains: readonly string[];
  /** External recipients whose domain is new for the account (baseline ∪ seen today). */
  newDomainRecipients: number;
  attachments: readonly { sha256: string; type: string | null }[];
  /** `email_messages.subject_key` (kept only as an HMAC in Redis, O5). */
  subjectKey: string | null;
  findings: {
    /** URL phishing / credential harvesting codes, Rspamd phishing codes or BEC link flags. */
    phishing: boolean;
    phishingCodes: readonly string[];
    /** Attachment or sandbox malicious verdict, malware hard block. */
    malware: boolean;
    spam: boolean;
    /** BEC outbound observation categories with counts > 0 (null: observations unavailable). */
    becCategories: readonly string[] | null;
    /** DLP financial detectors or observation financial identifiers present. */
    financial: boolean;
  };
  /** Account address is a platform `email` indicator (T4; first event of the day). */
  breachListed?: boolean | null;
}

export interface SubmissionObservation {
  type: 'smtp_submission';
  key: string;
  occurredAt: Date;
  /** Client prefix (O7 for connectors). */
  clientIpPrefix: string | null;
  /** HMAC of the sender address (O8 sender spread). */
  senderHash: string;
}

export interface ProviderObservation {
  type: 'provider';
  key: string;
  occurredAt: Date;
  stream: string;
  provider: string;
  eventId: string;
  riskLevel: 'low' | 'medium' | 'high' | null;
  mailbox: {
    change: string;
    targetDomain: string | null;
    targetDomainKnown: boolean;
    ruleHash: string | null;
    ruleTraits: readonly string[];
    clientType: string | null;
    clientTypeKnown: boolean;
  } | null;
  oauth: {
    appIdHash: string;
    scopes: readonly string[];
    consentType: 'user' | 'admin';
    publisherVerified: boolean | null;
  } | null;
  tokenAnomaly: boolean;
}

export type Observation =
  | AuthObservation
  | AccountChangeObservation
  | OutboundMessageObservation
  | SubmissionObservation
  | ProviderObservation;

/** The account being evaluated (`ato_accounts` row, D1). */
export interface AccountSnapshot {
  id: bigint;
  publicId: string;
  kind: AtoAccountKind;
  /** Last successful authentication location (Redis `ato:last`, else `last_auth_geo`). */
  lastSuccess: {
    at: Date;
    country: string | null;
    latitude: number | null;
    longitude: number | null;
    accuracyKm: number | null;
    anonymizerFlags: number | null;
    trusted: boolean;
  } | null;
}

/** A read view of `ato-baseline/1` (sets for membership tests). */
export interface BaselineView {
  mature: boolean;
  eventCount: number;
  activeDays: number;
  prefixes: ReadonlySet<string>;
  asns: ReadonlySet<number>;
  countries: ReadonlySet<string>;
  devices: ReadonlySet<string>;
  channels: ReadonlySet<string>;
  /** Auth successes per local hour (24 values). */
  hourHistogram: readonly number[];
  /** Outbound messages per local hour (24 values). */
  messageHourHistogram: readonly number[];
  dailyMessages: readonly number[];
  maxHourlyMessages: readonly number[];
  /** Maximum distinct external domains in one hour over the window. */
  maxHourlyExternalDomains: number;
  /** Maximum distinct success prefixes in one hour. */
  maxHourlyPrefixes: number;
  /** Maximum distinct senders of a connector in one hour. */
  maxHourlySenders: number;
  externalDomains: ReadonlySet<string>;
  attachmentTypes: ReadonlySet<string>;
  /** Connectors of a mailbox, or sender hashes of a connector. */
  peers: ReadonlySet<string>;
  clientPrefixes: ReadonlySet<string>;
  /** BEC intent categories seen in the window. */
  becCategories: ReadonlySet<string>;
  financialSeen: boolean;
  /** Messages with header From ≠ envelope sender seen in the window. */
  fromMismatchSeen: boolean;
  /** Mass-subject sends seen in the window (≥ O5 threshold in an hour). */
  massSubjectSeen: boolean;
}

/** Per-minute counter metrics of the windows (D8; index 0 = the current minute, 60 values). */
export const MINUTE_METRICS = [
  'af',
  'as',
  'mf',
  'data',
  'msg',
  'rcpt',
  'ext',
  'newdom',
  'spam',
  'rnp',
  'hfm',
] as const;
export type MinuteMetric = (typeof MINUTE_METRICS)[number];

/** Counts read from the Redis windows (D8) after this observation was recorded. */
export interface WindowSnapshot {
  /** Last 60 one-minute buckets per metric (index 0 = current minute). */
  minutes: Readonly<Record<MinuteMetric, readonly number[]>>;
  /** Last 24 one-hour buckets of messages (index 0 = current hour). */
  hourlyMessages: readonly number[];
  distinctFailureIps30m: number;
  distinctSuccessPrefixes60m: number;
  distinctExternalDomains60m: number;
  distinctSenders60m: number;
  /** Messages of the observation's subject key in 60 minutes (O5). */
  subjectMessages60m: number;
  /** Largest spread of the observation's attachments in 60 minutes (O4). */
  attachmentSpread: {
    sha256: string;
    type: string | null;
    recipients: number;
    domains: number;
  } | null;
}

/** Sum of the last `minutes` one-minute buckets of a series. */
export function sumLast(series: readonly number[], minutes: number): number {
  let total = 0;
  for (let i = 0; i < Math.min(minutes, series.length); i++) total += series[i] ?? 0;
  return total;
}

/** Values already seen today (Redis `ato:seen:*`), unioned with the baseline for novelty. */
export interface SeenToday {
  prefixes: ReadonlySet<string>;
  countries: ReadonlySet<string>;
  asns: ReadonlySet<string>;
  devices: ReadonlySet<string>;
  domains: ReadonlySet<string>;
  clientPrefixes: ReadonlySet<string>;
}

export interface TrustedContextView {
  kind: 'ip_cidr' | 'asn' | 'country' | 'device';
  value: string;
  expiresAt: Date;
}

export interface RuleContext {
  now: Date;
  /** Tenant learning period: baseline-relative rules record informational signals. */
  learning: boolean;
  /** IANA time zone of the organization (`organization_settings.timezone`). */
  timeZone: string;
  trustedNetworks: readonly string[];
  trustedContexts: readonly TrustedContextView[];
  /**
   * PX3 (step 8.5, ADR-0083): the observation is historical (a backfilled or initial-sweep provider
   * event). Every signal is recorded `informational` (weight 0, never scored), and the worker opens
   * or escalates no incident, proposes no response and requests no notification; auth events,
   * daily activity and baselines are still written. Default `false`.
   */
  historical?: boolean;
}

export interface RuleInput {
  observation: Observation;
  account: AccountSnapshot;
  baseline: BaselineView | null;
  windows: WindowSnapshot;
  seen: SeenToday;
  context: RuleContext;
}

/** One rule hit, before deduplication and persistence. */
export interface SignalCandidate {
  code: string;
  category: SignalCategory;
  strength: SignalStrength;
  weight: number;
  dedupeKey: string;
  dedupeWindowMinutes: number;
  evidence: Record<string, unknown>;
  sourceKind: SignalSourceKind;
  sourceRef: string | null;
  messageRef: { id: bigint; receivedAt: Date } | null;
  authEventRef: { id: bigint; occurredAt: Date } | null;
  /**
   * Learning period (baseline-relative rules) or a historical observation (PX3): stored with status
   * `informational` (weight 0, never scored).
   */
  informational: boolean;
  /** Novelty values to add to `ato:seen:*` once persisted (one signal per value and day). */
  seen?: { kind: keyof SeenToday; value: string } | null;
}

/** A persisted signal as correlation and scoring see it. */
export interface PersistedSignal {
  id?: bigint;
  accountId: bigint;
  code: string;
  category: SignalCategory;
  strength: SignalStrength;
  weight: number;
  status: SignalStatus;
  firstOccurredAt: Date;
  lastOccurredAt: Date;
}

export interface CorrelationInput {
  account: Pick<AccountSnapshot, 'id' | 'kind'>;
  /** Recent persisted signals of the account and of linked accounts (same address). */
  recent: readonly PersistedSignal[];
  /** The candidates of this observation (already deduplicated). */
  fresh: readonly (SignalCandidate & { occurredAt: Date })[];
  /** Successful authentications of the account in the last 2 hours (X2). */
  successTimes: readonly Date[];
  now: Date;
}
