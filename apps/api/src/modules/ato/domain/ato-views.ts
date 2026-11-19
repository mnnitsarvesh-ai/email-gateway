import { createHash } from 'node:crypto';
import {
  capabilitySet,
  type CapabilitySet,
  renderExplanation,
  ruleTitle,
  type StaticCapability,
} from '@email-gateway/ato-detection';
import type {
  AtoAccountActivityDaily,
  AtoAccountBaseline,
  AtoAccountIdentity,
  AtoAuthEvent,
  AtoResponseActionLog,
  AtoRiskScore,
  AtoTrustedContext,
} from '@email-gateway/database';
import { ATO_CAPABILITIES_MAX_AGE_MS } from '../ato.constants';
import type {
  AccountDetailView,
  AccountSummaryView,
  ActivityView,
  AuthEventView,
  CapabilitiesView,
  ResponseActionView,
  RestrictionView,
  ScorePointView,
  SignalView,
} from '../dto/ato.schemas';
import type {
  AccountRow,
  ResponseRow,
  RestrictionRow,
  SignalRow,
} from '../repositories/ato-read.repository';

const iso = (d: Date | null | undefined): string | null => (d ? d.toISOString() : null);

/**
 * Opaque, stable reference of a row of a partitioned table without a public id (signals, auth
 * events, score points): 20 hex characters of SHA-256 over the kind, id and partition time. Never
 * the internal id itself (responses carry public ids only, §5).
 */
export function opaqueRef(kind: string, id: bigint, at: Date): string {
  return createHash('sha256')
    .update(`ato-${kind}|${id.toString()}|${at.getTime()}`, 'utf8')
    .digest('hex')
    .slice(0, 20);
}
const num = (v: unknown): number | null =>
  v === null || v === undefined ? null : Number.isFinite(Number(v)) ? Number(v) : null;

type CapabilityState = CapabilitiesView['geoipCity'];

/** Parsed worker capabilities (D17): the view and the set rule availability is computed from. */
export interface Capabilities {
  view: CapabilitiesView;
  set: CapabilitySet;
  known: boolean;
}

const UNKNOWN_VIEW: CapabilitiesView = {
  status: 'unknown',
  updatedAt: null,
  geoipCity: 'unknown',
  geoipAsn: 'unknown',
  geoipAnonymous: 'unknown',
  dnsbl: 'unknown',
  breachIntel: 'unknown',
  becObservations: 'unknown',
  providers: [],
};

function geoState(value: unknown): CapabilityState {
  if (value === null || typeof value !== 'object') return 'unavailable';
  const v = value as { loaded?: unknown; stale?: unknown };
  if (v.loaded !== true) return 'unavailable';
  return v.stale === true ? 'stale' : 'available';
}

const countState = (value: unknown): CapabilityState =>
  typeof value === 'number' && value > 0 ? 'available' : 'unavailable';

/**
 * The `system_settings` row `ato.worker.capabilities` (written by the ato-worker every 5 minutes:
 * `{ geoipCity: { loaded, buildEpoch, stale }, geoipAsn, geoipAnonymous, dnsblZones, breachIndicators,
 * providers, becObservations?, updatedAt }`). Missing, malformed or older than 15 minutes → every
 * capability `unknown` (D17).
 */
export function parseCapabilities(
  raw: { value: unknown; updatedAt: Date } | null,
  now: Date,
): Capabilities {
  const unknown: Capabilities = { view: UNKNOWN_VIEW, set: capabilitySet({}), known: false };
  if (raw === null || raw.value === null || typeof raw.value !== 'object') return unknown;
  const v = raw.value as Record<string, unknown>;
  const reported = typeof v.updatedAt === 'string' ? new Date(v.updatedAt) : raw.updatedAt;
  if (
    Number.isNaN(reported.getTime()) ||
    now.getTime() - reported.getTime() > ATO_CAPABILITIES_MAX_AGE_MS
  ) {
    return unknown;
  }
  const view: CapabilitiesView = {
    status: 'known',
    updatedAt: reported.toISOString(),
    geoipCity: geoState(v.geoipCity),
    geoipAsn: geoState(v.geoipAsn),
    geoipAnonymous: geoState(v.geoipAnonymous),
    dnsbl: countState(v.dnsblZones),
    breachIntel: countState(v.breachIndicators),
    becObservations:
      v.becObservations === true
        ? 'available'
        : v.becObservations === false
          ? 'unavailable'
          : 'unknown',
    providers: Array.isArray(v.providers)
      ? v.providers.filter((p): p is string => typeof p === 'string' && /^[a-z0-9_]{1,32}$/.test(p))
      : [],
  };
  const flags: Partial<Record<StaticCapability, boolean>> = {
    geoip_city: view.geoipCity === 'available',
    geoip_asn: view.geoipAsn === 'available',
    geoip_anonymous: view.geoipAnonymous === 'available',
    dnsbl: view.dnsbl === 'available',
    breach_intel: view.breachIntel === 'available',
    bec_observations: view.becObservations === 'available',
  };
  return { view, set: capabilitySet(flags, view.providers), known: true };
}

export function accountSummary(row: AccountRow): AccountSummaryView {
  return {
    id: row.publicId,
    kind: row.kind,
    address: row.address,
    displayName: row.displayName,
    domainId: row.domainPublicId,
    status: row.status,
    riskScore: row.riskScore,
    riskLevel: row.riskLevel,
    riskUpdatedAt: iso(row.riskUpdatedAt),
    lastSignalAt: iso(row.lastSignalAt),
    firstSeenAt: row.firstSeenAt.toISOString(),
    lastSeenAt: row.lastSeenAt.toISOString(),
    protected: row.protected,
    activeIncident: row.activeIncident
      ? {
          id: row.activeIncident.publicId,
          severity: row.activeIncident.severity as 'low' | 'medium' | 'high' | 'critical',
          status: row.activeIncident.status as 'open' | 'investigating' | 'confirmed' | 'mitigated',
        }
      : null,
    override:
      row.override && row.override.clearedAt === null
        ? { verdict: row.override.verdict, expiresAt: row.override.expiresAt.toISOString() }
        : null,
  };
}

/** One-line summary of a stored `ato-score/1` explanation (rule titles and contributions). */
export function explanationText(stored: unknown, score: number, level: string): string | null {
  if (stored === null || typeof stored !== 'object') return null;
  const top = (stored as { top?: unknown }).top;
  const parts = Array.isArray(top)
    ? top.slice(0, 10).flatMap((c: unknown) => {
        const x = c as { code?: unknown; contribution?: unknown };
        return typeof x.code === 'string'
          ? [`${ruleTitle(x.code)} +${Number(x.contribution ?? 0)}`]
          : [];
      })
    : [];
  return `Risk ${score} (${level}): ${parts.length > 0 ? parts.join('; ') : 'no active signals'}`;
}

const median = (values: readonly number[]): number => {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor((sorted.length - 1) / 2)] ?? 0;
};
const arr = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
const hist = (v: unknown): number[] => {
  const a = arr<unknown>(v).map((x) => Math.max(0, Math.round(Number(x) || 0)));
  return a.length === 24 ? a : Array<number>(24).fill(0);
};

/** The baseline summary of the account detail (top prefixes, countries, ASNs, devices, volume). */
export function baselineSummary(row: AtoAccountBaseline | null): AccountDetailView['baseline'] {
  if (row === null) return null;
  const b = (row.baseline ?? {}) as Record<string, unknown>;
  const top = <T extends Record<string, unknown>>(v: unknown) =>
    arr<T>(v)
      .slice()
      .sort((x, y) => Number(y.n ?? 0) - Number(x.n ?? 0))
      .slice(0, 10);
  const daily = arr<number>(b.dailyMessages).map(Number);
  const recipients = arr<number>(b.dailyRecipients).map(Number);
  return {
    version: row.version,
    mature: row.mature,
    eventCount: row.eventCount,
    activeDays: row.activeDays,
    windowStart: iso(row.windowStart),
    windowEnd: iso(row.windowEnd),
    rebuiltAt: iso(row.rebuiltAt),
    timeZone: typeof b.timeZone === 'string' ? b.timeZone : 'UTC',
    prefixes: top<{ p: string; n: number }>(b.prefixes).map((x) => ({
      prefix: String(x.p),
      count: Number(x.n),
    })),
    countries: top<{ c: string; n: number }>(b.countries).map((x) => ({
      countryCode: String(x.c),
      count: Number(x.n),
    })),
    asns: top<{ a: number; n: number }>(b.asns).map((x) => ({
      asn: Number(x.a),
      count: Number(x.n),
    })),
    devices: top<{ d: string; n: number }>(b.devices).map((x) => ({
      deviceHash: String(x.d),
      count: Number(x.n),
    })),
    channels: arr<string>(b.channels).filter((c) => typeof c === 'string'),
    hourHistogram: hist(b.hourHistogram),
    messageHourHistogram: hist(b.messageHourHistogram),
    volume: {
      medianDailyMessages: median(daily),
      maxDailyMessages: daily.length === 0 ? 0 : Math.max(...daily),
      medianDailyRecipients: median(recipients),
      maxHourlyMessages: arr<number>(b.maxHourlyMessages).reduce(
        (m, x) => Math.max(m, Number(x) || 0),
        0,
      ),
    },
  };
}

export function restrictionView(row: RestrictionRow): RestrictionView {
  return {
    id: row.publicId,
    kind: row.kind,
    scope: row.scope,
    connectorId: row.connectorPublicId,
    connectorName: row.connectorName,
    mailboxAddress: row.mailboxAddress,
    ipCidr: row.ipCidr,
    mode: row.mode,
    status: row.status,
    reasonCode: row.reasonCode,
    responseId: row.responsePublicId,
    startsAt: row.startsAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    liftedAt: iso(row.liftedAt),
    liftReason: row.liftReason,
  };
}

export function accountDetail(
  row: AccountRow,
  extras: {
    restrictions: RestrictionRow[];
    baseline: AtoAccountBaseline | null;
    trustedContexts: Array<AtoTrustedContext & { incidentPublicId: string | null }>;
    linked: Array<{
      publicId: string;
      kind: AccountRow['kind'];
      riskLevel: AccountRow['riskLevel'];
    }>;
    identities: AtoAccountIdentity[];
  },
  capabilities: CapabilitiesView,
): AccountDetailView {
  const o = row.override && row.override.clearedAt === null ? row.override : null;
  return {
    ...accountSummary(row),
    rowVersion: row.rowVersion,
    explanation: {
      text: explanationText(row.riskExplanation, row.riskScore, row.riskLevel),
      structured: row.riskExplanation ?? null,
    },
    overrideDetail: o
      ? {
          id: o.publicId,
          verdict: o.verdict,
          reason: o.reason,
          expiresAt: o.expiresAt.toISOString(),
          createdAt: o.createdAt.toISOString(),
          contradictedAt: iso(o.contradictedAt),
        }
      : null,
    protection: { protected: row.protected, reason: row.protectedReason, at: iso(row.protectedAt) },
    restrictions: extras.restrictions.map(restrictionView),
    baseline: baselineSummary(extras.baseline),
    trustedContexts: extras.trustedContexts.map(trustedContextView),
    linkedAccounts: extras.linked.map((l) => ({
      id: l.publicId,
      kind: l.kind,
      riskLevel: l.riskLevel,
    })),
    identities: extras.identities.map((i) => ({
      provider: i.provider,
      userPrincipalName: i.userPrincipalName,
      firstSeenAt: i.firstSeenAt.toISOString(),
      lastSeenAt: i.lastSeenAt.toISOString(),
    })),
    capabilities,
  };
}

export function trustedContextView(
  c: AtoTrustedContext & { incidentPublicId: string | null },
): AccountDetailView['trustedContexts'][number] {
  return {
    id: c.publicId,
    kind: c.kind,
    value: c.value,
    reason: c.reason,
    source: c.source,
    incidentId: c.incidentPublicId,
    createdAt: c.createdAt.toISOString(),
    expiresAt: c.expiresAt.toISOString(),
  };
}

export function signalView(row: SignalRow): SignalView {
  const evidence =
    row.evidence !== null && typeof row.evidence === 'object' && !Array.isArray(row.evidence)
      ? (row.evidence as Record<string, unknown>)
      : {};
  return {
    id: opaqueRef('signal', row.id, row.detectedAt),
    ruleCode: row.ruleCode,
    title: ruleTitle(row.ruleCode),
    category: row.category,
    strength: row.strength,
    weight: row.weight,
    status: row.status,
    occurrences: row.occurrences,
    detectedAt: row.detectedAt.toISOString(),
    firstOccurredAt: row.firstOccurredAt.toISOString(),
    lastOccurredAt: row.lastOccurredAt.toISOString(),
    explanation: renderExplanation(row.ruleCode, evidence),
    evidence,
    sourceKind: row.sourceKind,
    incidentId: row.incidentPublicId,
    rulesVersion: row.rulesVersion,
    dismissedAt: iso(row.dismissedAt),
    dismissReason: row.dismissReason,
  };
}

export function authEventView(row: AtoAuthEvent): AuthEventView {
  return {
    id: opaqueRef('auth_event', row.id, row.occurredAt),
    occurredAt: row.occurredAt.toISOString(),
    lastOccurredAt: row.lastOccurredAt.toISOString(),
    source: row.source,
    channel: row.channel,
    outcome: row.outcome,
    failureCode: row.failureCode,
    ipAddress: row.ipAddress,
    ipPrefix: row.ipPrefix,
    geo: {
      status: row.geoStatus,
      countryCode: row.countryCode,
      region: row.region,
      city: row.city,
      latitude: num(row.latitude),
      longitude: num(row.longitude),
      accuracyKm: row.accuracyKm,
    },
    asn: row.asn,
    asnOrg: row.asnOrg,
    anonymizerFlags: row.anonymizerFlags,
    reputation: row.reputation ?? null,
    device: row.deviceHash ? { hash: row.deviceHash, label: row.deviceLabel } : null,
    mechanism: row.mechanism,
    attemptCount: row.attemptCount,
  };
}

export function scoreView(row: AtoRiskScore): ScorePointView {
  return {
    id: opaqueRef('score', row.id, row.computedAt),
    computedAt: row.computedAt.toISOString(),
    score: row.score,
    level: row.level,
    previousScore: row.previousScore,
    previousLevel: row.previousLevel,
    trigger: row.trigger,
    explanation: row.explanation ?? null,
    scorerVersion: row.scorerVersion,
    rulesVersion: row.rulesVersion,
    settingsVersion: row.settingsVersion,
  };
}

export function activityView(
  accountPublicId: string,
  range: { from: Date; to: Date },
  rows: AtoAccountActivityDaily[],
): ActivityView {
  return {
    account: accountPublicId,
    from: range.from.toISOString(),
    to: range.to.toISOString(),
    days: rows.map((r) => ({
      day: r.dayStart.toISOString(),
      authSuccess: r.authSuccess,
      authFailure: r.authFailure,
      messages: r.messages,
      recipients: r.recipients,
      externalRecipients: r.externalRecipients,
      internalRecipients: r.internalRecipients,
      attachments: r.attachments,
      findings: r.findings,
      maxHourMessages: r.maxHourMessages,
      topRecipientDomains: arr<{ d: unknown; n: unknown }>(r.recipientDomains)
        .filter((x) => typeof x.d === 'string')
        .sort((a, b) => Number(b.n) - Number(a.n))
        .slice(0, 10)
        .map((x) => ({ domain: String(x.d), count: Number(x.n) || 0 })),
      content:
        r.content !== null && typeof r.content === 'object' && !Array.isArray(r.content)
          ? (r.content as Record<string, unknown>)
          : {},
    })),
  };
}

/** What the caller may do with an action (portal buttons). */
export interface ResponseAbilities {
  /** Principal is a user with `ato:respond` and an MFA session (decide/rollback rules). */
  userWithMfaAndRespond: boolean;
  /** The caller's public id (users) or API key public id. */
  callerPublicId: string;
}

export function responseView(
  row: ResponseRow,
  connectorPublicIds: ReadonlyMap<string, string>,
  abilities: ResponseAbilities,
): ResponseActionView {
  const target = (row.target ?? {}) as Record<string, unknown>;
  const params = (row.params ?? {}) as Record<string, unknown>;
  const connectorId = typeof target.connectorId === 'string' ? target.connectorId : null;
  const rollbackTypes = [
    'restrict_smtp_sending',
    'block_smtp_auth',
    'require_mfa',
    'suspend_account',
    'remove_forwarding_rule',
  ];
  return {
    id: row.publicId,
    actionType: row.actionType as ResponseActionView['actionType'],
    provider: row.provider,
    impact: row.impact,
    status: row.status,
    requiresApproval: row.requiresApproval,
    authorization: row.authorization,
    incidentId: row.incidentPublicId,
    account: { id: row.accountPublicId, kind: row.accountKind },
    target: {
      scope: (typeof target.scope === 'string'
        ? target.scope
        : 'account') as ResponseActionView['target']['scope'],
      connectorId: connectorId ? (connectorPublicIds.get(connectorId) ?? null) : null,
      cidr: typeof target.cidr === 'string' ? target.cidr : null,
    },
    params: {
      durationMinutes: typeof params.durationMinutes === 'number' ? params.durationMinutes : null,
      mode: params.mode === 'reject' || params.mode === 'defer' ? params.mode : null,
      description: typeof params.description === 'string' ? params.description : null,
    },
    requestedBy: { type: row.requestedByType, id: row.requestedByPublicId },
    requestReason: row.requestReason,
    approvedBy: row.approvedByPublicId,
    decidedAt: iso(row.decidedAt),
    decisionReason: row.decisionReason,
    approvalExpiresAt: iso(row.approvalExpiresAt),
    executedAt: iso(row.executedAt),
    completedAt: iso(row.completedAt),
    effectiveUntil: iso(row.effectiveUntil),
    providerReference: row.providerReference,
    providerStatus: row.providerStatus,
    resultCode: row.resultCode,
    attemptCount: row.attempts,
    rollbackReason: row.rollbackReason,
    canDecide:
      row.status === 'pending_approval' &&
      abilities.userWithMfaAndRespond &&
      !(row.requestedByType === 'user' && row.requestedByPublicId === abilities.callerPublicId) &&
      row.requestedByKeyCreatorPublicId !== abilities.callerPublicId,
    canRollback:
      row.status === 'succeeded' &&
      abilities.userWithMfaAndRespond &&
      rollbackTypes.includes(row.actionType),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function attemptView(row: AtoResponseActionLog) {
  return {
    phase: row.phase,
    attemptNo: row.attemptNo,
    outcome: row.outcome,
    providerStatus: row.providerStatus,
    errorCode: row.errorCode,
    durationMs: row.durationMs,
    at: row.createdAt.toISOString(),
  };
}
