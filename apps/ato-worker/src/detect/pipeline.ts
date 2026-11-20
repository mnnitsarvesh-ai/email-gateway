import {
  type AtoStore,
  type AtoWindows,
  baselineView,
  capabilitySet,
  evaluateCorrelation,
  evaluateRules,
  parseBaseline,
  type AccountSnapshot,
  type AccountSubject,
  type ActivityDelta,
  type AuthEventInput,
  type BaselineView,
  type CapabilitySet,
  type EvidenceRefs,
  type GeoView,
  type LoadedSettings,
  type Observation,
  type PersistedSignal,
  type SeenToday,
  type SignalCandidate,
  type WindowSnapshot,
  atoSubjectHash,
} from '@email-gateway/ato-detection';
import { normalizeAtoMailboxAddress } from '@email-gateway/security-contracts';
import type { AtoAccount, AtoRiskSignal } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { Enricher } from '../enrichment/enricher';
import type { AtoGeoIp } from '../enrichment/geoip';
import type { AtoReputation } from '../enrichment/reputation';
import type { AtoMetrics } from '../metrics/ato-metrics';
import type { ProviderContextCache } from '../provider/provider-context';
import type { OrgContext } from '../reads/org-context';
import type { Db, Tx } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

/** Capabilities known to the worker (D17); the breach flag is refreshed by the maintenance role. */
export class WorkerCapabilities {
  breachIndicators = 0;

  constructor(
    private readonly geo: AtoGeoIp,
    private readonly reputation: AtoReputation,
  ) {}

  forStreams(providerStreams: readonly string[]): CapabilitySet {
    return capabilitySet(
      {
        geoip_city: this.geo.loaded('city'),
        geoip_asn: this.geo.loaded('asn'),
        geoip_anonymous: this.geo.loaded('anonymous'),
        dnsbl: this.reputation.dnsblConfigured,
        breach_intel: this.breachIndicators > 0,
        bec_observations: true,
      },
      providerStreams,
    );
  }
}

/** What a source handler asks the pipeline to detect for one account (D3, D9–D13). */
export interface DetectRequest {
  org: OrgContext;
  subject: AccountSubject;
  domainId?: bigint | null;
  /** Builds the observation from what the pipeline read (account, baseline view, seen today). */
  observation: (ctx: {
    account: AtoAccount;
    baseline: BaselineView;
    seen: SeenToday;
    breachListed: boolean | null;
  }) => Observation;
  /** The `ato_auth_events` row of an authentication observation (account filled in here). */
  authEvent?: Omit<AuthEventInput, 'organizationId' | 'accountId'> | null;
  /** The day-row delta of this observation, from the window snapshot (D9). */
  activity?: ((snapshot: WindowSnapshot, observation: Observation) => ActivityDelta | null) | null;
  /** A successful authentication: its location becomes the account's last success (G2). */
  success?: { geo: GeoView | null; trusted: boolean } | null;
  /** The account address checked against platform breach indicators (T4). */
  breachAddress?: string | null;
  /** Other located sessions / successes of the account in G3's window (users). */
  concurrentLocations?: AuthConcurrentLocations;
  /** Messages linked to an incident as evidence. */
  messages?: readonly { id: bigint; receivedAt: Date }[];
  /**
   * PX3 (step 8.5, D8.2): a historical observation (backfilled or initial-sweep provider event).
   * Signals are recorded `informational`; no rescoring, incident, response, notification or
   * same-day novelty mark follows. Auth events, day rows and the last success are still written.
   */
  historical?: boolean;
}

export type AuthConcurrentLocations = (account: AtoAccount) => Promise<
  {
    country: string;
    latitude: number;
    longitude: number;
    accuracyKm: number;
    at: Date;
  }[]
>;

/** The result of the unlocked phase: everything the short writer transaction needs. */
export interface PreparedDetection {
  req: DetectRequest;
  settings: LoadedSettings;
  account: AtoAccount;
  observation: Observation;
  candidates: SignalCandidate[];
  delta: ActivityDelta | null;
  providerKind: string | null;
  providerActions: ReadonlySet<string>;
  at: Date;
}

export interface DetectOutcome {
  account: AtoAccount;
  observation: Observation;
  created: AtoRiskSignal[];
  duplicates: number;
  incidentOpened: boolean;
  incidentEscalated: boolean;
}

/** Work done after the transaction committed (novelty marks, last success, metrics). */
export type AfterCommit = () => Promise<void>;

/** An account's `last_seen_at` is refreshed at most this often (one row write per minute). */
const LAST_SEEN_REFRESH_MS = 60_000;

/**
 * The detection pipeline (D3, D8–D13) in two phases so that the writer transaction stays short
 * (§9 "hot accounts": short transactions, lock only when signals exist):
 *
 * - `prepare` (no transaction, no row lock held): settings (created with the defaults on the first
 *   event, PO1), the account (created on first sight; `last_seen_at` refreshed at most once a
 *   minute), the baseline view, today's seen sets, the idempotent Redis windows (keyed by the
 *   observation, so a retried event never counts twice) and their snapshot, the last success,
 *   trusted contexts and the pure rule evaluation;
 * - `commit` (inside the caller's ledger transaction): the auth event row, the day row, and only
 *   when rules fired: signals deduplicated under the account lock, correlation over the recent
 *   signals of the account and its linked accounts, rescoring, the incident policy and automation.
 *
 * Same-day novelty marks and the last success location are written after the commit (`after`), so
 * a rolled-back transaction never suppresses a later signal.
 */
export class DetectionPipeline {
  constructor(
    private readonly deps: {
      store: AtoStore;
      windows: AtoWindows;
      enricher: Enricher;
      capabilities: WorkerCapabilities;
      providers: ProviderContextCache;
      metrics: AtoMetrics | null;
      logger: Logger;
      now: () => Date;
    },
  ) {}

  /** The organization's settings (created with the defaults on the first event, PO1). */
  async settings(db: Db, organizationId: bigint): Promise<LoadedSettings> {
    const loaded = await this.deps.store.loadSettings(db, organizationId);
    return loaded ?? this.deps.store.ensureSettings(db, organizationId);
  }

  /** The account of a subject: read first, created or refreshed (upsert) only when needed. */
  private async account(db: Db, req: DetectRequest, now: Date): Promise<AtoAccount> {
    const s = req.subject;
    const subjectHash =
      s.kind === 'mailbox'
        ? atoSubjectHash('mailbox', normalizeAtoMailboxAddress(s.address))
        : s.kind === 'gateway_user'
          ? atoSubjectHash('user', s.userId)
          : atoSubjectHash('connector', s.connectorId);
    const existing = await db.atoAccount.findUnique({
      where: {
        organizationId_kind_subjectHash: {
          organizationId: req.org.id,
          kind: s.kind,
          subjectHash,
        },
      },
    });
    if (
      existing &&
      existing.status === 'active' &&
      existing.lastSeenAt.getTime() >= now.getTime() - LAST_SEEN_REFRESH_MS
    ) {
      return existing;
    }
    let account = await this.deps.store.ensureAccount(db, {
      organizationId: req.org.id,
      subject: req.subject,
      domainId: req.domainId ?? null,
      at: now,
    });
    if (account.status === 'retired') {
      account = await db.atoAccount.update({
        where: { id: account.id },
        data: { status: 'active' },
      });
    }
    return account;
  }

  /** Phase 1 (no transaction): reads, Redis windows and the pure rule evaluation. */
  async prepare(db: Db, req: DetectRequest): Promise<PreparedDetection> {
    const { store, windows } = this.deps;
    const now = this.deps.now();
    const orgId = req.org.id;
    const settings = await this.settings(db, orgId);
    const account = await this.account(db, req, now);
    if (account.organizationId !== orgId) throw new InconsistentReadError('ato_account');
    const wa = { organizationId: orgId, accountId: account.id };
    const baselineRow = await db.atoAccountBaseline.findUnique({
      where: { accountId: account.id },
    });
    if (baselineRow && baselineRow.organizationId !== orgId) {
      throw new InconsistentReadError('ato_account_baseline');
    }
    const baseline = baselineView(parseBaseline(baselineRow?.baseline ?? null));
    const seen = await windows.seenToday(wa);
    const breachListed = req.breachAddress
      ? await this.deps.enricher.breachListed(orgId, account.id, req.breachAddress)
      : null;
    let observation = req.observation({ account, baseline, seen, breachListed });
    if (
      observation.type === 'auth' &&
      req.concurrentLocations &&
      observation.outcome === 'success'
    ) {
      observation = { ...observation, concurrentLocations: await req.concurrentLocations(account) };
    }
    // Idempotent windows (per observation key and account), then the snapshot at the event time.
    await windows.record(observation.key, wa, observation, now);
    const at = observation.occurredAt < now ? observation.occurredAt : now;
    const snapshot = await windows.snapshot(wa, observation, at);
    const providerCtx = await this.deps.providers.get(orgId);
    const snapshotAccount: AccountSnapshot = {
      id: account.id,
      publicId: account.publicId,
      kind: account.kind,
      lastSuccess: await this.lastSuccess(account),
    };
    const trustedContexts = await store.trustedContexts(db, orgId, account.id);
    const candidates = evaluateRules(
      {
        observation,
        account: snapshotAccount,
        baseline,
        windows: snapshot,
        seen,
        context: {
          now,
          learning: settings.learning,
          timeZone: req.org.timeZone,
          trustedNetworks: settings.settings.ipReputation.trustedNetworks,
          trustedContexts,
          historical: req.historical === true,
        },
      },
      settings.settings,
      this.deps.capabilities.forStreams(providerCtx.streams),
    );
    return {
      req,
      settings,
      account,
      observation,
      candidates,
      delta: req.activity ? req.activity(snapshot, observation) : null,
      providerKind: providerCtx.kind,
      providerActions: providerCtx.actions,
      at: now,
    };
  }

  /** Both phases in the caller's transaction (provider pages, which run in one transaction). */
  async run(tx: Tx, req: DetectRequest, after: AfterCommit[]): Promise<DetectOutcome> {
    return this.commit(tx, await this.prepare(tx, req), after);
  }

  /** Phase 2 (inside the ledger transaction): rows, signals, scoring, incident, automation. */
  async commit(tx: Tx, p: PreparedDetection, after: AfterCommit[]): Promise<DetectOutcome> {
    const { store, windows } = this.deps;
    const { req, settings } = p;
    const now = p.at;
    const orgId = req.org.id;
    let account = p.account;
    const wa = { organizationId: orgId, accountId: account.id };
    let observation = p.observation;

    // The auth event row: its reference becomes evidence of the signals.
    let authRef: { id: bigint; occurredAt: Date } | null = null;
    // An individual auth event recorded before (same dedupe key, e.g. a provider event read again
    // after the seen-set expired) was already counted in the day row: its delta is not applied
    // twice. Aggregate rows (successes) count every attempt, so their delta always applies.
    let repeated = false;
    if (req.authEvent && observation.type === 'auth') {
      const recorded = await store.recordAuthEvent(tx, {
        ...req.authEvent,
        organizationId: orgId,
        accountId: account.id,
      });
      repeated = !recorded.created && req.authEvent.aggregate !== true;
      authRef = { id: recorded.id, occurredAt: recorded.occurredAt };
      observation = { ...observation, authEventRef: authRef };
    }
    const candidates = p.candidates.map((c) =>
      authRef && c.sourceKind === 'auth_event' ? { ...c, authEventRef: authRef } : c,
    );
    if (p.delta && !repeated) {
      await store.upsertActivityDay(tx, {
        organizationId: orgId,
        accountId: account.id,
        delta: p.delta,
      });
    }
    if (req.success && observation.type === 'auth') {
      const geo = req.success.geo;
      const last = {
        at: observation.occurredAt.toISOString(),
        country: geo?.country ?? null,
        latitude: geo?.latitude ?? null,
        longitude: geo?.longitude ?? null,
        accuracyKm: geo?.accuracyKm ?? null,
        anonymizerFlags: geo?.anonymizerFlags ?? null,
        trusted: req.success.trusted,
      };
      const previous = account.lastAuthSuccessAt;
      if (!previous || previous <= observation.occurredAt) {
        await store.recordAuthSuccess(tx, {
          organizationId: orgId,
          accountId: account.id,
          at: observation.occurredAt,
          geo: last,
        });
        after.push(() => windows.setLastSuccess(wa, last));
      }
    }

    const outcome: DetectOutcome = {
      account,
      observation,
      created: [],
      duplicates: 0,
      incidentOpened: false,
      incidentEscalated: false,
    };
    if (candidates.length === 0) return outcome;

    // Signals under the account lock (dedupe is authoritative here, D8).
    const [locked] = await store.lockAccounts(tx, orgId, [account.id]);
    account = locked!;
    const recorded = await store.recordSignals(tx, {
      organizationId: orgId,
      account,
      candidates,
      settingsVersion: settings.version,
      at: now,
    });
    const created = [...recorded.created];
    let duplicates = recorded.duplicates.length;

    // PX3: a historical observation stops here (its signals are informational): no correlation,
    // rescoring, incident, automation, notification or novelty mark.
    if (req.historical === true) {
      const metrics = this.deps.metrics;
      after.push(() => {
        for (const s of created)
          metrics?.signals.inc({ category: s.category, strength: s.strength });
        return Promise.resolve();
      });
      return { ...outcome, account, created, duplicates };
    }

    // Correlation over the recent signals of the account and its linked accounts (same address).
    const fresh = recorded.created.filter((s) => s.status === 'active');
    if (fresh.length > 0) {
      const correlation = await this.correlate(tx, account, settings, candidates, fresh, now);
      if (correlation.length > 0) {
        const more = await store.recordSignals(tx, {
          organizationId: orgId,
          account,
          candidates: correlation,
          settingsVersion: settings.version,
          at: now,
        });
        created.push(...more.created);
        duplicates += more.duplicates.length;
      }
    }

    const rescore = await store.rescore(tx, {
      organizationId: orgId,
      accountId: account.id,
      trigger: 'signal',
      settings,
    });
    const contributorIps = new Map<string, string>();
    if (observation.type === 'auth' && observation.ip) {
      for (const s of created) contributorIps.set(s.ruleCode, observation.ip);
    }
    const evidence: EvidenceRefs = {
      signals: created
        .filter((s) => s.status === 'active')
        .map((s) => ({ id: s.id, detectedAt: s.detectedAt })),
      authEvents: authRef ? [authRef] : [],
      messages: req.messages ?? [],
      codes: created.map((s) => s.ruleCode),
    };
    // Automatic medium/high responses are capped per organization and hour (D13): when this
    // detection could run one, serialize on the organization's automation row now, before the
    // incident policy takes the organization's notification windows (one lock order).
    if (store.automationMayExecute(settings, rescore.result.level)) {
      await store.lockAutomation(tx, orgId);
    }
    const policy = await store.applyIncidentPolicy(tx, {
      organizationId: orgId,
      accountId: account.id,
      rescore,
      settings,
      evidence,
      newStrongSignal: created.some((s) => s.status === 'active' && s.strength === 'strong'),
      context: {
        hasAtoPolicyRule: req.org.hasAtoPolicyRule,
        providerActions: p.providerActions,
        contributorIps,
      },
    });
    let automation: Awaited<ReturnType<AtoStore['runAutomation']>> = [];
    if (policy.incident && (policy.opened || policy.escalated)) {
      automation = await store.runAutomation(tx, {
        organizationId: orgId,
        accountId: account.id,
        incident: policy.incident,
        recommendations: policy.recommendations,
        contributors: policy.contributors,
        settings,
        platformOrganization: req.org.kind === 'platform',
        providerKind: p.providerKind,
      });
    }

    // After the commit: same-day novelty marks of persisted signals, metrics.
    const marks = candidates
      .filter((c) => c.seen && created.some((s) => s.dedupeKey === c.dedupeKey))
      .map((c) => c.seen!);
    const metrics = this.deps.metrics;
    const incident = policy.incident;
    after.push(async () => {
      for (const m of marks) await windows.rememberSeen(wa, m.kind, m.value);
      if (!metrics) return;
      for (const s of created) metrics.signals.inc({ category: s.category, strength: s.strength });
      if (policy.opened && incident) metrics.incidentsOpened.inc({ severity: incident.severity });
      for (const a of automation) {
        if (a.guard) metrics.automationGuard.inc({ reason: a.guard });
        if (a.action) metrics.responses.inc({ action: a.actionType, outcome: a.action.status });
      }
    });
    return {
      account,
      observation,
      created,
      duplicates,
      incidentOpened: policy.opened,
      incidentEscalated: policy.escalated,
    };
  }

  private async lastSuccess(account: AtoAccount): Promise<AccountSnapshot['lastSuccess']> {
    const fromRedis = await this.deps.windows.lastSuccess({
      organizationId: account.organizationId,
      accountId: account.id,
    });
    const raw =
      fromRedis ??
      (account.lastAuthGeo && typeof account.lastAuthGeo === 'object'
        ? (account.lastAuthGeo as unknown as typeof fromRedis)
        : null);
    if (!raw || typeof raw.at !== 'string') return null;
    const at = new Date(raw.at);
    if (Number.isNaN(at.getTime())) return null;
    return {
      at,
      country: raw.country ?? null,
      latitude: raw.latitude ?? null,
      longitude: raw.longitude ?? null,
      accuracyKm: raw.accuracyKm ?? null,
      anonymizerFlags: raw.anonymizerFlags ?? null,
      trusted: raw.trusted === true,
    };
  }

  private async correlate(
    tx: Tx,
    account: AtoAccount,
    settings: LoadedSettings,
    candidates: readonly SignalCandidate[],
    fresh: readonly AtoRiskSignal[],
    now: Date,
  ): Promise<SignalCandidate[]> {
    const linked = account.address
      ? await tx.atoAccount.findMany({
          where: {
            organizationId: account.organizationId,
            address: account.address,
            id: { not: account.id },
          },
          select: { id: true },
          take: 5,
        })
      : [];
    const freshIds = new Set(fresh.map((s) => s.id));
    const recent = await this.deps.store.recentSignals(
      tx,
      account.organizationId,
      [account.id, ...linked.map((l) => l.id)],
      settings.settings,
      now,
    );
    const persisted: PersistedSignal[] = recent
      .filter((s) => !freshIds.has(s.id))
      .map((s) => ({
        id: s.id,
        accountId: s.accountId,
        code: s.ruleCode,
        category: s.category,
        strength: s.strength,
        weight: s.weight,
        status: s.status,
        firstOccurredAt: s.firstOccurredAt,
        lastOccurredAt: s.lastOccurredAt,
      }));
    const successes = await tx.atoAuthEvent.findMany({
      where: {
        organizationId: account.organizationId,
        accountId: account.id,
        outcome: 'success',
        occurredAt: { gte: new Date(now.getTime() - 2 * 3_600_000) },
      },
      select: { lastOccurredAt: true },
      orderBy: { occurredAt: 'desc' },
      take: 50,
    });
    const freshCandidates = candidates
      .filter((c) => fresh.some((s) => s.dedupeKey === c.dedupeKey))
      .map((c) => ({ ...c, occurredAt: now }));
    return evaluateCorrelation(
      {
        account: { id: account.id, kind: account.kind },
        recent: persisted,
        fresh: freshCandidates,
        successTimes: successes.map((s) => s.lastOccurredAt),
        now,
      },
      settings.settings,
    );
  }
}
