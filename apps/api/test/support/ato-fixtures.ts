/**
 * The in-memory account takeover and security incident world of the step 8.4 e2e suites
 * (docs/plan/steps/24-account-takeover-core.md §10.4): doubles of the two read repositories, the
 * account version repository and the transactional stores (`IncidentStores`: a category registry
 * with an in-memory ATO handler, an `IncidentStore` double enforcing the shared state machine with
 * the library's `checkTransition`, an `AtoStore` double enforcing the response state machine, the
 * four-eyes rule and the settings schema). Errors are the libraries' own coded errors, so the api's
 * mapping is exercised. The real writer, replica and stores run in the integration suites.
 * Nothing here is used by production code.
 */
import { randomUUID } from 'node:crypto';
import type { TestingModuleBuilder } from '@nestjs/testing';
import {
  AtoStoreError,
  atoIncidentFeedbackSchema,
  atoSettingsSchema,
  impactFor,
  normalizeAtoSettings,
  RESPONSE_CATALOGUE,
  type ResponseActionType,
  type ResponseTarget,
  supportsRollback,
} from '@email-gateway/ato-detection';
import type {
  AtoAccount,
  AtoAuthEvent,
  AtoResponseAction,
  AtoResponseActionLog,
  AtoRiskScore,
  AtoRiskSignal,
  AtoSmtpRestriction,
  AtoTrustedContext,
  SecurityIncident,
  SecurityIncidentEvent,
} from '@email-gateway/database';
import {
  checkTransition,
  IncidentActiveConflictError,
  type IncidentActor,
  type IncidentCategoryHandler,
  IncidentCategoryRegistry,
  IncidentError,
  type IncidentReport,
  IncidentVersionConflictError,
  isTerminalIncidentStatus,
  normalizeNote,
} from '@email-gateway/security-incidents';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import { AuditService } from '../../src/audit/audit.service';
import { atoNotEnabled } from '../../src/modules/ato/ato.errors';
import { AtoAccountVersionRepository } from '../../src/modules/ato/repositories/ato-account-version.repository';
import {
  type AccountFilters,
  type AccountKey,
  type AccountRow,
  type AccountSort,
  AtoReadRepository,
  type OverviewCounts,
  type ResponseFilters,
  type ResponseRow,
  type RestrictionFilters,
  type RestrictionRow,
  type SignalRow,
  type TimeKey,
} from '../../src/modules/ato/repositories/ato-read.repository';
import type { IncidentCategoryDefinition } from '../../src/modules/incidents/incident-categories';
import { IncidentStores } from '../../src/modules/incidents/incident-stores';
import {
  type IncidentFilters,
  type IncidentKey,
  type IncidentListRow,
  type IncidentMessageRow,
  IncidentsReadRepository,
  type IncidentSort,
} from '../../src/modules/incidents/repositories/incidents-read.repository';
import { OrganizationFeaturesService } from '../../src/tenancy/organization-features.service';
import { RecordingAuditService } from './messages-fixtures';

const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
const ACTIVE = ['open', 'investigating', 'confirmed', 'mitigated'];
const own = (scope: TenantScope) => scope.organizationId;
const byTimeDesc =
  <T>(at: (r: T) => Date, id: (r: T) => bigint) =>
  (a: T, b: T) =>
    at(b).getTime() - at(a).getTime() || (id(b) > id(a) ? 1 : id(b) < id(a) ? -1 : 0);
const beforeKey = (at: Date, id: bigint, key: TimeKey | undefined) =>
  key === undefined || at < key.at || (at.getTime() === key.at.getTime() && id < key.id);

/** The world every double reads and writes. */
export class AtoWorld {
  private seq = 1000n;
  accounts: AtoAccount[] = [];
  signals: AtoRiskSignal[] = [];
  authEvents: AtoAuthEvent[] = [];
  scores: AtoRiskScore[] = [];
  contexts: AtoTrustedContext[] = [];
  overrides: Array<{
    id: bigint;
    publicId: string;
    organizationId: bigint;
    accountId: bigint;
    verdict: 'benign' | 'compromised';
    reason: string;
    expiresAt: Date;
    createdAt: Date;
    contradictedAt: Date | null;
    clearedAt: Date | null;
  }> = [];
  restrictions: AtoSmtpRestriction[] = [];
  responses: AtoResponseAction[] = [];
  /** API key public id → public id of the user who created it (`api_keys.created_by_user_id`). */
  apiKeyCreators = new Map<string, string>();
  attempts: AtoResponseActionLog[] = [];
  incidents: SecurityIncident[] = [];
  events: SecurityIncidentEvent[] = [];
  links: Array<{
    organizationId: bigint;
    incidentId: bigint;
    linkType: string;
    refId: bigint;
    refTime: Date;
  }> = [];
  settings = new Map<
    bigint,
    {
      settings: unknown;
      version: number;
      rowVersion: number;
      learningStartedAt: Date;
      updatedAt: Date;
    }
  >();
  users: Array<{ id: bigint; publicId: string; organizationId: bigint; active: boolean }> = [];
  featureOff = new Set<bigint>();
  capabilities: { value: unknown; updatedAt: Date } | null = null;
  messages: IncidentMessageRow[] = [];
  messageLinks = new Map<bigint, bigint[]>();

  id(): bigint {
    this.seq += 1n;
    return this.seq;
  }

  reset(): void {
    for (const key of Object.keys(this) as Array<keyof this>) {
      const v = this[key];
      if (Array.isArray(v)) (v as unknown[]).length = 0;
      else if (v instanceof Map || v instanceof Set) v.clear();
    }
    this.capabilities = null;
  }

  addUser(organizationId: bigint, publicId: string = randomUUID()) {
    const user = { id: this.id(), publicId, organizationId, active: true };
    this.users.push(user);
    return user;
  }

  addAccount(organizationId: bigint, over: Partial<AtoAccount> = {}): AtoAccount {
    const now = new Date();
    const row: AtoAccount = {
      id: this.id(),
      publicId: randomUUID(),
      organizationId,
      kind: 'mailbox',
      subjectHash: 'a'.repeat(64),
      address: `user${this.seq}@corp.example`,
      domainId: null,
      userId: null,
      connectorId: null,
      status: 'active',
      protected: false,
      protectedReason: null,
      protectedByUserId: null,
      protectedAt: null,
      riskScore: 20,
      riskLevel: 'low',
      riskUpdatedAt: now,
      riskExplanation: { top: [{ code: 'ato.geo.impossible_travel', contribution: 20 }] },
      lastSignalAt: now,
      activeIncidentId: null,
      overrideId: null,
      firstSeenAt: new Date(now.getTime() - 30 * 86_400_000),
      lastSeenAt: now,
      lastAuthSuccessAt: null,
      lastAuthGeo: null,
      rowVersion: 1,
      createdAt: now,
      updatedAt: now,
      ...over,
    };
    this.accounts.push(row);
    return row;
  }

  addIncident(
    organizationId: bigint,
    account: AtoAccount,
    over: Partial<SecurityIncident> = {},
  ): SecurityIncident {
    const now = new Date();
    const row = {
      id: this.id(),
      publicId: randomUUID(),
      organizationId,
      category: 'account_takeover',
      subjectType: 'ato_account',
      subjectRefId: account.id,
      subjectRefTime: null,
      subjectPublicId: account.publicId,
      origin: 'detection',
      status: 'open',
      severity: 'high',
      titleCode: 'ato.geo.impossible_travel',
      reasonCodes: ['ato.geo.impossible_travel'],
      detectorVersion: 'ato-rules/1',
      detectedAt: now,
      firstEvidenceAt: new Date(now.getTime() - 60_000),
      lastEvidenceAt: now,
      evidenceCount: 2,
      assignedUserId: null,
      assignedAt: null,
      escalatedAt: null,
      confirmedAt: null,
      mitigatedAt: null,
      resolvedAt: null,
      resolvedByUserId: null,
      resolutionCode: null,
      resolutionNote: null,
      lastUpdateEventAt: null,
      createdByType: 'system',
      createdById: null,
      activeMarker: 1,
      rowVersion: 1,
      createdAt: now,
      updatedAt: now,
      ...over,
    } as SecurityIncident;
    this.incidents.push(row);
    account.activeIncidentId = row.id;
    this.event(row, 'created', { type: 'system', id: null });
    return row;
  }

  event(
    incident: SecurityIncident,
    eventType: string,
    actor: IncidentActor,
    extra: Partial<SecurityIncidentEvent> = {},
  ): SecurityIncidentEvent {
    const row = {
      id: this.id(),
      organizationId: incident.organizationId,
      incidentId: incident.id,
      eventType,
      actorType: actor.type,
      actorId: actor.id,
      fromStatus: null,
      toStatus: null,
      fromSeverity: null,
      toSeverity: null,
      note: null,
      details: null,
      createdAt: new Date(),
      ...extra,
    };
    this.events.push(row);
    return row;
  }

  addSignal(account: AtoAccount, over: Partial<AtoRiskSignal> = {}): AtoRiskSignal {
    const now = new Date();
    const row = {
      id: this.id(),
      detectedAt: now,
      organizationId: account.organizationId,
      accountId: account.id,
      ruleCode: 'ato.geo.impossible_travel',
      category: 'geography',
      strength: 'strong',
      weight: 35,
      status: 'active',
      dedupeKey: 'b'.repeat(64),
      occurrences: 1,
      firstOccurredAt: now,
      lastOccurredAt: now,
      evidence: { country: 'DE' },
      sourceKind: 'auth_event',
      sourceRef: null,
      messageId: null,
      messageReceivedAt: null,
      authEventId: null,
      authEventOccurredAt: null,
      incidentId: account.activeIncidentId,
      rulesVersion: 'ato-rules/1',
      settingsVersion: 1,
      dismissedAt: null,
      dismissedByUserId: null,
      dismissReason: null,
      createdAt: now,
      updatedAt: now,
      ...over,
    } as unknown as AtoRiskSignal;
    this.signals.push(row);
    return row;
  }

  addAuthEvent(account: AtoAccount, over: Partial<AtoAuthEvent> = {}): AtoAuthEvent {
    const now = new Date();
    const row = {
      id: this.id(),
      occurredAt: now,
      organizationId: account.organizationId,
      accountId: account.id,
      source: 'portal_login',
      channel: 'portal',
      outcome: 'success',
      failureCode: null,
      ipAddress: '203.0.113.45',
      ipPrefix: '203.0.113.0/24',
      countryCode: 'DE',
      region: null,
      city: null,
      latitude: null,
      longitude: null,
      accuracyKm: null,
      geoStatus: 'located',
      asn: 64501,
      asnOrg: 'EXAMPLE-AS',
      anonymizerFlags: null,
      reputation: null,
      deviceHash: null,
      deviceLabel: null,
      mechanism: null,
      attemptCount: 1,
      lastOccurredAt: now,
      sourceRef: null,
      dedupeKey: 'c'.repeat(64),
      createdAt: now,
      ...over,
    } as unknown as AtoAuthEvent;
    this.authEvents.push(row);
    return row;
  }

  addResponse(
    account: AtoAccount,
    incident: SecurityIncident | null,
    over: Partial<AtoResponseAction> = {},
  ): AtoResponseAction {
    const now = new Date();
    const row = {
      id: this.id(),
      publicId: randomUUID(),
      organizationId: account.organizationId,
      incidentId: incident?.id ?? null,
      accountId: account.id,
      actionType: 'restrict_smtp_sending',
      provider: 'gateway',
      impact: 'high',
      target: {
        scope: 'mailbox',
        accountPublicId: account.publicId,
        mailboxSha256: 'd'.repeat(64),
      },
      params: { durationMinutes: 240, mode: 'reject' },
      status: 'pending_approval',
      requiresApproval: true,
      authorization: 'manual',
      requestedByType: 'user',
      requestedById: randomUUID(),
      requestReason: 'Impossible travel followed by a burst',
      approvedByUserId: null,
      decidedAt: null,
      decisionReason: null,
      approvalExpiresAt: new Date(now.getTime() + 86_400_000),
      executedAt: null,
      completedAt: null,
      effectiveUntil: null,
      nextCheckAt: null,
      providerReference: null,
      providerStatus: null,
      resultCode: null,
      attempts: 0,
      restrictionId: null,
      rolledBackByUserId: null,
      rollbackReason: null,
      dedupeHash: randomUUID().replace(/-/g, '').padEnd(64, '0'),
      activeMarker: 1,
      rowVersion: 1,
      createdAt: now,
      updatedAt: now,
      ...over,
    } as unknown as AtoResponseAction;
    this.responses.push(row);
    return row;
  }

  accountRow(a: AtoAccount): AccountRow {
    const incident = this.incidents.find((i) => i.id === a.activeIncidentId);
    const o = this.overrides.find((x) => x.id === a.overrideId);
    return {
      ...a,
      domainPublicId: null,
      displayName: null,
      activeIncident:
        incident && ACTIVE.includes(incident.status)
          ? { publicId: incident.publicId, severity: incident.severity, status: incident.status }
          : null,
      override: o
        ? {
            publicId: o.publicId,
            verdict: o.verdict,
            reason: o.reason,
            expiresAt: o.expiresAt,
            createdAt: o.createdAt,
            contradictedAt: o.contradictedAt,
            clearedAt: o.clearedAt,
          }
        : null,
    };
  }

  responseRow(r: AtoResponseAction): ResponseRow {
    const a = this.accounts.find((x) => x.id === r.accountId)!;
    return {
      ...r,
      accountPublicId: a.publicId,
      accountKind: a.kind,
      incidentPublicId: this.incidents.find((i) => i.id === r.incidentId)?.publicId ?? null,
      approvedByPublicId: this.users.find((u) => u.id === r.approvedByUserId)?.publicId ?? null,
      requestedByPublicId: r.requestedById,
      requestedByKeyCreatorPublicId:
        r.requestedByType === 'api_key' && r.requestedById
          ? (this.apiKeyCreators.get(r.requestedById) ?? null)
          : null,
    };
  }

  restrictionRow(r: AtoSmtpRestriction): RestrictionRow {
    return {
      ...r,
      connectorPublicId: null,
      connectorName: null,
      responsePublicId: this.responses.find((x) => x.id === r.responseActionId)?.publicId ?? null,
    };
  }
}

// =================================================================== read repositories

class FakeAtoReads extends AtoReadRepository {
  constructor(private readonly w: AtoWorld) {
    super({} as never);
  }

  private accountsOf(scope: TenantScope, filters: AccountFilters, sort: AccountSort) {
    return this.w.accounts
      .filter((a) => a.organizationId === own(scope))
      .filter((a) => !filters.kinds || filters.kinds.includes(a.kind))
      .filter((a) => !filters.levels || filters.levels.includes(a.riskLevel))
      .filter((a) => filters.minScore === undefined || a.riskScore >= filters.minScore)
      .filter(
        (a) =>
          filters.hasActiveIncident === undefined ||
          (a.activeIncidentId !== null) === filters.hasActiveIncident,
      )
      .filter((a) => filters.protected === undefined || a.protected === filters.protected)
      .filter((a) => filters.q === undefined || (a.address ?? '').startsWith(filters.q))
      .filter((a) => sort !== '-lastSignalAt' || a.lastSignalAt !== null)
      .filter((a) => sort !== 'address' || a.address !== null)
      .sort((x, y) => {
        if (sort === '-riskScore') return y.riskScore - x.riskScore || (y.id > x.id ? 1 : -1);
        if (sort === 'address')
          return (x.address ?? '').localeCompare(y.address ?? '') || (x.id > y.id ? 1 : -1);
        return y.lastSignalAt!.getTime() - x.lastSignalAt!.getTime() || (y.id > x.id ? 1 : -1);
      });
  }

  private afterKey(sort: AccountSort, a: AtoAccount, key: AccountKey | undefined): boolean {
    if (key === undefined) return true;
    const k = this.accountKeyOf(sort, a);
    const cmp =
      k.value instanceof Date
        ? k.value.getTime() - (key.value as Date).getTime()
        : typeof k.value === 'number'
          ? k.value - (key.value as number)
          : String(k.value).localeCompare(String(key.value));
    if (sort === 'address') return cmp > 0 || (cmp === 0 && a.id > key.id);
    return cmp < 0 || (cmp === 0 && a.id < key.id);
  }

  override accountBoundary(): Promise<AccountKey | null> {
    return Promise.resolve(null);
  }

  override listAccounts(
    scope: TenantScope,
    input: {
      filters: AccountFilters;
      sort: AccountSort;
      after?: AccountKey | undefined;
      take: number;
    },
  ) {
    return Promise.resolve(
      this.accountsOf(scope, input.filters, input.sort)
        .filter((a) => this.afterKey(input.sort, a, input.after))
        .slice(0, input.take)
        .map((a) => this.w.accountRow(a)),
    );
  }

  override account(scope: TenantScope, publicId: string) {
    const a = this.w.accounts.find(
      (x) => x.publicId === publicId && x.organizationId === own(scope),
    );
    return Promise.resolve(a ? this.w.accountRow(a) : null);
  }

  override accountsByIds(scope: TenantScope, ids: readonly bigint[]) {
    return Promise.resolve(
      this.w.accounts
        .filter((a) => ids.includes(a.id) && a.organizationId === own(scope))
        .map((a) => this.w.accountRow(a)),
    );
  }

  override accountExtras(scope: TenantScope, account: Pick<AtoAccount, 'id'>) {
    return Promise.resolve({
      restrictions: this.w.restrictions
        .filter((r) => r.organizationId === own(scope) && r.status === 'active')
        .map((r) => this.w.restrictionRow(r)),
      baseline: null,
      trustedContexts: this.w.contexts
        .filter((c) => c.accountId === account.id && c.organizationId === own(scope))
        .map((c) => ({ ...c, incidentPublicId: null })),
      linked: [],
      identities: [],
    });
  }

  override incidentPublicIds(_scope: TenantScope, ids: readonly bigint[]) {
    return Promise.resolve(
      new Map(this.w.incidents.filter((i) => ids.includes(i.id)).map((i) => [i.id, i.publicId])),
    );
  }

  override signalBoundary(): Promise<TimeKey | null> {
    return Promise.resolve(null);
  }

  override signals(
    scope: TenantScope,
    input: {
      where: { accountId?: bigint; incidentId?: bigint };
      range: { from: Date; to: Date };
      categories?: readonly string[] | undefined;
      statuses?: readonly string[] | undefined;
      strengths?: readonly string[] | undefined;
      after?: TimeKey | undefined;
      take: number;
    },
  ): Promise<SignalRow[]> {
    return Promise.resolve(
      this.w.signals
        .filter((s) => s.organizationId === own(scope))
        .filter((s) => input.where.accountId === undefined || s.accountId === input.where.accountId)
        .filter(
          (s) => input.where.incidentId === undefined || s.incidentId === input.where.incidentId,
        )
        .filter((s) => s.detectedAt >= input.range.from && s.detectedAt < input.range.to)
        .filter((s) => !input.categories || input.categories.includes(s.category))
        .filter((s) => !input.statuses || input.statuses.includes(s.status))
        .filter((s) => !input.strengths || input.strengths.includes(s.strength))
        .filter((s) => beforeKey(s.detectedAt, s.id, input.after))
        .sort(
          byTimeDesc(
            (s) => s.detectedAt,
            (s) => s.id,
          ),
        )
        .slice(0, input.take)
        .map((s) => ({
          ...s,
          incidentPublicId: this.w.incidents.find((i) => i.id === s.incidentId)?.publicId ?? null,
        })),
    );
  }

  override authEventBoundary(): Promise<TimeKey | null> {
    return Promise.resolve(null);
  }

  override authEvents(
    scope: TenantScope,
    input: {
      accountId: bigint;
      range: { from: Date; to: Date };
      outcomes?: readonly string[] | undefined;
      after?: TimeKey | undefined;
      take: number;
    },
  ) {
    return Promise.resolve(
      this.w.authEvents
        .filter((e) => e.organizationId === own(scope) && e.accountId === input.accountId)
        .filter((e) => e.occurredAt >= input.range.from && e.occurredAt < input.range.to)
        .filter((e) => !input.outcomes || input.outcomes.includes(e.outcome))
        .filter((e) => beforeKey(e.occurredAt, e.id, input.after))
        .sort(
          byTimeDesc(
            (e) => e.occurredAt,
            (e) => e.id,
          ),
        )
        .slice(0, input.take),
    );
  }

  override incidentAuthEvents(
    scope: TenantScope,
    input: { incidentId: bigint; after?: TimeKey | undefined; take: number },
  ) {
    const ids = this.w.links
      .filter((l) => l.incidentId === input.incidentId && l.linkType === 'ato_auth_event')
      .map((l) => l.refId);
    return Promise.resolve(
      this.w.authEvents
        .filter((e) => e.organizationId === own(scope) && ids.includes(e.id))
        .filter((e) => beforeKey(e.occurredAt, e.id, input.after))
        .sort(
          byTimeDesc(
            (e) => e.occurredAt,
            (e) => e.id,
          ),
        )
        .slice(0, input.take),
    );
  }

  override activity() {
    return Promise.resolve([]);
  }

  override scores(
    scope: TenantScope,
    input: { accountId: bigint; after?: TimeKey | undefined; take: number },
  ) {
    return Promise.resolve(
      this.w.scores
        .filter((s) => s.organizationId === own(scope) && s.accountId === input.accountId)
        .filter((s) => beforeKey(s.computedAt, s.id, input.after))
        .sort(
          byTimeDesc(
            (s) => s.computedAt,
            (s) => s.id,
          ),
        )
        .slice(0, input.take),
    );
  }

  override atoIncident(scope: TenantScope, publicId: string) {
    const i = this.w.incidents.find(
      (x) =>
        x.publicId === publicId &&
        x.organizationId === own(scope) &&
        x.category === 'account_takeover',
    );
    return Promise.resolve(
      i
        ? {
            id: i.id,
            publicId: i.publicId,
            subjectRefId: i.subjectRefId,
            detectedAt: i.detectedAt,
            firstEvidenceAt: i.firstEvidenceAt,
          }
        : null,
    );
  }

  override responses(
    scope: TenantScope,
    input: { filters: ResponseFilters; after?: TimeKey | undefined; take: number },
  ) {
    const f = input.filters;
    return Promise.resolve(
      this.w.responses
        .filter((r) => r.organizationId === own(scope))
        .filter((r) => !f.statuses || f.statuses.includes(r.status))
        .filter((r) => !f.actionTypes || f.actionTypes.includes(r.actionType))
        .filter((r) => f.incidentId === undefined || r.incidentId === f.incidentId)
        .filter((r) => f.accountId === undefined || r.accountId === f.accountId)
        .filter((r) => beforeKey(r.createdAt, r.id, input.after))
        .sort(
          byTimeDesc(
            (r) => r.createdAt,
            (r) => r.id,
          ),
        )
        .slice(0, input.take)
        .map((r) => this.w.responseRow(r)),
    );
  }

  override response(scope: TenantScope, publicId: string) {
    const r = this.w.responses.find(
      (x) => x.publicId === publicId && x.organizationId === own(scope),
    );
    return Promise.resolve(r ? this.w.responseRow(r) : null);
  }

  override responseAttempts(_scope: TenantScope, actionId: bigint) {
    return Promise.resolve(this.w.attempts.filter((a) => a.actionId === actionId));
  }

  override restrictionById(scope: TenantScope, id: bigint) {
    const r = this.w.restrictions.find((x) => x.id === id && x.organizationId === own(scope));
    return Promise.resolve(r ? this.w.restrictionRow(r) : null);
  }

  override restrictions(
    scope: TenantScope,
    input: { filters: RestrictionFilters; beforeId?: bigint | undefined; take: number },
  ) {
    return Promise.resolve(
      this.w.restrictions
        .filter((r) => r.organizationId === own(scope) && input.filters.statuses.includes(r.status))
        .filter((r) => input.beforeId === undefined || r.id < input.beforeId)
        .sort((a, b) => (b.id > a.id ? 1 : -1))
        .slice(0, input.take)
        .map((r) => this.w.restrictionRow(r)),
    );
  }

  override connectorByPublicId() {
    return Promise.resolve(null);
  }

  override userIdByPublicId(scope: TenantScope, publicId: string) {
    return Promise.resolve(
      this.w.users.find((u) => u.publicId === publicId && u.organizationId === own(scope))?.id ??
        null,
    );
  }

  override providerKind() {
    return Promise.resolve(null);
  }

  override settingsRow(scope: TenantScope) {
    return Promise.resolve(this.w.settings.get(own(scope)) ?? null);
  }

  override capabilitiesRaw() {
    return Promise.resolve(this.w.capabilities);
  }

  override sourcesLastEvent() {
    return Promise.resolve({
      portal_login: null,
      smtp_auth: null,
      account_change: null,
      outbound_message: null,
      smtp_submission: null,
    });
  }

  override atoFieldsInUse() {
    return Promise.resolve(false);
  }

  override attention(scope: TenantScope) {
    return Promise.resolve({
      criticalIncidents: this.w.incidents.filter(
        (i) =>
          i.organizationId === own(scope) && i.severity === 'critical' && ACTIVE.includes(i.status),
      ).length,
      pendingApprovals: this.w.responses.filter(
        (r) => r.organizationId === own(scope) && r.status === 'pending_approval',
      ).length,
    });
  }

  override overview(scope: TenantScope): Promise<OverviewCounts> {
    const accounts = this.w.accounts.filter((a) => a.organizationId === own(scope));
    const incidents = this.w.incidents.filter((i) => i.organizationId === own(scope));
    const activeBySeverity = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const i of incidents) if (ACTIVE.includes(i.status)) activeBySeverity[i.severity] += 1;
    return Promise.resolve({
      monitored: {
        mailbox: accounts.filter((a) => a.kind === 'mailbox').length,
        gateway_user: accounts.filter((a) => a.kind === 'gateway_user').length,
        smtp_connector: accounts.filter((a) => a.kind === 'smtp_connector').length,
      },
      highRisk: accounts.filter((a) => a.riskScore >= 50).length,
      criticalRisk: accounts.filter((a) => a.riskScore >= 75).length,
      activeBySeverity,
      openedInRange: incidents.map((i) => ({ detectedAt: i.detectedAt, severity: i.severity })),
      resolvedInRange: {},
      failedLogins: 0,
      suspiciousLogins: 0,
      outboundSignals: 0,
      restrictedAccounts: 0,
      policyHeld: 0,
      topCountries: [],
      newCountrySignals: {},
      impossibleTravel: 0,
      pendingApproval: this.w.responses.filter(
        (r) => r.organizationId === own(scope) && r.status === 'pending_approval',
      ).length,
      executedInRange: 0,
      failedInRange: 0,
    });
  }

  override domainIdByPublicId() {
    return Promise.resolve(null);
  }

  override trustedContext(scope: TenantScope, accountId: bigint, publicId: string) {
    const c = this.w.contexts.find(
      (x) =>
        x.publicId === publicId && x.accountId === accountId && x.organizationId === own(scope),
    );
    return Promise.resolve(c ? { ...c, incidentPublicId: null } : null);
  }

  override connectorPublicIds() {
    return Promise.resolve(new Map<string, string>());
  }
}

class FakeIncidentReads extends IncidentsReadRepository {
  constructor(private readonly w: AtoWorld) {
    super({} as never);
  }

  override replicaClient() {
    return {} as never;
  }

  private row(i: SecurityIncident): IncidentListRow {
    return {
      ...i,
      assigneePublicId: this.w.users.find((u) => u.id === i.assignedUserId)?.publicId ?? null,
    };
  }

  override list(
    scope: TenantScope,
    input: {
      filters: IncidentFilters;
      sort: IncidentSort;
      after?: IncidentKey | undefined;
      take: number;
    },
  ) {
    const f = input.filters;
    const rank = (s: string) => SEVERITIES.indexOf(s as (typeof SEVERITIES)[number]);
    const rows = this.w.incidents
      .filter((i) => i.organizationId === own(scope) && f.categories.includes(i.category))
      .filter((i) => !f.statuses || f.statuses.includes(i.status))
      .filter((i) => !f.severities || f.severities.includes(i.severity))
      .filter((i) => f.assignee === undefined || i.assignedUserId === f.assignee)
      .filter((i) => f.subjectPublicId === undefined || i.subjectPublicId === f.subjectPublicId)
      .filter((i) => f.origin === undefined || i.origin === f.origin)
      .filter((i) => f.detectedFrom === undefined || i.detectedAt >= f.detectedFrom)
      .filter((i) => f.detectedTo === undefined || i.detectedAt < f.detectedTo)
      .sort((a, b) =>
        input.sort === '-severity'
          ? rank(b.severity) - rank(a.severity) ||
            byTimeDesc<SecurityIncident>(
              (x) => x.detectedAt,
              (x) => x.id,
            )(a, b)
          : byTimeDesc<SecurityIncident>(
              (x) => x.detectedAt,
              (x) => x.id,
            )(a, b),
      )
      .filter((i) => {
        const k = input.after;
        if (!k) return true;
        if (input.sort === '-severity' && k.severity) {
          const d = rank(i.severity) - rank(k.severity);
          if (d !== 0) return d < 0;
        }
        return beforeKey(i.detectedAt, i.id, k);
      });
    return Promise.resolve(rows.slice(0, input.take).map((i) => this.row(i)));
  }

  override get(scope: TenantScope, publicId: string, categories: readonly string[]) {
    const i = this.w.incidents.find(
      (x) =>
        x.publicId === publicId &&
        x.organizationId === own(scope) &&
        categories.includes(x.category),
    );
    return Promise.resolve(i ? this.row(i) : null);
  }

  override publicIdOf(scope: TenantScope, id: bigint) {
    return Promise.resolve(
      this.w.incidents.find((i) => i.id === id && i.organizationId === own(scope))?.publicId ??
        null,
    );
  }

  override activeUserId(scope: TenantScope, publicId: string) {
    return Promise.resolve(
      this.w.users.find(
        (u) => u.publicId === publicId && u.organizationId === own(scope) && u.active,
      )?.id ?? null,
    );
  }

  override timeline(
    scope: TenantScope,
    input: { incidentId: bigint; after?: TimeKey | undefined; take: number },
  ) {
    return Promise.resolve(
      this.w.events
        .filter((e) => e.organizationId === own(scope) && e.incidentId === input.incidentId)
        .filter(
          (e) =>
            !input.after ||
            e.createdAt > input.after.at ||
            (e.createdAt.getTime() === input.after.at.getTime() && e.id > input.after.id),
        )
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || (a.id > b.id ? 1 : -1))
        .slice(0, input.take),
    );
  }

  override messages(_scope: TenantScope, input: { incidentId: bigint; take: number }) {
    const ids = this.w.messageLinks.get(input.incidentId) ?? [];
    return Promise.resolve(
      this.w.messages.filter((m) => ids.includes(m.messageId)).slice(0, input.take),
    );
  }

  override linkCounts(_scope: TenantScope, incidentId: bigint) {
    const out: Record<string, number> = {};
    for (const l of this.w.links.filter((x) => x.incidentId === incidentId))
      out[l.linkType] = (out[l.linkType] ?? 0) + 1;
    return Promise.resolve(out);
  }

  override messagePublicIds(_scope: TenantScope, ids: readonly bigint[]) {
    return Promise.resolve(
      new Map(
        this.w.messages
          .filter((m) => ids.includes(m.messageId) && m.publicId)
          .map((m) => [m.messageId.toString(), m.publicId!]),
      ),
    );
  }

  override report(
    _registry: unknown,
    incident: SecurityIncident,
    options: { maxItems: number; now: Date },
  ): Promise<IncidentReport> {
    const events = this.w.events.filter((e) => e.incidentId === incident.id);
    return Promise.resolve({
      version: 'security-incident-report/1',
      generatedAt: options.now.toISOString(),
      incident: {
        id: incident.publicId,
        category: incident.category,
        subject: { type: incident.subjectType, id: incident.subjectPublicId },
        origin: incident.origin,
        status: incident.status,
        severity: incident.severity,
        titleCode: incident.titleCode,
        reasonCodes: incident.reasonCodes as string[],
        detectorVersion: incident.detectorVersion,
        detectedAt: incident.detectedAt.toISOString(),
        firstEvidenceAt: null,
        lastEvidenceAt: null,
        evidenceCount: incident.evidenceCount,
        assigned: incident.assignedUserId !== null,
        escalatedAt: null,
        confirmedAt: null,
        mitigatedAt: null,
        resolvedAt: null,
      },
      resolution: null,
      timeline: events.slice(0, options.maxItems).map((e) => ({
        at: e.createdAt.toISOString(),
        type: e.eventType,
        actorType: e.actorType,
        actorId: e.actorId,
        fromStatus: e.fromStatus,
        toStatus: e.toStatus,
        fromSeverity: e.fromSeverity,
        toSeverity: e.toSeverity,
        details: e.details,
      })),
      notes: [],
      evidence: {},
      messages: (this.w.messageLinks.get(incident.id) ?? []).map((id) => ({
        messageId: id.toString(),
        receivedAt: new Date().toISOString(),
        direction: 'outbound',
        senderMasked: 'j***@corp.example',
      })),
      truncated: events.length > options.maxItems,
      sections: [{ id: 'ato.detection', title: 'Detection reason', data: { peakRiskScore: 78 } }],
    });
  }
}

// =================================================================== stores

function fakeAtoHandler(w: AtoWorld): IncidentCategoryHandler {
  return {
    category: 'account_takeover',
    subjectTypes: ['ato_account'],
    permissions: { read: 'ato:read', manage: 'ato:manage' },
    feedbackSchema: atoIncidentFeedbackSchema,
    resolveSubject(_tx, organizationId, ref) {
      const a = w.accounts.find(
        (x) => x.publicId === ref.publicId && x.organizationId === organizationId,
      );
      return Promise.resolve(
        ref.type === 'ato_account' && a
          ? { refId: a.id, refTime: null, publicId: a.publicId }
          : null,
      );
    },
    loadDetail(_tx, incident) {
      const a = w.accounts.find((x) => x.id === incident.subjectRefId);
      return Promise.resolve({
        account: a
          ? {
              id: a.publicId,
              kind: a.kind,
              address: a.address,
              riskScore: a.riskScore,
              riskLevel: a.riskLevel,
            }
          : null,
        counts: { signals: w.signals.filter((s) => s.incidentId === incident.id).length },
      });
    },
    onTransition(_tx, incident, _from, to, actor, feedback) {
      if (to !== 'false_positive' && to !== 'resolved') return Promise.resolve();
      const a = w.accounts.find((x) => x.id === incident.subjectRefId);
      if (a && a.activeIncidentId === incident.id) a.activeIncidentId = null;
      if (to === 'false_positive') {
        const parsed = atoIncidentFeedbackSchema.parse(feedback ?? {});
        if (parsed.dismissSignals) {
          for (const s of w.signals.filter(
            (x) => x.incidentId === incident.id && x.status === 'active',
          )) {
            s.status = 'dismissed';
            s.dismissedAt = new Date();
          }
        }
        for (const c of parsed.trustedContexts) {
          w.contexts.push({
            id: w.id(),
            publicId: randomUUID(),
            organizationId: incident.organizationId,
            accountId: incident.subjectRefId,
            kind: c.kind,
            value: c.value,
            ipVersion: null,
            rangeStart: null,
            rangeEnd: null,
            reason: c.reason,
            source: 'false_positive_feedback',
            incidentId: incident.id,
            createdByUserId: actor.userId ?? null,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + c.expiresInDays * 86_400_000),
          });
        }
      }
      return Promise.resolve();
    },
    reportSections() {
      return Promise.resolve([]);
    },
  };
}

/** A second category for the cross-category tests (registered by the test only). */
export const FAKE_CATEGORY = 'fake_category';

class FakeIncidentStore {
  constructor(
    private readonly w: AtoWorld,
    private readonly registry: IncidentCategoryRegistry,
  ) {}

  private find(organizationId: bigint, incidentId: bigint) {
    const row = this.w.incidents.find(
      (i) => i.id === incidentId && i.organizationId === organizationId,
    );
    if (!row) throw new IncidentError('incident_not_found', 'Incident not found');
    return row;
  }

  private bump(row: SecurityIncident) {
    row.rowVersion += 1;
    row.updatedAt = new Date();
    row.activeMarker = ACTIVE.includes(row.status) ? 1 : null;
  }

  lockForUpdate(_tx: unknown, organizationId: bigint, incidentId: bigint) {
    return Promise.resolve(
      this.w.incidents.find((i) => i.id === incidentId && i.organizationId === organizationId) ??
        null,
    );
  }

  setSeverity(
    _tx: unknown,
    input: {
      organizationId: bigint;
      incidentId: bigint;
      severity: SecurityIncident['severity'];
      actor: IncidentActor;
    },
  ) {
    const row = this.find(input.organizationId, input.incidentId);
    if (isTerminalIncidentStatus(row.status)) throw new IncidentError('incident_closed', 'closed');
    if (row.severity === input.severity) return Promise.resolve(row);
    this.w.event(row, 'severity_changed', input.actor, {
      fromSeverity: row.severity,
      toSeverity: input.severity,
    });
    row.severity = input.severity;
    this.bump(row);
    return Promise.resolve(row);
  }

  assign(
    _tx: unknown,
    input: {
      organizationId: bigint;
      incidentId: bigint;
      assigneeUserId: bigint | null;
      actor: IncidentActor;
    },
  ) {
    const row = this.find(input.organizationId, input.incidentId);
    if (isTerminalIncidentStatus(row.status)) throw new IncidentError('incident_closed', 'closed');
    row.assignedUserId = input.assigneeUserId;
    this.w.event(row, 'assigned', input.actor);
    this.bump(row);
    return Promise.resolve(row);
  }

  async transition(
    _tx: unknown,
    input: {
      organizationId: bigint;
      incidentId: bigint;
      to: SecurityIncident['status'];
      actor: IncidentActor;
      resolutionCode?: SecurityIncident['resolutionCode'];
      note?: string | null;
      feedback?: unknown;
      expectedRowVersion?: number;
    },
  ) {
    const row = this.find(input.organizationId, input.incidentId);
    if (input.expectedRowVersion !== undefined && row.rowVersion !== input.expectedRowVersion) {
      throw new IncidentVersionConflictError(input.expectedRowVersion, row.rowVersion);
    }
    const refusal = checkTransition(row.status, input.to, input);
    if (refusal !== null) {
      const code = {
        transition_not_allowed: 'incident_transition_not_allowed',
        resolution_required: 'incident_resolution_required',
        resolution_invalid: 'incident_resolution_invalid',
        note_required: 'incident_note_required',
        note_invalid: 'incident_note_invalid',
      }[refusal] as never;
      throw new IncidentError(code, refusal, { from: row.status, to: input.to });
    }
    const handler = this.registry.get(row.category);
    let feedback: unknown;
    if (input.feedback !== undefined && input.feedback !== null) {
      const parsed = handler.feedbackSchema?.safeParse(input.feedback);
      if (!parsed?.success) throw new IncidentError('incident_feedback_invalid', 'bad feedback');
      feedback = parsed.data;
    }
    const from = row.status;
    this.w.event(row, 'status_changed', input.actor, {
      fromStatus: from,
      toStatus: input.to,
      note: normalizeNote(input.note),
    });
    row.status = input.to;
    if (isTerminalIncidentStatus(input.to)) {
      row.resolvedAt = new Date();
      row.resolutionCode = input.resolutionCode ?? null;
      row.resolutionNote = normalizeNote(input.note);
    }
    this.bump(row);
    await handler.onTransition?.({} as never, row, from, input.to, input.actor, feedback);
    return row;
  }

  addNote(
    _tx: unknown,
    input: { organizationId: bigint; incidentId: bigint; actor: IncidentActor; note: string },
  ) {
    const row = this.find(input.organizationId, input.incidentId);
    return Promise.resolve(
      this.w.event(row, 'note_added', input.actor, { note: input.note.trim() }),
    );
  }

  recordReportExport(_tx: unknown, row: SecurityIncident, actor: IncidentActor) {
    this.w.event(row, 'report_exported', actor);
    return Promise.resolve();
  }

  open(
    _tx: unknown,
    input: {
      organizationId: bigint;
      category: string;
      subject: { refId: bigint };
      severity: SecurityIncident['severity'];
      actor: IncidentActor;
      note?: string | null;
    },
  ) {
    const active = this.w.incidents.find(
      (i) =>
        i.organizationId === input.organizationId &&
        i.category === input.category &&
        i.subjectRefId === input.subject.refId &&
        ACTIVE.includes(i.status),
    );
    if (active) throw new IncidentActiveConflictError(active.id);
    const account = this.w.accounts.find((a) => a.id === input.subject.refId)!;
    const row = this.w.addIncident(input.organizationId, account, {
      origin: 'manual',
      severity: input.severity,
      createdByType: input.actor.type,
      createdById: input.actor.id,
      titleCode: null,
      reasonCodes: [],
    });
    return Promise.resolve(row);
  }
}

class FakeAtoStore {
  readonly incidents: FakeIncidentStore;
  constructor(
    private readonly w: AtoWorld,
    incidents: FakeIncidentStore,
  ) {
    this.incidents = incidents;
  }

  now(): Date {
    return new Date();
  }

  private account(organizationId: bigint, id: bigint) {
    const a = this.w.accounts.find((x) => x.id === id && x.organizationId === organizationId);
    if (!a) throw new AtoStoreError('ato_account_not_found', 'Account not found');
    return a;
  }

  findAccount(_tx: unknown, organizationId: bigint, publicId: string) {
    return Promise.resolve(
      this.w.accounts.find((a) => a.publicId === publicId && a.organizationId === organizationId) ??
        null,
    );
  }

  lockAccounts(_tx: unknown, organizationId: bigint, ids: readonly bigint[]) {
    return Promise.resolve(ids.map((id) => this.account(organizationId, id)));
  }

  setProtected(
    _tx: unknown,
    input: { organizationId: bigint; accountId: bigint; protected: boolean; reason: string | null },
  ) {
    const a = this.account(input.organizationId, input.accountId);
    a.protected = input.protected;
    a.protectedReason = input.protected ? input.reason : null;
    a.protectedAt = input.protected ? new Date() : null;
    return Promise.resolve(a);
  }

  setOverride(
    _tx: unknown,
    input: {
      organizationId: bigint;
      accountId: bigint;
      verdict: 'benign' | 'compromised';
      reason: string;
      expiresAt: Date;
    },
  ) {
    const a = this.account(input.organizationId, input.accountId);
    const o = {
      id: this.w.id(),
      publicId: randomUUID(),
      organizationId: input.organizationId,
      accountId: a.id,
      verdict: input.verdict,
      reason: input.reason,
      expiresAt: input.expiresAt,
      createdAt: new Date(),
      contradictedAt: null,
      clearedAt: null,
    };
    this.w.overrides.push(o);
    a.overrideId = o.id;
    a.riskScore =
      input.verdict === 'benign' ? Math.min(a.riskScore, 29) : Math.max(a.riskScore, 90);
    a.riskLevel = input.verdict === 'benign' ? 'low' : 'critical';
    return Promise.resolve({ overridePublicId: o.publicId, rescore: {} });
  }

  clearOverride(_tx: unknown, input: { organizationId: bigint; accountId: bigint }) {
    const a = this.account(input.organizationId, input.accountId);
    if (a.overrideId === null) return Promise.resolve(null);
    const o = this.w.overrides.find((x) => x.id === a.overrideId)!;
    o.clearedAt = new Date();
    a.overrideId = null;
    return Promise.resolve({});
  }

  addTrustedContext(
    _tx: unknown,
    input: {
      organizationId: bigint;
      accountId: bigint;
      kind: AtoTrustedContext['kind'];
      value: string;
      reason: string;
      expiresAt: Date;
    },
  ) {
    if (input.kind === 'country' && !/^[A-Za-z]{2}$/.test(input.value)) {
      throw new AtoStoreError('ato_trusted_context_invalid', 'Invalid country value');
    }
    const row = {
      id: this.w.id(),
      publicId: randomUUID(),
      organizationId: input.organizationId,
      accountId: input.accountId,
      kind: input.kind,
      value: input.kind === 'country' ? input.value.toUpperCase() : input.value,
      ipVersion: null,
      rangeStart: null,
      rangeEnd: null,
      reason: input.reason,
      source: 'analyst',
      incidentId: null,
      createdByUserId: null,
      createdAt: new Date(),
      expiresAt: input.expiresAt,
    } as AtoTrustedContext;
    this.w.contexts.push(row);
    return Promise.resolve({ publicId: row.publicId });
  }

  removeTrustedContext(_tx: unknown, input: { organizationId: bigint; publicId: string }) {
    const i = this.w.contexts.findIndex(
      (c) => c.publicId === input.publicId && c.organizationId === input.organizationId,
    );
    if (i < 0)
      throw new AtoStoreError('ato_trusted_context_not_found', 'Trusted context not found');
    this.w.contexts.splice(i, 1);
    return Promise.resolve();
  }

  findAction(_tx: unknown, organizationId: bigint, publicId: string) {
    return Promise.resolve(
      this.w.responses.find(
        (r) => r.publicId === publicId && r.organizationId === organizationId,
      ) ?? null,
    );
  }

  private log(
    action: AtoResponseAction,
    phase: AtoResponseActionLog['phase'],
    outcome: AtoResponseActionLog['outcome'],
  ) {
    this.w.attempts.push({
      id: this.w.id(),
      organizationId: action.organizationId,
      actionId: action.id,
      phase,
      attemptNo: 1,
      outcome,
      providerStatus: null,
      errorCode: null,
      durationMs: 1,
      createdAt: new Date(),
    });
  }

  private execute(action: AtoResponseAction) {
    const entry = RESPONSE_CATALOGUE[action.actionType as ResponseActionType];
    if (entry.provider === 'provider') {
      action.status = 'unsupported';
      action.providerStatus = 'unsupported';
      action.resultCode = 'no_provider_integration';
    } else if (
      action.actionType === 'restrict_smtp_sending' ||
      action.actionType === 'block_smtp_auth'
    ) {
      const r = {
        id: this.w.id(),
        publicId: randomUUID(),
        organizationId: action.organizationId,
        kind: action.actionType === 'restrict_smtp_sending' ? 'send_block' : 'auth_block',
        scope: (action.target as { scope: string }).scope,
        connectorId: null,
        mailboxSha256: 'd'.repeat(64),
        mailboxAddress: null,
        ipCidr: null,
        ipVersion: null,
        rangeStart: null,
        rangeEnd: null,
        mode: 'reject',
        status: 'active',
        reasonCode: 'ato_response',
        responseActionId: action.id,
        startsAt: new Date(),
        expiresAt: new Date(Date.now() + 4 * 3_600_000),
        liftedAt: null,
        liftedByType: null,
        liftedById: null,
        liftReason: null,
        subjectHash: 'e'.repeat(64),
        activeMarker: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      } as AtoSmtpRestriction;
      this.w.restrictions.push(r);
      action.restrictionId = r.id;
      action.status = 'succeeded';
      action.providerStatus = 'applied';
      action.resultCode = 'restriction_applied';
    } else {
      action.status = 'succeeded';
      action.providerStatus = 'unconfirmed';
      action.resultCode = 'queued_for_delivery';
    }
    action.completedAt = new Date();
    action.activeMarker = null;
    this.log(action, 'execute', action.status === 'succeeded' ? 'succeeded' : 'unsupported');
  }

  requestResponse(
    _tx: unknown,
    input: {
      organizationId: bigint;
      accountId: bigint;
      incidentId: bigint | null;
      actionType: ResponseActionType;
      target: ResponseTarget;
      params?: Record<string, unknown>;
      actor: IncidentActor;
      reason?: string | null;
    },
  ) {
    const account = this.account(input.organizationId, input.accountId);
    if (input.target.scope === 'connector_ip' && !input.target.cidr) {
      throw new AtoStoreError('ato_response_invalid', 'connector_ip needs a CIDR');
    }
    const active = this.w.responses.find(
      (r) =>
        r.organizationId === input.organizationId &&
        r.incidentId === input.incidentId &&
        r.actionType === input.actionType &&
        r.activeMarker === 1,
    );
    if (active)
      throw new AtoStoreError('ato_response_active', 'An active response exists', {
        actionPublicId: active.publicId,
      });
    const entry = RESPONSE_CATALOGUE[input.actionType];
    const impact = impactFor(input.actionType, input.target);
    const manual = entry.provider === 'manual';
    const requiresApproval = !manual && impact !== 'low';
    const action = this.w.addResponse(
      account,
      this.w.incidents.find((i) => i.id === input.incidentId) ?? null,
      {
        actionType: input.actionType,
        provider: entry.provider === 'provider' ? 'unbound' : entry.provider,
        impact,
        target: input.target as never,
        params: (input.params ?? {}) as never,
        status: manual ? 'attested' : requiresApproval ? 'pending_approval' : 'approved',
        requiresApproval,
        requestedByType: input.actor.type,
        requestedById: input.actor.id,
        requestReason: input.reason ?? null,
        approvalExpiresAt: requiresApproval ? new Date(Date.now() + 86_400_000) : null,
        providerStatus: manual ? 'unconfirmed' : null,
        resultCode: manual ? 'attested_by_analyst' : null,
        completedAt: manual ? new Date() : null,
        activeMarker: manual ? null : 1,
      },
    );
    this.log(action, 'authorize', requiresApproval ? 'pending' : 'succeeded');
    if (!manual && !requiresApproval) this.execute(action);
    return Promise.resolve(action);
  }

  decideResponse(
    _tx: unknown,
    input: {
      organizationId: bigint;
      actionId: bigint;
      decision: 'approve' | 'reject';
      actor: IncidentActor;
      reason?: string | null;
    },
  ) {
    const action = this.w.responses.find(
      (r) => r.id === input.actionId && r.organizationId === input.organizationId,
    );
    if (!action) throw new AtoStoreError('ato_response_not_found', 'Response not found');
    if (input.actor.type !== 'user') throw new AtoStoreError('ato_approver_invalid', 'users only');
    if (action.status !== 'pending_approval')
      throw new AtoStoreError('ato_response_state', `Action is ${action.status}`);
    if (action.approvalExpiresAt && action.approvalExpiresAt <= new Date()) {
      action.status = 'expired';
      throw new AtoStoreError('ato_response_expired', 'expired');
    }
    if (action.requestedByType === 'user' && action.requestedById === input.actor.id) {
      throw new AtoStoreError('ato_self_approval', 'self');
    }
    if (
      action.requestedByType === 'api_key' &&
      action.requestedById &&
      this.w.apiKeyCreators.get(action.requestedById) === input.actor.id
    ) {
      throw new AtoStoreError('ato_self_approval', 'key creator');
    }
    action.decidedAt = new Date();
    action.decisionReason = input.reason ?? null;
    action.approvedByUserId = input.decision === 'approve' ? (input.actor.userId ?? null) : null;
    if (input.decision === 'reject') {
      action.status = 'rejected';
      action.activeMarker = null;
      action.completedAt = new Date();
    } else {
      action.status = 'approved';
      this.execute(action);
    }
    return Promise.resolve(action);
  }

  cancelResponse(_tx: unknown, input: { organizationId: bigint; actionId: bigint }) {
    const action = this.w.responses.find(
      (r) => r.id === input.actionId && r.organizationId === input.organizationId,
    );
    if (!action) throw new AtoStoreError('ato_response_not_found', 'Response not found');
    if (action.status !== 'pending_approval')
      throw new AtoStoreError('ato_response_state', `Action is ${action.status}`);
    action.status = 'cancelled';
    action.activeMarker = null;
    action.completedAt = new Date();
    return Promise.resolve(action);
  }

  requestRollback(
    _tx: unknown,
    input: { organizationId: bigint; actionId: bigint; actor: IncidentActor; reason: string },
  ) {
    const action = this.w.responses.find(
      (r) => r.id === input.actionId && r.organizationId === input.organizationId,
    );
    if (!action) throw new AtoStoreError('ato_response_not_found', 'Response not found');
    if (input.actor.type !== 'user') throw new AtoStoreError('ato_approver_invalid', 'users only');
    if (action.status !== 'succeeded')
      throw new AtoStoreError('ato_response_state', `Action is ${action.status}`);
    if (!supportsRollback(action.actionType as ResponseActionType))
      throw new AtoStoreError('ato_rollback_unsupported', 'no rollback');
    const r = this.w.restrictions.find((x) => x.id === action.restrictionId);
    if (r) {
      r.status = 'lifted';
      r.liftedAt = new Date();
      r.liftReason = input.reason;
    }
    action.status = 'rolled_back';
    action.rollbackReason = input.reason;
    this.log(action, 'rollback', 'succeeded');
    return Promise.resolve(action);
  }

  loadSettings(_tx: unknown, organizationId: bigint) {
    const row = this.w.settings.get(organizationId);
    return Promise.resolve(row ? { rowVersion: row.rowVersion, version: row.version } : null);
  }

  ensureSettings(_tx: unknown, organizationId: bigint) {
    if (!this.w.settings.has(organizationId)) {
      this.w.settings.set(organizationId, {
        settings: normalizeAtoSettings({}),
        version: 1,
        rowVersion: 1,
        learningStartedAt: new Date(),
        updatedAt: new Date(),
      });
    }
    const row = this.w.settings.get(organizationId)!;
    return Promise.resolve({ rowVersion: row.rowVersion, version: row.version });
  }

  async saveSettings(
    _tx: unknown,
    input: { organizationId: bigint; settings: unknown; expectedRowVersion: number },
  ) {
    const parsed = atoSettingsSchema.safeParse(input.settings);
    if (!parsed.success) {
      throw new AtoStoreError('ato_settings_invalid', 'Invalid ATO settings', {
        issues: parsed.error.issues.map((i) => ({
          path: i.path.map(String).join('.'),
          message: i.message,
        })),
      });
    }
    await this.ensureSettings(_tx, input.organizationId);
    const row = this.w.settings.get(input.organizationId)!;
    if (row.rowVersion !== input.expectedRowVersion) {
      throw new AtoStoreError('ato_settings_conflict', 'conflict', { actual: row.rowVersion });
    }
    row.settings = normalizeAtoSettings(parsed.data);
    row.version += 1;
    row.rowVersion += 1;
    row.updatedAt = new Date();
    return { rowVersion: row.rowVersion };
  }
}

/** The `IncidentStores` double: the registry (ATO + extra categories) and the two stores. */
export function fakeIncidentStores(
  w: AtoWorld,
  extra: IncidentCategoryDefinition[] = [],
): IncidentStores {
  const atoDefinition: IncidentCategoryDefinition = {
    category: 'account_takeover',
    handler: () => fakeAtoHandler(w),
    featureKey: 'ato_detection',
    notEnabled: atoNotEnabled,
    subjectDisplays: (_db, _org, refIds) =>
      Promise.resolve(
        new Map(w.accounts.filter((a) => refIds.includes(a.id)).map((a) => [a.id, a.address])),
      ),
    openManual: (stores, tx, input) =>
      (stores.incidents as unknown as FakeIncidentStore).open(tx, {
        organizationId: input.organizationId,
        category: 'account_takeover',
        subject: input.subject,
        severity: input.severity,
        actor: input.actor,
        note: input.note,
      }),
  };
  const definitions = [atoDefinition, ...extra];
  const registry = new IncidentCategoryRegistry(
    definitions.map((d) =>
      d.handler({
        ato: () => {
          throw new Error('unused');
        },
        reportMaxItems: 500,
      }),
    ),
  );
  const incidents = new FakeIncidentStore(w, registry);
  const ato = new FakeAtoStore(w, incidents);
  return {
    registry,
    incidents,
    ato,
    definitions,
    now: () => new Date(),
    definition: (category: string) => definitions.find((d) => d.category === category),
  } as unknown as IncidentStores;
}

/** Overrides the step 8.4 providers with the doubles (plus features and audit). */
export function overrideAto(
  builder: TestingModuleBuilder,
  world: AtoWorld,
  audit: RecordingAuditService,
  extra: IncidentCategoryDefinition[] = [],
): TestingModuleBuilder {
  return builder
    .overrideProvider(AtoReadRepository)
    .useValue(new FakeAtoReads(world))
    .overrideProvider(IncidentsReadRepository)
    .useValue(new FakeIncidentReads(world))
    .overrideProvider(IncidentStores)
    .useValue(fakeIncidentStores(world, extra))
    .overrideProvider(AtoAccountVersionRepository)
    .useValue({
      bump: (_tx: unknown, scope: TenantScope, id: bigint) => {
        const a = world.accounts.find(
          (x) => x.id === id && x.organizationId === scope.organizationId,
        );
        if (a) a.rowVersion += 1;
        return Promise.resolve();
      },
    })
    .overrideProvider(AuditService)
    .useValue(audit)
    .overrideProvider(OrganizationFeaturesService)
    .useValue({
      isEnabled: (organizationId: bigint, key: string) =>
        Promise.resolve(
          (key === 'ato_detection' || key === 'fake_feature') &&
            !world.featureOff.has(organizationId),
        ),
    });
}

export { RecordingAuditService };
