import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService, uuidv7 } from '@email-gateway/common';
import {
  type ApiCopyDeliveredBasis,
  type ApiCopyRemediationAction,
  type ApiCopyRemediationState,
  type ApiCopyDirection,
  type ApiCopySource,
  type ApiCopyStatus,
  type ApiCopyVerdictAuthority,
  type ApiMailboxCoverageState,
  type ApiMailboxFeedStatus,
  type ApiMailboxStatus,
  type ApiModeFeedMode,
  type ApiModeHealthStatus,
  type ApiModeInventoryStatus,
  type IntegrationProvider,
  type MessageVerdict,
  Prisma,
  type ProtectionMode,
  type ProviderConnectionStatus,
  type ProviderGrantStatus,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { OrganizationAccess } from '../../organizations/domain/organization-access';
import type { DomainModeFacts } from '../domain/protection-mode';

type Client = Prisma.TransactionClient;

/** The `*.mailbox_remediation` profile keys (step API-1 D4). */
export const MAILBOX_PROFILES = ['m365.mailbox_remediation', 'google.mailbox_remediation'];
/** Journal intake kinds bound to a provider connection (8.6). */
const PROVIDER_JOURNAL_KINDS = ['microsoft_365_journal', 'google_workspace_copy'] as const;

// ---- rows ---------------------------------------------------------------------------------------

/** The organization of a protection-mode route (visible to the caller). */
export interface OrganizationModeRow {
  id: bigint;
  publicId: string;
  status: string;
  protectionMode: ProtectionMode;
  protectionModeChangedAt: Date | null;
}

/** A domain of a protection-mode change (with its MX conflict fact). */
export interface DomainModeRow extends DomainModeFacts {
  id: bigint;
  changedAt: Date | null;
}

export interface ApiConnectionRow {
  id: bigint;
  publicId: string;
  feedsEnabled: boolean;
  feedMode: ApiModeFeedMode;
  feedsEnabledAt: Date | null;
  inventoryStatus: ApiModeInventoryStatus;
  inventorySyncedAt: Date | null;
  inventoryRequestedAt: Date | null;
  nextInventoryAt: Date | null;
  mailboxesTotal: number | null;
  healthStatus: ApiModeHealthStatus;
  healthChecks: Prisma.JsonValue;
  healthChangedAt: Date | null;
  throttledUntil: Date | null;
  lastErrorCode: string | null;
  /** Step API-2 R5.1, R13: policy remediation paused on this connection. */
  remediationPaused: boolean;
  remediationPausedAt: Date | null;
  rowVersion: number;
}

export interface JournalSourceRef {
  publicId: string;
  displayName: string;
  kind: string;
  status: 'pending_verification' | 'active' | 'paused' | 'disabled';
  healthStatus: 'unknown' | 'healthy' | 'silent' | 'failing' | 'paused';
  verifiedAt: Date | null;
  addressVersion: number;
}

/** One 8.2 provider connection with everything the API-mode views need. */
export interface ConnectionFacts {
  id: bigint;
  publicId: string;
  displayName: string;
  provider: IntegrationProvider;
  status: ProviderConnectionStatus;
  externalTenantId: string | null;
  activeTenantKey: string | null;
  attestations: Prisma.JsonValue;
  /** The `*.mailbox_remediation` grant (any status), or null. */
  grant: {
    profile: string;
    status: ProviderGrantStatus;
    authMethod: string;
    clientId: string | null;
    subjectEmail: string | null;
  } | null;
  api: ApiConnectionRow | null;
  journalSources: JournalSourceRef[];
}

export interface ApiConnectionUpdate {
  feedsEnabled?: boolean;
  feedMode?: ApiModeFeedMode;
  feedsEnabledAt?: Date | null;
  remediationPaused?: boolean;
  remediationPausedAt?: Date | null;
}

/** Step API-2 R14: the remediation fields of an hourly counter row. */
export interface RemediationCounterRow {
  apiConnectionId: bigint;
  hour: Date;
  remediationSucceeded: number;
  remediationFailed: number;
  remediationSkipped: number;
  remediationSimulated: number;
  restoresSucceeded: number;
  restoresFailed: number;
  remediationThrottled: number;
  remediationLatencyCount: number;
  remediationLatencySumMs: bigint;
  remediationLatencyMaxMs: number;
}

/** Step API-2 R13: the bounded live backlog of one API-mode connection. */
export interface RemediationBacklog {
  pending: number;
  capped: boolean;
  oldestCreatedAt: Date | null;
}

/** An hourly counter row (`api_mode_counters`). */
export interface CounterRow {
  apiConnectionId: bigint;
  hour: Date;
  journalCopies: number;
  feedCopies: number;
  duplicates: number;
  skippedInternal: number;
  tooLarge: number;
  providerRequests: number;
  throttled429: number;
  throttled503: number;
  providerErrors: number;
  cursorResets: number;
  lagCount: number;
  lagLe60s: number;
  lagLe300s: number;
  lagLe900s: number;
  lagLe3600s: number;
  lagGt3600s: number;
  lagMaxMs: number;
}

export interface MailboxRow {
  id: bigint;
  publicId: string;
  connectionPublicId: string;
  primaryAddress: string;
  domain: { publicId: string; name: string } | null;
  status: ApiMailboxStatus;
  coverageState: ApiMailboxCoverageState;
  coverageChangedAt: Date | null;
  feedStatus: ApiMailboxFeedStatus;
  journalLastSeenAt: Date | null;
  lastSyncAt: Date | null;
  lastErrorCode: string | null;
}

export interface MailboxDetailRow extends MailboxRow {
  aliases: string[];
  feedStartedAt: Date | null;
  subscribed: boolean;
  subscriptionExpiresAt: Date | null;
  lastChangeAt: Date | null;
  lastGapAt: Date | null;
  consecutiveFailures: number;
}

export interface MailboxFilter {
  connectionPublicId?: string;
  coverage?: ApiMailboxCoverageState[];
  feedStatus?: ApiMailboxFeedStatus[];
  status?: ApiMailboxStatus[];
  domainPublicId?: string;
  /** Lower-case address prefix (primary or alias). */
  q?: string;
}

export interface CopyRow {
  id: bigint;
  publicId: string;
  receivedAt: Date;
  mailboxPublicId: string;
  mailboxAddress: string;
  connectionPublicId: string;
  messageId: bigint;
  source: ApiCopySource;
  seenJournal: boolean;
  seenApi: boolean;
  direction: ApiCopyDirection;
  status: ApiCopyStatus;
  verdict: MessageVerdict | null;
  riskScore: number | null;
  verdictAuthority: ApiCopyVerdictAuthority;
  providerDeliveredAt: Date | null;
  deliveredBasis: ApiCopyDeliveredBasis | null;
  verdictAt: Date | null;
  lagMs: number | null;
  subject: string | null;
  headerFrom: string | null;
  /** Step API-2 §3.2 / R13. */
  remediationState: ApiCopyRemediationState;
  remediationAction: ApiCopyRemediationAction | null;
  /** Public id of `last_action_id`. */
  remediationId: string | null;
  /** Public id of the copy's latest mailbox-located quarantine entry. */
  quarantineEntryId: string | null;
}

export interface CopyFilter {
  verdict?: MessageVerdict[];
  status?: ApiCopyStatus[];
  source?: ApiCopySource[];
  mailboxPublicId?: string;
  connectionPublicId?: string;
  minRiskScore?: number;
  remediationState?: ApiCopyRemediationState[];
}

/** The mailbox a Graph subscription id selects (public callback; no tenant input). */
export interface SubscriptionRow {
  id: bigint;
  feedStatus: ApiMailboxFeedStatus;
  clientStateHash: string | null;
  boundTenantId: string | null;
}

const apiConnectionSelect = {
  id: true,
  publicId: true,
  feedsEnabled: true,
  feedMode: true,
  feedsEnabledAt: true,
  inventoryStatus: true,
  inventorySyncedAt: true,
  inventoryRequestedAt: true,
  nextInventoryAt: true,
  mailboxesTotal: true,
  healthStatus: true,
  healthChecks: true,
  healthChangedAt: true,
  throttledUntil: true,
  lastErrorCode: true,
  remediationPaused: true,
  remediationPausedAt: true,
  rowVersion: true,
} satisfies Prisma.ApiModeConnectionSelect;

const connectionSelect = {
  id: true,
  publicId: true,
  displayName: true,
  provider: true,
  status: true,
  externalTenantId: true,
  activeTenantKey: true,
  attestations: true,
  grants: {
    where: { profile: { in: MAILBOX_PROFILES } },
    select: {
      profile: true,
      status: true,
      authMethod: true,
      clientId: true,
      subjectEmail: true,
      updatedAt: true,
    },
    orderBy: { updatedAt: 'desc' },
  },
  apiModeConnection: { select: apiConnectionSelect },
  journalIntakeSources: {
    where: { kind: { in: [...PROVIDER_JOURNAL_KINDS] } },
    select: {
      publicId: true,
      displayName: true,
      kind: true,
      status: true,
      healthStatus: true,
      verifiedAt: true,
      addressVersion: true,
    },
    orderBy: { id: 'asc' },
  },
} satisfies Prisma.ProviderConnectionSelect;

type ConnectionPayload = Prisma.ProviderConnectionGetPayload<{ select: typeof connectionSelect }>;

function toFacts(row: ConnectionPayload): ConnectionFacts {
  const grant = row.grants[0] ?? null;
  return {
    id: row.id,
    publicId: row.publicId,
    displayName: row.displayName,
    provider: row.provider,
    status: row.status,
    externalTenantId: row.externalTenantId,
    activeTenantKey: row.activeTenantKey,
    attestations: row.attestations,
    grant:
      grant === null
        ? null
        : {
            profile: grant.profile,
            status: grant.status,
            authMethod: grant.authMethod,
            clientId: grant.clientId,
            subjectEmail: grant.subjectEmail,
          },
    api: row.apiModeConnection,
    journalSources: row.journalIntakeSources.map((s) => ({ ...s })),
  };
}

const mailboxSelect = {
  id: true,
  publicId: true,
  primaryAddress: true,
  domainId: true,
  status: true,
  coverageState: true,
  coverageChangedAt: true,
  feedStatus: true,
  journalLastSeenAt: true,
  lastSyncAt: true,
  lastErrorCode: true,
  apiConnection: { select: { providerConnection: { select: { publicId: true } } } },
} satisfies Prisma.ApiMailboxSelect;

type MailboxPayload = Prisma.ApiMailboxGetPayload<{ select: typeof mailboxSelect }>;

/** The non-deleted domains (public id, name) by internal id, for mailbox views. */
type DomainNames = Map<bigint, { publicId: string; name: string }>;

const isoHour = (d: Date): Date => new Date(Math.floor(d.getTime() / 3_600_000) * 3_600_000);

/**
 * Data access of the API-mode module (step API-1 §3, D2, D10, D12): the protection modes of the
 * organization and its domains, the 8.2 connections with their API-mode rows (created lazily),
 * mailboxes and their addresses, per-mailbox copies and hourly counters, and the subscription
 * lookup of the public Graph callbacks. Tenant-owned rows are always filtered by the scope's
 * organization (foreign ids read as missing); views read the replica, mutations the writer inside
 * the caller's transaction. Feed cursors, subscription ids and client-state hashes are never
 * selected for a view.
 */
@Injectable()
export class ApiModeRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  // ---- protection mode (D2) ------------------------------------------------------------------

  /** The organization by public id if the access allows it (platform: any; else its own). */
  async findOrganization(
    access: OrganizationAccess,
    publicId: string,
    client: Client = this.prisma,
  ): Promise<OrganizationModeRow | null> {
    return client.organization.findFirst({
      where: {
        publicId,
        status: { not: 'deleted' },
        ...(access.kind === 'scoped' && { id: access.scope.organizationId }),
      },
      select: {
        id: true,
        publicId: true,
        status: true,
        protectionMode: true,
        protectionModeChangedAt: true,
      },
    });
  }

  /** Locks the organization row (`FOR UPDATE`) and re-reads its mode. */
  async lockOrganization(tx: Client, organizationId: bigint): Promise<OrganizationModeRow | null> {
    await tx.$queryRaw`SELECT id FROM organizations WHERE id = ${organizationId} FOR UPDATE`;
    return tx.organization.findUnique({
      where: { id: organizationId },
      select: {
        id: true,
        publicId: true,
        status: true,
        protectionMode: true,
        protectionModeChangedAt: true,
      },
    });
  }

  private async domainModeRows(
    client: Client,
    where: Prisma.DomainWhereInput,
  ): Promise<DomainModeRow[]> {
    const rows = await client.domain.findMany({
      where: { ...where, status: { not: 'deleted' } },
      select: {
        id: true,
        publicId: true,
        name: true,
        protectionMode: true,
        protectionModeChangedAt: true,
        mxRecords: { where: { pointsToGateway: true }, select: { id: true }, take: 1 },
      },
      orderBy: { id: 'asc' },
    });
    return rows.map((r) => ({
      id: r.id,
      publicId: r.publicId,
      name: r.name,
      configured: r.protectionMode,
      changedAt: r.protectionModeChangedAt,
      mxPointsToGateway: r.mxRecords.length > 0,
    }));
  }

  /** Every non-deleted domain of the organization with its mode and MX fact (the caller locks). */
  domainModes(tx: Client, organizationId: bigint): Promise<DomainModeRow[]> {
    return this.domainModeRows(tx, { organizationId });
  }

  /** Locks the scope's non-deleted domain (`FOR UPDATE`) and reads its mode and MX fact. */
  async lockDomain(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<DomainModeRow | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM domains
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
        AND status <> 'deleted'
      FOR UPDATE`;
    const id = rows[0]?.id;
    if (id === undefined) return null;
    const [row] = await this.domainModeRows(tx, tenantWhere(scope, { id }));
    return row ?? null;
  }

  async setOrganizationMode(
    tx: Client,
    organizationId: bigint,
    mode: ProtectionMode,
    now: Date,
  ): Promise<void> {
    await tx.organization.update({
      where: { id: organizationId },
      data: { protectionMode: mode, protectionModeChangedAt: now },
    });
  }

  async setDomainMode(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    mode: ProtectionMode | null,
    now: Date,
  ): Promise<boolean> {
    const { count } = await tx.domain.updateMany({
      where: tenantWhere(scope, { id }),
      data: { protectionMode: mode, protectionModeChangedAt: now },
    });
    return count === 1;
  }

  // ---- connections (D12 #4-#9) ---------------------------------------------------------------

  /** Every 8.2 provider connection of the organization (replica), oldest first. */
  async connections(scope: TenantScope): Promise<ConnectionFacts[]> {
    const rows = await this.reader.client.providerConnection.findMany({
      where: tenantWhere(scope),
      select: connectionSelect,
      orderBy: { id: 'asc' },
    });
    return rows.map(toFacts);
  }

  /** One connection by its 8.2 public id (replica unless a client is given). */
  async connection(
    scope: TenantScope,
    publicId: string,
    client?: Client,
  ): Promise<ConnectionFacts | null> {
    const row = await (client ?? this.reader.client).providerConnection.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: connectionSelect,
    });
    return row === null ? null : toFacts(row);
  }

  /**
   * The connection (locked `FOR UPDATE`) with its API-mode row created lazily (upsert on the
   * unique provider connection id) and locked for the rest of the transaction.
   */
  async lockConnection(
    tx: Client,
    scope: TenantScope,
    publicId: string,
    createdByUserId: bigint | null,
  ): Promise<ConnectionFacts | null> {
    const found = await tx.providerConnection.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, provider: true },
    });
    if (found === null) return null;
    // The provider connection row is locked first, so concurrent lazy creations of the same
    // API-mode row serialize here (the mailbox-worker creates it the same way).
    await tx.$queryRaw`
      SELECT id FROM provider_connections
      WHERE organization_id = ${scope.organizationId} AND id = ${found.id}
      FOR UPDATE`;
    await tx.apiModeConnection.upsert({
      where: { providerConnectionId: found.id },
      create: {
        publicId: uuidv7(),
        organizationId: scope.organizationId,
        providerConnectionId: found.id,
        provider: found.provider,
        createdByUserId,
      },
      update: {},
      select: { id: true },
    });
    await tx.$queryRaw`
      SELECT id FROM api_mode_connections
      WHERE organization_id = ${scope.organizationId} AND provider_connection_id = ${found.id}
      FOR UPDATE`;
    return this.connection(scope, publicId, tx);
  }

  /** CAS update of the API-mode row (`row_version + 1`); false when the version moved. */
  async updateApiConnection(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    rowVersion: number,
    data: ApiConnectionUpdate,
  ): Promise<boolean> {
    const { count } = await tx.apiModeConnection.updateMany({
      where: tenantWhere(scope, { id, rowVersion }),
      data: { ...data, rowVersion: { increment: 1 } },
    });
    return count === 1;
  }

  /**
   * D12 #9: requests an inventory now (`inventory_requested_at`, `next_inventory_at`). Not a
   * settings change: the CAS version of the settings does not move.
   */
  async requestInventory(tx: Client, scope: TenantScope, id: bigint, now: Date): Promise<void> {
    await tx.apiModeConnection.updateMany({
      where: tenantWhere(scope, { id }),
      data: { inventoryRequestedAt: now, nextInventoryAt: now },
    });
  }

  /**
   * D10.1: enabling feeds marks every in-scope mailbox with a provider id (`active`, its domain
   * effective `api`/`hybrid`) `feed_status = pending`, `next_sync_at = now`.
   */
  async markFeedsPending(
    tx: Client,
    scope: TenantScope,
    apiConnectionId: bigint,
    apiModeDomainIds: readonly bigint[],
    now: Date,
  ): Promise<number> {
    if (apiModeDomainIds.length === 0) return 0;
    const { count } = await tx.apiMailbox.updateMany({
      where: tenantWhere(scope, {
        apiConnectionId,
        status: 'active' as const,
        providerUserId: { not: null },
        domainId: { in: [...apiModeDomainIds] },
      }),
      data: { feedStatus: 'pending', nextSyncAt: now },
    });
    return count;
  }

  /** Non-deleted domains whose effective mode is `api` or `hybrid`. */
  async apiModeDomains(
    scope: TenantScope,
    client?: Client,
  ): Promise<Array<{ id: bigint; publicId: string; name: string; connectionId: bigint | null }>> {
    const db = client ?? this.reader.client;
    const [org, rows] = await Promise.all([
      db.organization.findUnique({
        where: { id: scope.organizationId },
        select: { protectionMode: true },
      }),
      db.domain.findMany({
        where: tenantWhere(scope, { status: { not: 'deleted' as const } }),
        select: {
          id: true,
          publicId: true,
          name: true,
          protectionMode: true,
          providerConnectionDomain: { select: { connectionId: true } },
        },
      }),
    ]);
    const orgMode = org?.protectionMode ?? 'inline';
    return rows
      .filter((r) => (r.protectionMode ?? orgMode) !== 'inline')
      .map((r) => ({
        id: r.id,
        publicId: r.publicId,
        name: r.name,
        connectionId: r.providerConnectionDomain?.connectionId ?? null,
      }));
  }

  /** Domains linked to the connection (names; verified at the gateway or not). */
  async linkedDomainNames(scope: TenantScope, connectionId: bigint): Promise<string[]> {
    const rows = await this.reader.client.providerConnectionDomain.findMany({
      where: tenantWhere(scope, { connectionId }),
      select: { domain: { select: { name: true, status: true } } },
    });
    return rows
      .filter((r) => r.domain.status === 'verified' || r.domain.status === 'active')
      .map((r) => r.domain.name)
      .sort();
  }

  /** Active mailboxes per API connection and coverage state (replica). */
  async coverage(
    scope: TenantScope,
    apiConnectionIds: readonly bigint[],
  ): Promise<Map<bigint, { covered: number; gap: number }>> {
    const out = new Map<bigint, { covered: number; gap: number }>();
    if (apiConnectionIds.length === 0) return out;
    const rows = await this.reader.client.apiMailbox.groupBy({
      by: ['apiConnectionId', 'coverageState'],
      where: tenantWhere(scope, {
        apiConnectionId: { in: [...apiConnectionIds] },
        status: 'active' as const,
      }),
      _count: { _all: true },
    });
    for (const r of rows) {
      const entry = out.get(r.apiConnectionId) ?? { covered: 0, gap: 0 };
      if (r.coverageState === 'covered') entry.covered += r._count._all;
      if (r.coverageState === 'gap') entry.gap += r._count._all;
      out.set(r.apiConnectionId, entry);
    }
    return out;
  }

  /** In-scope mailboxes with a provider id, and how many have an active feed (wizard). */
  async feedCounts(
    scope: TenantScope,
    apiConnectionId: bigint,
    apiModeDomainIds: readonly bigint[],
  ): Promise<{ inScope: number; active: number }> {
    if (apiModeDomainIds.length === 0) return { inScope: 0, active: 0 };
    const rows = await this.reader.client.apiMailbox.groupBy({
      by: ['feedStatus'],
      where: tenantWhere(scope, {
        apiConnectionId,
        status: 'active' as const,
        providerUserId: { not: null },
        domainId: { in: [...apiModeDomainIds] },
      }),
      _count: { _all: true },
    });
    return {
      inScope: rows.reduce((n, r) => n + r._count._all, 0),
      active: rows.find((r) => r.feedStatus === 'active')?._count._all ?? 0,
    };
  }

  /** Hourly counters of the connections from `from` (replica), oldest first. */
  async counters(
    scope: TenantScope,
    apiConnectionIds: readonly bigint[],
    from: Date,
  ): Promise<CounterRow[]> {
    if (apiConnectionIds.length === 0) return [];
    return this.reader.client.apiModeCounter.findMany({
      where: tenantWhere(scope, {
        apiConnectionId: { in: [...apiConnectionIds] },
        hour: { gte: isoHour(from) },
      }),
      select: {
        apiConnectionId: true,
        hour: true,
        journalCopies: true,
        feedCopies: true,
        duplicates: true,
        skippedInternal: true,
        tooLarge: true,
        providerRequests: true,
        throttled429: true,
        throttled503: true,
        providerErrors: true,
        cursorResets: true,
        lagCount: true,
        lagLe60s: true,
        lagLe300s: true,
        lagLe900s: true,
        lagLe3600s: true,
        lagGt3600s: true,
        lagMaxMs: true,
      },
      orderBy: [{ hour: 'asc' }, { apiConnectionId: 'asc' }],
    });
  }

  // ---- remediation summary (step API-2 R13) ------------------------------------------------

  /** The remediation fields of the hourly counters from `from` (replica). */
  async remediationCounters(
    scope: TenantScope,
    apiConnectionIds: readonly bigint[],
    from: Date,
  ): Promise<RemediationCounterRow[]> {
    if (apiConnectionIds.length === 0) return [];
    return this.reader.client.apiModeCounter.findMany({
      where: tenantWhere(scope, {
        apiConnectionId: { in: [...apiConnectionIds] },
        hour: { gte: isoHour(from) },
      }),
      select: {
        apiConnectionId: true,
        hour: true,
        remediationSucceeded: true,
        remediationFailed: true,
        remediationSkipped: true,
        remediationSimulated: true,
        restoresSucceeded: true,
        restoresFailed: true,
        remediationThrottled: true,
        remediationLatencyCount: true,
        remediationLatencySumMs: true,
        remediationLatencyMaxMs: true,
      },
      orderBy: [{ hour: 'asc' }, { apiConnectionId: 'asc' }],
    });
  }

  /**
   * The pending actions of each connection, counted up to `cap` (a bounded subquery on the
   * index `(api_connection_id, status)`), and the oldest one's creation time (replica).
   */
  async remediationBacklog(
    scope: TenantScope,
    apiConnectionIds: readonly bigint[],
    cap: number,
  ): Promise<Map<bigint, RemediationBacklog>> {
    const out = new Map<bigint, RemediationBacklog>();
    const db = this.reader.client;
    for (const id of apiConnectionIds) {
      const [count, oldest] = await Promise.all([
        db.$queryRaw<Array<{ n: bigint | number }>>`
          SELECT COUNT(*) AS n FROM (
            SELECT 1 FROM api_remediation_actions
            WHERE api_connection_id = ${id} AND status = 'pending'
              AND organization_id = ${scope.organizationId}
            LIMIT ${cap + 1}) t`,
        db.$queryRaw<Array<{ createdAt: Date }>>`
          SELECT created_at AS createdAt FROM api_remediation_actions
          WHERE api_connection_id = ${id} AND status = 'pending'
            AND organization_id = ${scope.organizationId}
          ORDER BY created_at ASC LIMIT 1`,
      ]);
      const n = Number(count[0]?.n ?? 0);
      out.set(id, {
        pending: Math.min(n, cap),
        capped: n > cap,
        oldestCreatedAt: oldest[0]?.createdAt ?? null,
      });
    }
    return out;
  }

  /** The organization's remediation policy row (mode only), or null = the platform default. */
  async organizationRemediationMode(
    scope: TenantScope,
  ): Promise<{ mode: 'detect_only' | 'enforce' } | null> {
    return this.reader.client.apiRemediationPolicy.findFirst({
      where: tenantWhere(scope, { domainId: null }),
      select: { mode: true },
    });
  }

  // ---- mailboxes (D12 #10-#12) ---------------------------------------------------------------

  private async domainNames(client: Client, ids: readonly (bigint | null)[]): Promise<DomainNames> {
    const wanted = [...new Set(ids.filter((id): id is bigint => id !== null))];
    if (wanted.length === 0) return new Map();
    const rows = await client.domain.findMany({
      where: { id: { in: wanted }, status: { not: 'deleted' } },
      select: { id: true, publicId: true, name: true },
    });
    return new Map(rows.map((r) => [r.id, { publicId: r.publicId, name: r.name }]));
  }

  private toMailbox(row: MailboxPayload, domains: DomainNames): MailboxRow {
    return {
      id: row.id,
      publicId: row.publicId,
      connectionPublicId: row.apiConnection.providerConnection.publicId,
      primaryAddress: row.primaryAddress,
      domain: row.domainId === null ? null : (domains.get(row.domainId) ?? null),
      status: row.status,
      coverageState: row.coverageState,
      coverageChangedAt: row.coverageChangedAt,
      feedStatus: row.feedStatus,
      journalLastSeenAt: row.journalLastSeenAt,
      lastSyncAt: row.lastSyncAt,
      lastErrorCode: row.lastErrorCode,
    };
  }

  /** A page of mailboxes, newest first (replica; keyset on id). */
  async mailboxes(
    scope: TenantScope,
    filter: MailboxFilter,
    page: { take: number; beforeId?: bigint },
  ): Promise<MailboxRow[]> {
    const db = this.reader.client;
    let domainId: bigint | undefined;
    if (filter.domainPublicId !== undefined) {
      const d = await db.domain.findFirst({
        where: tenantWhere(scope, { publicId: filter.domainPublicId }),
        select: { id: true },
      });
      if (d === null) return [];
      domainId = d.id;
    }
    const rows = await db.apiMailbox.findMany({
      where: tenantWhere(scope, {
        ...(filter.connectionPublicId !== undefined && {
          apiConnection: { providerConnection: { publicId: filter.connectionPublicId } },
        }),
        ...(filter.coverage && { coverageState: { in: filter.coverage } }),
        ...(filter.feedStatus && { feedStatus: { in: filter.feedStatus } }),
        ...(filter.status && { status: { in: filter.status } }),
        ...(domainId !== undefined && { domainId }),
        ...(filter.q !== undefined && {
          OR: [
            { primaryAddress: { startsWith: filter.q } },
            { addresses: { some: { address: { startsWith: filter.q } } } },
          ],
        }),
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: mailboxSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
    const names = await this.domainNames(
      db,
      rows.map((r) => r.domainId),
    );
    return rows.map((r) => this.toMailbox(r, names));
  }

  /** One mailbox with its aliases (replica). */
  async mailbox(scope: TenantScope, publicId: string): Promise<MailboxDetailRow | null> {
    const db = this.reader.client;
    const row = await db.apiMailbox.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: {
        ...mailboxSelect,
        feedStartedAt: true,
        subscriptionId: true,
        subscriptionExpiresAt: true,
        lastChangeAt: true,
        lastGapAt: true,
        consecutiveFailures: true,
        addresses: {
          where: { kind: 'alias' },
          select: { address: true },
          orderBy: { address: 'asc' },
        },
      },
    });
    if (row === null) return null;
    const names = await this.domainNames(db, [row.domainId]);
    return {
      ...this.toMailbox(row, names),
      aliases: row.addresses.map((a) => a.address),
      feedStartedAt: row.feedStartedAt,
      // Only whether a subscription exists: its id is never returned (N4).
      subscribed: row.subscriptionId !== null,
      subscriptionExpiresAt: row.subscriptionExpiresAt,
      lastChangeAt: row.lastChangeAt,
      lastGapAt: row.lastGapAt,
      consecutiveFailures: row.consecutiveFailures,
    };
  }

  /** Locks the scope's mailbox (`FOR UPDATE`): id, status and feed status. */
  async lockMailbox(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<{
    id: bigint;
    publicId: string;
    feedStatus: ApiMailboxFeedStatus;
    status: ApiMailboxStatus;
    connectionPublicId: string;
    grantActive: boolean;
  } | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM api_mailboxes
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
      FOR UPDATE`;
    const id = rows[0]?.id;
    if (id === undefined) return null;
    const row = await tx.apiMailbox.findFirst({
      where: tenantWhere(scope, { id }),
      select: {
        id: true,
        publicId: true,
        feedStatus: true,
        status: true,
        apiConnection: {
          select: {
            providerConnection: {
              select: {
                publicId: true,
                grants: {
                  where: { profile: { in: MAILBOX_PROFILES }, status: 'active' },
                  select: { id: true },
                  take: 1,
                },
              },
            },
          },
        },
      },
    });
    if (row === null) return null;
    return {
      id: row.id,
      publicId: row.publicId,
      feedStatus: row.feedStatus,
      status: row.status,
      connectionPublicId: row.apiConnection.providerConnection.publicId,
      grantActive: row.apiConnection.providerConnection.grants.length > 0,
    };
  }

  /**
   * D12 #12: clears the feed cursor (the worker re-initializes without backfill) and requests a
   * sync now.
   */
  async requestResync(tx: Client, scope: TenantScope, id: bigint, now: Date): Promise<void> {
    await tx.apiMailbox.updateMany({
      where: tenantWhere(scope, { id }),
      data: { feedCursor: null, feedStartedAt: null, syncRequestedAt: now, nextSyncAt: now },
    });
  }

  // ---- detections (D12 #13, #14) -------------------------------------------------------------

  private copySql(scope: TenantScope, where: Prisma.Sql, limit: number): Prisma.Sql {
    return Prisma.sql`
      SELECT c.id, c.public_id AS publicId, c.received_at AS receivedAt,
             mb.public_id AS mailboxPublicId, mb.primary_address AS mailboxAddress,
             pc.public_id AS connectionPublicId, c.message_id AS messageId, c.source,
             c.seen_journal AS seenJournal, c.seen_api AS seenApi, c.direction, c.status,
             c.verdict, c.risk_score AS riskScore, c.verdict_authority AS verdictAuthority,
             c.provider_delivered_at AS providerDeliveredAt, c.delivered_basis AS deliveredBasis,
             c.verdict_at AS verdictAt, c.lag_ms AS lagMs,
             m.subject, m.header_from AS headerFrom,
             c.remediation_state AS remediationState, c.remediation_action AS remediationAction,
             la.public_id AS remediationId,
             (SELECT q.public_id FROM quarantine_messages q
               WHERE q.api_copy_id = c.id AND q.api_copy_received_at = c.received_at
                 AND q.organization_id = c.organization_id
               ORDER BY q.id DESC LIMIT 1) AS quarantineEntryId
      FROM api_message_copies c
      JOIN api_mailboxes mb ON mb.id = c.mailbox_id AND mb.organization_id = c.organization_id
      JOIN api_mode_connections ac
        ON ac.id = c.api_connection_id AND ac.organization_id = c.organization_id
      JOIN provider_connections pc
        ON pc.id = ac.provider_connection_id AND pc.organization_id = c.organization_id
      LEFT JOIN email_messages m
        ON m.id = c.message_id AND m.received_at = c.received_at
       AND m.organization_id = c.organization_id
      LEFT JOIN api_remediation_actions la
        ON la.id = c.last_action_id AND la.organization_id = c.organization_id
      WHERE c.organization_id = ${scope.organizationId} AND ${where}
      ORDER BY c.received_at DESC, c.id DESC
      LIMIT ${limit}`;
  }

  private async copies(client: Client, sql: Prisma.Sql): Promise<CopyRow[]> {
    const rows = await client.$queryRaw<Array<Record<string, unknown>>>(sql);
    return rows.map((r) => ({
      id: BigInt(r.id as bigint),
      publicId: r.publicId as string,
      receivedAt: r.receivedAt as Date,
      mailboxPublicId: r.mailboxPublicId as string,
      mailboxAddress: r.mailboxAddress as string,
      connectionPublicId: r.connectionPublicId as string,
      messageId: BigInt(r.messageId as bigint),
      source: r.source as ApiCopySource,
      seenJournal: Boolean(r.seenJournal),
      seenApi: Boolean(r.seenApi),
      direction: r.direction as ApiCopyDirection,
      status: r.status as ApiCopyStatus,
      verdict: (r.verdict as MessageVerdict | null) ?? null,
      riskScore: r.riskScore === null ? null : Number(r.riskScore),
      verdictAuthority: r.verdictAuthority as ApiCopyVerdictAuthority,
      providerDeliveredAt: (r.providerDeliveredAt as Date | null) ?? null,
      deliveredBasis: (r.deliveredBasis as ApiCopyDeliveredBasis | null) ?? null,
      verdictAt: (r.verdictAt as Date | null) ?? null,
      lagMs: r.lagMs === null ? null : Number(r.lagMs),
      subject: (r.subject as string | null) ?? null,
      headerFrom: (r.headerFrom as string | null) ?? null,
      remediationState: (r.remediationState as ApiCopyRemediationState | null) ?? 'none',
      remediationAction: (r.remediationAction as ApiCopyRemediationAction | null) ?? null,
      remediationId: (r.remediationId as string | null) ?? null,
      quarantineEntryId: (r.quarantineEntryId as string | null) ?? null,
    }));
  }

  /** A page of copies in `[from, to)`, newest first (replica; keyset `(received_at, id)`). */
  detections(
    scope: TenantScope,
    filter: CopyFilter,
    range: { from: Date; to: Date },
    page: { take: number; before?: { at: Date; id: bigint } },
  ): Promise<CopyRow[]> {
    const terms: Prisma.Sql[] = [
      Prisma.sql`c.received_at >= ${range.from}`,
      Prisma.sql`c.received_at < ${range.to}`,
    ];
    if (filter.verdict) terms.push(Prisma.sql`c.verdict IN (${Prisma.join(filter.verdict)})`);
    if (filter.status) terms.push(Prisma.sql`c.status IN (${Prisma.join(filter.status)})`);
    if (filter.source) terms.push(Prisma.sql`c.source IN (${Prisma.join(filter.source)})`);
    if (filter.mailboxPublicId !== undefined) {
      terms.push(Prisma.sql`mb.public_id = ${filter.mailboxPublicId}`);
    }
    if (filter.connectionPublicId !== undefined) {
      terms.push(Prisma.sql`pc.public_id = ${filter.connectionPublicId}`);
    }
    if (filter.minRiskScore !== undefined) {
      terms.push(Prisma.sql`c.risk_score >= ${filter.minRiskScore}`);
    }
    if (filter.remediationState) {
      terms.push(Prisma.sql`c.remediation_state IN (${Prisma.join(filter.remediationState)})`);
    }
    if (page.before !== undefined) {
      terms.push(
        Prisma.sql`(c.received_at < ${page.before.at} OR (c.received_at = ${page.before.at} AND c.id < ${page.before.id}))`,
      );
    }
    return this.copies(
      this.reader.client,
      this.copySql(scope, Prisma.join(terms, ' AND '), page.take),
    );
  }

  /** One copy by public id (replica). */
  async detection(scope: TenantScope, publicId: string): Promise<CopyRow | null> {
    const rows = await this.copies(
      this.reader.client,
      this.copySql(scope, Prisma.sql`c.public_id = ${publicId}`, 1),
    );
    return rows[0] ?? null;
  }

  /** The last copies of a mailbox, newest first (replica). */
  recentCopies(scope: TenantScope, mailboxId: bigint, take: number): Promise<CopyRow[]> {
    return this.copies(
      this.reader.client,
      this.copySql(scope, Prisma.sql`c.mailbox_id = ${mailboxId}`, take),
    );
  }

  /** Reason codes of the latest risk score row of the copy's registry message (codes only). */
  async reasonCodes(scope: TenantScope, messageId: bigint, receivedAt: Date): Promise<string[]> {
    const row = await this.reader.client.messageRiskScore.findFirst({
      where: tenantWhere(scope, { messageId, receivedAt }),
      select: { reasonCodes: true },
      orderBy: [{ lifecycleRound: 'desc' }, { revision: 'desc' }, { id: 'desc' }],
    });
    const codes = row?.reasonCodes;
    return Array.isArray(codes) ? codes.filter((c): c is string => typeof c === 'string') : [];
  }

  // ---- public Graph callbacks (D12.4) ------------------------------------------------------

  /** The mailbox of a stored subscription id (writer; the id is the only selector, N3). */
  async mailboxBySubscription(subscriptionId: string): Promise<SubscriptionRow | null> {
    const row = await this.prisma.apiMailbox.findUnique({
      where: { subscriptionId },
      select: {
        id: true,
        feedStatus: true,
        clientStateHash: true,
        apiConnection: { select: { providerConnection: { select: { externalTenantId: true } } } },
      },
    });
    if (row === null) return null;
    return {
      id: row.id,
      feedStatus: row.feedStatus,
      clientStateHash: row.clientStateHash,
      boundTenantId: row.apiConnection.providerConnection.externalTenantId,
    };
  }

  /**
   * The coalescing UPDATE of an accepted notification (D12.4): `sync_requested_at =
   * COALESCE(sync_requested_at, NOW(3))`; lifecycle effects expire or forget the subscription.
   */
  async applyNotification(
    mailboxId: bigint,
    effect: { requestSync: boolean; expireSubscription: boolean; clearSubscription: boolean },
  ): Promise<void> {
    const sets: Prisma.Sql[] = [];
    if (effect.requestSync)
      sets.push(Prisma.sql`sync_requested_at = COALESCE(sync_requested_at, NOW(3))`);
    if (effect.expireSubscription) sets.push(Prisma.sql`subscription_expires_at = NOW(3)`);
    if (effect.clearSubscription) {
      sets.push(Prisma.sql`subscription_id = NULL`, Prisma.sql`subscription_expires_at = NULL`);
    }
    if (sets.length === 0) return;
    await this.prisma.$executeRaw`
      UPDATE api_mailboxes SET ${Prisma.join(sets, ', ')}, updated_at = NOW(3)
      WHERE id = ${mailboxId}`;
  }
}
