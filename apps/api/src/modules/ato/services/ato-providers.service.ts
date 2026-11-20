import { Inject, Injectable } from '@nestjs/common';
import { ATO_TRANSACTION_ISOLATION, PROVIDER_STREAMS } from '@email-gateway/ato-detection';
import { Prisma } from '@email-gateway/database';
import {
  type AtoProviderKind,
  backfillReplay,
  computeEffectiveCapabilities,
  cursorSeq,
  defaultBindingSettings,
  type DirectoryConnection,
  directoryRefHash,
  eligibilityOf,
  GOOGLE_ADAPTER_VERSION,
  type IdpBindingSettings,
  initialCursor,
  MICROSOFT_ADAPTER_VERSION,
  PROVIDER_RETENTION_DAYS,
  sha256Hex,
  STREAM_ROLES,
  validateBindingSettings,
} from '@email-gateway/idp-adapters';
import { ATO_USER_PAUSED_REASON } from '@email-gateway/provider-integrations';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
  type StoredResponse,
} from '../../../http/idempotency/idempotency.service';
import { IncidentStores } from '../../incidents/incident-stores';
import {
  ATO_OPERATIONS,
  ATO_PROVIDER_ACTION_DISABLED_CODE,
  ATO_PROVIDER_AUDIT,
  ATO_PROVIDER_RESOURCE,
  ATO_PROVIDER_USER_DISABLED_REASON,
  ATO_PROVIDERS_MAX_DISABLED_LISTED,
  ATO_TX_TIMEOUT_MS,
  type AtoConfig,
} from '../ato.constants';
import {
  atoProviderAlreadyBound,
  atoProviderBackfillActive,
  atoProviderBackfillRangeInvalid,
  atoProviderConflict,
  atoProviderConnectionIneligible,
  atoProviderConnectionInactive,
  atoProviderConnectionNotFound,
  atoProviderDirectoryInUse,
  atoProviderDisabled,
  atoProviderLimitReached,
  atoProviderNotFound,
  atoProviderSettingsInvalid,
  mapAtoStoreError,
} from '../ato.errors';
import type {
  BackfillBody,
  CreateProviderBody,
  ProviderConnectionsView,
  ProviderDetailView,
  ProviderHealthCheckView,
  ProviderListQuery,
  ProviderListView,
  ProviderReasonBody,
  ProviderRequirementsView,
  UpdateProviderBody,
} from '../dto/ato-providers.schemas';
import {
  changedPaths,
  connectionCandidateView,
  declaredCapabilities,
  detailView,
  kindOf,
  parseReport,
  requirementsView,
  summaryView,
} from '../mappers/ato-providers.mapper';
import { AtoConnectionDirectory } from '../providers/connection-directory.provider';
import {
  AtoProvidersRepository,
  type Db,
  type IntegrationRow,
  isBindingKeyViolation,
  isDirectoryKeyViolation,
  type StreamRow,
  type StreamWrite,
} from '../repositories/ato-providers.repository';
import { AtoAccessService, parsePublicId } from './ato-access.service';

type Tx = Prisma.TransactionClient;
type ProviderConfig = Pick<
  AtoConfig,
  | 'ATO_IDP_MAX_INTEGRATIONS_PER_ORG'
  | 'ATO_IDP_BACKFILL_MAX_DAYS'
  | 'ATO_IDP_HEALTH_INTERVAL_SECONDS'
>;

const DAY_MS = 86_400_000;
/** Non-disabled integrations read for a list (far above the configurable maximum of 50). */
const ACTIVE_LIST_LIMIT = 100;
/** Most permission names stored on an integration (§4.1 `granted_permissions`). */
const MAX_GRANTED_PERMISSIONS = 64;
/** Most directory domains stored on an integration (§4.1 `directory_domains`). */
const MAX_DIRECTORY_DOMAINS = 500;

const adapterVersion = (kind: AtoProviderKind): string =>
  kind === 'microsoft_entra' ? MICROSOFT_ADAPTER_VERSION : GOOGLE_ADAPTER_VERSION;

/** Permission names observed on the connection's ATO grants (D6: what was granted, never assumed). */
function grantedPermissions(entry: DirectoryConnection): string[] {
  const names = new Set<string>();
  for (const profile of entry.profiles) {
    if (profile.grant?.status !== 'active') continue;
    for (const name of profile.grant.observed ?? []) names.add(name);
  }
  return [...names].sort().slice(0, MAX_GRANTED_PERMISSIONS);
}

/**
 * Identity-provider integrations (step 8.5 §6 #1–#11, D4, D6, D8.1, D10; ADR-0082–0084): the
 * binding of a step 8.2 connection to ATO with its D4 eligibility (decided inside the writer
 * transaction under the organization lock: one integration per connection, at most
 * ATO_IDP_MAX_INTEGRATIONS_PER_ORG, the directory bound platform-wide at most once without
 * disclosing the other organization), its stream rows (per `STREAM_ROLES`), the
 * `ato-idp-binding/1` settings (validated as a whole, CAS on `row_version`, changed paths
 * audited), pause/resume, the probe request, the bounded backfill and the removal (pending
 * provider actions end `failed` `integration_disabled` through the 8.4 store). Every mutation is
 * transactional with its Idempotency-Key, audit row and stored response; reads run on the replica.
 */
@Injectable()
export class AtoProvidersService {
  constructor(
    @Inject(API_CONFIG) private readonly config: ProviderConfig,
    private readonly repo: AtoProvidersRepository,
    private readonly directory: AtoConnectionDirectory,
    private readonly access: AtoAccessService,
    private readonly stores: IncidentStores,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
  ) {}

  now(): Date {
    return new Date();
  }

  private ctx(now: Date) {
    return { now, healthIntervalSeconds: this.config.ATO_IDP_HEALTH_INTERVAL_SECONDS };
  }

  // ===================================================================== reads

  /** `GET /ato/providers` (#1). */
  async list(scope: TenantScope, query: ProviderListQuery): Promise<ProviderListView> {
    const max = this.config.ATO_IDP_MAX_INTEGRATIONS_PER_ORG;
    if (!(await this.access.enabled(scope))) {
      return { featureEnabled: false, limit: { max, used: 0 }, data: [] };
    }
    const rows = (
      await this.repo.list(scope, {
        includeDisabled: query.includeDisabled === 'true',
        disabledLimit: ATO_PROVIDERS_MAX_DISABLED_LISTED,
        activeLimit: ACTIVE_LIST_LIMIT,
      })
    ).flatMap((row) => {
      const kind = kindOf(row);
      return kind ? [{ row, kind }] : [];
    });
    const [streams, entries] = await Promise.all([
      this.repo.streams(
        scope,
        rows.map((r) => r.row.id),
      ),
      this.directory.list(scope),
    ]);
    const byConnection = new Map(entries.map((e) => [e.connection.publicId, e]));
    const ctx = this.ctx(this.now());
    return {
      featureEnabled: true,
      limit: { max, used: rows.filter((r) => r.row.status !== 'disabled').length },
      data: rows.map(({ row, kind }) =>
        summaryView(
          row,
          kind,
          streams.filter((s) => s.integrationId === row.id),
          row.connectorRef ? byConnection.get(row.connectorRef) : null,
          ctx,
        ),
      ),
    };
  }

  /** `GET /ato/providers/requirements` (#2): the static catalogue of both providers. */
  requirements(): ProviderRequirementsView {
    return requirementsView();
  }

  /** `GET /ato/providers/connections` (#3): 8.2 connections with their D4 eligibility. */
  async connections(scope: TenantScope): Promise<ProviderConnectionsView> {
    const max = this.config.ATO_IDP_MAX_INTEGRATIONS_PER_ORG;
    if (!(await this.access.enabled(scope))) {
      return { featureEnabled: false, limit: { max, used: 0 }, data: [] };
    }
    const [entries, bound] = await Promise.all([
      this.directory.list(scope),
      this.repo.nonDisabled(scope),
    ]);
    const boundBy = new Map(
      bound.flatMap((r) => (r.connectorRef && kindOf(r) ? [[r.connectorRef, r.publicId]] : [])),
    );
    return {
      featureEnabled: true,
      limit: { max, used: bound.filter((r) => kindOf(r) !== null).length },
      data: entries.map((entry) =>
        connectionCandidateView(
          entry,
          eligibilityOf(entry, new Set(boundBy.keys())),
          boundBy.get(entry.connection.publicId) ?? null,
        ),
      ),
    };
  }

  /** `GET /ato/providers/{id}` (#5): `404` for unknown, foreign, `fake` or feature off. */
  async get(scope: TenantScope, rawId: unknown): Promise<ProviderDetailView> {
    const id = parsePublicId(rawId, 'integrationId');
    if (!(await this.access.enabled(scope))) throw atoProviderNotFound();
    const row = await this.repo.findByPublicId(scope, id);
    const kind = row ? kindOf(row) : null;
    if (!row || !kind) throw atoProviderNotFound();
    return this.detail(scope, row, kind);
  }

  private async detail(
    scope: TenantScope,
    row: IntegrationRow,
    kind: AtoProviderKind,
    db?: Db,
  ): Promise<ProviderDetailView> {
    const [streams, entry] = await Promise.all([
      this.repo.streams(scope, [row.id], db),
      row.connectorRef ? this.directory.get(scope, row.connectorRef, db) : Promise.resolve(null),
    ]);
    return detailView(row, kind, streams, entry, this.ctx(this.now()));
  }

  // =================================================================== mutations

  /** The keyed, transactional frame of every mutation (feature gate inside the transaction). */
  private keyed<T>(
    principal: Principal,
    scope: TenantScope,
    idempotencyKey: unknown,
    operation: string,
    resourceId: string,
    body: unknown,
    work: (tx: Tx) => Promise<StoredResponse<T>>,
  ): Promise<IdempotentResult<T>> {
    const key = parseIdempotencyKey(idempotencyKey);
    return this.idempotency.execute<T>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId,
        fingerprint: requestFingerprint({ operation, resourceId, body }),
      },
      async (tx) => {
        await this.access.requireEnabled(scope, tx);
        return work(tx);
      },
      { timeoutMs: ATO_TX_TIMEOUT_MS, isolationLevel: ATO_TRANSACTION_ISOLATION },
    );
  }

  /** The integration under a row lock; `404` for unknown, foreign or unmanaged (`fake`) rows. */
  private async locked(
    tx: Tx,
    scope: TenantScope,
    id: string,
  ): Promise<{ row: IntegrationRow; kind: AtoProviderKind }> {
    const row = await this.repo.lockByPublicId(tx, scope, id);
    const kind = row ? kindOf(row) : null;
    if (!row || !kind) throw atoProviderNotFound();
    return { row, kind };
  }

  private async record(
    tx: Tx,
    principal: Principal,
    scope: TenantScope,
    action: string,
    row: IntegrationRow,
    sourceIp: string | null,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    await this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: ATO_PROVIDER_RESOURCE,
        resourceId: row.publicId,
        sourceIp,
        metadata: { provider: row.provider, ...metadata },
      },
      tx,
    );
  }

  private validate(kind: AtoProviderKind, settings: unknown): IdpBindingSettings {
    const result = validateBindingSettings(kind, settings, {
      backfillMaxDays: this.config.ATO_IDP_BACKFILL_MAX_DAYS,
    });
    if (!result.ok) throw atoProviderSettingsInvalid(result.issues);
    return result.settings;
  }

  /**
   * The stream rows of a new binding (D4, D8.1): roles, enabled flags and initial backfills. A
   * live stream covers provider time from now on (`covered_from`); a backfill of a revived binding
   * replays (skips) what the earlier stream rows had ingested.
   */
  private streamRows(
    kind: AtoProviderKind,
    settings: IdpBindingSettings,
    now: Date,
    earlier: ReadonlyMap<string, StreamRow> = new Map(),
  ): StreamWrite[] {
    return PROVIDER_STREAMS.map((stream): StreamWrite => {
      const role = STREAM_ROLES[kind][stream].role;
      if (role === 'unsupported') {
        return {
          stream,
          role,
          enabled: false,
          status: 'unsupported',
          availability: 'not_offered',
          nextPollAt: now,
        };
      }
      const enabled = settings.streams[stream].enabled;
      const retention = PROVIDER_RETENTION_DAYS[kind][stream];
      if (role === 'primary' && enabled && settings.backfillDays > 0 && retention > 0) {
        const from = new Date(
          Math.max(
            now.getTime() - settings.backfillDays * DAY_MS,
            now.getTime() - retention * DAY_MS,
          ),
        );
        return {
          stream,
          role,
          enabled,
          status: 'backfilling',
          cursor: initialCursor(adapterVersion(kind), from, 0),
          watermarkAt: from,
          backfillFrom: from,
          backfillRequestedAt: now,
          ...backfillReplay(earlier.get(stream) ?? null),
          nextPollAt: now,
        };
      }
      return { stream, role, enabled, status: 'active', coveredFrom: now, nextPollAt: now };
    });
  }

  private capabilitiesJson(
    kind: AtoProviderKind,
    settings: IdpBindingSettings,
    report: unknown,
    now: Date,
  ): Prisma.InputJsonValue {
    return computeEffectiveCapabilities({
      provider: kind,
      declared: declaredCapabilities(kind),
      report: parseReport(report),
      settings,
      now,
      healthIntervalSeconds: this.config.ATO_IDP_HEALTH_INTERVAL_SECONDS,
    }).capabilities as unknown as Prisma.InputJsonValue;
  }

  /** `POST /ato/providers` (#4, D4): binds a connection; `201` with the full view. */
  create(
    principal: Principal,
    scope: TenantScope,
    idempotencyKey: unknown,
    body: CreateProviderBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<ProviderDetailView>> {
    const connectionId = body.connectionId.toLowerCase();
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.providerCreate,
      '-',
      body,
      async (tx) => {
        await this.repo.lockOrganization(tx, scope);
        const entry = await this.directory.get(scope, connectionId, tx);
        if (!entry) throw atoProviderConnectionNotFound();
        const kind = entry.kind;
        if (!kind) throw atoProviderConnectionIneligible(['wrong_provider']);
        const nonDisabled = (await this.repo.nonDisabled(scope, tx)).filter(
          (r) => kindOf(r) !== null,
        );
        const bound = nonDisabled.find((r) => r.connectorRef === entry.connection.publicId);
        if (bound) throw atoProviderAlreadyBound(bound.publicId);
        const eligibility = eligibilityOf(entry, new Set());
        if (eligibility.eligibility !== 'eligible') {
          throw atoProviderConnectionIneligible(eligibility.reasons);
        }
        const tenant = entry.connection.externalTenantId;
        if (!tenant) throw atoProviderConnectionIneligible(['connection_inactive']);
        const max = this.config.ATO_IDP_MAX_INTEGRATIONS_PER_ORG;
        if (nonDisabled.length >= max) throw atoProviderLimitReached(max);
        const settings = this.validate(kind, body.settings ?? defaultBindingSettings());
        const directoryHash = directoryRefHash(kind, tenant);
        if (await this.repo.directoryInUse(tx, kind, directoryHash)) {
          throw atoProviderDirectoryInUse();
        }
        const now = this.now();
        const bindingKey = sha256Hex(`${kind}|${entry.connection.publicId}`);
        const userId = principal.kind === 'user' ? principal.userId : null;
        const data = {
          provider: kind,
          connectorRef: entry.connection.publicId,
          bindingKey,
          status: 'active' as const,
          capabilities: this.capabilitiesJson(kind, settings, null, now),
          cursors: {},
          lastSuccessAt: null,
          lastErrorCode: null,
          consecutiveFailures: 0,
          nextPollAt: now,
          displayName: entry.connection.displayName.slice(0, 128),
          directoryRefHash: directoryHash,
          directoryDomains: entry.providerVerifiedDomains.slice(0, MAX_DIRECTORY_DOMAINS),
          grantedPermissions: grantedPermissions(entry),
          settings: settings as unknown as Prisma.InputJsonValue,
          healthStatus: 'unknown' as const,
          healthDetail: Prisma.DbNull,
          healthCheckedAt: null,
          nextHealthAt: now,
          pausedReason: null,
          disabledReason: null,
          disabledAt: null,
          updatedByUserId: userId,
        };
        // A connection unbound earlier keeps its disabled row (binding_key is unique per
        // organization): binding it again revives that row with fresh settings and streams.
        const previous = await this.repo.byBindingKey(tx, scope, bindingKey);
        let row: IntegrationRow;
        try {
          row = previous
            ? await this.repo.update(tx, scope, previous.id, {
                ...data,
                settingsVersion: previous.settingsVersion + 1,
                rowVersion: previous.rowVersion + 1,
              })
            : await this.repo.create(tx, scope, {
                ...data,
                settingsVersion: 1,
                rowVersion: 1,
                createdByUserId: userId,
              });
        } catch (error) {
          if (isDirectoryKeyViolation(error)) throw atoProviderDirectoryInUse();
          if (isBindingKeyViolation(error))
            throw atoProviderConnectionIneligible(['already_bound']);
          throw error;
        }
        // A revived binding keeps what its streams already ingested: a backfill skips that range
        // (review fix, "backfill re-ingestion").
        const earlier = previous ? await this.repo.streams(scope, [previous.id], tx) : [];
        await this.repo.replaceStreams(
          tx,
          scope,
          row.id,
          this.streamRows(kind, settings, now, new Map(earlier.map((s) => [s.stream, s]))),
        );
        await this.record(tx, principal, scope, ATO_PROVIDER_AUDIT.bound, row, sourceIp, {
          connectionId: entry.connection.publicId,
          rebound: previous !== null,
          backfillDays: settings.backfillDays,
        });
        return { statusCode: 201, body: await this.detail(scope, row, kind, tx) };
      },
    );
  }

  /** `PATCH /ato/providers/{id}` (#6, D10): the full settings with CAS on `rowVersion`. */
  update(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: UpdateProviderBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<ProviderDetailView>> {
    const id = parsePublicId(rawId, 'integrationId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.providerUpdate,
      id,
      body,
      async (tx) => {
        const { row, kind } = await this.locked(tx, scope, id);
        if (row.status === 'disabled') throw atoProviderDisabled();
        if (row.rowVersion !== body.rowVersion) throw atoProviderConflict(row.rowVersion);
        const settings = this.validate(kind, body.settings);
        const paths = changedPaths(row.settings, settings);
        if (paths.length === 0) {
          return { statusCode: 200, body: await this.detail(scope, row, kind, tx) };
        }
        const now = this.now();
        const updated = await this.repo.update(tx, scope, row.id, {
          settings,
          settingsVersion: row.settingsVersion + 1,
          rowVersion: row.rowVersion + 1,
          capabilities: this.capabilitiesJson(kind, settings, row.healthDetail, now),
          updatedByUserId: principal.kind === 'user' ? principal.userId : null,
        });
        // Enabling a stream schedules it now; disabling stops its polls (the runner claims only
        // enabled primaries). Companion rows follow the flag for the adapter's page filter.
        for (const stream of await this.repo.streams(scope, [row.id], tx)) {
          const role = STREAM_ROLES[kind][stream.stream].role;
          const enabled = role !== 'unsupported' && settings.streams[stream.stream].enabled;
          if (enabled === stream.enabled) continue;
          await this.repo.updateStream(tx, scope, row.id, stream.stream, {
            enabled,
            ...(enabled && {
              nextPollAt: now,
              ...(stream.status === 'paused' && { status: 'active' as const }),
            }),
          });
        }
        await this.record(tx, principal, scope, ATO_PROVIDER_AUDIT.updated, updated, sourceIp, {
          changedPaths: paths.slice(0, 100),
          settingsVersion: updated.settingsVersion,
        });
        return { statusCode: 200, body: await this.detail(scope, updated, kind, tx) };
      },
    );
  }

  /** `POST /ato/providers/{id}/pause` (#7): `paused` (reason `user`); idempotent. */
  pause(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: ProviderReasonBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<ProviderDetailView>> {
    const id = parsePublicId(rawId, 'integrationId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.providerPause,
      id,
      body,
      async (tx) => {
        const { row, kind } = await this.locked(tx, scope, id);
        if (row.status === 'disabled') throw atoProviderDisabled();
        if (row.status === 'paused' && row.pausedReason === ATO_USER_PAUSED_REASON) {
          return { statusCode: 200, body: await this.detail(scope, row, kind, tx) };
        }
        const updated = await this.repo.update(tx, scope, row.id, {
          status: 'paused',
          pausedReason: ATO_USER_PAUSED_REASON,
          rowVersion: row.rowVersion + 1,
          updatedByUserId: principal.kind === 'user' ? principal.userId : null,
        });
        await this.record(tx, principal, scope, ATO_PROVIDER_AUDIT.paused, updated, sourceIp, {
          previousStatus: row.status,
          reason: body.reason,
        });
        return { statusCode: 200, body: await this.detail(scope, updated, kind, tx) };
      },
    );
  }

  /**
   * `POST /ato/providers/{id}/resume` (#8): `active` with polls and a probe now; `409
   * ato_provider_connection_inactive` while the 8.2 connection or its telemetry grant is not
   * active. Idempotent for an active integration.
   */
  resume(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: object,
    sourceIp: string | null,
  ): Promise<IdempotentResult<ProviderDetailView>> {
    const id = parsePublicId(rawId, 'integrationId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.providerResume,
      id,
      body,
      async (tx) => {
        const { row, kind } = await this.locked(tx, scope, id);
        if (row.status === 'disabled') throw atoProviderDisabled();
        if (row.status === 'active') {
          return { statusCode: 200, body: await this.detail(scope, row, kind, tx) };
        }
        const entry = row.connectorRef
          ? await this.directory.get(scope, row.connectorRef, tx)
          : null;
        const eligibility = entry ? eligibilityOf(entry, new Set()) : null;
        if (!entry || eligibility?.eligibility !== 'eligible') {
          throw atoProviderConnectionInactive();
        }
        const now = this.now();
        const updated = await this.repo.update(tx, scope, row.id, {
          status: 'active',
          pausedReason: null,
          nextPollAt: now,
          nextHealthAt: now,
          rowVersion: row.rowVersion + 1,
          updatedByUserId: principal.kind === 'user' ? principal.userId : null,
        });
        for (const stream of await this.repo.streams(scope, [row.id], tx)) {
          if (!stream.enabled || STREAM_ROLES[kind][stream.stream].role !== 'primary') continue;
          await this.repo.updateStream(tx, scope, row.id, stream.stream, { nextPollAt: now });
        }
        await this.record(tx, principal, scope, ATO_PROVIDER_AUDIT.resumed, updated, sourceIp, {
          previousStatus: row.status,
        });
        return { statusCode: 200, body: await this.detail(scope, updated, kind, tx) };
      },
    );
  }

  /** `POST /ato/providers/{id}/health-check` (#9): `next_health_at = now`; `202`. */
  healthCheck(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: object,
    sourceIp: string | null,
  ): Promise<IdempotentResult<ProviderHealthCheckView>> {
    const id = parsePublicId(rawId, 'integrationId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.providerHealthCheck,
      id,
      body,
      async (tx) => {
        const { row, kind } = await this.locked(tx, scope, id);
        if (row.status === 'disabled') throw atoProviderDisabled();
        const now = this.now();
        // A scheduling field only: no row_version bump (an open settings form stays valid).
        const updated = await this.repo.update(tx, scope, row.id, { nextHealthAt: now });
        await this.record(
          tx,
          principal,
          scope,
          ATO_PROVIDER_AUDIT.healthCheckRequested,
          updated,
          sourceIp,
          {},
        );
        const summary = summaryView(updated, kind, [], null, this.ctx(now));
        return {
          statusCode: 202,
          body: {
            id: updated.publicId,
            status: updated.status,
            health: summary.health,
            requestedAt: now.toISOString(),
          },
        };
      },
    );
  }

  /**
   * `POST /ato/providers/{id}/backfill` (#10, D8.1): re-reads the enabled primary streams (or the
   * listed ones) from `from`, clamped per stream by the provider retention; `from` must lie within
   * ATO_IDP_BACKFILL_MAX_DAYS. One backfill per stream at a time. `202` with the full view.
   */
  backfill(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: BackfillBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<ProviderDetailView>> {
    const id = parsePublicId(rawId, 'integrationId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.providerBackfill,
      id,
      body,
      async (tx) => {
        const { row, kind } = await this.locked(tx, scope, id);
        if (row.status === 'disabled') throw atoProviderDisabled();
        const now = this.now();
        const from = new Date(body.from);
        const maxDays = this.config.ATO_IDP_BACKFILL_MAX_DAYS;
        if (
          maxDays === 0 ||
          from.getTime() >= now.getTime() ||
          from.getTime() < now.getTime() - maxDays * DAY_MS
        ) {
          throw atoProviderBackfillRangeInvalid('range');
        }
        const streams = await this.repo.streams(scope, [row.id], tx);
        const byName = new Map(streams.map((s) => [s.stream, s]));
        const backfillable = (stream: (typeof PROVIDER_STREAMS)[number]) =>
          STREAM_ROLES[kind][stream].role === 'primary' &&
          PROVIDER_RETENTION_DAYS[kind][stream] > 0;
        let selected: Array<(typeof PROVIDER_STREAMS)[number]>;
        if (body.streams) {
          selected = [...new Set(body.streams)];
          for (const stream of selected) {
            if (!backfillable(stream)) {
              throw atoProviderBackfillRangeInvalid('stream_not_backfillable', stream);
            }
            if (!byName.get(stream)?.enabled) {
              throw atoProviderBackfillRangeInvalid('stream_disabled', stream);
            }
          }
        } else {
          selected = PROVIDER_STREAMS.filter((s) => backfillable(s) && byName.get(s)?.enabled);
        }
        if (selected.length === 0) throw atoProviderBackfillRangeInvalid('no_stream');
        const running = selected.filter((s) => byName.get(s)?.status === 'backfilling');
        if (running.length > 0) throw atoProviderBackfillActive(running);
        const version = adapterVersion(kind);
        for (const stream of selected) {
          const current = byName.get(stream)!;
          const start = new Date(
            Math.max(
              from.getTime(),
              now.getTime() - PROVIDER_RETENTION_DAYS[kind][stream] * DAY_MS,
            ),
          );
          const seq = Math.max(cursorSeq(current.cursor, version), Number(current.cursorSeq));
          await this.repo.updateStream(tx, scope, row.id, stream, {
            status: 'backfilling',
            // What the stream already ingested is skipped by the runner (review fix): the
            // re-read must not count those events again after the 6 h seen-set expired.
            ...backfillReplay(current),
            backfillFrom: start,
            backfillRequestedAt: now,
            backfillCompletedAt: null,
            watermarkAt: start,
            cursor: initialCursor(version, start, seq),
            nextPollAt: now,
          });
        }
        await this.record(
          tx,
          principal,
          scope,
          ATO_PROVIDER_AUDIT.backfillRequested,
          row,
          sourceIp,
          {
            streams: selected,
            days: Math.round((now.getTime() - from.getTime()) / DAY_MS),
          },
        );
        return { statusCode: 202, body: await this.detail(scope, row, kind, tx) };
      },
    );
  }

  /**
   * `DELETE /ato/providers/{id}` (#11): `disabled` (reason `user`); its in-flight provider actions
   * end `failed` `integration_disabled` through the 8.4 store (timeline, audit, completion event,
   * failure notification). Idempotent for a disabled integration.
   */
  remove(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: ProviderReasonBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<ProviderDetailView>> {
    const id = parsePublicId(rawId, 'integrationId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.providerRemove,
      id,
      body,
      async (tx) => {
        const { row, kind } = await this.locked(tx, scope, id);
        if (row.status === 'disabled') {
          return { statusCode: 200, body: await this.detail(scope, row, kind, tx) };
        }
        const now = this.now();
        const updated = await this.repo.update(tx, scope, row.id, {
          status: 'disabled',
          disabledReason: ATO_PROVIDER_USER_DISABLED_REASON,
          disabledAt: now,
          pausedReason: null,
          rowVersion: row.rowVersion + 1,
          updatedByUserId: principal.kind === 'user' ? principal.userId : null,
        });
        const pending = await this.repo.pendingProviderActions(tx, scope, row.id);
        try {
          for (const action of pending) {
            await this.stores.ato.completeProviderAction(tx, {
              organizationId: scope.organizationId,
              actionId: action.id,
              phase: action.status === 'rollback_requested' ? 'rollback' : 'execute',
              result: {
                status: 'failed',
                code: ATO_PROVIDER_ACTION_DISABLED_CODE,
                retryable: false,
              },
              final: true,
            });
          }
        } catch (error) {
          mapAtoStoreError(error);
        }
        await this.record(tx, principal, scope, ATO_PROVIDER_AUDIT.unbound, updated, sourceIp, {
          connectionId: row.connectorRef,
          previousStatus: row.status,
          endedActions: pending.length,
          reason: body.reason,
        });
        return { statusCode: 200, body: await this.detail(scope, updated, kind, tx) };
      },
    );
  }
}
