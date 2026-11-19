import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import {
  ATTESTATIONS,
  attestationByCode,
  healthCheckByCode,
  INTEGRATION_PROVIDERS,
  isMailFlowGrant,
  PERMISSION_PROFILES,
} from '@email-gateway/provider-integrations';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
} from '../../messages/domain/v1-list';
import { computeWizard, type WizardInput } from '../domain/wizard';
import {
  type AttestationBody,
  AttestationBodySchema,
  type AttestationsView,
  type CatalogView,
  type ConnectionDetailView,
  type ConnectionListQuery,
  type ConnectionPage,
  CreateConnectionBodySchema,
  type HealthCheckAccepted,
  type HealthView,
  type LinkedDomainList,
  ReplaceDomainsBodySchema,
  type UpdateConnectionBody,
  type WizardView,
} from '../dto/provider-connections.schemas';
import {
  attestationsDocumentOf,
  attestationsOf,
  toConnectionDetail,
  toConnectionSummary,
} from '../provider-connections.mapper';
import {
  HEALTH_TRANSITIONS_SHOWN,
  MAX_ATTESTATIONS,
  PROVIDER_AUDIT,
  PROVIDER_CONNECTION_RESOURCE_TYPE,
  PROVIDER_CONNECTIONS_RESOURCE,
  PROVIDER_OPERATIONS,
  PROVIDER_TX_TIMEOUT_MS,
} from '../provider-connections.constants';
import {
  attestationUnknown,
  connectionDisabled,
  connectionLimit,
  connectionNameExists,
  connectionNotFound,
  connectionVersionConflict,
  domainLinkedElsewhere,
  domainNotInOrganization,
  domainNotVerified,
  outboundActive,
} from '../provider-connections.errors';
import {
  type ConnectionAggregate,
  ProviderConnectionsRepository,
} from '../repositories/provider-connections.repository';
import { ProviderRunsRepository } from '../repositories/provider-runs.repository';
import { parseBody, parsePublicId, principalPublicId, principalUserId } from './provider-common';

type Tx = Prisma.TransactionClient;

export type ProviderConnectionsConfig = Pick<
  ApiConfig,
  | 'PROVIDER_MAX_CONNECTIONS_PER_ORG'
  | 'PROVIDER_MAX_DOMAINS_PER_CONNECTION'
  | 'PROVIDER_M365_MAILFLOW_APP_CLIENT_ID'
  | 'PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID'
  | 'PROVIDER_PROBE_DOMAIN'
  | 'GATEWAY_MX_HOSTS'
  | 'GATEWAY_EGRESS_NETWORKS'
  | 'GATEWAY_RELAY_HOSTS'
  | 'GATEWAY_RELAY_TLS_NAME'
  | 'GATEWAY_SPF_INCLUDE'
>;

const PROVIDER_NAMES = { microsoft_365: 'Microsoft 365', google_workspace: 'Google Workspace' };

/** The audit entry of a connection-scoped action (resource type `provider_connection`). */
export interface ProviderAuditInput {
  action: string;
  connectionPublicId: string;
  metadata: Record<string, unknown>;
}

/**
 * Microsoft 365 / Google Workspace connections of the caller's organization (step 8.2 §5.2 #1–5,
 * #7, #13, #14, #18, #22, #23; D1, D4, D13; ADR-0076, ADR-0080): the catalogue, the connection
 * list and detail, create and rename, the computed wizard, linked domains, attestations and
 * health. Tenant from the scope only; another organization's connection is `404`. Every
 * mutation writes its audit row in its transaction. The api never calls a provider (I1).
 */
@Injectable()
export class ProviderConnectionsService {
  constructor(
    @Inject(API_CONFIG) private readonly config: ProviderConnectionsConfig,
    private readonly connections: ProviderConnectionsRepository,
    private readonly runs: ProviderRunsRepository,
    private readonly idempotency: IdempotencyService,
    private readonly runner: TransactionRunner,
    private readonly limits: OrganizationLimitsService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  /** Platform methods are available only when the operator configured their client id (D2). */
  availableAuthMethods(): Set<string> {
    const out = new Set(['customer_app_secret', 'customer_service_account']);
    if (this.config.PROVIDER_M365_MAILFLOW_APP_CLIENT_ID) out.add('platform_app');
    if (this.config.PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID) out.add('platform_service_account');
    return out;
  }

  /** `GET /provider-integrations/catalog` (#1). */
  async catalog(): Promise<CatalogView> {
    const available = this.availableAuthMethods();
    const sets = await this.runs.activeEgressSets();
    return {
      providers: INTEGRATION_PROVIDERS.map((provider) => {
        const set = sets.find((s) => s.provider === provider);
        return {
          provider,
          displayName: PROVIDER_NAMES[provider],
          profiles: PERMISSION_PROFILES.filter((p) => p.provider === provider).map((p) => ({
            key: p.key,
            version: p.version,
            purpose: p.purpose,
            title: p.title,
            description: p.description,
            permissions: [...p.permissions],
            readOnly: p.readOnly,
            authMethods: [...p.authMethods],
            availableAuthMethods: p.authMethods.filter((m) => available.has(m)),
          })),
          attestations: ATTESTATIONS.filter((a) => a.provider === provider).map((a) => ({
            code: a.code,
            phase: a.phase,
            statement: a.statement,
            requiredFor: a.requiredFor,
          })),
          egressSet: set
            ? {
                version: set.version,
                publishedAt: set.publishedAt?.toISOString() ?? null,
                importedAt: set.importedAt.toISOString(),
                rangeCount: set.rangeCount,
              }
            : null,
        };
      }),
      probeDomain: this.config.PROVIDER_PROBE_DOMAIN,
      gateway: {
        mxHosts: this.config.GATEWAY_MX_HOSTS.map((mx) => mx.host),
        egressNetworks: [...this.config.GATEWAY_EGRESS_NETWORKS],
        relayHosts: [...this.config.GATEWAY_RELAY_HOSTS],
        relayTlsName: this.config.GATEWAY_RELAY_TLS_NAME,
        spfInclude: this.config.GATEWAY_SPF_INCLUDE,
      },
    };
  }

  /** `GET /provider-connections` (#2): newest first, signed tenant-bound cursor (replica). */
  async list(
    principal: Principal,
    scope: TenantScope,
    query: ConnectionListQuery,
  ): Promise<ConnectionPage> {
    const binding = listBinding({
      resource: PROVIDER_CONNECTIONS_RESOURCE,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const fetched = await this.connections.list(scope, {
      take: query.limit + 1,
      ...(decoded && { beforeId: decimalKey(decoded.keys[0]) }),
      ...(query.filters.provider?.values && { providers: query.filters.provider.values }),
      ...(query.filters.status?.values && { statuses: query.filters.status.values }),
      ...(query.filters.health?.values && { health: query.filters.health.values }),
    });
    const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf: (r) => r.id });
    return {
      data: fetched.slice(0, decision.rows).map(toConnectionSummary),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  /** The scope's connection aggregate (replica unless `tx`), or `404`. */
  async load(scope: TenantScope, rawId: unknown, tx?: Tx): Promise<ConnectionAggregate> {
    const aggregate = await this.connections.aggregate(scope, parsePublicId(rawId, 'id'), tx);
    if (!aggregate) throw connectionNotFound();
    return aggregate;
  }

  /** `GET /provider-connections/{id}` (#4). */
  async get(scope: TenantScope, rawId: unknown): Promise<ConnectionDetailView> {
    return toConnectionDetail(await this.load(scope, rawId));
  }

  /**
   * `POST /provider-connections` (#3): keyed; under the organization row lock the cap of live
   * connections (`409 connection_limit`) and the unique name (`409 connection_name_exists`).
   */
  async create(
    principal: Principal,
    scope: TenantScope,
    input: { idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ConnectionDetailView>> {
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(CreateConnectionBodySchema, input.body);
    return this.idempotency.execute<ConnectionDetailView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: PROVIDER_OPERATIONS.create,
        key,
        resourceId: '-',
        fingerprint: requestFingerprint({
          operation: PROVIDER_OPERATIONS.create,
          resourceId: '-',
          body,
        }),
      },
      async (tx) => {
        await this.limits.lockOrganization(tx, scope.organizationId);
        const max = this.config.PROVIDER_MAX_CONNECTIONS_PER_ORG;
        if ((await this.connections.countLive(tx, scope)) >= max) throw connectionLimit(max);
        if (await this.connections.nameTaken(tx, scope, body.displayName)) {
          throw connectionNameExists();
        }
        const created = await this.connections.create(tx, scope, {
          publicId: uuidv7(),
          provider: body.provider,
          displayName: body.displayName,
          createdByUserId: principalUserId(principal),
        });
        await this.record(tx, principal, scope, sourceIp, {
          action: PROVIDER_AUDIT.connectionCreated,
          connectionPublicId: created.publicId,
          metadata: { provider: body.provider, displayName: body.displayName },
        });
        const aggregate = await this.connections.aggregate(scope, created.publicId, tx);
        return { statusCode: 201, body: toConnectionDetail(aggregate!) };
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
  }

  /** `PATCH /provider-connections/{id}` (#5): rename only, CAS on `rowVersion`. */
  async update(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    body: UpdateConnectionBody,
    sourceIp: string | null,
  ): Promise<ConnectionDetailView> {
    const publicId = parsePublicId(rawId, 'id');
    return this.runner.run(
      async (tx) => {
        const aggregate = await this.connections.lock(tx, scope, publicId);
        if (!aggregate) throw connectionNotFound();
        const c = aggregate.connection;
        if (c.rowVersion !== body.rowVersion) throw connectionVersionConflict(c.rowVersion);
        if (c.status === 'disabled') throw connectionDisabled();
        if (body.displayName === c.displayName) return toConnectionDetail(aggregate);
        if (await this.connections.nameTaken(tx, scope, body.displayName, c.id)) {
          throw connectionNameExists();
        }
        if (
          !(await this.connections.update(tx, scope, c.id, c.rowVersion, {
            displayName: body.displayName,
          }))
        ) {
          throw connectionVersionConflict(c.rowVersion);
        }
        await this.record(tx, principal, scope, sourceIp, {
          action: PROVIDER_AUDIT.connectionUpdated,
          connectionPublicId: c.publicId,
          metadata: {
            changedPaths: ['displayName'],
            from: c.displayName,
            to: body.displayName,
            rowVersion: c.rowVersion + 1,
          },
        });
        return toConnectionDetail((await this.connections.aggregate(scope, c.publicId, tx))!);
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
  }

  /** The wizard inputs of an aggregate (D13). */
  async wizardInput(
    scope: TenantScope,
    aggregate: ConnectionAggregate,
    tx?: Tx,
  ): Promise<WizardInput> {
    const c = aggregate.connection;
    const grant = aggregate.grants.find((g) => isMailFlowGrant(g)) ?? null;
    const domainIds = aggregate.domains.map((d) => d.domainId);
    const [destinations, latestFullRun] = await Promise.all([
      this.connections.destinations(scope, domainIds, tx),
      this.runs.latestFullRunStatus(scope, c.id, tx),
    ]);
    return {
      provider: c.provider,
      connectionStatus: c.status,
      outboundMode: c.outboundMode,
      internalRouting: c.internalRouting,
      tenantVerified:
        c.tenantVerifiedAt !== null && c.externalTenantId !== null && c.activeTenantKey !== null,
      mailFlowGrant: grant?.status ?? null,
      domains: aggregate.domains.map((d) => ({
        gatewayActive: d.gatewayStatus === 'active',
        providerVerified: d.providerVerification === 'verified',
        destinationProvider: destinations.get(d.domainId)?.[0]?.provider ?? null,
      })),
      relayConnector: aggregate.connector !== null && aggregate.connector.status === 'active',
      attestations: attestationsOf(c.attestations).map((a) => a.code),
      latestFullRun,
    };
  }

  /** `GET /provider-connections/{id}/wizard` (#7): computed from rows, never stored. */
  async wizard(scope: TenantScope, rawId: unknown): Promise<WizardView> {
    const aggregate = await this.load(scope, rawId);
    const state = computeWizard(await this.wizardInput(scope, aggregate));
    return {
      connectionId: aggregate.connection.publicId,
      provider: aggregate.connection.provider,
      connectionStatus: aggregate.connection.status,
      ...state,
    };
  }

  /** `GET /provider-connections/{id}/domains` (#13). */
  async domains(scope: TenantScope, rawId: unknown): Promise<LinkedDomainList> {
    const aggregate = await this.load(scope, rawId);
    const ids = aggregate.domains.map((d) => d.domainId);
    const [dns, destinations] = await Promise.all([
      this.connections.dnsSummaries(scope, ids),
      this.connections.destinations(scope, ids),
    ]);
    return {
      data: aggregate.domains.map((d) => ({
        id: d.domainPublicId,
        name: d.name,
        gatewayStatus: d.gatewayStatus,
        providerVerification: d.providerVerification,
        providerCheckedAt: d.providerCheckedAt?.toISOString() ?? null,
        providerMxHost: d.providerMxHost,
        destinationProvider: destinations.get(d.domainId)?.[0]?.provider ?? null,
        inboundAppliedAt: d.inboundAppliedAt?.toISOString() ?? null,
        dns: dns.get(d.domainId) ?? { mx: null, spf: null, dkim: null },
      })),
    };
  }

  /**
   * `PUT /provider-connections/{id}/domains` (#14, D4): keyed; replaces the linked set. Each
   * domain must be the organization's (`404 domain_not_in_organization`), `active` at the
   * gateway (`422 domain_not_verified`) and not linked to another connection (`409
   * domain_linked_elsewhere`); unlinking needs outbound off (`409 outbound_active`). The provider
   * check of the new domains is requested from the integration-worker (`next_health_check_at =
   * now`); with no provider-verified domain left an `active` connection returns to `configuring`
   * (I10).
   */
  async replaceDomains(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<LinkedDomainList>> {
    const publicId = parsePublicId(input.id, 'id');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(ReplaceDomainsBodySchema, input.body);
    const ids = [...new Set(body.domainIds.map((id) => id.toLowerCase()))].sort();
    const max = this.config.PROVIDER_MAX_DOMAINS_PER_CONNECTION;
    if (ids.length > max) {
      throw new BadRequestException([
        `domainIds: at most ${max} domains (PROVIDER_MAX_DOMAINS_PER_CONNECTION)`,
      ]);
    }
    const result = await this.idempotency.execute<{ ok: true }>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: PROVIDER_OPERATIONS.domainsReplace,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({
          operation: PROVIDER_OPERATIONS.domainsReplace,
          resourceId: publicId,
          body: { domainIds: ids },
        }),
      },
      async (tx) => {
        const aggregate = await this.connections.lock(tx, scope, publicId);
        if (!aggregate) throw connectionNotFound();
        const c = aggregate.connection;
        if (c.status === 'disabled') throw connectionDisabled();
        const found = await this.connections.scopeDomains(tx, scope, ids);
        for (const id of ids) {
          const domain = found.find((d) => d.publicId === id);
          if (!domain) throw domainNotInOrganization(id);
          if (domain.linkedConnectionId !== null && domain.linkedConnectionId !== c.id) {
            throw domainLinkedElsewhere(id);
          }
          if (domain.status !== 'active') throw domainNotVerified(id);
        }
        const current = new Set(aggregate.domains.map((d) => d.domainId));
        const next = new Set(found.map((d) => d.id));
        const added = [...next].filter((id) => !current.has(id));
        const removed = [...current].filter((id) => !next.has(id));
        if (added.length === 0 && removed.length === 0)
          return { statusCode: 200, body: { ok: true } };
        if (removed.length > 0 && c.outboundMode !== 'off') throw outboundActive(c.outboundMode);
        await this.connections.unlinkDomains(tx, scope, c.id, removed);
        await this.connections.linkDomains(tx, scope, c.id, added);
        const remainingVerified = aggregate.domains.some(
          (d) => next.has(d.domainId) && d.providerVerification === 'verified',
        );
        const ok = await this.connections.update(tx, scope, c.id, c.rowVersion, {
          nextHealthCheckAt: this.now(),
          ...(c.status === 'active' && !remainingVerified && { status: 'configuring' as const }),
        });
        if (!ok) throw connectionVersionConflict(c.rowVersion);
        const names = (list: bigint[]) =>
          [...aggregate.domains.map((d) => ({ id: d.domainId, name: d.name })), ...found]
            .filter((d) => list.includes(d.id))
            .map((d) => d.name)
            .filter((n, i, all) => all.indexOf(n) === i)
            .sort();
        await this.record(tx, principal, scope, sourceIp, {
          action: PROVIDER_AUDIT.domainsLinked,
          connectionPublicId: c.publicId,
          metadata: {
            linked: names(added),
            unlinked: names(removed),
            count: next.size,
          },
        });
        return { statusCode: 200, body: { ok: true } };
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
    return { ...result, body: await this.domainsAfterWrite(scope, publicId) };
  }

  /** The linked domains read on the writer after a change (read-after-write). */
  private async domainsAfterWrite(scope: TenantScope, publicId: string): Promise<LinkedDomainList> {
    const aggregate = await this.connections.aggregate(scope, publicId, this.connections.writer);
    if (!aggregate) throw connectionNotFound();
    const ids = aggregate.domains.map((d) => d.domainId);
    const [dns, destinations] = await Promise.all([
      this.connections.dnsSummaries(scope, ids, this.connections.writer),
      this.connections.destinations(scope, ids, this.connections.writer),
    ]);
    return {
      data: aggregate.domains.map((d) => ({
        id: d.domainPublicId,
        name: d.name,
        gatewayStatus: d.gatewayStatus,
        providerVerification: d.providerVerification,
        providerCheckedAt: d.providerCheckedAt?.toISOString() ?? null,
        providerMxHost: d.providerMxHost,
        destinationProvider: destinations.get(d.domainId)?.[0]?.provider ?? null,
        inboundAppliedAt: d.inboundAppliedAt?.toISOString() ?? null,
        dns: dns.get(d.domainId) ?? { mx: null, spf: null, dkim: null },
      })),
    };
  }

  /**
   * `POST /provider-connections/{id}/attestations` (#18, D13): keyed; records (or withdraws) a
   * statement of the provider's guide (`422 attestation_unknown`). Attesting
   * `m365.internal_routing_rules_updated` during a route-token rotation switches the current
   * version to the pending one (D9).
   */
  async recordAttestation(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<AttestationsView>> {
    const publicId = parsePublicId(input.id, 'id');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body: AttestationBody = parseBody(AttestationBodySchema, input.body);
    return this.idempotency.execute<AttestationsView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: PROVIDER_OPERATIONS.attestationRecord,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({
          operation: PROVIDER_OPERATIONS.attestationRecord,
          resourceId: publicId,
          body,
        }),
      },
      async (tx) => {
        const aggregate = await this.connections.lock(tx, scope, publicId);
        if (!aggregate) throw connectionNotFound();
        const c = aggregate.connection;
        if (c.status === 'disabled') throw connectionDisabled();
        if (!attestationByCode(c.provider, body.code)) throw attestationUnknown();
        const items = attestationsOf(c.attestations).filter((a) => a.code !== body.code);
        const at = this.now();
        if (body.attested) {
          items.push({
            code: body.code,
            userId: principalPublicId(principal),
            at: at.toISOString(),
          });
        }
        const rotate =
          body.attested &&
          body.code === 'm365.internal_routing_rules_updated' &&
          c.routeTokenPendingVersion !== null;
        const ok = await this.connections.update(tx, scope, c.id, c.rowVersion, {
          attestations: attestationsDocumentOf(items.slice(-MAX_ATTESTATIONS)),
          ...(rotate && {
            routeTokenVersion: c.routeTokenPendingVersion!,
            routeTokenPendingVersion: null,
          }),
        });
        if (!ok) throw connectionVersionConflict(c.rowVersion);
        await this.record(tx, principal, scope, sourceIp, {
          action: PROVIDER_AUDIT.attestationRecorded,
          connectionPublicId: c.publicId,
          metadata: {
            attestation: body.code,
            attested: body.attested,
            ...(rotate && { routeTokenVersion: c.routeTokenPendingVersion }),
          },
        });
        return {
          statusCode: 200,
          body: {
            connectionId: c.publicId,
            attestations: items.slice(-MAX_ATTESTATIONS),
            rowVersion: c.rowVersion + 1,
          },
        };
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
  }

  /** `GET /provider-connections/{id}/health` (#22): latest checks, last 20 transitions. */
  async health(scope: TenantScope, rawId: unknown): Promise<HealthView> {
    const aggregate = await this.load(scope, rawId);
    const c = aggregate.connection;
    const [checks, events] = await Promise.all([
      this.runs.healthChecks(scope, c.id),
      this.runs.healthEvents(scope, c.id, HEALTH_TRANSITIONS_SHOWN),
    ]);
    const codes = (value: unknown): string[] =>
      Array.isArray(value)
        ? value.filter((v): v is string => typeof v === 'string').slice(0, 10)
        : [];
    return {
      connectionId: c.publicId,
      status: c.healthStatus,
      checkedAt: c.healthCheckedAt?.toISOString() ?? null,
      changedAt: c.healthChangedAt?.toISOString() ?? null,
      nextCheckAt: c.nextHealthCheckAt?.toISOString() ?? null,
      checks: checks.map((r) => ({
        code: r.checkCode,
        title: healthCheckByCode(r.checkCode)?.title ?? r.checkCode,
        subject: r.subject,
        status: r.status,
        severity: r.severity,
        evidence:
          r.evidence !== null && typeof r.evidence === 'object' && !Array.isArray(r.evidence)
            ? (r.evidence as Record<string, unknown>)
            : null,
        firstFailedAt: r.firstFailedAt?.toISOString() ?? null,
        checkedAt: r.checkedAt.toISOString(),
      })),
      transitions: events.map((e) => ({
        from: e.fromStatus,
        to: e.toStatus,
        failingChecks: codes(e.failingChecks),
        at: e.createdAt.toISOString(),
      })),
    };
  }

  /**
   * `POST /provider-connections/{id}/health/check` (#23): keyed; asks the integration-worker's
   * health role to check now (`next_health_check_at = now`). `202`.
   */
  async checkNow(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<HealthCheckAccepted>> {
    const publicId = parsePublicId(input.id, 'id');
    const key = parseIdempotencyKey(input.idempotencyKey);
    return this.idempotency.execute<HealthCheckAccepted>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: PROVIDER_OPERATIONS.healthCheck,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({
          operation: PROVIDER_OPERATIONS.healthCheck,
          resourceId: publicId,
          body: {},
        }),
      },
      async (tx) => {
        const aggregate = await this.connections.lock(tx, scope, publicId);
        if (!aggregate) throw connectionNotFound();
        const c = aggregate.connection;
        if (c.status === 'disabled') throw connectionDisabled();
        const at = this.now();
        if (
          !(await this.connections.update(tx, scope, c.id, c.rowVersion, { nextHealthCheckAt: at }))
        ) {
          throw connectionVersionConflict(c.rowVersion);
        }
        await this.record(tx, principal, scope, sourceIp, {
          action: PROVIDER_AUDIT.healthCheckRequested,
          connectionPublicId: c.publicId,
          metadata: { status: c.status },
        });
        return {
          statusCode: 202,
          body: { connectionId: c.publicId, nextHealthCheckAt: at.toISOString() },
        };
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
  }

  /** One audit row of the module, in the caller's transaction. */
  async record(
    tx: Tx | undefined,
    principal: Principal,
    scope: TenantScope,
    sourceIp: string | null,
    entry: ProviderAuditInput,
  ): Promise<void> {
    await this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action: entry.action,
        resourceType: PROVIDER_CONNECTION_RESOURCE_TYPE,
        resourceId: entry.connectionPublicId,
        sourceIp,
        metadata: entry.metadata,
      },
      tx,
    );
  }
}
