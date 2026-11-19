import { Inject, Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import {
  DEFAULT_PROVIDER_RELAY_PROOF,
  deriveRouteToken,
  providerRelayProofIssues,
} from '@email-gateway/mail-routing';
import {
  canonicalJson,
  defaultMicrosoftMxHost,
  maskRouteToken,
  signImpactToken,
  verifyImpactToken,
} from '@email-gateway/provider-integrations';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import type { ClientContext } from '../../auth/services/session.service';
import { DomainDestinationsService } from '../../domain-destinations/services/domain-destinations.service';
import type { PutDestinationsInput } from '../../domain-destinations/dto/domain-destinations.schemas';
import { connectorLimitReached } from '../../smtp-connectors/smtp-connectors.errors';
import { computeWizard, validateDone } from '../domain/wizard';
import {
  type AppliedView,
  ApplyBodySchema,
  type ChangeSetView,
  type DisconnectedView,
  DisconnectBodySchema,
  type MailFlowChange,
  type MailFlowStateView,
  type PreviewBody,
  type PreviewView,
} from '../dto/provider-connections.schemas';
import { relayProofOf, toConnectionDetail } from '../provider-connections.mapper';
import {
  CONNECTOR_MANAGE,
  DOMAIN_ROUTING_MANAGE,
  INTEGRATION_MANAGE,
  PROBE_PASS_MAX_AGE_MS,
  PROVIDER_AUDIT,
  PROVIDER_OPERATIONS,
  PROVIDER_TX_TIMEOUT_MS,
} from '../provider-connections.constants';
import {
  changeNotApplicable,
  connectionDisabled,
  connectionNotBound,
  connectionNotFound,
  connectionVersionConflict,
  domainNotLinked,
  impactChanged,
  proofPolicyInvalid,
  validationRequired,
} from '../provider-connections.errors';
import {
  type ConnectionAggregate,
  type ConnectionChanges,
  ProviderConnectionsRepository,
} from '../repositories/provider-connections.repository';
import { ProviderGrantsRepository } from '../repositories/provider-grants.repository';
import { ProviderRunsRepository } from '../repositories/provider-runs.repository';
import {
  parseBody,
  parsePublicId,
  principalPublicId,
  principalUserId,
  requirePermission,
} from './provider-common';
import { ProviderConnectionsService } from './provider-connections.service';
import { providerCleanupSteps } from './provider-grants.service';

type Tx = Prisma.TransactionClient;

export type ProviderMailFlowConfig = Pick<
  ApiConfig,
  | 'PROVIDER_IMPACT_TOKEN_KEY'
  | 'PROVIDER_IMPACT_TOKEN_TTL_SECONDS'
  | 'PROVIDER_ROUTE_TOKEN_KEY'
  | 'SMTP_CONNECTORS_MAX_PER_ORGANIZATION'
>;

const DAY_MS = 24 * 3_600_000;

/** What an apply writes, derived with the change set (never from the client). */
interface ApplyPlan {
  domains: Array<{
    domainId: bigint;
    publicId: string;
    input: PutDestinationsInput;
    changed: boolean;
  }>;
  connector: 'create' | 'enable' | 'disable' | 'none';
  connection: ConnectionChanges;
  revokeGrants: boolean;
}

interface Computed {
  changeSet: ChangeSetView;
  warnings: string[];
  plan: ApplyPlan;
}

/** The second permission of each change kind (D13, I4). */
export function changePermission(kind: MailFlowChange['kind']): string {
  return kind === 'inbound' ? DOMAIN_ROUTING_MANAGE : CONNECTOR_MANAGE;
}

/** `<base64url HMAC>.<expiry in Unix seconds>`: the expiry is bound by the HMAC. */
export function encodeImpactToken(signature: string, expiresAt: Date): string {
  return `${signature}.${Math.floor(expiresAt.getTime() / 1000)}`;
}

export function decodeImpactToken(token: string): { signature: string; expiresAt: Date } | null {
  const match = /^([A-Za-z0-9_-]{43})\.(\d{9,11})$/.exec(token);
  if (!match) return null;
  return { signature: match[1]!, expiresAt: new Date(Number(match[2]) * 1000) };
}

/**
 * Gateway-side mail-flow changes of a connection with explicit authorization (step 8.2 D13,
 * ADR-0080; I4): the concrete change set of a change (inbound destinations through the step 2.3
 * presets, the `provider_relay` connector, outbound mode, internal routing, the relay proof
 * policy, suspension and disconnection), the HMAC impact token bound to organization,
 * connection row version, change set, user and a 15-minute expiry, and the apply that
 * recomputes the change set, verifies the token in constant time and writes destinations,
 * connector and connection columns in ONE writer transaction (destinations through
 * `DomainDestinationsService.replaceInTransaction`, which also writes their audit rows and
 * `domain.routing.changed.v1`). Customer-side configuration is never touched (I3).
 */
@Injectable()
export class ProviderMailFlowService {
  private readonly impactKey: Buffer;

  constructor(
    @Inject(API_CONFIG) private readonly config: ProviderMailFlowConfig,
    private readonly connections: ProviderConnectionsRepository,
    private readonly grants: ProviderGrantsRepository,
    private readonly runs: ProviderRunsRepository,
    private readonly destinations: DomainDestinationsService,
    private readonly idempotency: IdempotencyService,
    private readonly base: ProviderConnectionsService,
  ) {
    this.impactKey = Buffer.from(config.PROVIDER_IMPACT_TOKEN_KEY, 'hex');
  }

  now(): Date {
    return new Date();
  }

  /** The concrete change set of `change` for the connection as it is now. */
  async compute(
    scope: TenantScope,
    aggregate: ConnectionAggregate,
    change: MailFlowChange,
    client: Tx | ProviderConnectionsRepository['writer'],
  ): Promise<Computed> {
    const c = aggregate.connection;
    if (c.status === 'disabled') throw connectionDisabled();
    const connector = aggregate.connector;
    const warnings: string[] = [];
    const changes: ChangeSetView['connection'] = [];
    const connection: ConnectionChanges = {};
    const setField = <K extends 'status' | 'outboundMode' | 'internalRouting'>(
      field: K,
      from: unknown,
      to: unknown,
    ) => {
      if (canonicalJson(from) === canonicalJson(to)) return;
      changes.push({ field, from, to });
      (connection as Record<string, unknown>)[field] = to;
    };
    const plan: ApplyPlan = { domains: [], connector: 'none', connection, revokeGrants: false };
    const domains: ChangeSetView['domains'] = [];
    let grantsRevoked = 0;
    const bound = () => {
      if (c.status !== 'active') throw connectionNotBound(c.status);
    };

    switch (change.kind) {
      case 'inbound': {
        bound();
        const ids = change.domainIds.map((id) => id.toLowerCase());
        for (const key of Object.keys(change.microsoftHosts ?? {})) {
          if (!ids.includes(key.toLowerCase())) throw domainNotLinked(key.toLowerCase());
        }
        const linked = ids.map((id) => {
          const domain = aggregate.domains.find((d) => d.domainPublicId === id);
          if (!domain) throw domainNotLinked(id);
          return domain;
        });
        const current = await this.connections.destinations(
          scope,
          linked.map((d) => d.domainId),
          client,
        );
        const hosts = Object.fromEntries(
          Object.entries(change.microsoftHosts ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
        );
        for (const d of [...linked].sort((a, b) => a.name.localeCompare(b.name))) {
          const input: PutDestinationsInput =
            c.provider === 'microsoft_365'
              ? {
                  provider: 'microsoft_365',
                  host:
                    hosts[d.domainPublicId] ?? d.providerMxHost ?? defaultMicrosoftMxHost(d.name),
                }
              : { provider: 'google_workspace' };
          const proposed = await this.destinations.plan(input, client);
          const now = current.get(d.domainId) ?? [];
          const view = (rows: typeof now | typeof proposed) =>
            rows.map((r) => ({
              host: r.host,
              port: r.port,
              priority: r.priority,
              tlsMode: r.tlsMode,
            }));
          const changed =
            canonicalJson(view(now)) !== canonicalJson(view(proposed)) ||
            now.some((r) => r.provider !== c.provider);
          if (d.providerVerification !== 'verified') warnings.push('domain_not_provider_verified');
          if (
            c.provider === 'microsoft_365' &&
            d.providerMxHost !== null &&
            input.provider === 'microsoft_365' &&
            input.host.toLowerCase() !== d.providerMxHost.toLowerCase()
          ) {
            warnings.push('destination_differs_from_provider_mx');
          }
          domains.push({
            domainId: d.domainPublicId,
            name: d.name,
            current: { provider: now[0]?.provider ?? null, servers: view(now) },
            proposed: { provider: c.provider, servers: view(proposed) },
            changed,
          });
          plan.domains.push({ domainId: d.domainId, publicId: d.domainPublicId, input, changed });
        }
        break;
      }
      case 'outbound': {
        bound();
        if (c.outboundMode === 'probe_only' && connector?.status === 'active') {
          throw changeNotApplicable('already_probe_only');
        }
        plan.connector =
          connector === null ? 'create' : connector.status === 'active' ? 'none' : 'enable';
        setField('outboundMode', c.outboundMode, 'probe_only');
        if (c.internalRouting) setField('internalRouting', true, false);
        if (aggregate.domains.some((d) => !d.outboundEnabled)) {
          warnings.push('domain_outbound_not_enabled');
        }
        break;
      }
      case 'activate': {
        bound();
        const state = computeWizard(await this.base.wizardInput(scope, aggregate, client));
        if (!validateDone(state)) throw validationRequired('validation_not_passed');
        if (change.internalRouting && change.outboundMode !== 'active') {
          throw changeNotApplicable('internal_routing_needs_outbound');
        }
        if (change.outboundMode === 'active') {
          if (connector === null || connector.status !== 'active' || c.outboundMode === 'off') {
            throw changeNotApplicable('outbound_not_enabled');
          }
          const since = new Date(this.now().getTime() - PROBE_PASS_MAX_AGE_MS);
          if (!(await this.runs.probePassedSince(client, scope, c.id, since))) {
            throw validationRequired('probe_not_passed');
          }
        } else if (connector?.status === 'active') {
          plan.connector = 'disable';
        }
        setField('outboundMode', c.outboundMode, change.outboundMode);
        setField('internalRouting', c.internalRouting, change.internalRouting);
        if (changes.length === 0 && plan.connector === 'none') {
          throw changeNotApplicable('already_applied');
        }
        if (change.internalRouting && !state.missingAttestations.length) {
          // nothing to warn
        } else if (change.internalRouting) {
          warnings.push('internal_routing_attestation_missing');
        }
        break;
      }
      case 'proof': {
        const issues = providerRelayProofIssues(c.provider, change.relayProof);
        if (issues.length > 0) throw proofPolicyInvalid(issues.length);
        const from = relayProofOf(c).policy;
        const to = { ...change.relayProof };
        if (canonicalJson(from) === canonicalJson(to)) throw changeNotApplicable('already_applied');
        changes.push({ field: 'relayProof', from, to });
        connection.relayProof =
          canonicalJson(to) === canonicalJson(DEFAULT_PROVIDER_RELAY_PROOF[c.provider]) ? null : to;
        if (c.provider === 'microsoft_365' && to.tenantHeader === 'off') {
          warnings.push('tenant_header_off');
        }
        break;
      }
      case 'suspend': {
        if (c.outboundMode !== 'probe_only' && c.outboundMode !== 'active') {
          throw changeNotApplicable('outbound_not_on');
        }
        setField('outboundMode', c.outboundMode, 'suspended');
        setField('internalRouting', c.internalRouting, false);
        break;
      }
      case 'disable_outbound': {
        if (c.outboundMode === 'off' && connector?.status !== 'active') {
          throw changeNotApplicable('outbound_off');
        }
        setField('outboundMode', c.outboundMode, 'off');
        setField('internalRouting', c.internalRouting, false);
        if (connector?.status === 'active') plan.connector = 'disable';
        break;
      }
      case 'disable': {
        grantsRevoked = aggregate.grants.filter((g) => g.status !== 'revoked').length;
        plan.revokeGrants = grantsRevoked > 0;
        if (connector?.status === 'active') plan.connector = 'disable';
        setField('outboundMode', c.outboundMode, 'off');
        setField('internalRouting', c.internalRouting, false);
        setField('status', c.status, 'disabled');
        break;
      }
    }
    return {
      changeSet: {
        kind: change.kind,
        domains,
        connector:
          plan.connector === 'none' && connector === null && change.kind !== 'outbound'
            ? null
            : { action: plan.connector, id: connector?.publicId ?? null },
        connection: changes,
        grantsRevoked,
      },
      warnings: [...new Set(warnings)].sort(),
      plan,
    };
  }

  private tokenBody(
    scope: TenantScope,
    aggregate: ConnectionAggregate,
    principal: Principal,
    changeSet: ChangeSetView,
    expiresAt: Date,
  ) {
    return {
      orgId: scope.organizationId,
      connectionId: aggregate.connection.publicId,
      rowVersion: aggregate.connection.rowVersion,
      changeSet,
      userId: principalPublicId(principal),
      expiresAt,
    };
  }

  /**
   * `POST /provider-connections/{id}/mail-flow/preview` (#15): the change set and the impact
   * token (read on the writer so the apply recomputes the same set). Audited with the change
   * kind and counts only.
   */
  async preview(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    body: PreviewBody,
    sourceIp: string | null,
  ): Promise<PreviewView> {
    requirePermission(principal, changePermission(body.change.kind));
    const writer = this.connections.writer;
    const aggregate = await this.connections.aggregate(scope, parsePublicId(rawId, 'id'), writer);
    if (!aggregate) throw connectionNotFound();
    const computed = await this.compute(scope, aggregate, body.change, writer);
    const ttlMs = this.config.PROVIDER_IMPACT_TOKEN_TTL_SECONDS * 1000;
    const expiresAt = new Date(Math.floor((this.now().getTime() + ttlMs) / 1000) * 1000);
    const signature = signImpactToken(
      this.impactKey,
      this.tokenBody(scope, aggregate, principal, computed.changeSet, expiresAt),
    );
    await this.base.record(undefined, principal, scope, sourceIp, {
      action: PROVIDER_AUDIT.mailFlowPreviewed,
      connectionPublicId: aggregate.connection.publicId,
      metadata: {
        kind: body.change.kind,
        domains: computed.changeSet.domains.length,
        changedDomains: computed.changeSet.domains.filter((d) => d.changed).length,
        fields: computed.changeSet.connection.map((f) => f.field),
      },
    });
    return {
      change: body.change,
      changeSet: computed.changeSet,
      impactToken: encodeImpactToken(signature, expiresAt),
      expiresAt: expiresAt.toISOString(),
      warnings: computed.warnings,
    };
  }

  /**
   * `POST /provider-connections/{id}/mail-flow/apply` (#16): keyed. In one writer transaction
   * with the connection locked: recompute, verify the impact token (`409 impact_changed`), write
   * destinations, connector and connection columns (CAS), audit `integration.mail_flow_applied`
   * with the change set.
   */
  async apply(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    client: ClientContext,
  ): Promise<IdempotentResult<AppliedView>> {
    const publicId = parsePublicId(input.id, 'id');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(ApplyBodySchema, input.body);
    requirePermission(principal, changePermission(body.change.kind));
    if (body.change.kind === 'disable') throw changeNotApplicable('use_disconnect');
    return this.execute(
      principal,
      scope,
      publicId,
      key,
      PROVIDER_OPERATIONS.mailFlowApply,
      body,
      client,
      (aggregate, changeSet, at) => ({
        connection: toConnectionDetail(aggregate),
        changeSet,
        appliedAt: at.toISOString(),
      }),
    );
  }

  /**
   * `DELETE /provider-connections/{id}` (#6, D13 disconnect): keyed; the `disable` change with its
   * impact token: grants revoked and credentials wiped, relay connector disabled (kept for
   * history), outbound off, status `disabled`, tenant binding released. Inbound destinations are
   * KEPT. Returns the provider-side cleanup steps.
   */
  async disconnect(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    client: ClientContext,
  ): Promise<IdempotentResult<DisconnectedView>> {
    const publicId = parsePublicId(input.id, 'id');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(DisconnectBodySchema, input.body);
    return this.execute(
      principal,
      scope,
      publicId,
      key,
      PROVIDER_OPERATIONS.disconnect,
      { change: { kind: 'disable' }, impactToken: body.impactToken, confirm: true },
      client,
      (aggregate) => ({
        connection: toConnectionDetail(aggregate),
        providerCleanupSteps: providerCleanupSteps(aggregate.connection.provider),
        destinationsKept: true as const,
      }),
    );
  }

  private execute<T>(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    key: string,
    operation: string,
    body: { change: MailFlowChange; impactToken: string; confirm: true },
    client: ClientContext,
    respond: (aggregate: ConnectionAggregate, changeSet: ChangeSetView, at: Date) => T,
  ): Promise<IdempotentResult<T>> {
    return this.idempotency.execute<T>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        const aggregate = await this.connections.lock(tx, scope, publicId);
        if (!aggregate) throw connectionNotFound();
        const c = aggregate.connection;
        const computed = await this.compute(scope, aggregate, body.change, tx);
        const token = decodeImpactToken(body.impactToken);
        const now = this.now();
        if (
          token === null ||
          !verifyImpactToken(
            this.impactKey,
            token.signature,
            this.tokenBody(scope, aggregate, principal, computed.changeSet, token.expiresAt),
            now,
          )
        ) {
          throw impactChanged();
        }
        const plan = computed.plan;
        for (const d of plan.domains.filter((x) => x.changed)) {
          await this.destinations.replaceInTransaction(
            tx,
            principal,
            scope,
            d.publicId,
            d.input,
            client,
          );
        }
        if (plan.domains.length > 0) {
          await this.connections.markInboundApplied(
            tx,
            scope,
            c.id,
            plan.domains.map((d) => d.domainId),
            principalUserId(principal),
            now,
          );
        }
        if (plan.connector === 'create') {
          const count = await this.connections.countConnectors(tx, scope);
          if (count >= this.config.SMTP_CONNECTORS_MAX_PER_ORGANIZATION) {
            throw connectorLimitReached(this.config.SMTP_CONNECTORS_MAX_PER_ORGANIZATION);
          }
          await this.connections.createRelayConnector(tx, scope, {
            name: `provider-relay-${c.publicId}`,
            providerConnectionId: c.id,
            createdByUserId: principalUserId(principal),
          });
        } else if (plan.connector === 'enable' || plan.connector === 'disable') {
          await this.connections.setRelayConnectorStatus(
            tx,
            scope,
            aggregate.connector!.id,
            plan.connector === 'enable' ? 'active' : 'disabled',
          );
        }
        if (plan.revokeGrants) await this.grants.revokeAll(tx, scope, c.id);
        const disconnecting = body.change.kind === 'disable';
        const writes: ConnectionChanges = {
          ...plan.connection,
          ...(disconnecting && {
            activeTenantKey: null,
            disabledAt: now,
            disabledByUserId: principalUserId(principal),
            nextHealthCheckAt: null,
          }),
          ...(!disconnecting && { nextHealthCheckAt: now }),
        };
        if (!(await this.connections.update(tx, scope, c.id, c.rowVersion, writes))) {
          throw connectionVersionConflict(c.rowVersion);
        }
        await this.base.record(tx, principal, scope, client.ip, {
          action: disconnecting
            ? PROVIDER_AUDIT.connectionDisconnected
            : PROVIDER_AUDIT.mailFlowApplied,
          connectionPublicId: c.publicId,
          metadata: {
            kind: body.change.kind,
            changeSet: {
              domains: computed.changeSet.domains.map((d) => ({
                name: d.name,
                changed: d.changed,
                provider: d.proposed.provider,
                hosts: d.proposed.servers.map((s) => s.host),
              })),
              connector: computed.changeSet.connector,
              connection: computed.changeSet.connection,
              grantsRevoked: computed.changeSet.grantsRevoked,
            },
            ...(disconnecting && { destinationsKept: true }),
          },
        });
        const after = await this.connections.aggregate(scope, publicId, tx);
        return { statusCode: 200, body: respond(after!, computed.changeSet, now) };
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
  }

  /**
   * `GET /provider-connections/{id}/mail-flow` (#17): desired vs observed per domain, outbound
   * mode, proof policy, relay activity of the last 24 h and the route token (its value only with
   * `integration:manage`, masked otherwise; Microsoft 365 only).
   */
  async state(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
  ): Promise<MailFlowStateView> {
    const aggregate = await this.base.load(scope, rawId);
    const c = aggregate.connection;
    const ids = aggregate.domains.map((d) => d.domainId);
    const [destinations, dns, activity] = await Promise.all([
      this.connections.destinations(scope, ids),
      this.connections.dnsSummaries(scope, ids),
      this.runs.relayActivity(scope, c.id, new Date(this.now().getTime() - DAY_MS)),
    ]);
    const proof = relayProofOf(c);
    let routeToken: MailFlowStateView['routeToken'] = null;
    if (c.provider === 'microsoft_365') {
      const token = deriveRouteToken(
        this.config.PROVIDER_ROUTE_TOKEN_KEY,
        c.publicId,
        c.routeTokenVersion,
      );
      routeToken = {
        version: c.routeTokenVersion,
        pendingVersion: c.routeTokenPendingVersion,
        value: principal.permissions.has(INTEGRATION_MANAGE) ? token : null,
        masked: maskRouteToken(token),
      };
    }
    return {
      connectionId: c.publicId,
      outboundMode: c.outboundMode,
      internalRouting: c.internalRouting,
      relayProof: proof.policy,
      relayProofIsDefault: proof.isDefault,
      relayConnector: aggregate.connector
        ? { id: aggregate.connector.publicId, status: aggregate.connector.status }
        : null,
      domains: aggregate.domains.map((d) => {
        const rows = destinations.get(d.domainId) ?? [];
        const summary = dns.get(d.domainId);
        return {
          id: d.domainPublicId,
          name: d.name,
          destinations: {
            provider: rows[0]?.provider ?? null,
            servers: rows.map((r) => ({
              host: r.host,
              port: r.port,
              priority: r.priority,
              tlsMode: r.tlsMode,
            })),
          },
          inboundAppliedAt: d.inboundAppliedAt?.toISOString() ?? null,
          dns: { mx: summary?.mx ?? null, spf: summary?.spf ?? null },
        };
      }),
      relayActivity24h: {
        ...activity,
        lastAcceptedAt: c.lastRelayAcceptedAt?.toISOString() ?? null,
      },
      routeToken,
    };
  }
}
