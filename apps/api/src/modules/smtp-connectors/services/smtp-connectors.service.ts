import { BadRequestException, ConflictException, Inject, Injectable, Logger } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { PasswordHasher } from '../../../crypto/password-hasher';
import { TransactionRunner } from '../../../database/transaction-runner';
import { type Page, pageWindow, toPage } from '../../../http/pagination';
import { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import type { ClientContext } from '../../auth/services/session.service';
import { toConnectorView } from '../connector.mapper';
import { generateSaslSecret, generateSaslUsername } from '../domain/credentials';
import {
  isPublicNetwork,
  NON_PUBLIC_NETWORK_MESSAGE,
  type ParsedNetwork,
  parseNetwork,
} from '../domain/networks';
import type {
  ConnectorView,
  CreateConnectorInput,
  CreatedConnector,
  ListConnectorsQuery,
  RotatedSecret,
  UpdateConnectorInput,
} from '../dto/smtp-connectors.schemas';
import {
  ConnectorAuditAction,
  CONNECTOR_RESOURCE_TYPE,
  NETWORK_LOCK_TIMEOUT_SECONDS,
  USERNAME_ATTEMPTS,
} from '../smtp-connectors.constants';
import {
  connectorLimitReached,
  connectorNameExists,
  connectorNotFound,
  fingerprintExists,
  NOT_SASL,
  networkLockBusy,
  networkOverlap,
} from '../smtp-connectors.errors';
import {
  type ConnectorRow,
  connectorUniqueViolation,
  type ConnectorWrite,
  SmtpConnectorsRepository,
} from '../repositories/smtp-connectors.repository';

type Client = Prisma.TransactionClient;

export type SmtpConnectorsConfig = Pick<
  ApiConfig,
  'SMTP_CONNECTORS_MAX_PER_ORGANIZATION' | 'SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS'
>;

/**
 * Outbound SMTP connectors of an organization (step 2.2 D10, §4.1): SASL credentials, source
 * networks and client-certificate fingerprints that let a tenant's servers relay through
 * `postfix-outbound`. Every method works inside the caller's tenant scope (another tenant's
 * connector is `404`); global rules (one connector per username, certificate and address)
 * are checked without revealing the other tenant. Mutations are audited in their transaction.
 */
@Injectable()
export class SmtpConnectorsService {
  private readonly logger = new Logger(SmtpConnectorsService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: SmtpConnectorsConfig,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly hasher: PasswordHasher,
    private readonly limits: OrganizationLimitsService,
    private readonly connectors: SmtpConnectorsRepository,
  ) {}

  /**
   * `POST /smtp-connectors`. The secret (sasl) is generated and hashed before the transaction
   * (Argon2id takes a while). Inside one writer transaction with the organization row locked:
   * per-organization limit, unique name, unique fingerprint, unique generated username, insert,
   * then the networks under the global network lock, then the audit row. Returns the
   * credentials once.
   */
  async create(
    principal: Principal,
    scope: TenantScope,
    input: CreateConnectorInput,
    client: ClientContext,
  ): Promise<CreatedConnector> {
    const networks = this.publicOnly((input.networks ?? []).map((cidr) => parseNetwork(cidr)));
    const password = input.authType === 'sasl' ? generateSaslSecret() : null;
    const secretHash = password === null ? null : await this.hasher.hash(password);

    for (let attempt = 1; ; attempt++) {
      try {
        const { id, username } = await this.transactions.run(async (tx) => {
          await this.limits.lockOrganization(tx, scope.organizationId);
          const count = await this.connectors.count(tx, scope);
          if (count >= this.config.SMTP_CONNECTORS_MAX_PER_ORGANIZATION) {
            throw connectorLimitReached(this.config.SMTP_CONNECTORS_MAX_PER_ORGANIZATION);
          }
          if (await this.connectors.nameTaken(tx, scope, input.name)) throw connectorNameExists();
          const fingerprint = input.certificateFingerprintSha256 ?? null;
          if (fingerprint !== null && (await this.connectors.fingerprintTaken(tx, fingerprint))) {
            throw fingerprintExists();
          }
          const saslUsername = input.authType === 'sasl' ? await this.allocateUsername(tx) : null;
          const now = new Date();
          const created = await this.connectors.create(tx, scope, {
            name: input.name,
            authType: input.authType,
            saslUsername,
            secretHash,
            secretSetAt: saslUsername === null ? null : now,
            certFingerprintSha256: fingerprint,
            requireTls: input.requireTls ?? true,
            createdByUserId: principal.kind === 'user' ? principal.userId : null,
          });
          await this.writeNetworks(tx, scope, created.id, networks, false);
          await this.record(
            tx,
            principal,
            scope,
            client,
            ConnectorAuditAction.Created,
            created.publicId,
            {
              name: input.name,
              authType: input.authType,
              saslUsername,
              certificateFingerprintSha256: fingerprint,
              networks: networks.map((n) => n.cidr),
              requireTls: input.requireTls ?? true,
            },
          );
          return { id: created.publicId, username: saslUsername };
        });
        const view = await this.get(scope, id);
        return {
          ...view,
          ...(username !== null && password !== null && { credentials: { username, password } }),
        };
      } catch (err) {
        const violated = connectorUniqueViolation(err);
        // A concurrent insert won a unique key between the check and the insert.
        if (violated === 'username' && attempt < USERNAME_ATTEMPTS) continue;
        if (violated === 'name') throw connectorNameExists();
        if (violated === 'fingerprint') throw fingerprintExists();
        throw err;
      }
    }
  }

  /** `GET /smtp-connectors`: newest first, from the replica. */
  async list(scope: TenantScope, query: ListConnectorsQuery): Promise<Page<ConnectorView>> {
    const rows = await this.connectors.list(
      scope,
      {
        ...(query.status && { status: query.status }),
        ...(query.authType && { authType: query.authType }),
      },
      pageWindow(query),
    );
    return toPage(rows, query.limit, toConnectorView);
  }

  /** `GET /smtp-connectors/{id}` (writer). */
  async get(scope: TenantScope, publicId: string): Promise<ConnectorView> {
    const row = await this.connectors.findByPublicId(scope, publicId);
    if (!row) throw connectorNotFound();
    return toConnectorView(row);
  }

  /**
   * `PATCH /smtp-connectors/{id}`: name, status, requireTls and the networks (replaced
   * atomically under the global network lock with the same checks as on create).
   */
  async update(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    input: UpdateConnectorInput,
    client: ClientContext,
  ): Promise<ConnectorView> {
    const parsed = input.networks?.map((cidr) => parseNetwork(cidr));
    const networks = parsed === undefined ? undefined : this.publicOnly(parsed);
    try {
      await this.transactions.run(async (tx) => {
        const row = await this.connectors.lockByPublicId(tx, scope, publicId);
        if (!row) throw connectorNotFound();
        assertUpdateAllowed(row, input);

        const write: ConnectorWrite = {};
        const changes: Record<string, unknown> = {};
        if (input.name !== undefined && input.name !== row.name) {
          if (await this.connectors.nameTaken(tx, scope, input.name, row.id)) {
            throw connectorNameExists();
          }
          write.name = input.name;
          changes.name = { from: row.name, to: input.name };
        }
        if (input.status !== undefined && input.status !== row.status) {
          write.status = input.status;
          changes.status = { from: row.status, to: input.status };
        }
        if (input.requireTls !== undefined && input.requireTls !== row.requireTls) {
          write.requireTls = input.requireTls;
          changes.requireTls = { from: row.requireTls, to: input.requireTls };
        }
        if (networks !== undefined) {
          const before = row.networks.map((n) => n.cidr);
          const after = networks.map((n) => n.cidr);
          if (!sameSet(before, after)) {
            await this.writeNetworks(tx, scope, row.id, networks, true);
            changes.networks = { from: before, to: after };
          }
        }
        if (Object.keys(changes).length === 0) return; // nothing changed: no write, no audit
        if (Object.keys(write).length > 0) await this.connectors.update(tx, scope, row.id, write);
        else await this.connectors.touch(tx, scope, row.id, new Date());
        await this.record(tx, principal, scope, client, ConnectorAuditAction.Updated, publicId, {
          changes,
        });
      });
    } catch (err) {
      if (connectorUniqueViolation(err) === 'name') throw connectorNameExists();
      throw err;
    }
    return this.get(scope, publicId);
  }

  /**
   * `POST /smtp-connectors/{id}/rotate-secret`: sasl only (`409` otherwise). The new password
   * is returned once; the previous one stops working at commit (and the adapter's
   * verification cache is keyed on `updated_at`, which changes).
   */
  async rotateSecret(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    client: ClientContext,
  ): Promise<RotatedSecret> {
    const found = await this.connectors.findByPublicId(scope, publicId);
    if (!found) throw connectorNotFound();
    if (found.authType !== 'sasl') throw new ConflictException(NOT_SASL);
    const password = generateSaslSecret();
    const secretHash = await this.hasher.hash(password);
    const at = new Date();
    const username = await this.transactions.run(async (tx) => {
      const row = await this.connectors.lockByPublicId(tx, scope, publicId);
      if (!row) throw connectorNotFound();
      if (row.authType !== 'sasl' || row.saslUsername === null) {
        throw new ConflictException(NOT_SASL);
      }
      await this.connectors.setSecret(tx, scope, row.id, secretHash, at);
      await this.record(
        tx,
        principal,
        scope,
        client,
        ConnectorAuditAction.SecretRotated,
        publicId,
        { saslUsername: row.saslUsername },
      );
      return row.saslUsername;
    });
    return {
      id: publicId,
      credentials: { username, password },
      secretSetAt: at.toISOString(),
    };
  }

  /** `DELETE /smtp-connectors/{id}`: hard delete, networks cascade. */
  async remove(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    client: ClientContext,
  ): Promise<void> {
    await this.transactions.run(async (tx) => {
      const row = await this.connectors.lockByPublicId(tx, scope, publicId);
      if (!row) throw connectorNotFound();
      await this.connectors.delete(tx, scope, row.id);
      await this.record(tx, principal, scope, client, ConnectorAuditAction.Deleted, publicId, {
        name: row.name,
        authType: row.authType,
        networks: row.networks.map((n) => n.cidr),
      });
    });
  }

  // ---- internals -----------------------------------------------------------------------

  /** A generated username no connector uses yet (100 random bits, so a retry is rare). */
  private async allocateUsername(tx: Client): Promise<string> {
    for (let i = 0; i < USERNAME_ATTEMPTS; i++) {
      const username = generateSaslUsername();
      if (!(await this.connectors.usernameTaken(tx, username))) return username;
    }
    throw new Error('Could not allocate a unique SASL username');
  }

  /**
   * Refuses (400, per index like the DTO's errors) networks that overlap a non-public range,
   * unless SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS (dedicated deployments, local stack).
   */
  private publicOnly(networks: ParsedNetwork[]): ParsedNetwork[] {
    if (this.config.SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS) return networks;
    const refused = networks.flatMap((network, index) =>
      isPublicNetwork(network) ? [] : [`networks.${index}: ${NON_PUBLIC_NETWORK_MESSAGE}`],
    );
    if (refused.length > 0) throw new BadRequestException(refused);
    return networks;
  }

  /**
   * Writes the connector's networks under the global named lock: optionally deletes the
   * current ones first (replacement), checks each new network against every stored network of
   * every organization (`409` on overlap, without details), inserts them, and releases the lock
   * on the same connection. Lock timeout → `503`.
   */
  private async writeNetworks(
    tx: Client,
    scope: TenantScope,
    connectorId: bigint,
    networks: readonly ParsedNetwork[],
    replace: boolean,
  ): Promise<void> {
    if (networks.length === 0 && !replace) return;
    if (!(await this.connectors.acquireNetworkLock(tx, NETWORK_LOCK_TIMEOUT_SECONDS))) {
      throw networkLockBusy();
    }
    try {
      if (replace) await this.connectors.deleteNetworks(tx, scope, connectorId);
      for (const network of networks) {
        if (await this.connectors.overlapsExisting(tx, network)) {
          // Overlaps are a cross-tenant signal (a probe, or a claim of someone else's range):
          // logged for alerting, never with the other tenant (the reply has no details).
          this.logger.warn({
            message: 'Connector network refused: overlaps an existing connector network',
            organizationId: scope.organizationId.toString(),
            ipVersion: network.ipVersion,
            prefix: network.prefix,
          });
          throw networkOverlap();
        }
      }
      await this.connectors.insertNetworks(tx, scope, connectorId, networks);
    } finally {
      try {
        await this.connectors.releaseNetworkLock(tx);
      } catch (err) {
        // The lock dies with the connection at the latest; never mask the original outcome.
        this.logger.error({ message: 'Releasing the connector network lock failed', err });
      }
    }
  }

  private async record(
    tx: Client,
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    action: ConnectorAuditAction,
    publicId: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    await this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: CONNECTOR_RESOURCE_TYPE,
        resourceId: publicId,
        sourceIp: client.ip,
        metadata,
      },
      tx,
    );
  }
}

/** Rules of D10 that depend on the stored connector (`400` with the field path). */
export function assertUpdateAllowed(
  row: Pick<ConnectorRow, 'authType'>,
  input: UpdateConnectorInput,
): void {
  if (input.networks !== undefined) {
    if (row.authType === 'sasl') {
      throw new BadRequestException(['networks: is not allowed for sasl']);
    }
    if (row.authType === 'source_ip' && input.networks.length === 0) {
      throw new BadRequestException(['networks: must contain at least one network for source_ip']);
    }
  }
  if (input.requireTls === false && row.authType !== 'source_ip') {
    throw new BadRequestException([
      'requireTls: cannot be false: TLS is always required for sasl and client_certificate',
    ]);
  }
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((item) => set.has(item));
}
