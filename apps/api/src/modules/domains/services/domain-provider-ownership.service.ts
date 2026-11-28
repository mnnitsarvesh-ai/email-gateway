import { ConflictException, Inject, Injectable, Logger } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope, type TenantScope } from '../../../auth-contracts/tenant-scope';
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
import { TransactionRunner } from '../../../database/transaction-runner';
import { KeyValueStore } from '../../../kv/key-value-store';
import type { ClientContext } from '../../auth/services/session.service';
import { parseBody } from '../../api-mode/services/protection-mode.service';
import { connectionNotFound } from '../../provider-connections/provider-connections.errors';
import { BoundConnectionsReader } from '../../provider-connections/repositories/bound-connections.repository';
import {
  chooseConnection,
  PROVIDER_CHECK_DOMAIN_STATUSES,
  providerResultAction,
} from '../domain/provider-ownership';
import {
  DomainAuditAction,
  domainKvKeys,
  PROVIDER_CHECK_OPERATION,
  PROVIDER_CHECK_WINDOW_SECONDS,
  PROVIDER_RESULT_BATCH_SIZE,
} from '../domains.constants';
import {
  DOMAIN_OWNED_ELSEWHERE,
  domainNotFound,
  domainNotPending,
  providerConnectionUnavailable,
  TooManyProviderChecksException,
} from '../domains.errors';
import {
  type ProviderOwnershipCheckResponse,
  ProviderOwnershipCheckBodySchema,
} from '../dto/domains.schemas';
import { DomainOwnershipRepository } from '../repositories/domain-ownership.repository';
import {
  DomainsRepository,
  isUniqueViolation,
  isWriteConflict,
} from '../repositories/domains.repository';
import { ProviderVerificationsRepository } from '../repositories/provider-verifications.repository';
import { acquireCheckLock, releaseCheckLock } from './check-lock';
import { DomainEventsService } from './domain-events.service';
import { DomainVerificationService } from './domain-verification.service';

type Tx = Prisma.TransactionClient;

export type ProviderOwnershipConfig = Pick<
  ApiConfig,
  'DOMAIN_PROVIDER_CHECKS_PER_HOUR' | 'DOMAIN_PROVIDER_CHECK_TTL_MINUTES'
>;

/** Counts of one scheduler pass over provider rows. */
export interface ProviderResultSummary {
  due: number;
  verified: number;
  superseded: number;
  failed: number;
  expired: number;
  skipped: number;
  errors: number;
}

const MINUTE_MS = 60_000;

/**
 * Ownership through the organization's bound provider tenant (step API-4 B3, ADR-0107;
 * docs/plan/steps/38-api-mode-parity-onboarding.md). `POST /domains/{id}/ownership/provider-check`
 * requests a check (keyed; at most DOMAIN_PROVIDER_CHECKS_PER_HOUR per organization in a Redis
 * fixed window): a `failed` domain is restarted first exactly as `POST /domains/{id}/verify` does
 * (D3), a name owned by another organization is the existing `409`, a pending provider row of the
 * domain is reused, else a `domain_verifications` row `method = provider_tenant` is written for
 * the integration-worker. The scheduler then applies the worker's answers through
 * `DomainVerificationService.claimThroughProvider` (the one first-to-verify-wins path).
 */
@Injectable()
export class DomainProviderOwnershipService {
  private readonly logger = new Logger(DomainProviderOwnershipService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: ProviderOwnershipConfig,
    private readonly kv: KeyValueStore,
    private readonly idempotency: IdempotencyService,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly domains: DomainsRepository,
    private readonly ownership: DomainOwnershipRepository,
    private readonly providerVerifications: ProviderVerificationsRepository,
    private readonly connections: BoundConnectionsReader,
    private readonly verification: DomainVerificationService,
    private readonly events: DomainEventsService,
  ) {}

  now(): Date {
    return new Date();
  }

  /** `POST /domains/{domainId}/ownership/provider-check` (B3.2): `202` with the pending row. */
  async request(
    principal: Principal,
    scope: TenantScope,
    domainPublicId: string,
    input: { idempotencyKey: unknown; body: unknown },
    client: ClientContext,
  ): Promise<IdempotentResult<ProviderOwnershipCheckResponse>> {
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(ProviderOwnershipCheckBodySchema, input.body ?? {});
    await this.countRequest(scope);
    const operation = PROVIDER_CHECK_OPERATION;
    return this.idempotency.execute<ProviderOwnershipCheckResponse>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: domainPublicId,
        fingerprint: requestFingerprint({ operation, resourceId: domainPublicId, body }),
      },
      async (tx) => ({
        statusCode: 202,
        body: await this.requestIn(tx, principal, scope, domainPublicId, body, client.ip),
      }),
    );
  }

  /** Redis fixed window per organization (`429` with `Retry-After`). */
  private async countRequest(scope: TenantScope): Promise<void> {
    const counter = domainKvKeys.providerCheckCounter(scope.organizationId);
    const count = await this.kv.incrWithTtl(counter, PROVIDER_CHECK_WINDOW_SECONDS);
    if (count > this.config.DOMAIN_PROVIDER_CHECKS_PER_HOUR) {
      const ttl = await this.kv.ttl(counter);
      throw new TooManyProviderChecksException(ttl > 0 ? ttl : PROVIDER_CHECK_WINDOW_SECONDS);
    }
  }

  private async requestIn(
    tx: Tx,
    principal: Principal,
    scope: TenantScope,
    domainPublicId: string,
    body: { connectionId?: string | undefined },
    sourceIp: string | null,
  ): Promise<ProviderOwnershipCheckResponse> {
    let domain = await this.domains.lockByPublicId(tx, scope, domainPublicId);
    if (!domain) throw domainNotFound();
    if (!PROVIDER_CHECK_DOMAIN_STATUSES.has(domain.status)) throw domainNotPending(domain.status);
    // Owned by another organization: the same 409 as creating the name (D4).
    const owner = await this.ownership.findVerifiedOwner(tx, domain.name);
    if (owner && owner.organizationId !== scope.organizationId) {
      throw new ConflictException(DOMAIN_OWNED_ELSEWHERE);
    }
    if (
      body.connectionId !== undefined &&
      (await this.providerVerifications.connectionId(tx, scope, body.connectionId)) === null
    ) {
      throw connectionNotFound();
    }
    const [capable, previous, pending] = await Promise.all([
      this.connections.ownershipCapableConnections(scope, tx),
      this.providerVerifications.latest(scope, domain.id, tx),
      this.providerVerifications.lockPending(tx, scope, domain.id),
    ]);
    const choice = chooseConnection(
      capable,
      body.connectionId,
      pending?.providerConnectionId ?? previous?.providerConnectionId ?? null,
    );
    if (!choice.ok) throw providerConnectionUnavailable(choice.reason, choice.candidates);
    const now = this.now();
    const actor = this.audit.actorFrom(principal);
    if (domain.status === 'failed') {
      // D3: restart exactly as `POST /domains/{id}/verify` (new TXT row, same token).
      const status = await this.verification.restartLocked(tx, scope, domain, actor, sourceIp, now);
      domain = { ...domain, status };
    }
    // Idempotent: a pending provider row of the same connection is reused.
    if (pending && pending.providerConnectionId === choice.connection.id) {
      return {
        verificationId: pending.id.toString(),
        status: 'pending',
        connectionId: choice.connection.publicId,
        expiresAt: pending.expiresAt.toISOString(),
        reused: true,
      };
    }
    if (pending) {
      await this.providerVerifications.finish(tx, scope, pending.id, {
        status: 'expired',
        lastError: 'replaced',
        now,
      });
    }
    const row = await this.providerVerifications.create(tx, scope, {
      domainId: domain.id,
      providerConnectionId: choice.connection.id,
      expiresAt: new Date(
        now.getTime() + this.config.DOMAIN_PROVIDER_CHECK_TTL_MINUTES * MINUTE_MS,
      ),
    });
    await this.events.record(tx, {
      organizationId: scope.organizationId,
      domain,
      action: DomainAuditAction.ProviderVerificationRequested,
      actor,
      sourceIp,
      metadata: { connectionId: choice.connection.publicId, verificationId: row.id.toString() },
    });
    return {
      verificationId: row.id.toString(),
      status: 'pending',
      connectionId: choice.connection.publicId,
      expiresAt: row.expiresAt.toISOString(),
      reused: false,
    };
  }

  /**
   * B3.4 (the scheduler, every tick): pending provider rows with a result or past their expiry,
   * each under the domain's check lock (serialized with TXT checks and manual verification) and
   * in one writer transaction with the domain row locked.
   */
  async applyDue(now: Date): Promise<ProviderResultSummary> {
    const summary: ProviderResultSummary = {
      due: 0,
      verified: 0,
      superseded: 0,
      failed: 0,
      expired: 0,
      skipped: 0,
      errors: 0,
    };
    const due = await this.providerVerifications.due(now, PROVIDER_RESULT_BATCH_SIZE);
    summary.due = due.length;
    for (const row of due) {
      let lock;
      try {
        lock = await acquireCheckLock(this.kv, row.domainId);
      } catch (err) {
        this.logger.warn({ message: 'Provider ownership result skipped: KV unavailable', err });
        summary.skipped++;
        continue;
      }
      if (!lock) {
        summary.skipped++;
        continue;
      }
      try {
        const outcome = await this.applyOne(systemScope(row.organizationId), row, now);
        if (outcome === 'won') summary.verified++;
        else if (outcome === 'lost') summary.superseded++;
        else if (outcome === 'failed') summary.failed++;
        else if (outcome === 'expired') summary.expired++;
        else summary.skipped++;
      } catch (err) {
        summary.errors++;
        this.logger.error({
          message: 'Provider ownership result failed',
          verificationId: row.id.toString(),
          err,
        });
      } finally {
        await releaseCheckLock(this.kv, lock);
      }
    }
    return summary;
  }

  /**
   * One provider row (exposed for the scheduler's tests). A concurrent winner of the name fails
   * the claim on the `verified_name` unique key: the transaction is retried once and then lands
   * in the "owned elsewhere" branch (D4), as a TXT check does.
   */
  async applyOne(
    scope: TenantScope,
    row: { id: bigint; domainId: bigint },
    now: Date,
  ): Promise<'won' | 'lost' | 'failed' | 'expired' | 'none'> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.transactions.run((tx) => this.applyIn(tx, scope, row, now));
      } catch (err) {
        if (attempt === 0 && (isUniqueViolation(err) || isWriteConflict(err))) continue;
        throw err;
      }
    }
  }

  private async applyIn(
    tx: Tx,
    scope: TenantScope,
    row: { id: bigint; domainId: bigint },
    now: Date,
  ): Promise<'won' | 'lost' | 'failed' | 'expired' | 'none'> {
    const domain = await this.domains.lockById(tx, scope, row.domainId);
    const verification = await this.providerVerifications.lock(tx, scope, row.id);
    if (!verification) return 'none';
    const action = providerResultAction(domain?.status ?? null, verification, now);
    if (action.kind === 'done' || action.kind === 'wait') return 'none';
    if (action.kind === 'expire') {
      await this.providerVerifications.finish(tx, scope, verification.id, {
        status: 'expired',
        now,
      });
      return 'expired';
    }
    if (action.kind === 'fail' || domain === null) {
      await this.providerVerifications.finish(tx, scope, verification.id, {
        status: 'failed',
        lastError: action.kind === 'fail' ? action.lastError : 'domain_not_pending',
        now,
      });
      return 'failed';
    }
    const connectionPublicId =
      verification.providerConnectionId === null
        ? null
        : await this.providerVerifications.connectionPublicId(
            tx,
            scope,
            verification.providerConnectionId,
          );
    const result = await this.verification.claimThroughProvider(
      tx,
      scope,
      domain,
      connectionPublicId,
      now,
    );
    await this.providerVerifications.finish(tx, scope, verification.id, {
      status: result === 'won' ? 'verified' : 'failed',
      ...(result === 'won' ? { verifiedAt: now } : { lastError: 'owned_elsewhere' }),
      now,
    });
    return result;
  }
}
