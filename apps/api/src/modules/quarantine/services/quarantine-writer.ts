import { Inject, Injectable, Logger } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import {
  idempotencyKeyHash,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
  type StoredResponse,
} from '../../../http/idempotency/idempotency.service';
import type { ClientContext } from '../../auth/services/session.service';
import type { QuarantineConfig } from '../quarantine.constants';
import {
  AuditedRefusal,
  InconsistentQuarantineReadError,
  inconsistentRead,
} from '../quarantine.errors';
import { QuarantineMetrics } from './quarantine-metrics';

type Tx = Prisma.TransactionClient;

/** `maxWait` of every quarantine writer transaction (§6). */
export const QUARANTINE_TX_MAX_WAIT_MS = 10_000;

export interface QuarantineAuditEntry {
  principal: Principal;
  scope: TenantScope;
  client: ClientContext;
  action: string;
  resourceType: string;
  resourceId: string | null;
  metadata: Record<string, unknown>;
}

/** One idempotent quarantine mutation (`api_idempotency_keys`). */
export interface IdempotentMutation {
  principal: Principal;
  scope: TenantScope;
  operation: string;
  key: string;
  resourceId: string;
  body: unknown;
}

/**
 * The quarantine writer (step 5.3 §6, Q13.1): every writer transaction has the
 * `QUARANTINE_TX_TIMEOUT_MS` budget (≥ 120 s, the 4.2 §6 mitigation), an echo-check mismatch
 * (`InconsistentQuarantineReadError`) retries the whole transaction once and a second mismatch is
 * `503 inconsistent_read`. A refusal that must be audited (`AuditedRefusal`) rolls the
 * transaction back and is audited in its own transaction before its error is thrown.
 */
@Injectable()
export class QuarantineWriter {
  private readonly logger = new Logger(QuarantineWriter.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: Pick<QuarantineConfig, 'QUARANTINE_TX_TIMEOUT_MS'>,
    private readonly transactions: TransactionRunner,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
    private readonly metrics: QuarantineMetrics,
  ) {}

  get txOptions(): { timeoutMs: number; maxWaitMs: number } {
    return {
      timeoutMs: this.config.QUARANTINE_TX_TIMEOUT_MS,
      maxWaitMs: QUARANTINE_TX_MAX_WAIT_MS,
    };
  }

  /** One writer transaction with the retry rule. */
  run<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
    return this.retrying(() => this.transactions.run(fn, this.txOptions));
  }

  /**
   * An idempotent mutation: Idempotency-Key lookup, `work` and the stored response in one writer
   * transaction (IdempotencyService), with the retry rule and audited refusals.
   */
  async idempotent<T>(
    mutation: IdempotentMutation,
    client: ClientContext,
    work: (tx: Tx) => Promise<StoredResponse<T>>,
  ): Promise<IdempotentResult<T>> {
    try {
      return await this.retrying(() =>
        this.idempotency.execute<T>(
          {
            organizationId: mutation.scope.organizationId,
            principal: principalKey(mutation.principal),
            operation: mutation.operation,
            key: mutation.key,
            resourceId: mutation.resourceId,
            fingerprint: requestFingerprint({
              operation: mutation.operation,
              resourceId: mutation.resourceId,
              body: mutation.body,
            }),
          },
          work,
          { timeoutMs: this.config.QUARANTINE_TX_TIMEOUT_MS },
        ),
      );
    } catch (error) {
      if (!(error instanceof AuditedRefusal)) throw error;
      await this.recordRefusal(mutation.principal, mutation.scope, client, error, mutation.key);
      throw error.error;
    }
  }

  /** Writes an audited refusal's row in its own transaction (best effort is not enough: awaited). */
  async recordRefusal(
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    refusal: AuditedRefusal,
    idempotencyKey?: string,
  ): Promise<void> {
    await this.transactions.run(
      (tx) =>
        this.record(tx, {
          principal,
          scope,
          client,
          action: refusal.audit.action,
          resourceType: 'quarantine_entry',
          resourceId: refusal.audit.resourceId,
          metadata: {
            ...refusal.audit.metadata,
            errorCode: refusal.error.code,
            ...(idempotencyKey !== undefined && {
              idempotencyKeyHash: idempotencyKeyHash(idempotencyKey),
            }),
          },
        }),
      this.txOptions,
    );
  }

  /** One audit row in the caller's transaction (or autocommit without one). */
  record(tx: Tx | undefined, entry: QuarantineAuditEntry): Promise<void> {
    return this.audit.record(
      {
        organizationId: entry.scope.organizationId,
        actor: this.audit.actorFrom(entry.principal),
        action: entry.action,
        resourceType: entry.resourceType,
        resourceId: entry.resourceId,
        sourceIp: entry.client.ip,
        metadata: entry.metadata,
      },
      tx,
    );
  }

  private async retrying<T>(fn: () => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await fn();
      } catch (error) {
        if (!(error instanceof InconsistentQuarantineReadError)) throw error;
        this.metrics.inconsistentReads.inc({ read: error.read });
        this.logger.warn({ message: 'inconsistent quarantine read', read: error.read, attempt });
        if (attempt >= 2) throw inconsistentRead();
      }
    }
  }
}
