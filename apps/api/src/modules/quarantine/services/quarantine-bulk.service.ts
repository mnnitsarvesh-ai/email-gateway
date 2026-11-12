import { createHash } from 'node:crypto';
import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import {
  BULK_ACTION_PERMISSIONS,
  bulkActionNeedsUserMfa,
  type BulkItemResult,
  type BulkRequest,
  type BulkResult,
  bulkResult,
  checkBulkRequest,
} from '@email-gateway/quarantine';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import {
  IDEMPOTENCY_TTL_MS,
  idempotencyKeyHash,
  idempotencyKeyReused,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  IdempotencyRepository,
  isIdempotencyKeyViolation,
} from '../../../http/idempotency/idempotency.repository';
import type { IdempotentResult } from '../../../http/idempotency/idempotency.service';
import { KeyValueStore } from '../../../kv/key-value-store';
import type { ClientContext } from '../../auth/services/session.service';
import {
  type QuarantineConfig,
  QUARANTINE_AUDIT,
  QUARANTINE_OPERATIONS,
  QUARANTINE_RESOURCE,
} from '../quarantine.constants';
import { bulkLimit, bulkRateLimited } from '../quarantine.errors';
import { QuarantineApprovalsService } from './quarantine-approvals.service';
import { QuarantineDispositionService } from './quarantine-disposition.service';
import { QuarantineMetrics } from './quarantine-metrics';
import { QuarantineReleaseService } from './quarantine-release.service';
import { QuarantineWriter } from './quarantine-writer';

type Config = Pick<
  QuarantineConfig,
  | 'QUARANTINE_BULK_MAX_ITEMS'
  | 'QUARANTINE_BULK_MAX_ITEMS_PER_MINUTE'
  | 'QUARANTINE_BULK_DEADLINE_MS'
>;

/** The Idempotency-Key of one item: derived from the request's key and the item id. */
export function bulkItemKey(key: string, id: string): string {
  return `qb.${createHash('sha256').update(key).digest('hex').slice(0, 32)}.${id}`;
}

/** Maps one item's failure to its result (partial failure is never an HTTP error, Q18). */
export function itemFailure(id: string, error: unknown): BulkItemResult | null {
  if (error instanceof CodedHttpException) {
    return error.getStatus() === 404
      ? { id, status: 'not_found', code: error.code }
      : { id, status: 'refused', code: error.code };
  }
  if (error instanceof HttpException) {
    const status = error.getStatus();
    if (status === 404) return { id, status: 'not_found' };
    if (status === 403) return { id, status: 'refused', code: 'forbidden' };
    if (status === 400 || status === 409 || status === 422) {
      return { id, status: 'refused', code: `http_${status}` };
    }
  }
  return null;
}

/**
 * Bulk actions (step 5.3 Q18): request limits (`400 quarantine_bulk_limit`), the action's
 * permission (approve/deny also a user session with MFA), a per-organization per-minute item
 * counter in Redis incremented by the item count before any work (`429
 * quarantine_bulk_rate_limited`), then each item through the **same service method** as its
 * single-item route in its own writer transaction (same re-validation, SoD, CAS, audit; item
 * Idempotency-Keys derived from the request's key), sequentially until the deadline (remaining
 * items `skipped`/`deadline`). The whole response is stored under the request's Idempotency-Key;
 * one `quarantine.bulk` audit row records the action and the counts.
 */
@Injectable()
export class QuarantineBulkService {
  private readonly logger = new Logger(QuarantineBulkService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly kv: KeyValueStore,
    private readonly transactions: TransactionRunner,
    private readonly records: IdempotencyRepository,
    private readonly release: QuarantineReleaseService,
    private readonly disposition: QuarantineDispositionService,
    private readonly approvals: QuarantineApprovalsService,
    private readonly writer: QuarantineWriter,
    private readonly metrics: QuarantineMetrics,
  ) {}

  async bulk(
    principal: Principal,
    scope: TenantScope,
    key: string,
    raw: unknown,
    client: ClientContext,
    now: () => number = Date.now,
  ): Promise<IdempotentResult<BulkResult>> {
    const check = checkBulkRequest(raw, { maxItems: this.config.QUARANTINE_BULK_MAX_ITEMS });
    if (!check.ok) {
      this.metrics.request('bulk', 'limit');
      throw bulkLimit(check.cause, this.config.QUARANTINE_BULK_MAX_ITEMS);
    }
    const request = check.request;
    this.authorize(principal, request);
    const fingerprint = requestFingerprint({
      operation: QUARANTINE_OPERATIONS.bulk,
      resourceId: 'bulk',
      body: request,
    });
    const replay = await this.stored(principal, scope, key, fingerprint);
    if (replay !== null) {
      this.metrics.request('bulk', 'replayed');
      return replay;
    }
    await this.countItems(scope, request.ids.length, now());

    const deadline = now() + this.config.QUARANTINE_BULK_DEADLINE_MS;
    const results: BulkItemResult[] = [];
    for (const id of request.ids) {
      if (now() > deadline) {
        results.push({ id, status: 'skipped', code: 'deadline' });
        continue;
      }
      results.push(await this.item(principal, scope, key, request, id, client));
    }
    for (const r of results)
      this.metrics.bulkItems.inc({ action: request.action, result: r.status });
    const body = bulkResult(request.action, results);
    const stored = await this.store(principal, scope, key, fingerprint, body, client);
    this.metrics.request('bulk', stored.replayed ? 'replayed' : 'done');
    return stored;
  }

  private authorize(principal: Principal, request: BulkRequest): void {
    if (!principal.permissions.has(BULK_ACTION_PERMISSIONS[request.action])) {
      throw new ForbiddenException('Missing permission');
    }
    if (bulkActionNeedsUserMfa(request.action)) {
      if (principal.kind !== 'user') throw new ForbiddenException('This operation requires a user');
      if (!principal.mfaAuthenticated) throw new ForbiddenException('MFA required');
    }
  }

  /** A live stored response of the same request → replay; another request → `422`. */
  private async stored(
    principal: Principal,
    scope: TenantScope,
    key: string,
    fingerprint: string,
  ): Promise<IdempotentResult<BulkResult> | null> {
    return this.transactions.run(async (tx) => {
      const existing = await this.records.lock(tx, scope.organizationId, key);
      if (existing === null) return null;
      if (existing.expiresAt.getTime() <= Date.now()) {
        await this.records.delete(tx, existing.id);
        return null;
      }
      if (
        existing.principal === principalKey(principal) &&
        existing.operation === QUARANTINE_OPERATIONS.bulk &&
        existing.resourceId === 'bulk' &&
        existing.requestSha256 === fingerprint
      ) {
        return {
          replayed: true,
          statusCode: existing.statusCode,
          body: existing.response as BulkResult,
        };
      }
      throw idempotencyKeyReused();
    });
  }

  /** The per-organization per-minute item counter (fixed window, Redis), before any work. */
  private async countItems(scope: TenantScope, items: number, nowMs: number): Promise<void> {
    const minute = Math.floor(nowMs / 60_000);
    let total: number;
    try {
      total = await this.kv.incrByWithTtl(
        `quarantine-bulk-items:${scope.organizationId.toString()}:${minute}`,
        items,
        120,
      );
    } catch (err) {
      this.logger.error({ message: 'Bulk item counter unavailable', err });
      throw new ServiceUnavailableException('Service temporarily unavailable');
    }
    if (total > this.config.QUARANTINE_BULK_MAX_ITEMS_PER_MINUTE) {
      this.metrics.request('bulk', 'rate_limited');
      throw bulkRateLimited(Math.max(1, 60 - Math.floor((nowMs % 60_000) / 1000)));
    }
  }

  private async item(
    principal: Principal,
    scope: TenantScope,
    key: string,
    request: BulkRequest,
    id: string,
    client: ClientContext,
  ): Promise<BulkItemResult> {
    const itemKey = bulkItemKey(key, id);
    try {
      switch (request.action) {
        case 'release': {
          const r = await this.release.release({
            principal,
            scope,
            entryId: id,
            key: itemKey,
            body: { reason: request.reason },
            client,
          });
          return r.body.outcome === 'queued'
            ? { id, status: 'queued', releaseId: r.body.releaseId }
            : { id, status: 'approval_requested', approvalRequestId: r.body.approvalRequestId };
        }
        case 'reject':
          await this.disposition.reject({
            principal,
            scope,
            entryId: id,
            key: itemKey,
            body: {
              reason: request.reason,
              ...(request.notifySender !== undefined && { notifySender: request.notifySender }),
            },
            client,
          });
          return { id, status: 'done' };
        case 'delete':
          await this.disposition.delete({
            principal,
            scope,
            entryId: id,
            key: itemKey,
            body: { reason: request.reason },
            client,
          });
          return { id, status: 'done' };
        case 'approve': {
          const r = await this.approvals.approve({
            principal,
            scope,
            approvalId: id,
            key: itemKey,
            body: { reason: request.reason },
            client,
          });
          return r.body.releaseId === null
            ? { id, status: 'done' }
            : { id, status: 'queued', releaseId: r.body.releaseId };
        }
        case 'deny':
          await this.approvals.deny({
            principal,
            scope,
            approvalId: id,
            key: itemKey,
            body: { reason: request.reason },
            client,
          });
          return { id, status: 'done' };
      }
    } catch (error) {
      const mapped = itemFailure(id, error);
      if (mapped !== null) return mapped;
      this.logger.error({ message: 'bulk item failed', action: request.action, err: error });
      return { id, status: 'refused', code: 'error' };
    }
  }

  /** Stores the whole response under the key with the `quarantine.bulk` audit row. */
  private async store(
    principal: Principal,
    scope: TenantScope,
    key: string,
    fingerprint: string,
    body: BulkResult,
    client: ClientContext,
  ): Promise<IdempotentResult<BulkResult>> {
    try {
      await this.transactions.run(async (tx) => {
        await this.records.insert(tx, {
          organizationId: scope.organizationId,
          idempotencyKey: key,
          operation: QUARANTINE_OPERATIONS.bulk,
          principal: principalKey(principal),
          requestSha256: fingerprint,
          resourceId: 'bulk',
          statusCode: HttpStatus.OK,
          response: body,
          expiresAt: new Date(Date.now() + IDEMPOTENCY_TTL_MS),
        });
        await this.writer.record(tx, {
          principal,
          scope,
          client,
          action: QUARANTINE_AUDIT.bulk,
          resourceType: QUARANTINE_RESOURCE.entry,
          resourceId: null,
          metadata: {
            action: body.action,
            itemCount: body.results.length,
            counts: body.counts,
            idempotencyKeyHash: idempotencyKeyHash(key),
          },
        });
      });
      return { replayed: false, statusCode: HttpStatus.OK, body };
    } catch (error) {
      if (!isIdempotencyKeyViolation(error)) throw error;
      // A concurrent request with the same key stored first: its response wins.
      const replay = await this.stored(principal, scope, key, fingerprint);
      if (replay === null) throw idempotencyKeyReused();
      return replay;
    }
  }
}
