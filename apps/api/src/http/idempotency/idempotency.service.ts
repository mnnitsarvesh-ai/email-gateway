import { Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { TransactionRunner } from '../../database/transaction-runner';
import {
  IDEMPOTENCY_TTL_MS,
  IdempotencyInProgressException,
  idempotencyKeyReused,
} from './idempotency-key';
import {
  type IdempotencyRecord,
  IdempotencyRepository,
  isIdempotencyRace,
  isWriteConflict,
} from './idempotency.repository';

type Tx = Prisma.TransactionClient;

/** What identifies one idempotent request (L11). */
export interface IdempotentRequest {
  organizationId: bigint;
  /** `user:<publicId>` | `api_key:<publicId>` (principalKey). */
  principal: string;
  /** e.g. `message.rescan`. */
  operation: string;
  /** The validated Idempotency-Key header. */
  key: string;
  /** Public id of the addressed resource. */
  resourceId: string;
  /** requestFingerprint({ operation, resourceId, body }). */
  fingerprint: string;
}

/** A 2xx response that is stored under the key. */
export interface StoredResponse<T> {
  statusCode: number;
  body: T;
}

export interface IdempotentResult<T> extends StoredResponse<T> {
  /** true when the stored response of an earlier request is returned (nothing was done). */
  replayed: boolean;
}

/**
 * Thrown by a `work` function when it finds that a concurrent request with the same key already
 * applied its effect (e.g. the message history already has the transition key): the transaction
 * rolls back and `execute` retries once, which then replays the stored response.
 */
export class IdempotencyRaceError extends Error {
  override readonly name = 'IdempotencyRaceError';
  constructor() {
    super('a concurrent request with the same Idempotency-Key committed first');
  }
}

export interface ExecuteOptions {
  /** Writer transaction timeout (default 10 s). */
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * The Idempotency-Key store (step 3.3 L11): exactly-once API writes that commit atomically with
 * their effect, their audit row and the stored response (one writer transaction).
 *
 * - `runOnce` (inside the caller's transaction): `SELECT … FOR UPDATE` by
 *   `(organization_id, idempotency_key)`. A live record with the same principal, operation and
 *   fingerprint → its stored response is returned (`replayed: true`, `work` does not run); any
 *   other live record → `422 idempotency_key_reused`; a live `pending` reservation of the step
 *   6.1 interceptor with the same request → `409 idempotency_request_in_progress` (with the
 *   seconds until it expires as Retry-After). An expired record is deleted and treated as
 *   absent. Otherwise `work` runs and its 2xx response is stored (expires in 24 h). A `work`
 *   that throws (4xx, 5xx) rolls everything back: errors are never stored under the key.
 * - `execute`: `runOnce` in its own writer transaction. A concurrent request that stored the
 *   same key first makes the insert fail with P2002 (or with an InnoDB deadlock, P2034, when
 *   both gap-locked the absent key; or `work` throws IdempotencyRaceError); the whole
 *   transaction is retried once, which then replays or refuses. A second race is a key
 *   reuse (`422`).
 */
@Injectable()
export class IdempotencyService {
  constructor(
    private readonly runner: TransactionRunner,
    private readonly records: IdempotencyRepository,
  ) {}

  now(): Date {
    return new Date();
  }

  async runOnce<T>(
    tx: Tx,
    request: IdempotentRequest,
    work: (tx: Tx) => Promise<StoredResponse<T>>,
  ): Promise<IdempotentResult<T>> {
    const existing = await this.records.lock(tx, request.organizationId, request.key);
    if (existing) {
      const live = this.checkLive<T>(existing, request);
      if (live) return live;
      await this.records.delete(tx, existing.id);
    }
    const result = await work(tx);
    if (
      !Number.isInteger(result.statusCode) ||
      result.statusCode < 200 ||
      result.statusCode > 299
    ) {
      throw new Error('IdempotencyService stores 2xx responses only');
    }
    await this.records.insert(tx, {
      organizationId: request.organizationId,
      idempotencyKey: request.key,
      operation: request.operation,
      principal: request.principal,
      requestSha256: request.fingerprint,
      resourceId: request.resourceId,
      statusCode: result.statusCode,
      response: result.body as Prisma.InputJsonValue,
      expiresAt: new Date(this.now().getTime() + IDEMPOTENCY_TTL_MS),
    });
    return { replayed: false, ...result };
  }

  /**
   * The decision for an existing record (inside the locking transaction): a replay of a live
   * completed match, a refusal (`422` mismatch, `409` live pending match), or null when the
   * record expired (the caller deletes and replaces it).
   */
  checkLive<T>(
    existing: IdempotencyRecord,
    request: IdempotentRequest,
  ): IdempotentResult<T> | null {
    const remainingMs = existing.expiresAt.getTime() - this.now().getTime();
    if (remainingMs <= 0) return null;
    const same =
      existing.principal === request.principal &&
      existing.operation === request.operation &&
      existing.resourceId === request.resourceId &&
      existing.requestSha256 === request.fingerprint;
    if (!same) throw idempotencyKeyReused();
    if (existing.state === 'pending') {
      throw new IdempotencyInProgressException(Math.max(1, Math.ceil(remainingMs / 1000)));
    }
    return { replayed: true, statusCode: existing.statusCode, body: existing.response as T };
  }

  async execute<T>(
    request: IdempotentRequest,
    work: (tx: Tx) => Promise<StoredResponse<T>>,
    options: ExecuteOptions = {},
  ): Promise<IdempotentResult<T>> {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.runner.run((tx) => this.runOnce(tx, request, work), { timeoutMs });
      } catch (error) {
        const race = error instanceof IdempotencyRaceError || isIdempotencyRace(error);
        if (!race) throw error;
        // The retry sees the committed record and replays (or refuses) it. Racing twice means the
        // effect exists without a live record (a key reused after its record expired).
        // A second deadlock is not a key reuse: it goes up as it is (500, retryable).
        if (attempt >= 2) throw isWriteConflict(error) ? error : idempotencyKeyReused();
      }
    }
  }
}
