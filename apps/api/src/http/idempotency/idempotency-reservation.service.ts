import { Inject, Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../api-config.token';
import type { ApiConfig } from '../../config';
import { TransactionRunner } from '../../database/transaction-runner';
import { IDEMPOTENCY_TTL_MS, idempotencyKeyReused } from './idempotency-key';
import { IdempotencyReservationRepository } from './idempotency-reservation.repository';
import {
  IdempotencyRepository,
  isIdempotencyRace,
  isWriteConflict,
} from './idempotency.repository';
import { type IdempotentRequest, IdempotencyService } from './idempotency.service';

/** Writer budget of the two short reservation transactions (no handler work inside). */
const RESERVATION_TX_TIMEOUT_MS = 15_000;

export interface Reservation {
  id: bigint;
  organizationId: bigint;
  idempotencyKey: string;
}

export type ReservationOutcome =
  | { kind: 'replay'; statusCode: number; body: unknown }
  | { kind: 'reserved'; reservation: Reservation };

/**
 * The reservation mechanism of step 6.1 D9 (at most once per key) for legacy services that own
 * their transactions, used by `IdempotencyInterceptor`:
 *
 * 1. `reserve` (transaction 1, short): `SELECT … FOR UPDATE` the key; a live completed match →
 *    replay; a live mismatch → `422 idempotency_key_reused`; a live pending match →
 *    `409 idempotency_request_in_progress`; an expired row is replaced; otherwise a `pending`
 *    row is inserted, expiring after `API_IDEMPOTENCY_PENDING_TTL_SECONDS`. A concurrent
 *    reservation (P2002, or the InnoDB deadlock of two gap locks on the absent key, P2034) is
 *    retried once, which then sees the winner's row.
 * 2. the handler runs (outside any idempotency transaction);
 * 3. `complete` (transaction 2): the 2xx status and body are stored, `state = completed`, 24 h;
 *    or `release`: the pending row is deleted so the client may retry with the same key.
 *
 * A crash between 2 and 3 leaves the pending row until it expires; a retry after that may run
 * the effect again (the documented at-most-once window).
 */
@Injectable()
export class IdempotencyReservationService {
  private readonly logger = new Logger(IdempotencyReservationService.name);

  constructor(
    private readonly runner: TransactionRunner,
    private readonly records: IdempotencyRepository,
    private readonly reservations: IdempotencyReservationRepository,
    private readonly idempotency: IdempotencyService,
    @Inject(API_CONFIG)
    private readonly config: Pick<ApiConfig, 'API_IDEMPOTENCY_PENDING_TTL_SECONDS'>,
  ) {}

  now(): Date {
    return this.idempotency.now();
  }

  async reserve(request: IdempotentRequest): Promise<ReservationOutcome> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.runner.run((tx) => this.reserveIn(tx, request), {
          timeoutMs: RESERVATION_TX_TIMEOUT_MS,
        });
      } catch (error) {
        if (!isIdempotencyRace(error)) throw error;
        // A concurrent request reserved the key between our lock and insert (P2002), or both
        // gap-locked the absent key and InnoDB rolled this one back (deadlock, P2034); the retry
        // sees the winner's row (409 in progress, a replay or 422). Racing twice cannot happen
        // with a live row.
        // A second deadlock is not a key reuse: it goes up as it is (500, retryable).
        if (attempt >= 2) throw isWriteConflict(error) ? error : idempotencyKeyReused();
      }
    }
  }

  private async reserveIn(
    tx: Prisma.TransactionClient,
    request: IdempotentRequest,
  ): Promise<ReservationOutcome> {
    const existing = await this.records.lock(tx, request.organizationId, request.key);
    if (existing) {
      const live = this.idempotency.checkLive(existing, request);
      if (live) return { kind: 'replay', statusCode: live.statusCode, body: live.body };
      await this.records.delete(tx, existing.id);
    }
    const id = await this.reservations.reserve(tx, {
      organizationId: request.organizationId,
      idempotencyKey: request.key,
      operation: request.operation,
      principal: request.principal,
      requestSha256: request.fingerprint,
      resourceId: request.resourceId,
      expiresAt: new Date(
        this.now().getTime() + this.config.API_IDEMPOTENCY_PENDING_TTL_SECONDS * 1000,
      ),
    });
    return {
      kind: 'reserved',
      reservation: { id, organizationId: request.organizationId, idempotencyKey: request.key },
    };
  }

  /** Stores the handler's 2xx response under the reservation (transaction 2). */
  async complete(reservation: Reservation, statusCode: number, body: unknown): Promise<void> {
    if (!Number.isInteger(statusCode) || statusCode < 200 || statusCode > 299) {
      throw new Error('IdempotencyReservationService stores 2xx responses only');
    }
    const stored = await this.runner.run(
      (tx) =>
        this.reservations.complete(tx, reservation, {
          statusCode,
          body:
            body === null || body === undefined ? Prisma.JsonNull : (body as Prisma.InputJsonValue),
          expiresAt: new Date(this.now().getTime() + IDEMPOTENCY_TTL_MS),
        }),
      { timeoutMs: RESERVATION_TX_TIMEOUT_MS },
    );
    if (!stored) {
      // The reservation expired and was replaced (or purged) while the handler ran: the effect
      // happened, the response is served, but a retry with this key is not a replay.
      this.logger.warn({
        message: 'Idempotency reservation was gone when the response was stored',
        reservationId: reservation.id.toString(10),
      });
    }
  }

  /** Deletes the pending reservation after a failed handler (best effort, logged). */
  async release(reservation: Reservation): Promise<void> {
    try {
      await this.runner.run((tx) => this.reservations.release(tx, reservation), {
        timeoutMs: RESERVATION_TX_TIMEOUT_MS,
      });
    } catch (err) {
      this.logger.error({
        message: 'Could not release an idempotency reservation; it expires on its own',
        reservationId: reservation.id.toString(10),
        err,
      });
    }
  }
}
