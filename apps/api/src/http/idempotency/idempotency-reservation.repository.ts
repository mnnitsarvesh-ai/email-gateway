import { Injectable } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';

type Tx = Prisma.TransactionClient;

/** A `pending` reservation of the interceptor (step 6.1 D9). */
export interface NewReservation {
  organizationId: bigint;
  idempotencyKey: string;
  operation: string;
  principal: string;
  requestSha256: string;
  resourceId: string;
  expiresAt: Date;
}

/**
 * The reservation rows of `api_idempotency_keys` (step 6.1 D9, `state = pending`) on the writer,
 * always inside the caller's transaction. Locking and expiry deletion stay in
 * IdempotencyRepository (one key space for both mechanisms).
 */
@Injectable()
export class IdempotencyReservationRepository {
  /**
   * Inserts a `pending` reservation (status_code 0, response JSON null) and returns its id.
   * A concurrent reservation of the same key fails with P2002 (isIdempotencyKeyViolation).
   */
  async reserve(tx: Tx, record: NewReservation): Promise<bigint> {
    const row = await tx.apiIdempotencyKey.create({
      data: { ...record, statusCode: 0, response: Prisma.JsonNull, state: 'pending' },
      select: { id: true, organizationId: true, idempotencyKey: true },
    });
    // Echo check (step 6.1 D15): the insert must answer with the row it wrote.
    if (
      row.organizationId !== record.organizationId ||
      row.idempotencyKey !== record.idempotencyKey
    ) {
      throw new Error('idempotency reservation insert did not echo its key');
    }
    return row.id;
  }

  /**
   * Turns the reservation `id` into the stored 2xx response (24 h). False when the reservation
   * is gone or no longer pending (it expired and another request replaced it).
   */
  async complete(
    tx: Tx,
    reservation: { id: bigint; organizationId: bigint; idempotencyKey: string },
    response: {
      statusCode: number;
      body: Prisma.InputJsonValue | typeof Prisma.JsonNull;
      expiresAt: Date;
    },
  ): Promise<boolean> {
    const { count } = await tx.apiIdempotencyKey.updateMany({
      where: {
        id: reservation.id,
        organizationId: reservation.organizationId,
        idempotencyKey: reservation.idempotencyKey,
        state: 'pending',
      },
      data: {
        state: 'completed',
        statusCode: response.statusCode,
        response: response.body,
        expiresAt: response.expiresAt,
      },
    });
    return count === 1;
  }

  /** Removes a still-pending reservation (the handler failed; the key may be retried). */
  async release(
    tx: Tx,
    reservation: { id: bigint; organizationId: bigint; idempotencyKey: string },
  ): Promise<boolean> {
    const { count } = await tx.apiIdempotencyKey.deleteMany({
      where: {
        id: reservation.id,
        organizationId: reservation.organizationId,
        idempotencyKey: reservation.idempotencyKey,
        state: 'pending',
      },
    });
    return count === 1;
  }
}
