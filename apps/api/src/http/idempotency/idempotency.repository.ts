import { Injectable } from '@nestjs/common';
import { type ApiIdempotencyState, Prisma } from '@email-gateway/database';

type Tx = Prisma.TransactionClient;

/** One `api_idempotency_keys` row as the service reads it. */
export interface IdempotencyRecord {
  id: bigint;
  operation: string;
  principal: string;
  requestSha256: string;
  resourceId: string;
  statusCode: number;
  response: unknown;
  expiresAt: Date;
  /**
   * `completed` (stored 2xx) or `pending` (a reservation of the interceptor, step 6.1 D9);
   * absent means `completed` (records built before 6.1).
   */
  state?: ApiIdempotencyState;
}

export interface NewIdempotencyRecord {
  organizationId: bigint;
  idempotencyKey: string;
  operation: string;
  principal: string;
  requestSha256: string;
  resourceId: string;
  statusCode: number;
  response: Prisma.InputJsonValue;
  expiresAt: Date;
}

interface RecordRow {
  id: bigint;
  operation: string;
  principal: string;
  request_sha256: string;
  resource_id: string;
  status_code: number | bigint;
  response: unknown;
  expires_at: Date;
  state: ApiIdempotencyState;
}

/** The unique key `(organization_id, idempotency_key)` of `api_idempotency_keys`. */
const UNIQUE_KEY = 'api_idempotency_keys_organization_id_idempotency_key_key';

/** A P2002 on `(organization_id, idempotency_key)`: a concurrent request stored the key first. */
export function isIdempotencyKeyViolation(error: unknown): boolean {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== 'P2002') {
    return false;
  }
  const target = (error.meta as { target?: unknown } | undefined)?.target;
  if (typeof target === 'string') return target === UNIQUE_KEY || target.includes('idempotency');
  if (Array.isArray(target)) {
    return target.some((t) => typeof t === 'string' && /idempotency_?key/i.test(t));
  }
  return false;
}

/** MySQL ER_LOCK_DEADLOCK, as a raw query reports it (P2010 `meta.code`). */
const MYSQL_DEADLOCK = '1213';

/**
 * An InnoDB deadlock or write conflict (P2034, or 1213 from a raw query). Two requests with the
 * same new key both `SELECT … FOR UPDATE` the absent row under REPEATABLE READ: their gap locks
 * are compatible, each insert's insert-intention lock waits on the other's gap lock, and InnoDB
 * rolls one back. The loser's retry then sees the winner's row (step 6.1 D9).
 */
export function isWriteConflict(error: unknown): boolean {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) return false;
  if (error.code === 'P2034') return true;
  const code = (error.meta as { code?: unknown } | undefined)?.code;
  return error.code === 'P2010' && String(code) === MYSQL_DEADLOCK;
}

/**
 * A lost race for one `(organization_id, idempotency_key)`: the unique key (P2002) or the
 * deadlock of the lock-then-insert pattern (isWriteConflict). Retried once by both services.
 */
export function isIdempotencyRace(error: unknown): boolean {
  return isIdempotencyKeyViolation(error) || isWriteConflict(error);
}

/**
 * `api_idempotency_keys` (step 3.3 L11; not partitioned, no foreign key, owned by the api) on
 * the writer, always inside the caller's transaction. The key column is `utf8mb4_bin`
 * (case-sensitive). Expired rows are purged by `db:partitions` retention.
 */
@Injectable()
export class IdempotencyRepository {
  /** `SELECT … FOR UPDATE` on the unique key: serializes requests that reuse one key. */
  async lock(tx: Tx, organizationId: bigint, key: string): Promise<IdempotencyRecord | null> {
    const rows = await tx.$queryRaw<RecordRow[]>`
      SELECT id, operation, principal, request_sha256, resource_id, status_code, response,
             expires_at, state
      FROM api_idempotency_keys
      WHERE organization_id = ${organizationId} AND idempotency_key = ${key}
      FOR UPDATE`;
    const row = rows[0];
    if (!row) return null;
    return {
      id: BigInt(row.id),
      operation: row.operation,
      principal: row.principal,
      requestSha256: row.request_sha256,
      resourceId: row.resource_id,
      statusCode: Number(row.status_code),
      response:
        typeof row.response === 'string' ? (JSON.parse(row.response) as unknown) : row.response,
      expiresAt: row.expires_at,
      state: row.state,
    };
  }

  /** Removes an expired record so the key can be stored again (same transaction). */
  async delete(tx: Tx, id: bigint): Promise<void> {
    await tx.apiIdempotencyKey.delete({ where: { id }, select: { id: true } });
  }

  async insert(tx: Tx, record: NewIdempotencyRecord): Promise<void> {
    await tx.apiIdempotencyKey.create({
      data: { ...record, state: 'completed' },
      select: { id: true },
    });
  }
}
