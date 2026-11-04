import { Injectable } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';

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
             expires_at
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
    };
  }

  /** Removes an expired record so the key can be stored again (same transaction). */
  async delete(tx: Tx, id: bigint): Promise<void> {
    await tx.apiIdempotencyKey.delete({ where: { id }, select: { id: true } });
  }

  async insert(tx: Tx, record: NewIdempotencyRecord): Promise<void> {
    await tx.apiIdempotencyKey.create({ data: record, select: { id: true } });
  }
}
