import { Prisma, type PrismaClient } from '@email-gateway/database';

/** A writer client or an interactive transaction of it. */
export type Db = PrismaClient | Prisma.TransactionClient;

/** Resource type of every audit row of this worker (§5.4). */
export const AUDIT_RESOURCE_TYPE = 'provider_connection';

/**
 * A restriction of a job to some organizations (integration suites run the jobs in-process
 * against the shared writer). `undefined` = every organization; an empty list matches nothing.
 */
export function orgFilter(column: string, ids: readonly bigint[] | undefined): Prisma.Sql {
  if (ids === undefined) return Prisma.empty;
  return ids.length === 0
    ? Prisma.sql`AND 1 = 0`
    : Prisma.sql`AND ${Prisma.raw(column)} IN (${Prisma.join(ids)})`;
}

/** `BIGINT` from a raw row value (MySQL returns bigint, number or string). */
export const big = (value: bigint | number | string): bigint => BigInt(value);
/** `INT`/`TINYINT(1)` from a raw row value. */
export const num = (value: bigint | number | string | boolean | null | undefined): number =>
  Number(value ?? 0);

/**
 * One system audit row (actor `system`, the integration-worker; the pattern of the
 * archive-worker). `metadata` holds ids, codes, counts and domain names only (D12): never a
 * secret, token, consent state, probe token, route token or provider error body.
 */
export async function systemAudit(
  db: Db,
  row: {
    organizationId: bigint | null;
    action: string;
    resourceId: string | null;
    correlationId: string;
    metadata: Prisma.InputJsonValue;
    at?: Date;
  },
): Promise<void> {
  await db.auditLog.create({
    data: {
      ...(row.at ? { createdAt: row.at } : {}),
      organizationId: row.organizationId,
      actorType: 'system',
      actorId: null,
      action: row.action,
      resourceType: AUDIT_RESOURCE_TYPE,
      resourceId: row.resourceId,
      correlationId: row.correlationId.slice(0, 128),
      sourceIp: null,
      metadata: row.metadata,
    },
    select: { id: true },
  });
}

/** JSON column value from a string list (`null` stays SQL NULL). */
export const jsonList = (value: readonly string[] | null) =>
  value === null ? Prisma.DbNull : [...value];

/** Strings of a JSON array column (anything else = empty). */
export const stringsOf = (value: Prisma.JsonValue | null | undefined): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
