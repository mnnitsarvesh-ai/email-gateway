import { Prisma, type PrismaClient } from '@email-gateway/database';

/** A writer client or an interactive transaction of it. */
export type Db = PrismaClient | Prisma.TransactionClient;

/** `stream_cursors` row of a forward sweep (A2, A10, A15). */
export interface StreamCursorRow {
  positionId: bigint | null;
  lastEventAt: Date | null;
}

export async function readCursor(db: Db, name: string): Promise<StreamCursorRow | null> {
  const row = await db.streamCursor.findUnique({
    where: { name },
    select: { name: true, positionId: true, lastEventAt: true },
  });
  if (row === null || row.name !== name) return null;
  return { positionId: row.positionId, lastEventAt: row.lastEventAt };
}

export async function writeCursor(
  db: Db,
  name: string,
  positionId: bigint | null,
  lastEventAt: Date | null,
): Promise<void> {
  await db.streamCursor.upsert({
    where: { name },
    create: { name, positionId, lastEventAt },
    update: { positionId, lastEventAt },
  });
}

export async function deleteCursor(db: Db, name: string): Promise<void> {
  await db.streamCursor.deleteMany({ where: { name } });
}

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

/** True when `organizationId` passes the restriction. */
export function orgAllowed(organizationId: bigint, ids: readonly bigint[] | undefined): boolean {
  return ids === undefined || ids.includes(organizationId);
}

/** `BIGINT` from a raw row value (MySQL returns bigint, number or string). */
export const big = (value: bigint | number | string): bigint => BigInt(value);
/** `INT`/`TINYINT(1)` from a raw row value. */
export const num = (value: bigint | number | string | boolean | null | undefined): number =>
  Number(value ?? 0);

/** One system audit row (actor `system`, the archive-worker; same semantics as the webhook-worker's). */
export async function systemAudit(
  db: Db,
  row: {
    organizationId: bigint | null;
    action: string;
    resourceType: string;
    resourceId: string | null;
    correlationId: string;
    metadata: Prisma.InputJsonValue;
  },
): Promise<void> {
  await db.auditLog.create({
    data: {
      organizationId: row.organizationId,
      actorType: 'system',
      actorId: null,
      action: row.action,
      resourceType: row.resourceType,
      resourceId: row.resourceId,
      correlationId: row.correlationId.slice(0, 128),
      sourceIp: null,
      metadata: row.metadata,
    },
    select: { id: true },
  });
}

/** Organizations that ever captured (a tenant key exists): the per-organization job list. */
export async function archiveOrganizations(
  db: Db,
  only: readonly bigint[] | undefined,
): Promise<bigint[]> {
  const rows = await db.$queryRaw<Array<{ organization_id: bigint | number }>>`
    SELECT DISTINCT organization_id FROM archive_encryption_keys
    WHERE status <> 'destroyed' ${orgFilter('organization_id', only)}
    ORDER BY organization_id`;
  return rows.map((r) => big(r.organization_id));
}
