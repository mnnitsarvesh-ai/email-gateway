import type { Prisma, PrismaClient } from '@email-gateway/database';

export type Db = PrismaClient | Prisma.TransactionClient;

/** Budget of a writer transaction (≥ 120 s, the 4.2 §6 wrong-read rule) and its pool wait. */
export const TX_TIMEOUT_MS = 120_000;
export const TX_MAX_WAIT_MS = 30_000;
export const TX_OPTIONS = { timeout: TX_TIMEOUT_MS, maxWait: TX_MAX_WAIT_MS } as const;

/** A BIGINT from a raw query (bigint, number or decimal string). */
export const big = (value: bigint | number | string): bigint => BigInt(value);

/** A nullable BIGINT from a raw query. */
export const bigOrNull = (value: bigint | number | string | null | undefined): bigint | null =>
  value === null || value === undefined ? null : BigInt(value);

/** A boolean column from a raw query (`TINYINT(1)` arrives as a number). */
export const bool = (value: unknown): boolean => value === true || Number(value) === 1;

/** A MySQL deadlock (1213), lock wait timeout (1205) or Prisma's write conflict (P2034). */
export function isLockConflict(error: unknown): boolean {
  const e = error as { code?: unknown; meta?: { code?: unknown }; message?: unknown } | null;
  if (e?.code === 'P2034') return true;
  const mysql = e?.meta?.code;
  if (mysql === '1213' || mysql === '1205' || mysql === 1213 || mysql === 1205) return true;
  return e?.code === 'P2010' && typeof e.message === 'string' && /\b(1213|1205)\b/.test(e.message);
}

/** A unique-key violation (Prisma P2002 or a raw MySQL 1062). */
export function isDuplicateKey(error: unknown): boolean {
  const e = error as { code?: unknown; meta?: { code?: unknown }; message?: unknown } | null;
  if (e?.code === 'P2002') return true;
  const mysql = e?.meta?.code;
  if (mysql === '1062' || mysql === 1062) return true;
  return e?.code === 'P2010' && typeof e.message === 'string' && /\b1062\b/.test(e.message);
}

/** Runs an idempotent unit again after a lost deadlock (at most three attempts). */
export async function retryLockConflict<T>(fn: () => Promise<T>): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (attempt >= 3 || !isLockConflict(error)) throw error;
      await new Promise((resolve) => setTimeout(resolve, 25 * attempt + Math.random() * 50));
    }
  }
}

/**
 * A system `audit_logs` row (actor `system`, no actor id or IP; metadata ids, enums and counts
 * only), written in the caller's transaction.
 */
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
