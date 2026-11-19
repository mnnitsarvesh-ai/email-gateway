/**
 * Audit rows of the shared incident model. Mirrors the api's `AuditService.record`
 * (apps/api/src/audit/audit.service.ts): the same credential scrubbing at any depth, the same
 * column clipping, `requestId` from the request context into the metadata and `correlationId`
 * from `@email-gateway/logger`, written with the caller's transaction client so the audit row
 * commits or rolls back with the change it describes. Workers (system actor) and the api use it.
 */
import { Prisma } from '@email-gateway/database';
import { getCorrelationId, getRequestId } from '@email-gateway/logger';
import type { IncidentActor } from './vocabulary';

/** Defensive scrub: callers must not pass credentials in audit metadata (same rule as the api). */
export const SENSITIVE_METADATA_KEY = /password|secret|token|code|key$/i;
/**
 * Identifiers that match the pattern by name but are not credentials (the api's list plus the
 * incident model's `resolutionCode`, `titleCode` and `reasonCodes` and the ATO responses'
 * `resultCode`, which are rule/enum codes).
 */
export const SAFE_METADATA_KEYS: ReadonlySet<string> = new Set([
  'statusCode',
  'planCode',
  'featureKey',
  'limitKey',
  'roleKey',
  'permissionKey',
  'resolutionCode',
  'titleCode',
  'reasonCodes',
  'resultCode',
]);

const LIMITS = { actorId: 64, action: 100, resourceType: 64, resourceId: 64, ip: 45, corr: 128 };

function clip(value: string | null | undefined, max: number): string | null {
  return value == null ? null : value.slice(0, max);
}

/**
 * Makes metadata JSON-safe and credential-free: drops sensitive keys at any depth, writes
 * `bigint` as decimal strings and dates as ISO strings (identical to the api's scrub).
 */
export function scrubMetadata(value: unknown): Prisma.InputJsonValue | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'bigint') return value.toString(10);
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map((item) => scrubMetadata(item));
  if (typeof value === 'object') {
    const out: Record<string, Prisma.InputJsonValue | null> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_METADATA_KEY.test(key) && !SAFE_METADATA_KEYS.has(key)) continue;
      if (item === undefined || typeof item === 'function' || typeof item === 'symbol') continue;
      out[key] = scrubMetadata(item);
    }
    return out;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) return null;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  return null;
}

export interface LibraryAuditEntry {
  /** Target tenant; null for platform-only actions. */
  organizationId: bigint | null;
  actor: IncidentActor;
  /** `<resource>.<verb>`. */
  action: string;
  resourceType: string;
  /** Public id or key of the resource, never a numeric id. */
  resourceId?: string | null;
  sourceIp?: string | null;
  metadata?: Record<string, unknown>;
}

/** Writes one `audit_logs` row with the caller's client (inside its transaction). */
export async function writeAuditRow(
  tx: Prisma.TransactionClient,
  entry: LibraryAuditEntry,
): Promise<void> {
  const requestId = getRequestId();
  const metadata = {
    ...(entry.metadata ?? {}),
    ...(entry.actor.override && { override: entry.actor.override }),
    ...(requestId !== undefined && { requestId }),
  };
  const scrubbed = Object.keys(metadata).length > 0 ? scrubMetadata(metadata) : null;
  await tx.auditLog.create({
    data: {
      organizationId: entry.organizationId,
      actorType: entry.actor.type,
      actorId: clip(entry.actor.id, LIMITS.actorId),
      action: entry.action.slice(0, LIMITS.action),
      resourceType: entry.resourceType.slice(0, LIMITS.resourceType),
      resourceId: clip(entry.resourceId, LIMITS.resourceId),
      correlationId: clip(getCorrelationId(), LIMITS.corr),
      sourceIp: clip(entry.sourceIp, LIMITS.ip),
      metadata: scrubbed === null ? Prisma.DbNull : scrubbed,
    },
    select: { id: true },
  });
}
