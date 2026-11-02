import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { type AuditActorType, Prisma } from '@email-gateway/database';
import { getCorrelationId } from '@email-gateway/logger';
import type { Principal } from '../auth-contracts/principal';

export interface AuditActor {
  type: AuditActorType;
  /** Public id of the user or API key; null for the system. */
  id: string | null;
  /** Set by `actorFrom` under a platform override; copied into `metadata.override`. */
  override?: { id: string; reason: string };
}

export const SYSTEM_ACTOR: AuditActor = Object.freeze({ type: 'system', id: null });

export interface AuditEntry {
  /** Target tenant; null for platform-only actions. */
  organizationId: bigint | null;
  actor: AuditActor;
  /** `<resource>.<verb>`, e.g. `user.invited` (D14). */
  action: string;
  resourceType: string;
  /** Public id or key of the resource, never a numeric id. */
  resourceId?: string | null;
  sourceIp?: string | null;
  metadata?: Record<string, unknown>;
}

/** Defensive scrub (D14): callers must not pass credentials in audit metadata. */
export const SENSITIVE_METADATA_KEY = /password|secret|token|code|key$/i;
/** Identifiers that match the pattern by name but are not credentials. */
export const SAFE_METADATA_KEYS: ReadonlySet<string> = new Set([
  'statusCode',
  'planCode',
  'featureKey',
  'limitKey',
  'roleKey',
  'permissionKey',
]);

const LIMITS = { actorId: 64, action: 100, resourceType: 64, resourceId: 64, ip: 45, corr: 128 };

function clip(value: string | null | undefined, max: number): string | null {
  return value == null ? null : value.slice(0, max);
}

/**
 * Makes metadata JSON-safe and credential-free: drops sensitive keys at any depth, writes
 * `bigint` as decimal strings and dates as ISO strings.
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

/**
 * Append-only audit trail (`audit_logs`, partitioned monthly, D14) on the writer. Pass the
 * transaction client so the audit row commits or rolls back with the change it describes.
 */
@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  /** The actor of a request; under a platform override it carries the override for metadata. */
  actorFrom(principal: Principal): AuditActor {
    if (principal.kind === 'api_key') return { type: 'api_key', id: principal.apiKeyPublicId };
    return {
      type: 'user',
      id: principal.userPublicId,
      ...(principal.override && {
        override: { id: principal.override.id, reason: principal.override.reason },
      }),
    };
  }

  async record(entry: AuditEntry, tx?: Prisma.TransactionClient): Promise<void> {
    const client = tx ?? this.prisma;
    const metadata = {
      ...(entry.metadata ?? {}),
      ...(entry.actor.override && { override: entry.actor.override }),
    };
    const scrubbed = Object.keys(metadata).length > 0 ? scrubMetadata(metadata) : null;
    await client.auditLog.create({
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
    });
  }
}
