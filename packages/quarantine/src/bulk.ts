import { z } from 'zod';
import { QUARANTINE_PERMISSIONS } from './vocabulary';

/**
 * Bulk actions (step 5.3 Q18): limits per request, per-item results. Each item runs the same
 * service method as the single-item route in its own transaction (api); this module validates the
 * request and shapes the response.
 */

export const BULK_ACTIONS = ['release', 'reject', 'delete', 'approve', 'deny'] as const;
export type BulkAction = (typeof BULK_ACTIONS)[number];

/** The permission each bulk action requires (approve/deny also need a user session with MFA). */
export const BULK_ACTION_PERMISSIONS: Readonly<Record<BulkAction, string>> = Object.freeze({
  release: QUARANTINE_PERMISSIONS.release,
  reject: QUARANTINE_PERMISSIONS.reject,
  delete: QUARANTINE_PERMISSIONS.delete,
  approve: QUARANTINE_PERMISSIONS.approve,
  deny: QUARANTINE_PERMISSIONS.approve,
});

/** approve/deny: `@UserOnly()` + MFA (Q18). */
export const bulkActionNeedsUserMfa = (action: BulkAction): boolean =>
  action === 'approve' || action === 'deny';

/** Platform defaults (env `QUARANTINE_BULK_MAX_ITEMS`, 1–500). */
export const QUARANTINE_BULK_MAX_ITEMS = 100;
export const QUARANTINE_BULK_MAX_ITEMS_BOUND = 500;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export const bulkRequestSchema = z.strictObject({
  action: z.enum(BULK_ACTIONS),
  ids: z.array(z.string().regex(UUID)).max(QUARANTINE_BULK_MAX_ITEMS_BOUND),
  reason: z.string().trim().min(1).max(512),
  notifySender: z.boolean().optional(),
});
export type BulkRequest = z.infer<typeof bulkRequestSchema>;

export type BulkRequestCheck =
  | { ok: true; request: BulkRequest }
  | {
      ok: false;
      code: 'quarantine_bulk_limit';
      cause: 'invalid' | 'empty' | 'too_many' | 'duplicate_ids';
    };

/**
 * Q18 request limits: a valid body, `1 ≤ ids ≤ maxItems` (`QUARANTINE_BULK_MAX_ITEMS`), unique
 * ids. Every refusal is `400 quarantine_bulk_limit` with the cause.
 */
export function checkBulkRequest(input: unknown, limits: { maxItems: number }): BulkRequestCheck {
  const parsed = bulkRequestSchema.safeParse(input);
  if (!parsed.success) {
    const ids = (input as { ids?: unknown } | null)?.ids;
    if (Array.isArray(ids) && ids.length > QUARANTINE_BULK_MAX_ITEMS_BOUND) {
      return { ok: false, code: 'quarantine_bulk_limit', cause: 'too_many' };
    }
    return { ok: false, code: 'quarantine_bulk_limit', cause: 'invalid' };
  }
  const { ids } = parsed.data;
  if (ids.length === 0) return { ok: false, code: 'quarantine_bulk_limit', cause: 'empty' };
  const max = Math.min(Math.max(1, Math.floor(limits.maxItems)), QUARANTINE_BULK_MAX_ITEMS_BOUND);
  if (ids.length > max) return { ok: false, code: 'quarantine_bulk_limit', cause: 'too_many' };
  if (new Set(ids).size !== ids.length) {
    return { ok: false, code: 'quarantine_bulk_limit', cause: 'duplicate_ids' };
  }
  return { ok: true, request: parsed.data };
}

export const BULK_ITEM_STATUSES = [
  'queued',
  'approval_requested',
  'done',
  'refused',
  'not_found',
  'skipped',
] as const;
export type BulkItemStatus = (typeof BULK_ITEM_STATUSES)[number];

export const bulkItemResultSchema = z.strictObject({
  id: z.string().regex(UUID),
  status: z.enum(BULK_ITEM_STATUSES),
  code: z.string().max(64).optional(),
  releaseId: z.string().regex(UUID).optional(),
  approvalRequestId: z.string().regex(UUID).optional(),
});
export type BulkItemResult = z.infer<typeof bulkItemResultSchema>;

export const bulkResultSchema = z.strictObject({
  action: z.enum(BULK_ACTIONS),
  results: z.array(bulkItemResultSchema).max(QUARANTINE_BULK_MAX_ITEMS_BOUND),
  counts: z.strictObject(
    Object.fromEntries(BULK_ITEM_STATUSES.map((s) => [s, z.number().int().min(0)])) as Record<
      BulkItemStatus,
      z.ZodNumber
    >,
  ),
});
export type BulkResult = z.infer<typeof bulkResultSchema>;

/** Builds the response body with the per-status counts (partial failure is per item). */
export function bulkResult(action: BulkAction, results: readonly BulkItemResult[]): BulkResult {
  const counts = Object.fromEntries(BULK_ITEM_STATUSES.map((s) => [s, 0])) as Record<
    BulkItemStatus,
    number
  >;
  for (const r of results) counts[r.status] += 1;
  return { action, results: [...results], counts };
}
