import type { Prisma } from '@email-gateway/database';
import { type InconsistencySink, wrongRead } from '../evaluation/errors';

/** The object an ALLOW delivers before header edits (step 4.3 U20, step 5.2 P20). */
export type BaseObject = 'rewritten' | 'original';

/**
 * True when `key` is a rewritten copy of `organizationId`: `org/<org>/rewrite/…` with no `.`,
 * `..` or empty segment (moved from the delivery-worker's development pass-through, P14).
 */
export function isRewriteKeyOf(key: string, organizationId: bigint): boolean {
  return (
    key.startsWith(`org/${organizationId.toString()}/rewrite/`) &&
    !key.split('/').some((segment) => segment === '..' || segment === '.' || segment === '')
  );
}

export interface DeliveryObjectRequest {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  round: number;
  scanId: bigint;
  /** `email_messages.eml_object_key` from the locked writer row (organization-prefixed). */
  original: string;
}

export interface DeliveryObject {
  key: string;
  object: BaseObject;
  /** Why a rewritten copy was not used (`missing_key`, `key_prefix`), for the log. */
  fallback?: 'missing_key' | 'key_prefix';
}

/**
 * P20: the round's `url_rewrites` row with `status = rewritten` (writer, echo-checked: message,
 * organization, `received_at`, round, scan, status) when its key is a well-formed rewritten copy
 * of the organization, else the original EML. A shifted read throws
 * `InconsistentPolicyReadError` (retryable). Never another tenant's or an unexpected object.
 */
export async function deliveryObject(
  tx: Prisma.TransactionClient,
  request: DeliveryObjectRequest,
  sink: InconsistencySink,
): Promise<DeliveryObject> {
  const row = await tx.urlRewrite.findFirst({
    where: {
      messageId: request.messageId,
      receivedAt: request.receivedAt,
      organizationId: request.organizationId,
      lifecycleRound: request.round,
      scanId: request.scanId,
      status: 'rewritten',
    },
    select: {
      messageId: true,
      receivedAt: true,
      organizationId: true,
      lifecycleRound: true,
      scanId: true,
      status: true,
      objectKey: true,
    },
    orderBy: { id: 'desc' },
  });
  if (row === null) return { key: request.original, object: 'original' };
  if (
    row.messageId !== request.messageId ||
    row.organizationId !== request.organizationId ||
    row.receivedAt.getTime() !== request.receivedAt.getTime() ||
    row.lifecycleRound !== request.round ||
    row.scanId !== request.scanId ||
    row.status !== 'rewritten'
  ) {
    return wrongRead(sink, 'url_rewrite', 'rewrite echo');
  }
  if (row.objectKey === null) {
    return { key: request.original, object: 'original', fallback: 'missing_key' };
  }
  if (!isRewriteKeyOf(row.objectKey, request.organizationId)) {
    return { key: request.original, object: 'original', fallback: 'key_prefix' };
  }
  return { key: row.objectKey, object: 'rewritten' };
}
