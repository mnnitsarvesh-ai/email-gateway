import type { ApiCopySource, PrismaClient } from '@email-gateway/database';
import { big, bigOrNull, TX_OPTIONS } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

/** How long a feed's in-flight dedupe claim holds (D10.3 a). */
export const FEED_CLAIM_TTL_MS = 15 * 60_000;

export type FeedClaim =
  /** This feed holds the claim: fetch, then commit with the claim id. */
  | { kind: 'claimed'; claimId: bigint }
  /** Another copy of this Message-ID is recorded for the mailbox: no fetch (it was marked seen). */
  | { kind: 'duplicate'; copyId: bigint }
  /** This very provider message was already recorded (a replayed page). */
  | { kind: 'already' };

/**
 * D10.3 a: the metadata-first dedupe claim of a feed item with a Message-ID. In one writer
 * transaction: `INSERT IGNORE` (mailbox, hash, claimed_by = graph|gmail, copy NULL, expiry now +
 * 15 min), then the row `FOR UPDATE`:
 * - inserted, or an in-flight feed claim (a crashed earlier attempt; the mailbox lease serializes
 *   feeds) → claimed (expiry renewed);
 * - a recorded copy of another provider message or of the journal → `duplicate`: that copy gets
 *   `provider_message_id` (if NULL) and `seen_api = 1`, nothing is fetched;
 * - the recorded copy is this provider message → `already`.
 */
export async function claimForFeed(
  prisma: PrismaClient,
  input: {
    organizationId: bigint;
    mailboxId: bigint;
    hash: string;
    source: Extract<ApiCopySource, 'graph' | 'gmail'>;
    providerMessageId: string;
    now: Date;
  },
): Promise<FeedClaim> {
  const expires = new Date(input.now.getTime() + FEED_CLAIM_TTL_MS);
  return prisma.$transaction(async (tx) => {
    const inserted = await tx.$executeRaw`
      INSERT IGNORE INTO api_copy_dedupe_keys
        (organization_id, mailbox_id, message_id_hash, claimed_by, copy_id, copy_received_at,
         claim_expires_at, created_at)
      VALUES (${input.organizationId}, ${input.mailboxId}, ${input.hash}, ${input.source}, NULL,
              NULL, ${expires}, ${input.now})`;
    const rows = await tx.$queryRaw<
      Array<{
        id: bigint | number;
        organization_id: bigint | number;
        copy_id: bigint | number | null;
        copy_received_at: Date | null;
      }>
    >`
      SELECT id, organization_id, copy_id, copy_received_at FROM api_copy_dedupe_keys
      WHERE mailbox_id = ${input.mailboxId} AND message_id_hash = ${input.hash}
      FOR UPDATE`;
    const row = rows[0];
    if (!row || big(row.organization_id) !== input.organizationId) {
      throw new InconsistentReadError('api_copy_dedupe_keys');
    }
    const claimId = big(row.id);
    const copyId = bigOrNull(row.copy_id);
    if (inserted === 1) return { kind: 'claimed', claimId };
    if (copyId === null || row.copy_received_at === null) {
      await tx.$executeRaw`
        UPDATE api_copy_dedupe_keys SET claimed_by = ${input.source}, claim_expires_at = ${expires}
        WHERE id = ${claimId} AND copy_id IS NULL`;
      return { kind: 'claimed', claimId };
    }
    const copies = await tx.$queryRaw<
      Array<{
        source: string;
        provider_message_id: string | null;
        organization_id: bigint | number;
      }>
    >`
      SELECT source, provider_message_id, organization_id FROM api_message_copies
      WHERE id = ${copyId} AND received_at = ${row.copy_received_at}`;
    const copy = copies[0];
    if (copy && big(copy.organization_id) !== input.organizationId) {
      throw new InconsistentReadError('api_message_copies');
    }
    if (
      copy &&
      copy.source === input.source &&
      copy.provider_message_id === input.providerMessageId
    ) {
      return { kind: 'already' };
    }
    await tx.$executeRaw`
      UPDATE api_message_copies
      SET provider_message_id = COALESCE(provider_message_id, ${input.providerMessageId.slice(0, 256)}),
          seen_api = 1, updated_at = ${input.now}
      WHERE id = ${copyId} AND received_at = ${row.copy_received_at}
        AND organization_id = ${input.organizationId}`;
    return { kind: 'duplicate', copyId };
  }, TX_OPTIONS);
}
