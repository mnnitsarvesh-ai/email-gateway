import { uuidv7 } from '@email-gateway/common';
import type { MessageVerdict, PrismaClient } from '@email-gateway/database';
import { big, type Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

export interface MailboxRef {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  apiConnectionId: bigint;
}

/**
 * D7 step 3: the mailbox of a recipient address of the organization (`api_mailbox_addresses`,
 * lower case), or a new `discovered` mailbox (no provider user id, primary = the address) with its
 * primary address row under `apiConnectionId`. Idempotent and race-safe: the address is unique per
 * organization (`INSERT IGNORE`); the loser of a concurrent creation removes its own mailbox row
 * and uses the winner's.
 */
export async function resolveOrDiscoverMailbox(
  prisma: PrismaClient,
  input: {
    organizationId: bigint;
    apiConnectionId: bigint;
    address: string;
    domainId: bigint | null;
    now: Date;
  },
): Promise<MailboxRef> {
  const address = input.address.trim().toLowerCase();
  const found = await findMailboxByAddress(prisma, input.organizationId, address);
  if (found) return found;
  return prisma.$transaction(async (tx) => {
    const publicId = uuidv7(input.now.getTime());
    await tx.$executeRaw`
      INSERT INTO api_mailboxes
        (public_id, organization_id, api_connection_id, provider_user_id, primary_address,
         domain_id, status, coverage_state, feed_status, created_at, updated_at)
      VALUES (${publicId}, ${input.organizationId}, ${input.apiConnectionId}, NULL, ${address},
              ${input.domainId}, 'discovered', 'out_of_scope', 'off', ${input.now}, ${input.now})`;
    const created = await tx.apiMailbox.findUnique({
      where: { publicId },
      select: { id: true },
    });
    if (!created) throw new InconsistentReadError('api_mailboxes');
    const inserted = await tx.$executeRaw`
      INSERT IGNORE INTO api_mailbox_addresses (organization_id, mailbox_id, address, kind, created_at)
      VALUES (${input.organizationId}, ${created.id}, ${address}, 'primary', ${input.now})`;
    if (inserted === 1) {
      return {
        id: created.id,
        publicId,
        organizationId: input.organizationId,
        apiConnectionId: input.apiConnectionId,
      };
    }
    await tx.apiMailbox.delete({ where: { id: created.id } });
    const winner = await findMailboxByAddress(tx, input.organizationId, address);
    if (!winner) throw new InconsistentReadError('api_mailbox_addresses');
    return winner;
  });
}

export async function findMailboxByAddress(
  db: Db,
  organizationId: bigint,
  address: string,
): Promise<MailboxRef | null> {
  const row = await db.apiMailboxAddress.findUnique({
    where: { organizationId_address: { organizationId, address } },
    select: {
      organizationId: true,
      mailbox: {
        select: { id: true, publicId: true, organizationId: true, apiConnectionId: true },
      },
    },
  });
  if (!row) return null;
  if (row.organizationId !== organizationId || row.mailbox.organizationId !== organizationId) {
    throw new InconsistentReadError('api_mailbox_addresses');
  }
  return row.mailbox;
}

export interface InlineLink {
  messageId: bigint;
  receivedAt: Date;
  finalVerdict: MessageVerdict | null;
}

/**
 * D7 step 5: the gateway message (`ingest_source = 'gateway'`) of the organization with the same
 * Message-ID key and a recipient row for `address`, received within ± `windowHours` of the copy
 * (index `email_messages_org_message_id_key_received_idx`, then `email_recipients`).
 */
export async function findInlineMessage(
  db: Db,
  input: {
    organizationId: bigint;
    messageIdKey: string;
    address: string;
    around: Date;
    windowHours: number;
  },
): Promise<InlineLink | null> {
  const span = input.windowHours * 3_600_000;
  const from = new Date(input.around.getTime() - span);
  const to = new Date(input.around.getTime() + span);
  const rows = await db.$queryRaw<
    Array<{ id: bigint | number; received_at: Date; final_verdict: MessageVerdict | null }>
  >`
    SELECT m.id, m.received_at, m.final_verdict
    FROM email_messages m
    WHERE m.organization_id = ${input.organizationId}
      AND m.message_id_key = ${input.messageIdKey.slice(0, 255)}
      AND m.received_at >= ${from} AND m.received_at <= ${to}
      AND m.ingest_source = 'gateway'
      AND EXISTS (
        SELECT 1 FROM email_recipients r
        WHERE r.message_id = m.id AND r.received_at = m.received_at
          AND r.organization_id = m.organization_id AND r.address = ${input.address})
    ORDER BY m.received_at DESC, m.id DESC
    LIMIT 1`;
  const row = rows[0];
  return row
    ? { messageId: big(row.id), receivedAt: row.received_at, finalVerdict: row.final_verdict }
    : null;
}
