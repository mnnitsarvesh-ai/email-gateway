import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { ApiCopyStatus, Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { EntryRow } from '../domain/entry';

type Tx = Prisma.TransactionClient;

/** The API-mode copy behind a mailbox-located entry (writer facts of a release or delete). */
export interface EntryCopyFacts {
  copyId: bigint;
  copyReceivedAt: Date;
  copyPublicId: string;
  status: ApiCopyStatus;
  remediationGeneration: number;
  apiConnectionId: bigint;
  mailboxId: bigint;
  messageId: bigint;
}

/** What the location block of a mailbox entry shows (replica; R10.5). */
export interface MailboxLocationFacts {
  mailboxes: Map<bigint, { address: string; provider: string; connectionPublicId: string }>;
  copies: Map<string, string>;
  /** Per entry id: the latest remediation action of the entry (creation or restore). */
  actions: Map<bigint, { publicId: string; status: string }>;
}

const copyKey = (id: bigint, receivedAt: Date): string =>
  `${id.toString()}:${receivedAt.getTime()}`;

/**
 * Reads of the API-mode rows behind mailbox-located quarantine entries (step API-2 R9, R10,
 * ADR-0102): the copy of an entry on the writer (status for `decideMailboxRestore`, the current
 * remediation generation, connection and mailbox for the restore or soft-delete action row) and,
 * on the replica, the facts of the entries' location blocks (mailbox address, provider,
 * connection, detection and the latest remediation action). Tenant-scoped; provider ids never
 * selected.
 */
@Injectable()
export class QuarantineMailboxRepository {
  constructor(private readonly reader: PrismaReadService) {}

  async copyOfEntry(
    tx: Tx,
    scope: TenantScope,
    entry: Pick<EntryRow, 'apiCopyId' | 'apiCopyReceivedAt'>,
  ): Promise<EntryCopyFacts | null> {
    if (entry.apiCopyId === null || entry.apiCopyReceivedAt === null) return null;
    const row = await tx.apiMessageCopy.findFirst({
      where: tenantWhere(scope, { id: entry.apiCopyId, receivedAt: entry.apiCopyReceivedAt }),
      select: {
        id: true,
        receivedAt: true,
        publicId: true,
        status: true,
        remediationGeneration: true,
        apiConnectionId: true,
        mailboxId: true,
        messageId: true,
      },
    });
    return row === null
      ? null
      : {
          copyId: row.id,
          copyReceivedAt: row.receivedAt,
          copyPublicId: row.publicId,
          status: row.status,
          remediationGeneration: row.remediationGeneration,
          apiConnectionId: row.apiConnectionId,
          mailboxId: row.mailboxId,
          messageId: row.messageId,
        };
  }

  /** Location facts of a page of entries (only the mailbox-located ones are looked up). */
  async locationFacts(
    scope: TenantScope,
    rows: ReadonlyArray<
      Pick<
        EntryRow,
        | 'id'
        | 'location'
        | 'apiCopyId'
        | 'apiCopyReceivedAt'
        | 'apiMailboxId'
        | 'apiRemediationActionId'
      >
    >,
  ): Promise<MailboxLocationFacts> {
    const facts: MailboxLocationFacts = {
      mailboxes: new Map(),
      copies: new Map(),
      actions: new Map(),
    };
    const mailboxRows = rows.filter((r) => r.location === 'mailbox');
    if (mailboxRows.length === 0) return facts;
    const db = this.reader.client;
    const mailboxIds = [
      ...new Set(mailboxRows.flatMap((r) => (r.apiMailboxId === null ? [] : [r.apiMailboxId]))),
    ];
    const copyRefs = mailboxRows.flatMap((r) =>
      r.apiCopyId === null || r.apiCopyReceivedAt === null
        ? []
        : [{ id: r.apiCopyId, receivedAt: r.apiCopyReceivedAt }],
    );
    const entryIds = mailboxRows.map((r) => r.id);
    const actionIds = mailboxRows.flatMap((r) =>
      r.apiRemediationActionId === null ? [] : [r.apiRemediationActionId],
    );
    const [mailboxes, copies, actions] = await Promise.all([
      mailboxIds.length === 0
        ? Promise.resolve([])
        : db.apiMailbox.findMany({
            where: tenantWhere(scope, { id: { in: mailboxIds } }),
            select: {
              id: true,
              primaryAddress: true,
              apiConnection: {
                select: { provider: true, providerConnection: { select: { publicId: true } } },
              },
            },
          }),
      copyRefs.length === 0
        ? Promise.resolve([])
        : db.apiMessageCopy.findMany({
            where: tenantWhere(scope, {
              OR: copyRefs.map((c) => ({ id: c.id, receivedAt: c.receivedAt })),
            }),
            select: { id: true, receivedAt: true, publicId: true },
          }),
      db.apiRemediationAction.findMany({
        where: tenantWhere(scope, {
          OR: [
            { quarantineEntryId: { in: entryIds } },
            ...(actionIds.length > 0 ? [{ id: { in: actionIds } }] : []),
          ],
        }),
        select: { id: true, publicId: true, status: true, quarantineEntryId: true },
        orderBy: { id: 'asc' },
        take: 1000,
      }),
    ]);
    for (const m of mailboxes) {
      facts.mailboxes.set(m.id, {
        address: m.primaryAddress,
        provider: m.apiConnection.provider,
        connectionPublicId: m.apiConnection.providerConnection.publicId,
      });
    }
    for (const c of copies) facts.copies.set(copyKey(c.id, c.receivedAt), c.publicId);
    for (const entry of mailboxRows) {
      // Ascending ids: the last match is the entry's latest action (a restore after the creation).
      for (const a of actions) {
        if (a.quarantineEntryId === entry.id || a.id === entry.apiRemediationActionId) {
          facts.actions.set(entry.id, { publicId: a.publicId, status: a.status });
        }
      }
    }
    return facts;
  }
}

export { copyKey as mailboxCopyKey };
