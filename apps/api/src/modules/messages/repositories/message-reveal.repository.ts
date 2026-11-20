import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { GATEWAY_MESSAGE_WHERE } from '../../tenant-data/gateway-messages';
import { assertEcho, InconsistentReadError } from '../../../http/listing/echo-check';
import type { MessageRef } from './message-data.repository';

/** A message of a bulk reveal with its stored subject. */
export interface RevealedSubjectRow {
  ref: MessageRef;
  subject: string | null;
}

/**
 * Reads of the bulk subject reveal (step 7.2 §2 E6) on the replica (`PrismaReadService`): the
 * registry rows of the requested public ids within the scope's organization (another tenant's id
 * is simply not found), then the subjects of those messages by `(id, received_at)` (primary key,
 * pruned to their partitions). Every row is echo-checked (organization, id set, the exact
 * `(id, received_at)` pairs; D15); a mismatch is `503 inconsistent_read`. A registry row whose
 * `email_messages` row is gone (partition retention) is not found. The single reveal reads through
 * MessageDataRepository (detail, recipients, user ids) and MessageHeadersRepository.
 */
@Injectable()
export class MessageRevealRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  /** The scope's messages with these public ids (registry rows), in no particular order. */
  async refs(scope: TenantScope, publicIds: readonly string[]): Promise<MessageRef[]> {
    const ids = [...new Set(publicIds)];
    if (ids.length === 0) return [];
    const rows = await this.db.messageIdentity.findMany({
      where: tenantWhere(scope, { publicId: { in: ids } }),
      select: { id: true, publicId: true, receivedAt: true, organizationId: true },
    });
    assertEcho('messages.reveal.identities', rows, {
      organizationId: scope.organizationId,
      publicId: ids,
    });
    if (rows.length === 0) return rows;
    // Step 8.6 D5: journal intake messages are not gateway messages (treated as not found).
    const gateway = await this.db.emailMessage.findMany({
      where: tenantWhere(scope, {
        OR: rows.map((r) => ({ id: r.id, receivedAt: r.receivedAt })),
        ...GATEWAY_MESSAGE_WHERE,
      }),
      select: { id: true, receivedAt: true, organizationId: true },
    });
    assertEcho('messages.reveal.gateway', gateway, { organizationId: scope.organizationId });
    const keep = new Set(gateway.map((g) => `${g.id}:${g.receivedAt.getTime()}`));
    return rows.filter((r) => keep.has(`${r.id}:${r.receivedAt.getTime()}`));
  }

  /** The stored subjects of these messages (absent when the message row is gone). */
  async subjects(scope: TenantScope, refs: readonly MessageRef[]): Promise<RevealedSubjectRow[]> {
    if (refs.length === 0) return [];
    const rows = await this.db.emailMessage.findMany({
      where: tenantWhere(scope, {
        OR: refs.map((ref) => ({ id: ref.id, receivedAt: ref.receivedAt })),
      }),
      select: { id: true, receivedAt: true, organizationId: true, subject: true },
    });
    assertEcho('messages.reveal.subjects', rows, {
      organizationId: scope.organizationId,
      id: refs.map((ref) => ref.id),
    });
    const byKey = new Map(refs.map((ref) => [`${ref.id}:${ref.receivedAt.getTime()}`, ref]));
    return rows.map((row) => {
      const ref = byKey.get(`${row.id}:${row.receivedAt.getTime()}`);
      if (!ref) throw new InconsistentReadError('messages.reveal.subjects');
      return { ref, subject: row.subject };
    });
  }
}
