import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';
import type { MessageRef } from './message-data.repository';

/** Most `email_headers` rows read for one message (the stored limit is 200, §2 E7). */
export const MAX_HEADER_ROWS = 500;

/** One stored header row (step 3.1: decoded value, ≤ 2 048 code points). */
export interface HeaderRow {
  seq: number;
  name: string;
  value: string;
}

/**
 * The stored headers and the parse state of one message (step 7.2 §2 E6, E7) on the replica
 * (`PrismaReadService`): `email_headers` by `(message_id, received_at)` — its unique key
 * `(message_id, seq, received_at)`, one partition — in `seq` order, at most MAX_HEADER_ROWS rows,
 * and the step 3.1 parse row by its `(message_id, received_at)` unique key. Every row is
 * echo-checked (organization, message, partition key; D15); a mismatch is `503 inconsistent_read`.
 */
@Injectable()
export class MessageHeadersRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  /** The step 3.1 parse status of the message, or null when no parse row exists. */
  async parseStatus(scope: TenantScope, message: MessageRef): Promise<string | null> {
    const row = await this.db.emailMessageParse.findFirst({
      where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
      select: { status: true, organizationId: true, messageId: true, receivedAt: true },
    });
    if (!row) return null;
    assertEcho('messages.headers.parse', [row], {
      organizationId: scope.organizationId,
      messageId: message.id,
      receivedAt: message.receivedAt,
    });
    return row.status;
  }

  /**
   * The stored header rows of the message in `seq` order, optionally only those named (compared
   * under the column collation, case-insensitively).
   */
  async headers(
    scope: TenantScope,
    message: MessageRef,
    names?: readonly string[],
  ): Promise<HeaderRow[]> {
    const rows = await this.db.emailHeader.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        ...(names !== undefined && { name: { in: [...names] } }),
      }),
      select: {
        seq: true,
        name: true,
        value: true,
        organizationId: true,
        messageId: true,
        receivedAt: true,
      },
      orderBy: { seq: 'asc' },
      take: MAX_HEADER_ROWS,
    });
    assertEcho('messages.headers', rows, {
      organizationId: scope.organizationId,
      messageId: message.id,
      receivedAt: message.receivedAt,
    });
    return rows.map((r) => ({ seq: r.seq, name: r.name, value: r.value }));
  }
}
