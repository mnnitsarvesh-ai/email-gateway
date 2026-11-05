import { Injectable } from '@nestjs/common';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { decodeScanCursor, encodeScanCursor, roundOf } from '../domain/message-scans';
import type { MessageScansPage, MessageScansQuery } from '../dto/message-scans.schemas';
import { messageNotFound } from '../messages.errors';
import { MessageLifecycleReadRepository } from '../repositories/message-lifecycle-read.repository';
import { MessageScansReadRepository } from '../repositories/message-scans-read.repository';

/**
 * `GET /messages/{messageId}/scans` (step 4.1 S16): the scan rounds of a message of the caller's
 * organization, newest round first, from the read replica (a few seconds behind the writer: a
 * round that just completed may still show as running). Another organization's message is
 * `404 message_not_found`.
 */
@Injectable()
export class MessageScansReadService {
  constructor(
    private readonly messages: MessageLifecycleReadRepository,
    private readonly rounds: MessageScansReadRepository,
  ) {}

  async list(
    scope: TenantScope,
    messageId: string,
    query: MessageScansQuery,
  ): Promise<MessageScansPage> {
    const beforeRound = query.cursor === undefined ? undefined : decodeScanCursor(query.cursor);
    const message = await this.messages.findMessage(scope, messageId);
    if (!message) throw messageNotFound();
    const rows = await this.rounds.rounds(scope, message, {
      take: query.limit + 1,
      ...(beforeRound !== undefined && { beforeRound }),
    });
    const page = rows.slice(0, query.limit);
    const scanIds = page.map((row) => row.id);
    const [engineRows, authRows] = await Promise.all([
      this.rounds.engineResults(scope, message, scanIds),
      this.rounds.authResults(scope, message, scanIds),
    ]);
    const last = page.at(-1);
    return {
      messageId: message.publicId,
      data: page.map((scan) => roundOf(scan, engineRows, authRows)),
      nextCursor: rows.length > query.limit && last ? encodeScanCursor(last.lifecycleRound) : null,
    };
  }
}
