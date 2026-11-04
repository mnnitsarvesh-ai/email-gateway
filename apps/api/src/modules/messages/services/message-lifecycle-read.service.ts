import { Injectable } from '@nestjs/common';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { Page } from '../../../http/pagination';
import {
  allowedActions,
  decodeHistoryCursor,
  encodeHistoryCursor,
} from '../domain/lifecycle-operations';
import type {
  LifecycleHistoryEntry,
  LifecycleHistoryQuery,
  LifecycleView,
} from '../dto/messages.schemas';
import { messageNotFound } from '../messages.errors';
import {
  type LifecycleHistoryRow,
  type LifecycleMessageRow,
  MessageLifecycleReadRepository,
} from '../repositories/message-lifecycle-read.repository';

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

export function toHistoryEntry(row: LifecycleHistoryRow): LifecycleHistoryEntry {
  return {
    version: row.version,
    fromState: row.fromStatus,
    toState: row.toStatus,
    reasonCode: row.reasonCode,
    lifecycleRound: row.lifecycleRound,
    actor: {
      role: row.actorRole as LifecycleHistoryEntry['actor']['role'],
      type: row.actorType,
      service: row.actorService,
      id: row.actorId,
    },
    causationEventId: row.eventId,
    correlationId: row.correlationId,
    occurredAt: iso(row.occurredAt),
    changedAt: row.changedAt.toISOString(),
  };
}

/**
 * The lifecycle read APIs (step 3.3 L12) of the caller's organization, from the read replica (a
 * few seconds behind the writer; right after a rescan or release the previous state may still
 * show). Another organization's message is `404 message_not_found`. Ids, states, codes, counts
 * and times only: never subjects, addresses or bodies.
 */
@Injectable()
export class MessageLifecycleReadService {
  constructor(private readonly messages: MessageLifecycleReadRepository) {}

  /** `GET /messages/{messageId}/lifecycle`. */
  async lifecycle(scope: TenantScope, messageId: string): Promise<LifecycleView> {
    const message = await this.message(scope, messageId);
    const [parse, counts, deliverySeq] = await Promise.all([
      this.messages.parseOf(scope, message),
      this.messages.recipientCounts(scope, message),
      this.messages.maxDeliverySeq(scope, message),
    ]);
    const byStatus: LifecycleView['recipients']['byStatus'] = {};
    let total = 0;
    for (const [status, count] of [...counts.entries()].sort(([a], [b]) => a.localeCompare(b))) {
      if (count <= 0) continue;
      byStatus[status] = count;
      total += count;
    }
    const state = message.status;
    return {
      messageId: message.publicId,
      receivedAt: message.receivedAt.toISOString(),
      direction: message.direction,
      state,
      statusReason: message.statusReason,
      version: message.version,
      lifecycleRound: message.lifecycleRound,
      statusChangedAt: message.statusChangedAt.toISOString(),
      parse: parse
        ? {
            status: parse.status as NonNullable<LifecycleView['parse']>['status'],
            completedAt: iso(parse.completedAt),
          }
        : null,
      recipients: { total, byStatus },
      deliverySeq,
      actions: allowedActions(state),
    };
  }

  /**
   * `GET /messages/{messageId}/lifecycle/history`: the applied transitions, oldest first (by
   * version, unique per message), cursor-paginated. Rows written before step 3.3 show
   * `actor.role = 'legacy'` and may contain pairs the transition table no longer allows.
   */
  async history(
    scope: TenantScope,
    messageId: string,
    query: LifecycleHistoryQuery,
  ): Promise<Page<LifecycleHistoryEntry>> {
    const afterVersion = query.cursor === undefined ? undefined : decodeHistoryCursor(query.cursor);
    const message = await this.message(scope, messageId);
    const rows = await this.messages.history(scope, message, {
      take: query.limit + 1,
      ...(afterVersion !== undefined && { afterVersion }),
    });
    const page = rows.slice(0, query.limit);
    const last = page.at(-1);
    return {
      data: page.map(toHistoryEntry),
      nextCursor: rows.length > query.limit && last ? encodeHistoryCursor(last.version) : null,
    };
  }

  private async message(scope: TenantScope, publicId: string): Promise<LifecycleMessageRow> {
    const message = await this.messages.findMessage(scope, publicId);
    if (!message) throw messageNotFound();
    return message;
  }
}
