import { Injectable } from '@nestjs/common';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { referencedIds } from '../../bec/domain/bec-result';
import {
  BEC_ENGINE,
  decodeScanCursor,
  encodeScanCursor,
  NO_BEC,
  roundOf,
  URL_ENGINE,
} from '../domain/message-scans';
import type { MessageScansPage, MessageScansQuery } from '../dto/message-scans.schemas';
import { messageNotFound } from '../messages.errors';
import {
  type LifecycleMessageRow,
  MessageLifecycleReadRepository,
} from '../repositories/message-lifecycle-read.repository';
import { MessageScansReadRepository } from '../repositories/message-scans-read.repository';

/**
 * `GET /messages/{messageId}/scans` (step 4.1 S16; step 4.2 A16: per-attachment results on the
 * `attachment` engine entry; step 4.3 U16: per-URL results and the rewrite on the `url` entry;
 * step 4.4 B15: the explainable BEC verdict on the `bec` entry): the scan rounds of a message of the caller's organization, newest
 * round first, from the read replica (a few seconds behind the writer: a round that just
 * completed may still show as running). Every query filters by the scope's organization;
 * another organization's message is `404 message_not_found`.
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
    const [engineRows, authRows, results, submissions] = await Promise.all([
      this.rounds.engineResults(scope, message, scanIds),
      this.rounds.authResults(scope, message, scanIds),
      this.rounds.attachmentResults(scope, message, scanIds),
      this.rounds.sandboxSubmissions(scope, message, scanIds),
    ]);
    // Step 4.3 U16: URL rows only when a page round has a url engine row.
    const hasUrl = engineRows.some((row) => row.engine === URL_ENGINE);
    const [urls, urlResults, rewrites, inspections, clicks] = hasUrl
      ? await Promise.all([
          this.rounds.messageUrls(scope, message),
          this.rounds.urlResults(scope, message, scanIds),
          this.rounds.urlRewrites(scope, message, scanIds),
          this.rounds.urlInspections(scope, message, scanIds),
          this.rounds.urlClicks(scope, message),
        ])
      : [[], [], [], [], []];
    // Step 4.4 B15: BEC rows only when a page round has a bec engine row.
    const hasBec = engineRows.some((row) => row.engine === BEC_ENGINE);
    const becInputs = hasBec ? await this.becInputs(scope, message, scanIds) : NO_BEC;
    const parts = await this.rounds.attachmentParts(
      scope,
      message,
      results.map((row) => row.partIndex),
    );
    const attachments = { results, parts, submissions };
    const urlInputs = { urls, results: urlResults, rewrites, inspections, clicks };
    const last = page.at(-1);
    return {
      messageId: message.publicId,
      data: page.map((scan) =>
        roundOf(scan, engineRows, authRows, attachments, urlInputs, becInputs),
      ),
      nextCursor: rows.length > query.limit && last ? encodeScanCursor(last.lifecycleRound) : null,
    };
  }

  /**
   * The BEC results and feedback references of the page's rounds; internal ids referenced by
   * stored evidence (if any) are mapped to the organization's public ids, else dropped.
   */
  private async becInputs(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ) {
    const [results, feedback] = await Promise.all([
      this.rounds.becResults(scope, message, scanIds),
      this.rounds.becFeedback(scope, message, scanIds),
    ]);
    const refs = referencedIds([]);
    for (const row of results) referencedIds(row.rules, refs);
    const big = (set: Set<string>) => [...set].map((id) => BigInt(id));
    const any =
      refs.executive.size + refs.vendor.size + refs.trusted.size + refs.suppression.size > 0;
    const ids = any
      ? await this.rounds.becPublicIds(scope, {
          executive: big(refs.executive),
          vendor: big(refs.vendor),
          trusted: big(refs.trusted),
          suppression: big(refs.suppression),
        })
      : NO_BEC.ids;
    return { results, feedback, ids };
  }
}
