import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../api-config.token';
import { AuditService } from '../../audit/audit.service';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import { CursorCodec, cursorInvalid } from '../../http/cursor/cursor-codec';
import { rangeWindow, resolveRange } from '../../http/listing/range';
import { decideKeysetPage } from '../../http/listing/scan-budget';
import { attachmentOf } from '../messages/domain/message-scans';
import {
  decodeListCursor,
  encodeListCursor,
  intKey,
  listBinding,
  sha256Hex,
  timeIdKeyOf,
  timeIdKeys,
} from '../messages/domain/v1-list';
import { MessageDataRepository } from '../messages/repositories/message-data.repository';
import { MessageDataService } from '../messages/services/message-data.service';
import { MessagesRepository } from '../tenant-data/messages.repository';
import {
  ATTACHMENT_SEARCH_RESOURCE,
  type AttachmentLatestScan,
  type AttachmentSearchPage,
  type AttachmentSearchQuery,
  MESSAGE_ATTACHMENTS_RESOURCE,
  type MessageAttachmentItem,
  type MessageAttachmentsPage,
  type MessageAttachmentsQuery,
  SHA256_HEX,
} from './attachments.schemas';
import {
  type AttachmentPart,
  AttachmentsRepository,
  type LatestResultRow,
} from './attachments.repository';

const DAY_MS = 86_400_000;
const MAX_PART_INDEX = 65_535;

type Config = Pick<ApiConfig, 'API_MESSAGES_MAX_RANGE_DAYS'>;

/** The newest round's result per attachment id (highest scan id). */
export function latestResults(rows: readonly LatestResultRow[]): Map<bigint, LatestResultRow> {
  const latest = new Map<bigint, LatestResultRow>();
  for (const row of rows) {
    const current = latest.get(row.attachmentId);
    if (!current || row.scanId > current.scanId) latest.set(row.attachmentId, row);
  }
  return latest;
}

/**
 * One attachment of a message as the API item: the part's metadata (sanitized filename as in
 * the scans view) and its latest round mapped by the scans view mapper (`attachmentOf`).
 */
export function toAttachmentItem(
  part: AttachmentPart,
  latest: LatestResultRow | undefined,
  round: number | undefined,
): MessageAttachmentItem {
  let latestScan: AttachmentLatestScan | null = null;
  if (latest && round !== undefined) {
    const view = attachmentOf(latest, part, undefined);
    latestScan = {
      round,
      verdict: view.verdict,
      reasonCodes: view.reasonCodes,
      detectedType: view.detectedType,
      typeFamily: view.typeFamily,
      typeMismatch: view.typeMismatch,
      clamav: view.clamav,
      yara: view.yara,
      archive: view.archive,
      knownHash: view.knownHash,
    };
  }
  return {
    partIndex: part.partIndex,
    filename: part.filename,
    declaredContentType: part.declaredContentType,
    detectedContentType: part.detectedContentType,
    sizeBytes: part.sizeBytes,
    sha256: part.sha256,
    disposition: part.disposition,
    depth: part.depth,
    verdict: latestScan?.verdict ?? null,
    latestScan,
  };
}

/** The validated, lower-cased hash of `GET /attachments` (`400` when missing or malformed). */
export function searchHash(query: AttachmentSearchQuery): string {
  const raw = query.filters.sha256?.values?.[0];
  if (raw === undefined) throw new BadRequestException(['sha256: Required']);
  if (!SHA256_HEX.test(raw)) {
    throw new BadRequestException(['sha256: must be 64 hexadecimal characters']);
  }
  return raw.toLowerCase();
}

/**
 * Attachment metadata and verdicts (step 6.1 WP2, §3.3) of the caller's organization from the
 * read replica: the attachments of a message and the audited hash search. Never content.
 */
@Injectable()
export class AttachmentsService {
  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly repository: AttachmentsRepository,
    private readonly messages: MessageDataService,
    private readonly messageData: MessageDataRepository,
    private readonly identities: MessagesRepository,
    private readonly codec: CursorCodec,
    private readonly audit: AuditService,
  ) {}

  now(): Date {
    return new Date();
  }

  async ofMessage(
    principal: Principal,
    scope: TenantScope,
    messageId: string,
    query: MessageAttachmentsQuery,
  ): Promise<MessageAttachmentsPage> {
    const binding = listBinding({
      resource: MESSAGE_ATTACHMENTS_RESOURCE,
      principal,
      filters: { messageId: { values: [messageId] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const afterPartIndex = decoded ? intKey(decoded.keys[0], MAX_PART_INDEX) : undefined;
    const message = await this.messages.messageRef(scope, messageId);
    const fetched = await this.repository.parts(scope, message, {
      take: query.limit + 1,
      afterPartIndex,
    });
    const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf: (p) => p.partIndex });
    const parts = fetched.slice(0, decision.rows);
    const latest = latestResults(
      await this.repository.results(
        scope,
        message,
        parts.map((p) => p.id),
      ),
    );
    const rounds = await this.messageData.scanRounds(
      scope,
      message,
      [...latest.values()].map((r) => r.scanId),
    );
    return {
      data: parts.map((part) => {
        const result = latest.get(part.id);
        return toAttachmentItem(part, result, result ? rounds.get(result.scanId) : undefined);
      }),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [String(decision.next)]),
    };
  }

  async search(
    principal: Principal,
    scope: TenantScope,
    query: AttachmentSearchQuery,
    sourceIp: string | null = null,
  ): Promise<AttachmentSearchPage> {
    const sha256 = searchHash(query);
    const filters = { sha256: { values: [sha256] } };
    const binding = listBinding({
      resource: ATTACHMENT_SEARCH_RESOURCE,
      principal,
      filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    if (decoded && !decoded.window) throw cursorInvalid();
    const range = resolveRange(query, {
      defaultMs: DAY_MS,
      maxDays: this.config.API_MESSAGES_MAX_RANGE_DAYS,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const fetched = await this.repository.search(scope, {
      sha256,
      range,
      after: timeIdKeyOf(decoded),
      direction: binding.direction,
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched,
      limit: query.limit,
      keyOf: (r) => ({ at: r.receivedAt, id: r.id }),
    });
    const rows = fetched.slice(0, decision.rows);
    const [publicIds, verdicts] = await Promise.all([
      this.identities.publicIdMap(
        scope,
        rows.map((r) => r.messageId),
      ),
      this.repository.latestVerdicts(scope, rows),
    ]);
    const data = rows.flatMap((row) => {
      const messageId = publicIds.get(row.messageId);
      if (!messageId) return [];
      return [
        {
          messageId,
          receivedAt: row.receivedAt.toISOString(),
          partIndex: row.partIndex,
          filename: row.filename,
          sizeBytes: row.sizeBytes,
          detectedContentType: row.detectedContentType,
          verdict: (verdicts.get(row.id) ??
            null) as AttachmentSearchPage['data'][number]['verdict'],
        },
      ];
    });
    if (query.cursor === undefined) {
      await this.audit.record({
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action: 'attachment.searched',
        resourceType: 'attachment',
        resourceId: null,
        sourceIp,
        metadata: {
          filters: ['sha256'],
          filterHash: binding.filterHash,
          valueSha256: { sha256: sha256Hex(sha256) },
          range: { from: range.from.toISOString(), to: range.to.toISOString() },
          resultCount: data.length,
        },
      });
    }
    return {
      data,
      nextCursor: decision.next
        ? encodeListCursor(this.codec, binding, timeIdKeys(decision.next), rangeWindow(range))
        : null,
    };
  }
}
