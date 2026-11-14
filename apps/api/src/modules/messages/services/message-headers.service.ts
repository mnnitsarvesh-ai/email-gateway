import { Injectable } from '@nestjs/common';
import { PARTITION_REGISTRY, type PartitionSpec, retentionCutoff } from '@email-gateway/database';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  classifyHeader,
  SAFE_HEADER_NAMES,
  STORED_HEADER_NAMES,
} from '../domain/sensitive-masking';
import type { HeaderAvailability, MessageHeadersView } from '../dto/message-sensitive.schemas';
import {
  type HeaderRow,
  MessageHeadersRepository,
} from '../repositories/message-headers.repository';
import { MessageDataService } from './message-data.service';

/**
 * The `email_headers` retention of the partitioning registry (3 monthly partitions plus the
 * current month, docs/plan/steps/01-database.md D3): older messages have no header rows left.
 */
export const EMAIL_HEADERS_RETENTION: PartitionSpec = (() => {
  const spec = PARTITION_REGISTRY.find((s) => s.table === 'email_headers');
  if (!spec || spec.granularity !== 'month' || spec.retention === null) {
    throw new Error('The partitioning registry has no monthly retention for email_headers');
  }
  return spec;
})();

/** Parse states whose header rows were written (step 3.1 M13). */
const PARSED = new Set(['parsed', 'parsed_with_defects']);

/**
 * `availability` of §2 E7: `available` when rows are stored; otherwise `not_parsed` when the
 * parse row is missing or not `parsed`/`parsed_with_defects`, `retention_expired` when the
 * message is older than the `email_headers` retention cutoff (`retentionCutoff`, the rule the
 * partition job drops by), else `none_stored`. A message with rows is `available` whatever its
 * parse state (a `parse_limit_exceeded` parse may have stored its headers; step 7.2 WP2
 * deviation 2).
 */
export function headerAvailability(input: {
  parseStatus: string | null;
  rowCount: number;
  receivedAt: Date;
  now: Date;
  spec?: PartitionSpec;
}): HeaderAvailability {
  if (input.rowCount > 0) return 'available';
  if (input.parseStatus === null || !PARSED.has(input.parseStatus)) return 'not_parsed';
  const cutoff = retentionCutoff(input.spec ?? EMAIL_HEADERS_RETENTION, input.now);
  if (cutoff !== null && input.receivedAt.getTime() < cutoff.getTime()) return 'retention_expired';
  return 'none_stored';
}

/** One stored row as the API shows it: the safe subset in clear, every other value withheld. */
export function toHeaderView(row: HeaderRow): MessageHeadersView['headers'][number] {
  const masked = classifyHeader(row.name) === 'masked';
  return { seq: row.seq, name: row.name, value: masked ? null : row.value, masked };
}

/**
 * `GET /messages/{messageId}/headers` (step 7.2 §2 E7, ADR-0062): the stored allow-list rows of
 * the scope's message from the replica, the safe subset in clear and To, Cc, Subject and any
 * unknown name withheld (`value: null`, `masked: true`) for every caller. The full header block
 * stays in the EML in object storage and is never fetched. Unknown and foreign ids are `404
 * message_not_found`. Not audited (metadata behind `message:read`; the masked values leave only
 * through the audited reveal).
 */
@Injectable()
export class MessageHeadersService {
  constructor(
    private readonly messages: MessageDataService,
    private readonly repository: MessageHeadersRepository,
  ) {}

  now(): Date {
    return new Date();
  }

  async headers(scope: TenantScope, messageId: string): Promise<MessageHeadersView> {
    const message = await this.messages.messageRef(scope, messageId);
    const [parseStatus, rows] = await Promise.all([
      this.repository.parseStatus(scope, message),
      this.repository.headers(scope, message),
    ]);
    return {
      messageId: message.publicId,
      availability: headerAvailability({
        parseStatus,
        rowCount: rows.length,
        receivedAt: message.receivedAt,
        now: this.now(),
      }),
      storedHeaderNames: [...STORED_HEADER_NAMES],
      safeHeaderNames: [...SAFE_HEADER_NAMES],
      headers: rows.map(toHeaderView),
    };
  }
}
