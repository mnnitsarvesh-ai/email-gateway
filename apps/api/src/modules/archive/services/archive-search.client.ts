import { Inject, Injectable, Logger } from '@nestjs/common';
import { tenantAliasName } from '@email-gateway/archive';
import { OpenSearchError, type OpenSearchHit, OpenSearchService } from '@email-gateway/common';
import { API_CONFIG } from '../../../api-config.token';
import type { ArchiveConfig } from '../archive.constants';
import { archiveSearchUnavailable } from '../archive.errors';

/** The `_source` fields of an archive index document the api reads (§4.3). */
export interface ArchiveSearchSource {
  org_id?: string;
  message_id?: string;
  received_at?: string;
  captured_at?: string | null;
  direction?: string;
  category?: string;
  sources?: string[] | string;
  status?: string;
  envelope_from?: string;
  header_from?: string | null;
  recipients?: string[] | string;
  size_bytes?: number;
  attachment_count?: number;
  attachment_names?: string[] | string;
  verdict?: string | null;
  final_action?: string | null;
  risk_score?: number | null;
  malicious?: boolean;
  retain_until?: string | null;
  legal_hold?: boolean;
  lock_mode?: string;
}

/**
 * The api's OpenSearch access (step 8.1 A16, A17, ADR-0068): searches go **only** through the
 * tenant alias `<prefix>-t<organizationId>` derived from the authenticated scope, with custom
 * routing = the organization (the query builder adds the `org_id` term filter as well). No user
 * input ever names an index. `ARCHIVE_SEARCH_URL` unset or OpenSearch unreachable → `503
 * archive_search_unavailable` on the search routes only. A tenant without documents (no alias
 * yet) gets an empty result. Errors are logged by kind, status and OpenSearch error type only.
 */
@Injectable()
export class ArchiveSearchClient {
  private readonly logger = new Logger(ArchiveSearchClient.name);
  private readonly client: OpenSearchService | null;
  private readonly prefix: string;

  constructor(
    @Inject(API_CONFIG)
    config: Pick<
      ArchiveConfig,
      | 'ARCHIVE_SEARCH_URL'
      | 'ARCHIVE_SEARCH_USERNAME'
      | 'ARCHIVE_SEARCH_PASSWORD'
      | 'ARCHIVE_SEARCH_TIMEOUT_MS'
      | 'ARCHIVE_SEARCH_INDEX_PREFIX'
    >,
  ) {
    this.prefix = config.ARCHIVE_SEARCH_INDEX_PREFIX;
    this.client =
      config.ARCHIVE_SEARCH_URL === undefined
        ? null
        : new OpenSearchService({
            url: config.ARCHIVE_SEARCH_URL,
            username: config.ARCHIVE_SEARCH_USERNAME,
            password: config.ARCHIVE_SEARCH_PASSWORD,
            timeoutMs: config.ARCHIVE_SEARCH_TIMEOUT_MS,
          });
  }

  get configured(): boolean {
    return this.client !== null;
  }

  /** The tenant alias of an organization (exposed for tests and the status route). */
  aliasOf(organizationId: bigint): string {
    return tenantAliasName(this.prefix, organizationId);
  }

  /** One search through the tenant alias (body from `buildArchiveSearchQuery` only). */
  async search(
    organizationId: bigint,
    body: Record<string, unknown>,
  ): Promise<{ timedOut: boolean; hits: OpenSearchHit<ArchiveSearchSource>[] }> {
    if (this.client === null) throw archiveSearchUnavailable();
    try {
      return await this.client.search<ArchiveSearchSource>(this.aliasOf(organizationId), body, {
        routing: organizationId.toString(),
      });
    } catch (error) {
      if (error instanceof OpenSearchError && error.errorType === 'index_not_found_exception') {
        return { timedOut: false, hits: [] };
      }
      this.logger.warn({
        message: 'archive search failed',
        kind: error instanceof OpenSearchError ? error.kind : 'unknown',
        status: error instanceof OpenSearchError ? error.status : null,
        errorType: error instanceof OpenSearchError ? error.errorType : null,
      });
      throw archiveSearchUnavailable();
    }
  }

  /** Whether the cluster answers (status route); never throws. */
  async available(): Promise<boolean> {
    if (this.client === null) return false;
    try {
      await this.client.clusterHealth();
      return true;
    } catch {
      return false;
    }
  }
}
