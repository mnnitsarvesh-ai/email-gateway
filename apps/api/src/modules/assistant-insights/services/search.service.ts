import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
} from '../../messages/domain/v1-list';
import { likeContainsPattern, snippetOf } from '../domain/search-text';
import type { SearchPage, SearchQuery } from '../dto/insights.schemas';
import { CURSOR_RESOURCES, type InsightsConfig } from '../insights.constants';
import { assistantSearchTimeout, SearchTimeoutError } from '../insights.errors';
import { InsightsMetrics } from '../insights-metrics';
import { type SearchRow, SearchRepository } from '../repositories/search.repository';

/** The keyset order of the search: newest message first (`-id`). */
export const SEARCH_SORT = '-id';

/**
 * `GET /assistant/search` (step AI-6 D4): the caller's own messages and conversation titles that
 * contain `q`, newest first. The owner scope is that of `GET /assistant/conversations`: the
 * scope's organization (the override target under a platform override), the caller's user id,
 * non-deleted conversations; content of other users is never read (not even for admins: Q9).
 * Bounded by ASSISTANT_SEARCH_SCAN_MAX_MESSAGES and ASSISTANT_SEARCH_TIMEOUT_MS (`503
 * assistant_search_timeout`); metric `assistant_search_seconds{outcome}`. v1 cursor bound to the
 * query (`assistant_search`).
 */
@Injectable()
export class AssistantSearchService {
  constructor(
    @Inject(API_CONFIG) private readonly config: InsightsConfig,
    private readonly repository: SearchRepository,
    private readonly codec: CursorCodec,
    private readonly metrics: InsightsMetrics,
  ) {}

  async search(
    principal: UserPrincipal,
    scope: TenantScope,
    query: SearchQuery,
  ): Promise<SearchPage> {
    const binding = listBinding({
      resource: CURSOR_RESOURCES.search,
      principal,
      filters: { q: { values: [query.q] } },
      sort: SEARCH_SORT,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const started = process.hrtime.bigint();
    const seconds = () => Number(process.hrtime.bigint() - started) / 1_000_000_000;
    let fetched: SearchRow[];
    try {
      fetched = await this.repository.search(
        { scope, userId: principal.userId },
        {
          pattern: likeContainsPattern(query.q),
          scanMax: this.config.ASSISTANT_SEARCH_SCAN_MAX_MESSAGES,
          timeoutMs: this.config.ASSISTANT_SEARCH_TIMEOUT_MS,
          ...(decoded && { beforeId: decimalKey(decoded.keys[0]) }),
          take: query.limit + 1,
        },
      );
    } catch (err) {
      if (err instanceof SearchTimeoutError) {
        this.metrics.searchSeconds.observe({ outcome: 'timeout' }, seconds());
        throw assistantSearchTimeout();
      }
      this.metrics.searchSeconds.observe({ outcome: 'error' }, seconds());
      throw err;
    }
    this.metrics.searchSeconds.observe({ outcome: 'ok' }, seconds());
    const decision = decideKeysetPage({
      fetched,
      limit: query.limit,
      keyOf: (row: SearchRow) => [row.id.toString()],
    });
    return {
      data: fetched.slice(0, decision.rows).map((row) => ({
        conversationId: row.conversationPublicId,
        conversationTitle: row.conversationTitle,
        messageId: row.publicId,
        role: row.role,
        seq: row.seq,
        createdAt: row.createdAt.toISOString(),
        snippet: snippetOf(row.content, query.q),
      })),
      nextCursor:
        decision.next === null ? null : encodeListCursor(this.codec, binding, decision.next),
    };
  }
}
