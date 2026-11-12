import { createHash } from 'node:crypto';
import { canonicalJson } from '../idempotency/idempotency-key';
import { canonicalFilters, type ParsedFilter } from './list-query';

/**
 * The filter hash bound into a v1 cursor (step 6.1 D3, D4): the first 16 hex characters of the
 * SHA-256 of the canonical JSON `{ filters, resource, sort }` (keys sorted at every depth,
 * equality lists sorted, dates as ISO strings). A cursor issued for one filter set is
 * `cursor_invalid` under another.
 */
export function filterHash(input: {
  resource: string;
  filters: Record<string, ParsedFilter<unknown> | undefined>;
  sort: string;
}): string {
  return createHash('sha256')
    .update(
      canonicalJson({
        filters: canonicalFilters(input.filters),
        resource: input.resource,
        sort: input.sort,
      }),
      'utf8',
    )
    .digest('hex')
    .slice(0, 16);
}
