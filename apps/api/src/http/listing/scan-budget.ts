/**
 * Scan-bounded keyset pages (step 6.1 D5 plan 4, D6) as pure decisions that repositories call.
 *
 * Step 1 reads the boundary key: the key of the `budget`-th index entry after the cursor
 * (`SELECT … ORDER BY <keyset> LIMIT 1 OFFSET budget − 1`, index-only); none when fewer entries
 * are left. Step 2 runs the filtered query between the cursor and that boundary (inclusive) with
 * `LIMIT limit + 1`. Then `nextCursor` is the last row when the page filled, else the boundary
 * (a short, possibly empty page: the budget ended it), else null (the index is exhausted). MySQL
 * never examines more than the budget per request.
 */

/** `OFFSET` of the boundary query: the budget-th entry after the cursor. */
export function boundaryOffset(budget: number): number {
  if (!Number.isSafeInteger(budget) || budget < 1) {
    throw new Error('scan budget must be a positive integer');
  }
  return budget - 1;
}

export interface ScanPageDecision<K> {
  /** Rows to return (at most `limit`). */
  rows: number;
  /** Keyset position of the next page, or null on the last page. */
  next: K | null;
  /** True when the budget (not the limit) ended the page: `api_list_scan_budget_exhausted_total`. */
  budgetExhausted: boolean;
}

/**
 * Decides one scan-bounded page. `fetched` are the step 2 rows (at most `limit + 1`, in keyset
 * order), `keyOf` gives a row's keyset position and `boundary` the step 1 key (or null).
 */
export function decideScanPage<R, K>(input: {
  fetched: readonly R[];
  limit: number;
  boundary: K | null;
  keyOf: (row: R) => K;
}): ScanPageDecision<K> {
  const { fetched, limit, boundary, keyOf } = input;
  if (fetched.length > limit) {
    return { rows: limit, next: keyOf(fetched[limit - 1]!), budgetExhausted: false };
  }
  if (boundary !== null) {
    return { rows: fetched.length, next: boundary, budgetExhausted: true };
  }
  return { rows: fetched.length, next: null, budgetExhausted: false };
}

/**
 * Plain keyset page (no budget): `fetched` holds at most `limit + 1` rows; the extra row only
 * tells that another page exists.
 */
export function decideKeysetPage<R, K>(input: {
  fetched: readonly R[];
  limit: number;
  keyOf: (row: R) => K;
}): { rows: number; next: K | null } {
  const { fetched, limit, keyOf } = input;
  if (fetched.length > limit) return { rows: limit, next: keyOf(fetched[limit - 1]!) };
  return { rows: fetched.length, next: null };
}
