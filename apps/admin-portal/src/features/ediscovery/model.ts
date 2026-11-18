import type { EdiscoverySearch } from '@/features/archive/model';

/** Polling interval of queued/running searches and queued/building exports (ms). */
export const JOB_POLL_MS = 5_000;

export const INCOMPLETE_REASON_TEXT: Readonly<Record<string, string>> = {
  index_lag:
    'The search index was behind when the search completed: recently archived or changed records may be missing.',
  unverified_days:
    'Some days of the range have not been verified against the archive yet: the results may be incomplete for those days.',
  mismatched_days:
    'The index and the archive disagreed for some days of the range when the search ran (a repair was queued): the results may be incomplete.',
};

/** Completeness of a completed search (A18): reported, never assumed. */
export function completenessOf(
  search: Pick<EdiscoverySearch, 'status' | 'indexComplete' | 'incompleteReason' | 'truncated'>,
): { complete: boolean; lines: string[] } {
  const lines: string[] = [];
  if (search.status !== 'completed') return { complete: false, lines };
  if (search.indexComplete === false) {
    lines.push(
      INCOMPLETE_REASON_TEXT[search.incompleteReason ?? ''] ??
        `The results may be incomplete (${search.incompleteReason ?? 'unknown reason'}).`,
    );
  }
  if (search.truncated) {
    lines.push(
      'The search stopped at the maximum number of hits: narrow the criteria to see every match.',
    );
  }
  return { complete: lines.length === 0, lines };
}

export function isActiveJob(status: string): boolean {
  return status === 'queued' || status === 'running' || status === 'building';
}
