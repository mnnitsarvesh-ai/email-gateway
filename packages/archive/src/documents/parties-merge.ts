import type { IngestSource } from '../vocabulary';
import type { ArchiveParties } from './records';

type PartyRecipient = ArchiveParties['recipients'][number];

/**
 * Union of the parties of two copies of one message (step 8.6 D7, ADR-0088), pure. `a` is the
 * record's current parties, `b` the merged copy's.
 *
 * - Recipients are matched by lower-cased address; `a`'s order is kept and `b`'s new recipients
 *   are appended with `seq` numbers after `a`'s highest.
 * - `sources` are united; an entry without `sources` takes the default of its side
 *   (`aSource` / `bSource`), so 8.1 parties (no `sources`) merge correctly.
 * - For a recipient in both: the gateway's facts (`direction`, `status`, `finalAction`) win over
 *   an intake copy's (the gateway saw the real delivery); otherwise `a` wins and a NULL direction
 *   is filled from `b`. `field` is `a`'s, else `b`'s.
 * - The envelope sender and header From stay `a`'s (filled from `b` when `a` has none).
 * - At most `max` recipients (default 65 535, the schema bound; `recipient_count` is an unsigned
 *   smallint): further new recipients are dropped and `truncated` is set.
 */
export interface MergePartiesOptions {
  /** Source of `a`'s entries without `sources` (default `gateway`). */
  aSource?: IngestSource;
  /** Source of `b`'s entries without `sources` (default `journal_intake`). */
  bSource?: IngestSource;
  max?: number;
}

export interface MergedParties {
  parties: ArchiveParties;
  /** Recipients appended from `b`. */
  added: number;
  truncated: boolean;
}

const unite = (x: readonly IngestSource[], y: readonly IngestSource[]): IngestSource[] => {
  const set = new Set([...x, ...y]);
  return (['gateway', 'journal_intake'] as const).filter((s) => set.has(s));
};

export function mergeParties(
  a: ArchiveParties,
  b: ArchiveParties,
  options: MergePartiesOptions = {},
): MergedParties {
  const aSource = options.aSource ?? 'gateway';
  const bSource = options.bSource ?? 'journal_intake';
  const max = options.max ?? 65_535;
  if (!Number.isInteger(max) || max < 1 || max > 65_535)
    throw new RangeError('max must be 1 … 65 535');
  const recipients: PartyRecipient[] = a.recipients.map((r) => ({
    ...r,
    sources: r.sources ? unite(r.sources, []) : [aSource],
  }));
  const byAddress = new Map<string, number>();
  recipients.forEach((r, i) => {
    const key = r.address.trim().toLowerCase();
    if (!byAddress.has(key)) byAddress.set(key, i);
  });
  let nextSeq = recipients.reduce((m, r) => Math.max(m, r.seq + 1), 0);
  let added = 0;
  let truncated = false;
  for (const r of b.recipients) {
    const sources = r.sources ? unite(r.sources, []) : [bSource];
    const key = r.address.trim().toLowerCase();
    const at = byAddress.get(key);
    if (at !== undefined) {
      const current = recipients[at]!;
      const gatewayB = sources.includes('gateway') && !current.sources!.includes('gateway');
      recipients[at] = {
        ...current,
        ...(gatewayB
          ? {
              direction: r.direction ?? current.direction,
              status: r.status,
              finalAction: r.finalAction,
            }
          : { direction: current.direction ?? r.direction }),
        ...(current.field === undefined && r.field !== undefined ? { field: r.field } : {}),
        sources: unite(current.sources!, sources),
      };
      continue;
    }
    if (recipients.length >= max || nextSeq > 65_535) {
      truncated = true;
      continue;
    }
    const entry: PartyRecipient = { ...r, seq: nextSeq++, sources };
    byAddress.set(key, recipients.length);
    recipients.push(entry);
    added++;
  }
  return {
    parties: {
      v: 1,
      from: a.from !== '' ? a.from : b.from,
      headerFrom: a.headerFrom ?? b.headerFrom,
      recipients,
    },
    added,
    truncated,
  };
}
