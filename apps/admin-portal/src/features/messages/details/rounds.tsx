'use client';

import { ChevronLeftIcon, ChevronRightIcon } from 'lucide-react';
import { createContext, useContext, useId, type ReactNode } from 'react';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useCursorList, type CursorListState } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { humanize } from '@/lib/format';
import { EnumBadge } from '../controls';
import { SCAN_STATUS_TONE, SCAN_VERDICT_TONE } from '../semantic';

export type ScanRound = ListItem<'MessageScansController_scansOf_v1'>;
export type Engine = ScanRound['engines'][number];

/** Rounds per page of `GET /messages/{id}/scans` (the same key as page 11: one cached read). */
export const ROUNDS_PER_PAGE = 10;

interface RoundState {
  readonly list: CursorListState<'MessageScansController_scansOf_v1'>;
  readonly requested: number | undefined;
  readonly onRoundChange: (round: number | undefined) => void;
}

const RoundContext = createContext<RoundState | null>(null);

/**
 * The scan rounds of sections 4–10 (§2 E11): one `useCursorList` over the scans operation, kept
 * mounted while the user moves between round-scoped sections (the cursor stack survives), and
 * deduplicated with every other reader of the same page by TanStack Query.
 */
export function RoundScope({
  messageId,
  round,
  onRoundChange,
  children,
}: {
  messageId: string;
  round: number | undefined;
  onRoundChange: (round: number | undefined) => void;
  children: ReactNode;
}) {
  const list = useCursorList('MessageScansController_scansOf_v1', undefined, {
    path: { messageId },
    limit: ROUNDS_PER_PAGE,
  });
  return (
    <RoundContext.Provider value={{ list, requested: round, onRoundChange }}>
      {children}
    </RoundContext.Provider>
  );
}

/** The engine entry of a round (`rspamd`, `bec`, `url`, `attachment`, `sandbox`, `dlp`). */
export function engineOf(round: ScanRound, engine: string): Engine | undefined {
  return round.engines.find((entry) => entry.engine === engine);
}

function roundLabel(round: ScanRound, newest: boolean): string {
  return `Round ${round.round} · ${humanize(round.scanKind)} · ${humanize(round.status)}${newest ? ' (newest)' : ''}`;
}

/**
 * The round selector plus the selected round: loading, error, "no rounds yet", a requested round
 * that is not loaded (with older pages offered), then `children(round)`.
 */
export function RoundPanel({ children }: { children: (round: ScanRound) => ReactNode }) {
  const state = useContext(RoundContext);
  const id = useId();
  if (!state) throw new Error('RoundPanel outside RoundScope');
  const { list, requested, onRoundChange } = state;
  const { isLoading, error, isFetching } = list.query;
  if (isLoading) return <LoadingState label="Loading scan rounds" rows={4} />;
  if (error && list.rows.length === 0) {
    return <ErrorState error={error} onRetry={() => void list.query.refetch()} compact />;
  }
  if (list.rows.length === 0) {
    return (
      <EmptyState
        title="No scan rounds yet"
        description="The message has not been scanned yet, or its scan is still being recorded."
      />
    );
  }
  const selected =
    requested === undefined ? list.rows[0] : list.rows.find((round) => round.round === requested);
  const newestRound = list.page === 1 ? list.rows[0]?.round : undefined;
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-end gap-3 rounded-md border bg-muted/30 p-3">
        <div className="grid gap-1">
          <label htmlFor={id} className="text-xs font-medium text-muted-foreground">
            Scan round
          </label>
          <select
            id={id}
            className="h-9 max-w-full min-w-0 rounded-md border border-input bg-background px-2 text-sm"
            value={selected ? String(selected.round) : ''}
            onChange={(event) => {
              const value = Number(event.target.value);
              onRoundChange(value === newestRound ? undefined : value);
            }}
          >
            {selected ? null : <option value="">Round {requested} (not loaded)</option>}
            {list.rows.map((round) => (
              <option key={round.scanId} value={String(round.round)}>
                {roundLabel(round, round.round === newestRound)}
              </option>
            ))}
          </select>
        </div>
        {selected ? (
          <div className="flex flex-wrap items-center gap-2 pb-1">
            <EnumBadge value={selected.status} tones={SCAN_STATUS_TONE} />
            <EnumBadge
              value={selected.verdict}
              tones={SCAN_VERDICT_TONE}
              emptyLabel="No verdict yet"
            />
            <span className="font-mono text-xs text-muted-foreground">scan {selected.scanId}</span>
          </div>
        ) : null}
        {list.hasPrevious || list.hasNext ? (
          <div className="ml-auto flex items-center gap-1">
            <Button
              variant="outline"
              size="sm"
              onClick={list.previous}
              disabled={!list.hasPrevious || isFetching}
            >
              <ChevronLeftIcon aria-hidden />
              Newer rounds
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={list.next}
              disabled={!list.hasNext || isFetching}
            >
              Older rounds
              <ChevronRightIcon aria-hidden />
            </Button>
          </div>
        ) : null}
      </div>
      {selected ? (
        children(selected)
      ) : (
        <p role="status" className="text-sm text-muted-foreground">
          Round {requested} is not among the loaded rounds.
          {list.hasNext
            ? ' Load older rounds to find it, or pick a round above.'
            : ' Pick a round above.'}
        </p>
      )}
    </div>
  );
}
