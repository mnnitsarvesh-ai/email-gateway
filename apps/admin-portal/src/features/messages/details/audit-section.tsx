'use client';

import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { DateTime, SensitiveValue, UntrustedText } from '@/components/domain';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { EntryHistory } from '@/features/quarantine/entry-detail';
import { CursorPager, Section } from '../controls';
import { NoData } from './parts';
import { useMessageEntries } from './quarantine-section';
import type { MessageDetailBody } from './summary-section';

type AuditRow = ListItem<'AuditLogsController_search_v1'>;

const MINUTE = 60_000;
const DAY = 86_400_000;
/** `API_AUDIT_MAX_RANGE_DAYS` (§2 E3): one audit search covers at most 90 days. */
export const AUDIT_WINDOW_DAYS = 90;

/** Audit window `index` (0 = the first 90 days after the message was received), or null. */
export function auditWindow(
  receivedAt: string,
  now: number,
  index: number,
): { from: string; to: string; hasLater: boolean } | null {
  const start = Date.parse(receivedAt) - MINUTE + index * AUDIT_WINDOW_DAYS * DAY;
  if (start >= now) return null;
  const end = Math.min(now, start + AUDIT_WINDOW_DAYS * DAY);
  return {
    from: new Date(start).toISOString(),
    to: new Date(end).toISOString(),
    hasLater: start + AUDIT_WINDOW_DAYS * DAY < now,
  };
}

function metadataText(metadata: AuditRow['metadata']): string | null {
  if (!metadata) return null;
  const entries = Object.entries(metadata).filter(([key]) => key !== 'requestId');
  if (entries.length === 0) return null;
  return entries
    .map(([key, value]) => `${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`)
    .join(' · ');
}

function AuditGroup({
  title,
  description,
  resourceType,
  messageId,
  bounds,
}: {
  title: string;
  description: string;
  resourceType: 'message' | 'dlp_evidence';
  messageId: string;
  bounds: { from: string; to: string };
}) {
  const list = useCursorList(
    'AuditLogsController_search_v1',
    { resourceType, resourceId: messageId, from: bounds.from, to: bounds.to, sort: '-createdAt' },
    { limit: 25, queryOptions: { refetchOnWindowFocus: false } },
  );
  const { isLoading, error, isFetching } = list.query;
  return (
    <Section title={title} description={description} headingLevel={3}>
      {isLoading ? (
        <LoadingState label={`Loading ${title.toLowerCase()}`} rows={3} />
      ) : error && list.rows.length === 0 ? (
        <ErrorState error={error} onRetry={() => void list.query.refetch()} compact />
      ) : list.rows.length === 0 ? (
        <NoData>No event recorded in this window.</NoData>
      ) : (
        <>
          <ol className="grid gap-2" aria-label={title}>
            {list.rows.map((row) => {
              const metadata = metadataText(row.metadata);
              return (
                <li key={row.id} className="grid gap-0.5 rounded-md border p-2 text-sm">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-medium">{row.action}</span>
                    <span className="text-xs text-muted-foreground">
                      by {humanize(row.actor.type)}
                      {row.actor.id ? ` ${row.actor.id}` : ''} ·{' '}
                      <DateTime value={row.createdAt} mode="absolute" />
                      {row.sourceIp ? ` · from ${row.sourceIp}` : ''}
                    </span>
                  </span>
                  {metadata ? <UntrustedText value={metadata} mono maxLength={240} /> : null}
                </li>
              );
            })}
          </ol>
          <CursorPager
            label={title}
            state={{
              page: list.page,
              hasNext: list.hasNext,
              hasPrevious: list.hasPrevious,
              isShortPage: list.isShortPage,
              next: list.next,
              previous: list.previous,
              rowCount: list.rows.length,
              isFetching,
            }}
          />
        </>
      )}
    </Section>
  );
}

function QuarantineHistories({ message }: { message: MessageDetailBody }) {
  const list = useMessageEntries(message);
  const { isLoading, error, isFetching } = list.query;
  return (
    <Section
      title="Quarantine entry histories"
      headingLevel={3}
      description="The actions recorded on each quarantine entry of this message (operator reasons included)."
    >
      {isLoading ? (
        <LoadingState label="Loading quarantine entries" rows={3} />
      ) : error && list.rows.length === 0 ? (
        <ErrorState error={error} onRetry={() => void list.query.refetch()} compact />
      ) : list.rows.length === 0 ? (
        <NoData>This message has no quarantine entry.</NoData>
      ) : (
        <>
          <ul className="grid gap-3" aria-label="Quarantine entry histories">
            {list.rows.map((entry) => (
              <li key={entry.id} className="grid gap-2 rounded-md border p-3">
                <span className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-medium">{humanize(entry.state)}</span>
                  <span className="text-muted-foreground">recipient</span>
                  <SensitiveValue
                    value={entry.recipient}
                    masked={entry.recipientMasked}
                    kind="address"
                  />
                </span>
                <EntryHistory entryId={entry.id} />
              </li>
            ))}
          </ul>
          <CursorPager
            label="Quarantine entry histories"
            state={{
              page: list.page,
              hasNext: list.hasNext,
              hasPrevious: list.hasPrevious,
              isShortPage: list.isShortPage,
              next: list.next,
              previous: list.previous,
              rowCount: list.rows.length,
              isFetching,
            }}
          />
        </>
      )}
    </Section>
  );
}

/** Actions of this page that write an audit row of the message (resource `message`). */
const AUDITED_MUTATIONS = new Set<unknown>([
  'MessageRevealController_reveal_v1',
  'MessageLifecycleController_rescan_v1',
]);

/**
 * The end of the latest audit window: the moment the section opened, moved forward whenever a
 * reveal or rescan of this page succeeds, so its new audit row falls inside `[from, to)`.
 */
function useAuditNow(): number {
  const queryClient = useQueryClient();
  const [now, setNow] = useState(() => Date.now());
  useEffect(
    () =>
      queryClient.getMutationCache().subscribe((event) => {
        if (
          event.type === 'updated' &&
          event.mutation.state.status === 'success' &&
          AUDITED_MUTATIONS.has(event.mutation.options.mutationKey?.[0])
        ) {
          setNow(Date.now() + 1_000);
        }
      }),
    [queryClient],
  );
  return now;
}

/**
 * Section 14: audit history (§2 E3, E11): the `message` and `dlp_evidence` audit rows of this
 * message (resource plan of `GET /audit/logs`) and the quarantine entry histories, as three
 * groups with their own cursors (paginated streams are never merged).
 */
export function AuditSection({ message }: { message: MessageDetailBody }) {
  const canQuarantine = useCan('QuarantineEntriesController_search_v1');
  const now = useAuditNow();
  const [index, setIndex] = useState(0);
  const bounds =
    auditWindow(message.receivedAt, now, index) ?? auditWindow(message.receivedAt, now, 0);
  if (!bounds) return null;
  return (
    <div className="grid gap-4">
      <Section
        title="Audit history"
        description={
          <>
            Audit rows of this message from <DateTime value={bounds.from} mode="absolute" /> to{' '}
            <DateTime value={bounds.to} mode="absolute" /> (one search covers at most{' '}
            {AUDIT_WINDOW_DAYS} days). Reveals of masked values appear as message.revealed.
          </>
        }
        actions={
          <>
            {index > 0 ? (
              <Button variant="outline" size="sm" onClick={() => setIndex((i) => i - 1)}>
                Earlier window
              </Button>
            ) : null}
            {bounds.hasLater ? (
              <Button variant="outline" size="sm" onClick={() => setIndex((i) => i + 1)}>
                Later window
              </Button>
            ) : null}
          </>
        }
      >
        <p className="text-xs text-muted-foreground">
          Audit rows hold ids, counts and hashes, never subjects, addresses or matched values.
        </p>
      </Section>
      <AuditGroup
        title="Message events"
        description="Reveals, rescans and other actions on the message (resource message)."
        resourceType="message"
        messageId={message.id}
        bounds={bounds}
      />
      <AuditGroup
        title="DLP evidence access"
        description="Reads and purges of the decrypted DLP evidence (resource dlp_evidence)."
        resourceType="dlp_evidence"
        messageId={message.id}
        bounds={bounds}
      />
      {canQuarantine ? <QuarantineHistories message={message} /> : null}
    </div>
  );
}
