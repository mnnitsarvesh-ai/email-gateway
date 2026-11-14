'use client';

import { useId, useState } from 'react';
import { DateTime, DeliveryStatusBadge, UntrustedText } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { formatNumber, humanize } from '@/lib/format';
import { CursorPager, EnumBadge, Section } from '../controls';
import { MESSAGE_STATUS_TONE } from '../semantic';
import { DataGrid, NoData, QueryBoundary } from './parts';
import { RecipientAddress } from './people-section';

type Delivery = SuccessBody<'DeliveriesController_forMessage_v1'>['deliveries'][number];

/** Section 12: delivery timeline (deliveries, delivery events v0, lifecycle history v0). */
export function DeliverySection({ messageId }: { messageId: string }) {
  const query = useApiQuery('DeliveriesController_forMessage_v1', { path: { messageId } });
  return (
    <div className="grid gap-4">
      <Section
        title="Delivery timeline"
        description="Per-recipient deliveries. Recipient addresses are masked (revealed by position when you used Reveal); addresses inside SMTP replies are always masked."
      >
        <QueryBoundary query={query} label="Loading deliveries" rows={4}>
          {() => {
            const deliveries = query.data?.deliveries ?? [];
            if (deliveries.length === 0) {
              return (
                <EmptyState
                  title="No deliveries"
                  description="No delivery was planned for this message (quarantined, rejected or still being scanned)."
                />
              );
            }
            return <DeliveriesTable deliveries={deliveries} />;
          }}
        </QueryBoundary>
      </Section>
      <DeliveryEvents messageId={messageId} deliveries={query.data?.deliveries ?? []} />
      <LifecycleHistory messageId={messageId} />
    </div>
  );
}

function DeliveriesTable({ deliveries }: { deliveries: readonly Delivery[] }) {
  return (
    <DataGrid
      caption="Deliveries"
      rows={deliveries}
      rowKey={(row) => `${row.rcptSeq}-${row.deliverySeq}`}
      columns={[
        {
          header: 'Recipient',
          rowHeader: true,
          className: 'max-w-64',
          cell: (row) => (
            <span className="grid gap-0.5">
              <span className="text-xs text-muted-foreground">
                #{row.rcptSeq}
                {row.deliverySeq > 0 ? ` · delivery ${row.deliverySeq} (release)` : ''}
              </span>
              <RecipientAddress
                rcptSeq={row.rcptSeq}
                value={row.recipient}
                masked={row.recipientMasked}
              />
            </span>
          ),
        },
        {
          header: 'Status',
          cell: (row) => (
            <span className="grid gap-0.5">
              <DeliveryStatusBadge status={row.status} />
              {row.statusChangedAt ? (
                <span className="text-xs text-muted-foreground">
                  <DateTime value={row.statusChangedAt} />
                </span>
              ) : null}
            </span>
          ),
        },
        {
          header: 'Attempts',
          className: 'text-xs',
          cell: (row) => (
            <span className="grid">
              <span className="tabular-nums">{formatNumber(row.attemptCount)}</span>
              {row.lastAttemptAt ? <DateTime value={row.lastAttemptAt} /> : null}
            </span>
          ),
        },
        {
          header: 'Delivered',
          className: 'text-xs',
          cell: (row) => (
            <DateTime value={row.deliveredAt} mode="absolute" emptyLabel="Not delivered" />
          ),
        },
        {
          header: 'Remote server',
          cell: (row) => (
            <UntrustedText value={row.remoteHost} mono maxLength={60} emptyLabel="None" />
          ),
        },
        {
          header: 'SMTP reply',
          className: 'max-w-[28rem]',
          cell: (row) => (
            <span className="grid gap-0.5 text-xs">
              {row.finalSmtpCode !== null || row.enhancedStatus ? (
                <span className="font-mono">
                  {row.finalSmtpCode ?? ''} {row.enhancedStatus ?? ''}
                </span>
              ) : null}
              <UntrustedText
                value={row.finalSmtpResponse}
                mono
                maxLength={160}
                emptyLabel="No reply recorded"
              />
              {row.lastErrorClass || row.failureReason ? (
                <span className="text-muted-foreground">
                  {[row.lastErrorClass, row.failureReason]
                    .filter(Boolean)
                    .map((v) => humanize(v ?? ''))
                    .join(' · ')}
                </span>
              ) : null}
              {row.dsnGenerated ? <span>Bounce notice sent to the sender</span> : null}
            </span>
          ),
        },
      ]}
    />
  );
}

function DeliveryEvents({
  messageId,
  deliveries,
}: {
  messageId: string;
  deliveries: readonly Delivery[];
}) {
  const id = useId();
  const [rcptSeq, setRcptSeq] = useState<number | null>(null);
  const positions = [...new Set(deliveries.map((d) => d.rcptSeq))].sort((a, b) => a - b);
  const list = useCursorList(
    'DeliveriesController_events_v1',
    rcptSeq === null ? undefined : { rcptSeq },
    { path: { messageId }, limit: 25 },
  );
  const { isLoading, error, isFetching } = list.query;
  return (
    <Section
      title="Delivery events"
      headingLevel={3}
      description="Every recorded delivery status change, oldest first. Addresses inside event details are masked."
      actions={
        positions.length > 1 ? (
          <div className="flex items-center gap-2 text-xs">
            <label htmlFor={id} className="text-muted-foreground">
              Recipient
            </label>
            <select
              id={id}
              className="h-8 rounded-md border border-input bg-background px-2 text-sm"
              value={rcptSeq === null ? '' : String(rcptSeq)}
              onChange={(event) =>
                setRcptSeq(event.target.value === '' ? null : Number(event.target.value))
              }
            >
              <option value="">All recipients</option>
              {positions.map((position) => (
                <option key={position} value={String(position)}>
                  Recipient #{position}
                </option>
              ))}
            </select>
          </div>
        ) : null
      }
    >
      {isLoading ? (
        <LoadingState label="Loading delivery events" rows={4} />
      ) : error && list.rows.length === 0 ? (
        <ErrorState error={error} onRetry={() => void list.query.refetch()} compact />
      ) : list.rows.length === 0 ? (
        <NoData>No delivery event is recorded.</NoData>
      ) : (
        <>
          <ol className="grid gap-2" aria-label="Delivery events">
            {list.rows.map((event, index) => (
              <li
                key={`${event.occurredAt}-${index}`}
                className="grid gap-0.5 rounded-md border p-2 text-sm"
              >
                <span className="flex flex-wrap items-center gap-2">
                  <span className="text-xs text-muted-foreground">#{event.rcptSeq}</span>
                  {event.fromStatus ? <DeliveryStatusBadge status={event.fromStatus} /> : null}
                  {event.fromStatus ? <span aria-hidden>→</span> : null}
                  <span className="sr-only">{event.fromStatus ? 'to' : ''}</span>
                  <DeliveryStatusBadge status={event.toStatus} />
                  <span className="text-xs text-muted-foreground">
                    {humanize(event.source)} · <DateTime value={event.occurredAt} mode="absolute" />
                    {event.applied ? '' : ' · not applied (out of order)'}
                  </span>
                </span>
                {event.smtpCode !== null || event.remoteHost ? (
                  <span className="font-mono text-xs">
                    {event.smtpCode ?? ''} {event.enhancedStatus ?? ''} {event.remoteHost ?? ''}
                  </span>
                ) : null}
                {event.detail ? <UntrustedText value={event.detail} mono maxLength={200} /> : null}
              </li>
            ))}
          </ol>
          <CursorPager
            label="Delivery events"
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

function LifecycleHistory({ messageId }: { messageId: string }) {
  const list = useCursorList('MessageLifecycleController_history_v1', undefined, {
    path: { messageId },
    limit: 25,
  });
  const { isLoading, error, isFetching } = list.query;
  return (
    <Section
      title="Lifecycle history"
      headingLevel={3}
      description="Every state change of the message, with the service or person that made it."
    >
      {isLoading ? (
        <LoadingState label="Loading the lifecycle history" rows={4} />
      ) : error && list.rows.length === 0 ? (
        <ErrorState error={error} onRetry={() => void list.query.refetch()} compact />
      ) : list.rows.length === 0 ? (
        <NoData>No state change is recorded.</NoData>
      ) : (
        <>
          <ol className="grid gap-2" aria-label="Lifecycle history">
            {list.rows.map((change) => (
              <li key={change.version} className="grid gap-0.5 rounded-md border p-2 text-sm">
                <span className="flex flex-wrap items-center gap-2">
                  {change.fromState ? (
                    <EnumBadge value={change.fromState} tones={MESSAGE_STATUS_TONE} />
                  ) : null}
                  {change.fromState ? <span aria-hidden>→</span> : null}
                  <span className="sr-only">{change.fromState ? 'to' : ''}</span>
                  <EnumBadge value={change.toState} tones={MESSAGE_STATUS_TONE} />
                  <span className="text-xs text-muted-foreground">
                    version {change.version} · round {change.lifecycleRound} ·{' '}
                    <DateTime value={change.changedAt} mode="absolute" />
                  </span>
                </span>
                <span className="text-xs text-muted-foreground">
                  {humanize(change.actor.role)} ({humanize(change.actor.type)},{' '}
                  {change.actor.service})
                  {change.reasonCode ? (
                    <>
                      {' '}
                      · <span className="font-mono">{change.reasonCode}</span>
                    </>
                  ) : null}
                </span>
              </li>
            ))}
          </ol>
          <CursorPager
            label="Lifecycle history"
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
