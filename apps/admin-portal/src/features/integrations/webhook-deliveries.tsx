'use client';

import { HistoryIcon } from 'lucide-react';
import { useId, useMemo, useState } from 'react';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { FormErrorSummary } from '@/components/form';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan } from '@/lib/auth/me';
import { formatDuration, humanize } from '@/lib/format';
import { DetailList, FilterSelect, FormDialog, MutationError } from '@/features/domains/kit';
import {
  DELIVERY_STATUSES,
  DELIVERY_TRIGGERS,
  WebhookDeliveryBadge,
  type Webhook,
  type WebhookDelivery,
} from './model';

const URL_SHAPE = {
  dstatus: z.enum(DELIVERY_STATUSES).optional().catch(undefined),
  eventType: z
    .string()
    .regex(/^[a-z.]{3,64}$/)
    .optional()
    .catch(undefined),
  trigger: z.enum(DELIVERY_TRIGGERS).optional().catch(undefined),
  dsort: z.enum(['-occurredAt']).optional().catch(undefined),
};

/** One delivery with every attempt; response snippets are untrusted text (never HTML or links). */
export function DeliveryDetail({
  webhookId,
  deliveryId,
}: {
  webhookId: string;
  deliveryId: string;
}) {
  const delivery = useApiQuery('WebhookDeliveriesController_get_v1', {
    path: { webhookId, deliveryId },
  });
  if (delivery.isLoading) return <LoadingState label="Loading the delivery" rows={4} />;
  if (delivery.error)
    return <ErrorState error={delivery.error} onRetry={() => void delivery.refetch()} />;
  const data = delivery.data;
  if (!data) return null;
  return (
    <div className="grid gap-4 text-sm">
      <DetailList
        items={[
          { label: 'Status', value: <WebhookDeliveryBadge status={data.status} /> },
          { label: 'Event', value: <code className="font-mono text-xs">{data.eventType}</code> },
          {
            label: 'Event ID',
            value: <code className="font-mono text-xs break-all">{data.eventId}</code>,
          },
          { label: 'Trigger', value: humanize(data.trigger) },
          { label: 'Occurred', value: <DateTime value={data.occurredAt} mode="absolute" /> },
          {
            label: 'Next attempt',
            value: <DateTime value={data.nextAttemptAt} emptyLabel="None scheduled" />,
          },
          {
            label: 'Last error',
            value: <UntrustedText value={data.lastError} emptyLabel="None" maxLength={200} />,
          },
        ]}
      />
      <div className="grid gap-2">
        <h3 className="font-semibold">Attempts</h3>
        {data.attempts.length === 0 ? (
          <p className="text-muted-foreground">No attempt yet.</p>
        ) : (
          <ol className="grid gap-2" aria-label="Delivery attempts">
            {data.attempts.map((attempt) => (
              <li key={attempt.attemptNo} className="grid gap-1 rounded-md border p-2">
                <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="font-medium">Attempt {attempt.attemptNo}</span>
                  <span>{humanize(attempt.outcome)}</span>
                  <span className="tabular-nums">
                    {attempt.httpStatus !== null && attempt.httpStatus !== undefined
                      ? `HTTP ${attempt.httpStatus}`
                      : 'No HTTP response'}
                  </span>
                  <span className="tabular-nums text-muted-foreground">
                    {formatDuration(attempt.latencyMs)}
                  </span>
                  <DateTime value={attempt.attemptedAt} className="text-muted-foreground" />
                </span>
                {attempt.errorCode ? (
                  <span className="text-xs">
                    Error: <code className="font-mono">{attempt.errorCode}</code>
                  </span>
                ) : null}
                {attempt.retryAfterSeconds ? (
                  <span className="text-xs">Retry-After {attempt.retryAfterSeconds} s</span>
                ) : null}
                <span className="grid gap-0.5 text-xs">
                  <span className="text-muted-foreground">Response (untrusted, sanitized):</span>
                  <UntrustedText
                    value={attempt.responseSnippet}
                    mono
                    maxLength={512}
                    emptyLabel="(no body)"
                    className="whitespace-pre-wrap"
                  />
                </span>
              </li>
            ))}
          </ol>
        )}
      </div>
      <div className="grid gap-1">
        <h3 className="font-semibold">Event envelope</h3>
        {data.event ? (
          <pre className="max-h-64 overflow-auto rounded-md bg-muted p-2 font-mono text-xs whitespace-pre-wrap">
            {JSON.stringify(data.event, null, 2)}
          </pre>
        ) : (
          <p className="text-muted-foreground">No longer stored (past retention).</p>
        )}
      </div>
    </div>
  );
}

/** POST /webhooks/{id}/replays: a range ≤ 72 h of original deliveries in some statuses. */
export const replaySchema = z
  .object({
    from: z.string().min(1, 'Choose the start'),
    to: z.string().min(1, 'Choose the end'),
    statuses: z
      .array(z.enum(['succeeded', 'failed', 'dead', 'cancelled']))
      .min(1, 'Choose at least one status'),
    eventTypes: z.array(z.string()),
  })
  .strict()
  .superRefine((value, ctx) => {
    const from = Date.parse(value.from);
    const to = Date.parse(value.to);
    if (!Number.isFinite(from) || !Number.isFinite(to)) return;
    if (to <= from)
      ctx.addIssue({ code: 'custom', path: ['to'], message: 'The end must be after the start' });
    else if (to - from > 72 * 3_600_000)
      ctx.addIssue({ code: 'custom', path: ['to'], message: 'At most 72 hours' });
  });

export function replayBody(
  values: z.output<typeof replaySchema>,
): RequestBody<'WebhookDeliveriesController_createReplay_v1'> {
  return {
    from: new Date(values.from).toISOString(),
    to: new Date(values.to).toISOString(),
    statuses: values.statuses,
    ...(values.eventTypes.length > 0
      ? {
          eventTypes: values.eventTypes as NonNullable<
            RequestBody<'WebhookDeliveriesController_createReplay_v1'>['eventTypes']
          >,
        }
      : {}),
  };
}

const TERMINAL = new Set(['completed', 'failed', 'cancelled']);

/** Live progress of a range replay (`GET /webhooks/{id}/replays/{replayId}`, polled). */
export function ReplayProgress({ webhookId, replayId }: { webhookId: string; replayId: string }) {
  const replay = useApiQuery(
    'WebhookDeliveriesController_getReplay_v1',
    { path: { webhookId, replayId } },
    {
      refetchInterval: (query) =>
        query.state.data && TERMINAL.has(query.state.data.status)
          ? false
          : Math.min(10_000, 2_000 * (query.state.dataUpdateCount + 1)),
    },
  );
  if (replay.isLoading) return <LoadingState label="Loading the replay" rows={2} />;
  if (replay.error)
    return <ErrorState error={replay.error} onRetry={() => void replay.refetch()} compact />;
  const data = replay.data;
  if (!data) return null;
  return (
    <div className="grid gap-1 rounded-md border p-3 text-sm" role="status" aria-live="polite">
      <span className="font-medium">Replay {humanize(data.status).toLowerCase()}</span>
      <span>
        {data.matchedCount} matching deliveries, {data.createdCount} replayed
        {data.truncated ? ' (the range was truncated; replay the rest separately)' : ''}.
      </span>
      {data.errorCode ? (
        <span>
          Stopped: <code className="font-mono text-xs">{data.errorCode}</code>
        </span>
      ) : null}
    </div>
  );
}

function BulkReplay({
  webhook,
  onStarted,
}: {
  webhook: Webhook;
  onStarted: (replayId: string) => void;
}) {
  const id = useId();
  const now = new Date();
  const local = (d: Date) =>
    new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  const [values, setValues] = useState({
    from: local(new Date(now.getTime() - 24 * 3_600_000)),
    to: local(now),
    statuses: ['failed', 'dead'] as ('succeeded' | 'failed' | 'dead' | 'cancelled')[],
    eventTypes: [] as string[],
  });
  const [messages, setMessages] = useState<string[]>([]);
  const create = useApiMutation('WebhookDeliveriesController_createReplay_v1', {
    successMessage: 'Replay queued.',
  });
  return (
    <form
      className="grid min-w-0 gap-4 [&>*]:min-w-0"
      aria-label="Replay deliveries"
      onSubmit={(event) => {
        event.preventDefault();
        const parsed = replaySchema.safeParse(values);
        if (!parsed.success) return setMessages(parsed.error.issues.map((i) => i.message));
        setMessages([]);
        void create
          .submit({ path: { webhookId: webhook.id }, body: replayBody(parsed.data) })
          .then((outcome) => {
            if (outcome.ok) onStarted(outcome.data.replayId);
            else if (
              outcome.error.code === 'webhook_replay_in_progress' &&
              typeof outcome.error.details.replayId === 'string'
            ) {
              setMessages([
                'A replay of this webhook is already running; its progress is shown instead.',
              ]);
              onStarted(outcome.error.details.replayId);
            } else if (outcome.error.code === 'webhook_not_active')
              setMessages(['Only active webhooks can replay. Resume the webhook first.']);
          });
      }}
    >
      <FormErrorSummary messages={messages} />
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label htmlFor={`${id}-from`}>From (your time zone)</Label>
          <Input
            id={`${id}-from`}
            type="datetime-local"
            value={values.from}
            onChange={(e) => setValues({ ...values, from: e.target.value })}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-to`}>To (at most 72 hours later)</Label>
          <Input
            id={`${id}-to`}
            type="datetime-local"
            value={values.to}
            onChange={(e) => setValues({ ...values, to: e.target.value })}
          />
        </div>
      </div>
      <fieldset className="grid gap-2">
        <legend className="mb-1 text-sm font-medium">Original delivery status</legend>
        <div className="flex flex-wrap gap-4">
          {(['failed', 'dead', 'succeeded', 'cancelled'] as const).map((status) => (
            <div key={status} className="flex items-center gap-2">
              <Checkbox
                id={`${id}-${status}`}
                checked={values.statuses.includes(status)}
                onCheckedChange={(v) =>
                  setValues({
                    ...values,
                    statuses:
                      v === true
                        ? [...values.statuses, status]
                        : values.statuses.filter((s) => s !== status),
                  })
                }
              />
              <Label htmlFor={`${id}-${status}`} className="font-normal">
                {humanize(status)}
              </Label>
            </div>
          ))}
        </div>
      </fieldset>
      <fieldset className="grid gap-2">
        <legend className="mb-1 text-sm font-medium">
          Event types (empty: all of the webhook)
        </legend>
        <div className="flex flex-wrap gap-4">
          {webhook.eventTypes.map((type) => (
            <div key={type} className="flex items-center gap-2">
              <Checkbox
                id={`${id}-${type}`}
                checked={values.eventTypes.includes(type)}
                onCheckedChange={(v) =>
                  setValues({
                    ...values,
                    eventTypes:
                      v === true
                        ? [...values.eventTypes, type]
                        : values.eventTypes.filter((t) => t !== type),
                  })
                }
              />
              <Label htmlFor={`${id}-${type}`} className="font-mono text-xs font-normal">
                {type}
              </Label>
            </div>
          ))}
        </div>
      </fieldset>
      <MutationError error={create.error} />
      <p className="text-xs text-muted-foreground">
        Replays re-send the stored events (same event id) with a new delivery id and signature. Each
        event can be replayed at most 10 times.
      </p>
      <Button type="submit" className="justify-self-start" disabled={create.isPending}>
        Replay deliveries
      </Button>
    </form>
  );
}

/** Delivery history (`GET /webhooks/{id}/deliveries`, v1, range ≤ 31 days) with replays. */
export function WebhookDeliveries({ webhook }: { webhook: Webhook }) {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const [range] = useRangeState();
  const canReplay = useCan('WebhookDeliveriesController_replay_v1');
  const [detail, setDetail] = useState<WebhookDelivery | null>(null);
  const [replaying, setReplaying] = useState<WebhookDelivery | null>(null);
  const [bulk, setBulk] = useState(false);
  const [replayId, setReplayId] = useState<string | null>(null);
  const replay = useApiMutation('WebhookDeliveriesController_replay_v1', {
    invalidates: ['WebhookDeliveriesController_list_v1'],
    successMessage: 'Delivery replayed.',
  });
  const catalog = useApiQuery('WebhooksController_eventTypes_v1');
  const list = useCursorList(
    'WebhookDeliveriesController_list_v1',
    {
      from: range.from,
      to: range.to,
      ...(filters.dstatus ? { status: filters.dstatus } : {}),
      ...(filters.eventType ? { eventType: filters.eventType } : {}),
      ...(filters.trigger ? { trigger: filters.trigger } : {}),
      ...(filters.dsort ? { sort: filters.dsort } : {}),
    },
    { path: { webhookId: webhook.id } },
  );

  const columns = useMemo<DataTableColumn<WebhookDelivery>[]>(
    () => [
      {
        id: 'occurredAt',
        header: 'Event time',
        meta: { label: 'Event time' },
        cell: ({ row }) => <DateTime value={row.original.occurredAt} />,
      },
      {
        id: 'eventType',
        header: 'Event',
        meta: { label: 'Event' },
        cell: ({ row }) => <code className="font-mono text-xs">{row.original.eventType}</code>,
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => <WebhookDeliveryBadge status={row.original.status} />,
      },
      {
        id: 'trigger',
        header: 'Trigger',
        meta: { label: 'Trigger' },
        cell: ({ row }) => humanize(row.original.trigger),
      },
      {
        id: 'attempts',
        header: 'Attempts',
        meta: { label: 'Attempts', className: 'tabular-nums' },
        cell: ({ row }) => row.original.attemptCount,
      },
      {
        id: 'response',
        header: 'Last response',
        meta: { label: 'Last response' },
        cell: ({ row }) =>
          row.original.lastResponseCode ? (
            `HTTP ${row.original.lastResponseCode}`
          ) : (
            <span className="text-muted-foreground">None</span>
          ),
      },
      {
        id: 'latency',
        header: 'Latency',
        meta: { label: 'Latency', className: 'tabular-nums' },
        cell: ({ row }) =>
          formatDuration(row.original.lastLatencyMs) || (
            <span className="text-muted-foreground">None</span>
          ),
      },
      {
        id: 'error',
        header: 'Last error',
        meta: { label: 'Last error' },
        cell: ({ row }) => (
          <UntrustedText value={row.original.lastError} emptyLabel="None" maxLength={60} />
        ),
      },
    ],
    [],
  );
  const eventTypes = [...(catalog.data?.data ?? []).map((t) => t.type), 'webhook.ping'];

  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <RangePicker />
        <Can op="WebhookDeliveriesController_createReplay_v1">
          <Button variant="outline" size="sm" onClick={() => setBulk(true)}>
            <HistoryIcon aria-hidden />
            Replay a range
          </Button>
        </Can>
      </div>
      {replayId ? <ReplayProgress webhookId={webhook.id} replayId={replayId} /> : null}
      <DataTable
        tableId="webhook-deliveries"
        caption="Webhook deliveries"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `${row.eventType} at ${row.occurredAt}`}
        sort={{
          operationId: 'WebhookDeliveriesController_list_v1',
          columnId: 'occurredAt',
          value: filters.dsort,
          onChange: (dsort) => setFilters({ dsort: dsort as '-occurredAt' | undefined }),
        }}
        filters={
          <>
            <FilterSelect
              label="Delivery status"
              value={filters.dstatus}
              onChange={(dstatus) =>
                setFilters({ dstatus: dstatus as (typeof DELIVERY_STATUSES)[number] | undefined })
              }
              options={DELIVERY_STATUSES.map((s) => ({ value: s, label: humanize(s) }))}
            />
            <FilterSelect
              label="Event type"
              value={filters.eventType}
              onChange={(eventType) => setFilters({ eventType })}
              options={eventTypes.map((t) => ({ value: t, label: t }))}
            />
            <FilterSelect
              label="Trigger"
              value={filters.trigger}
              onChange={(trigger) =>
                setFilters({ trigger: trigger as (typeof DELIVERY_TRIGGERS)[number] | undefined })
              }
              options={DELIVERY_TRIGGERS.map((t) => ({ value: t, label: humanize(t) }))}
            />
          </>
        }
        isFiltered={Boolean(filters.dstatus || filters.eventType || filters.trigger)}
        onClearFilters={() =>
          setFilters({ dstatus: undefined, eventType: undefined, trigger: undefined })
        }
        rowActions={(row) => [
          { label: 'Details', onSelect: () => setDetail(row) },
          ...(canReplay && row.status !== 'pending'
            ? [{ label: 'Replay', onSelect: () => setReplaying(row) }]
            : []),
        ]}
        emptyState={
          <EmptyState
            icon={HistoryIcon}
            title="No deliveries in this range"
            description="Only events that occur while the webhook is active are delivered; choose another range."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <code className="font-mono text-xs">{row.eventType}</code>
            <span className="flex items-center gap-2">
              <WebhookDeliveryBadge status={row.status} />{' '}
              <DateTime value={row.occurredAt} className="text-xs" />
            </span>
          </div>
        )}
      />
      <FormDialog
        open={detail !== null}
        onOpenChange={(open) => !open && setDetail(null)}
        title="Delivery details"
        wide
      >
        {detail ? <DeliveryDetail webhookId={webhook.id} deliveryId={detail.id} /> : null}
      </FormDialog>
      <FormDialog open={bulk} onOpenChange={setBulk} title="Replay a range of deliveries" wide>
        <BulkReplay
          webhook={webhook}
          onStarted={(id) => {
            setReplayId(id);
            setBulk(false);
          }}
        />
      </FormDialog>
      <ConfirmDialog
        open={replaying !== null}
        onOpenChange={(open) => {
          if (!open) {
            setReplaying(null);
            replay.reset();
          }
        }}
        title="Replay this delivery?"
        description="The stored event is sent again with a new delivery id and signature. Receivers deduplicate by EG-Event-Id."
        confirmLabel="Replay"
        error={
          replay.error ? (
            <div className="grid gap-1">
              <MutationError error={replay.error} />
              {replay.error.code === 'webhook_event_expired' ? (
                <p className="text-xs text-muted-foreground">
                  The event is past retention (2 months) and can no longer be replayed.
                </p>
              ) : null}
              {replay.error.code === 'webhook_replay_limit' ? (
                <p className="text-xs text-muted-foreground">
                  This event has been replayed the maximum number of times.
                </p>
              ) : null}
            </div>
          ) : undefined
        }
        onConfirm={async () =>
          replaying
            ? (await replay.submit({ path: { webhookId: webhook.id, deliveryId: replaying.id } }))
                .ok
            : false
        }
      />
    </div>
  );
}
