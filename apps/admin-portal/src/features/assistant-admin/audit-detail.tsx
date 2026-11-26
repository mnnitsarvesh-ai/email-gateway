'use client';

import type { ReactNode } from 'react';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { DetailList } from '@/features/domains/kit';
import { decisionLabel } from '@/features/assistant/model';
import { sectionLabel } from '@/features/assistant/report-card';
import { useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { formatBytes, formatDuration, formatNumber, humanize } from '@/lib/format';
import { FEEDBACK_REASON_LABEL, KEY_SOURCE_LABEL, formatCostMicros, userLabel } from './model';

/**
 * The metadata-only audit of one conversation (design 34 D4, I24): `GET
 * /assistant/admin/conversations/{id}` only. Every field shown is named here; the view has no
 * title, message, card, transcript or report HTML field and never requests a content route
 * (messages, executions or reports of the owner).
 */

export type AuditConversation = SuccessBody<'AssistantAdminAuditController_conversation_v1'>;
type AuditTurn = AuditConversation['turns'][number];
export type AuditExecution = AuditConversation['executions'][number];
type AuditConfirmation = AuditConversation['confirmations'][number];
type AuditReport = AuditConversation['reports'][number];

const STATUS_TONE: Readonly<Record<string, Tone>> = {
  completed: 'success',
  succeeded: 'success',
  executed: 'success',
  available: 'success',
  sent: 'success',
  active: 'success',
  running: 'info',
  queued: 'info',
  pending: 'info',
  pending_confirmation: 'warning',
  executing: 'info',
  archived: 'neutral',
  cancelled: 'neutral',
  expired: 'neutral',
  purged: 'neutral',
  deleted: 'neutral',
  refused: 'warning',
  failed: 'danger',
  timeout: 'danger',
};

export function StatusBadge({ status }: { status: string }) {
  return <ToneBadge tone={STATUS_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

/**
 * The stored, already redacted parameters of a tool call as indented JSON text (React escapes
 * it; values that came from mail stay inert text).
 */
export function ParamsViewer({ value, label }: { value: unknown; label: string }) {
  if (value === null || value === undefined)
    return <span className="text-muted-foreground">None</span>;
  let text: string;
  try {
    text = JSON.stringify(value, null, 2) ?? 'null';
  } catch {
    text = 'The parameters cannot be shown.';
  }
  return (
    <details className="max-w-full text-xs">
      <summary className="cursor-pointer text-primary">{label}</summary>
      <pre className="mt-1 max-h-72 max-w-full overflow-auto rounded-md border bg-muted/40 p-2 font-mono break-words whitespace-pre-wrap">
        {text}
      </pre>
    </details>
  );
}

function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-xs break-all">{children}</span>;
}

function Table({
  caption,
  headers,
  children,
}: {
  caption: string;
  headers: readonly string[];
  children: ReactNode;
}) {
  return (
    <div className="max-w-full overflow-x-auto rounded-md border">
      <table className="w-full text-left text-xs">
        <caption className="sr-only">{caption}</caption>
        <thead className="bg-muted/50">
          <tr>
            {headers.map((header) => (
              <th key={header} scope="col" className="px-2 py-1.5 font-medium whitespace-nowrap">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y align-top">{children}</tbody>
      </table>
    </div>
  );
}

const td = 'px-2 py-1.5';

function Section({
  title,
  count,
  children,
}: {
  title: string;
  count: number;
  children: ReactNode;
}) {
  return (
    <section aria-label={title} className="grid gap-2">
      <h3 className="text-sm font-semibold">
        {title} <span className="font-normal text-muted-foreground">({count})</span>
      </h3>
      {count === 0 ? <p className="text-xs text-muted-foreground">None.</p> : children}
    </section>
  );
}

function TurnsTable({ turns }: { turns: readonly AuditTurn[] }) {
  return (
    <Table
      caption="Turns"
      headers={[
        '#',
        'Status',
        'Model',
        'Key',
        'Data sharing',
        'Prompt',
        'Tools',
        'Tokens',
        'Est. cost',
        'Latency',
        'Error',
        'Started',
      ]}
    >
      {turns.map((turn) => (
        <tr key={turn.seq}>
          <td className={td}>{turn.seq}</td>
          <td className={td}>
            <StatusBadge status={turn.status} />
          </td>
          <td className={td}>
            <Mono>
              {turn.provider} / {turn.model}
              {turn.fallbackFrom ? ` (fallback from ${turn.fallbackFrom})` : ''}
            </Mono>
          </td>
          <td className={td}>{KEY_SOURCE_LABEL[turn.keySource]}</td>
          <td className={td}>{humanize(turn.dataSharing)}</td>
          <td className={td}>
            <Mono>{turn.promptVersion}</Mono>
          </td>
          <td className={td}>
            {formatNumber(turn.toolCalls)} in {formatNumber(turn.rounds)} rounds
          </td>
          <td className={`${td} tabular-nums`}>
            {formatNumber(
              turn.tokens.input +
                turn.tokens.output +
                turn.tokens.cacheRead +
                turn.tokens.cacheWrite,
            )}
          </td>
          <td className={td}>{formatCostMicros(turn.costMicros)}</td>
          <td className={td}>{turn.latencyMs === null ? '—' : formatDuration(turn.latencyMs)}</td>
          <td className={td}>{turn.errorCode ? <Mono>{turn.errorCode}</Mono> : '—'}</td>
          <td className={td}>
            <DateTime value={turn.startedAt} mode="absolute" />
          </td>
        </tr>
      ))}
    </Table>
  );
}

export function ExecutionsTable({ executions }: { executions: readonly AuditExecution[] }) {
  return (
    <Table
      caption="Tool calls"
      headers={[
        '#',
        'Tool',
        'Operation',
        'Risk',
        'Decision',
        'Status',
        'HTTP',
        'Parameters',
        'Time',
      ]}
    >
      {executions.map((execution) => (
        <tr key={execution.id}>
          <td className={td}>
            {execution.seq}
            {execution.turnSeq !== null ? (
              <span className="block text-muted-foreground">turn {execution.turnSeq}</span>
            ) : null}
          </td>
          <td className={td}>
            <Mono>{execution.tool}</Mono>
            {execution.module ? (
              <span className="block text-muted-foreground">{execution.module}</span>
            ) : null}
          </td>
          <td className={td}>
            <Mono>
              {execution.method} {execution.operationId}
            </Mono>
          </td>
          <td className={td}>
            {humanize(execution.access)} · {humanize(execution.risk)}
          </td>
          <td className={td}>{decisionLabel(execution.decision)}</td>
          <td className={td}>
            <StatusBadge status={execution.status} />
            {execution.errorCode ? (
              <span className="mt-0.5 block">
                <Mono>{execution.errorCode}</Mono>
              </span>
            ) : null}
          </td>
          <td className={td}>{execution.httpStatus ?? '—'}</td>
          <td className={`${td} min-w-48`}>
            <ParamsViewer value={execution.paramsRedacted} label="Redacted parameters" />
            {execution.resourceRef ? (
              <span className="mt-0.5 block text-muted-foreground">
                Resource <Mono>{execution.resourceRef}</Mono>
              </span>
            ) : null}
          </td>
          <td className={td}>
            <DateTime value={execution.createdAt} mode="absolute" />
            <span className="block text-muted-foreground">
              {execution.latencyMs === null ? '' : formatDuration(execution.latencyMs)}
            </span>
            <span className="block">
              <Mono>{execution.correlationId}</Mono>
            </span>
          </td>
        </tr>
      ))}
    </Table>
  );
}

function ConfirmationsTable({ rows }: { rows: readonly AuditConfirmation[] }) {
  return (
    <Table
      caption="Confirmations"
      headers={['Operation', 'Risk', 'Re-authentication', 'Status', 'Created', 'Decided', 'Result']}
    >
      {rows.map((row) => (
        <tr key={row.id}>
          <td className={td}>
            <Mono>{row.operationId}</Mono>
          </td>
          <td className={td}>{humanize(row.risk)}</td>
          <td className={td}>{row.requiresReauth ? 'Required' : 'No'}</td>
          <td className={td}>
            <StatusBadge status={row.status} />
          </td>
          <td className={td}>
            <DateTime value={row.createdAt} mode="absolute" />
          </td>
          <td className={td}>
            <DateTime value={row.decidedAt} mode="absolute" emptyLabel="—" />
          </td>
          <td className={td}>
            {row.resultHttpStatus ?? '—'}
            {row.errorCode ? (
              <span className="block">
                <Mono>{row.errorCode}</Mono>
              </span>
            ) : null}
          </td>
        </tr>
      ))}
    </Table>
  );
}

function ReportsTable({ rows }: { rows: readonly AuditReport[] }) {
  return (
    <Table
      caption="Reports"
      headers={['Status', 'Period', 'Sections', 'Size', 'Background', 'Emails']}
    >
      {rows.map((row) => (
        <tr key={row.id}>
          <td className={td}>
            <StatusBadge status={row.status} />
            {row.errorCode ? (
              <span className="mt-0.5 block">
                <Mono>{row.errorCode}</Mono>
              </span>
            ) : null}
          </td>
          <td className={td}>
            <DateTime value={row.period.from} mode="absolute" /> –{' '}
            <DateTime value={row.period.to} mode="absolute" />
          </td>
          <td className={td}>
            {row.sections.map(sectionLabel).join(', ') || '—'}
            {row.omitted.length > 0 ? (
              <span className="block text-muted-foreground">
                Omitted: {row.omitted.map((entry) => sectionLabel(entry.section)).join(', ')}
              </span>
            ) : null}
          </td>
          <td className={td}>{row.sizeBytes === null ? '—' : formatBytes(row.sizeBytes)}</td>
          <td className={td}>
            {row.async ? `Yes (${row.jobStatus ? humanize(row.jobStatus) : 'unknown'})` : 'No'}
          </td>
          <td className={td}>
            {row.deliveries.length === 0
              ? 'None'
              : row.deliveries.map((delivery, index) => (
                  <span key={`${delivery.requestedAt}-${index}`} className="block">
                    {humanize(delivery.recipientKind)}
                    {delivery.recipientDomain ? ` @${delivery.recipientDomain}` : ''} ·{' '}
                    {humanize(delivery.status)}
                    {delivery.errorCode ? ` (${delivery.errorCode})` : ''}
                  </span>
                ))}
          </td>
        </tr>
      ))}
    </Table>
  );
}

/** The audit document as allow-listed sections (exported for tests). */
export function AuditConversationView({ data }: { data: AuditConversation }) {
  const confirmationCounts = Object.entries(data.totals.confirmations)
    .filter(([, count]) => count > 0)
    .map(([status, count]) => `${count} ${humanize(status).toLowerCase()}`)
    .join(', ');
  return (
    <div className="grid gap-5">
      <DetailList
        items={[
          {
            label: 'Person',
            value: `${userLabel(data.user)}${data.user.email && data.user.displayName ? ` (${data.user.email})` : ''}`,
          },
          { label: 'Conversation', value: <Mono>{data.id}</Mono> },
          { label: 'Status', value: <StatusBadge status={data.status} /> },
          { label: 'Created', value: <DateTime value={data.createdAt} mode="absolute" /> },
          {
            label: 'Last question',
            value: <DateTime value={data.lastTurnAt} mode="absolute" emptyLabel="None" />,
          },
          {
            label: 'Turns',
            value: `${formatNumber(data.turnCount)} in ${formatNumber(data.segmentCount)} segments`,
          },
          {
            label: 'Tokens',
            value: `${formatNumber(data.totals.tokens)} · estimated ${formatCostMicros(data.totals.estimatedCostMicros)}`,
          },
          {
            label: 'Tool calls',
            value: `${formatNumber(data.totals.toolCalls)} (${formatNumber(data.totals.deniedCalls)} refused)`,
          },
          { label: 'Confirmations', value: confirmationCounts || 'None' },
          { label: 'Reports', value: formatNumber(data.totals.reports) },
          {
            label: 'Ratings',
            value: `${data.totals.feedback.up} helpful, ${data.totals.feedback.down} not helpful`,
          },
          {
            label: 'Content',
            value: data.contentPurged ? 'Deleted after retention' : 'Kept (not shown here)',
          },
          ...(data.underPlatformOverride
            ? [
                {
                  label: 'Platform override',
                  value: 'Used by a platform operator in your organization',
                },
              ]
            : []),
        ]}
      />
      {data.truncated ? (
        <p className="text-xs text-muted-foreground">
          Long conversation: only the first 1,000 rows of each list are shown.
        </p>
      ) : null}
      <Section title="Turns" count={data.turns.length}>
        <TurnsTable turns={data.turns} />
      </Section>
      <Section title="Tool calls" count={data.executions.length}>
        <ExecutionsTable executions={data.executions} />
      </Section>
      <Section title="Confirmations" count={data.confirmations.length}>
        <ConfirmationsTable rows={data.confirmations} />
      </Section>
      <Section title="Reports" count={data.reports.length}>
        <ReportsTable rows={data.reports} />
      </Section>
      <Section title="Ratings" count={data.feedback.length}>
        <ul className="grid gap-1 text-xs">
          {data.feedback.map((entry) => (
            <li key={entry.messageId}>
              {entry.rating === 'up' ? 'Helpful' : 'Not helpful'}
              {entry.reason ? ` · ${FEEDBACK_REASON_LABEL[entry.reason]}` : ''} · answer{' '}
              <Mono>{entry.messageId}</Mono>
            </li>
          ))}
        </ul>
      </Section>
    </div>
  );
}

/** The drawer of one conversation's audit (`?conversation=<id>` on the audit tab). */
export function AuditConversationDrawer({
  conversationId,
  onClose,
}: {
  conversationId: string | null;
  onClose: () => void;
}) {
  const query = useApiQuery(
    'AssistantAdminAuditController_conversation_v1',
    { path: { conversationId: conversationId ?? '' } },
    { enabled: Boolean(conversationId), staleTime: 60_000, refetchOnWindowFocus: false },
  );
  return (
    <Sheet open={conversationId !== null} onOpenChange={(open) => (open ? undefined : onClose())}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-5xl">
        <SheetHeader>
          <SheetTitle>Conversation audit</SheetTitle>
          <SheetDescription>
            Metadata only: what was asked and answered is never shown to administrators.
          </SheetDescription>
        </SheetHeader>
        <div className="px-4 pb-6">
          {query.isLoading ? (
            <LoadingState label="Loading the conversation audit" rows={6} />
          ) : query.error ? (
            <ErrorState error={query.error} onRetry={() => void query.refetch()} />
          ) : query.data ? (
            <AuditConversationView data={query.data} />
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}
