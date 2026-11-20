'use client';

import { ClockIcon, InfoIcon, ServerCrashIcon } from 'lucide-react';
import Link from 'next/link';
import { useId, useState, type ReactNode } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import type { DataTableColumn } from '@/components/data-table';
import {
  DateTime,
  DirectionBadge,
  RiskScore,
  SensitiveValue,
  UntrustedText,
  VerdictBadge,
} from '@/components/domain';
import { ToneBadge } from '@/components/domain/tone-badge';
import { FormErrorSummary } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { ApiError } from '@/lib/api/errors';
import { formatBytes } from '@/lib/format';
import { EnumBadge } from '@/features/messages/controls';
import type { RevealedArchiveValues } from './hooks';
import {
  CATEGORY_TONE,
  INGEST_SOURCE_LABEL,
  LOCK_TONE,
  RECORD_STATUS_TONE,
  archiveMessageHref,
  explainArchiveError,
  isRetryable,
  type ArchiveIngestSource,
  type ArchiveMessage,
} from './model';

/** A row of the archive lists: a search result or the `message` of an eDiscovery hit. */
export type ArchiveRow = ArchiveMessage;

/** Masked subject cell, or the revealed subject of this page view. */
export function ArchiveSubject({
  row,
  revealed,
}: {
  row: Pick<ArchiveRow, 'subject' | 'subjectMasked'>;
  revealed?: RevealedArchiveValues;
}) {
  if (revealed && revealed.subject !== undefined) {
    return (
      <SensitiveValue
        value={revealed.subject}
        masked={row.subjectMasked}
        revealed
        maxLength={90}
        emptyLabel="(no subject)"
      />
    );
  }
  if (!row.subjectMasked && !row.subject) {
    return <span className="text-muted-foreground">(no subject)</span>;
  }
  return <SensitiveValue value={row.subject} masked={row.subjectMasked} maxLength={90} />;
}

/** Masked recipients (`f***@example.com`), or the revealed addresses of this page view. */
export function ArchiveRecipients({
  row,
  revealed,
}: {
  row: Pick<ArchiveRow, 'recipients' | 'recipientsTruncated'>;
  revealed?: RevealedArchiveValues;
}) {
  if (revealed && revealed.recipients.size > 0) {
    return (
      <ul className="grid gap-0.5" aria-label="Recipients (revealed)">
        {[...revealed.recipients.entries()].map(([seq, address]) => (
          <li key={seq}>
            <SensitiveValue value={address} masked kind="address" revealed maxLength={60} />
          </li>
        ))}
      </ul>
    );
  }
  if (row.recipients.length === 0) return <span className="text-muted-foreground">None</span>;
  return (
    <ul className="grid gap-0.5" aria-label="Recipients (masked)">
      {row.recipients.slice(0, 3).map((address, index) => (
        <li key={`${address}-${index}`}>
          <SensitiveValue value={address} masked kind="address" maxLength={60} />
        </li>
      ))}
      {row.recipients.length > 3 || row.recipientsTruncated ? (
        <li className="text-xs text-muted-foreground">and more</li>
      ) : null}
    </ul>
  );
}

/** Columns of the archive search results (A17): masked by default, linked to the details. */
export function archiveColumns(
  revealed: ReadonlyMap<string, RevealedArchiveValues>,
): DataTableColumn<ArchiveRow>[] {
  return [
    {
      id: 'receivedAt',
      header: 'Received',
      meta: { label: 'Received', className: 'whitespace-nowrap', hideable: false },
      cell: ({ row }) => (
        <Link
          href={archiveMessageHref(row.original.messageId)}
          className="font-medium text-primary underline-offset-2 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          <DateTime value={row.original.receivedAt} />
          <span className="sr-only">, open archived message</span>
        </Link>
      ),
    },
    {
      id: 'direction',
      header: 'Direction',
      meta: { label: 'Direction' },
      cell: ({ row }) => <DirectionBadge direction={row.original.direction} />,
    },
    {
      id: 'from',
      header: 'From',
      meta: { label: 'From', className: 'min-w-48 max-w-64' },
      cell: ({ row }) => (
        <UntrustedText
          value={row.original.envelopeFrom}
          maxLength={60}
          emptyLabel="(null sender)"
        />
      ),
    },
    {
      id: 'recipients',
      header: 'Recipients',
      meta: { label: 'Recipients', className: 'min-w-48' },
      cell: ({ row }) => (
        <ArchiveRecipients row={row.original} revealed={revealed.get(row.original.messageId)} />
      ),
    },
    {
      id: 'subject',
      header: 'Subject',
      meta: { label: 'Subject', className: 'min-w-48 max-w-80' },
      cell: ({ row }) => (
        <ArchiveSubject row={row.original} revealed={revealed.get(row.original.messageId)} />
      ),
    },
    {
      id: 'category',
      header: 'Category',
      meta: { label: 'Category' },
      cell: ({ row }) => <EnumBadge value={row.original.category} tones={CATEGORY_TONE} />,
    },
    {
      // Step 8.6: gateway, journal intake, or both (merged copies of one message).
      id: 'ingestSources',
      header: 'Copies from',
      meta: { label: 'Copies from' },
      cell: ({ row }) => <IngestSourcesBadges sources={row.original.ingestSources} />,
    },
    {
      id: 'verdict',
      header: 'Verdict',
      meta: { label: 'Verdict' },
      cell: ({ row }) => (
        <span className="flex flex-wrap items-center gap-1">
          <VerdictBadge verdict={row.original.verdict} />
          {row.original.malicious ? (
            <EnumBadge value="malicious" tones={{ malicious: 'danger' }} />
          ) : null}
        </span>
      ),
    },
    {
      id: 'risk',
      header: 'Risk',
      meta: { label: 'Risk score' },
      cell: ({ row }) =>
        row.original.riskScore === null ? (
          <span className="text-muted-foreground">None</span>
        ) : (
          <RiskScore score={row.original.riskScore} />
        ),
    },
    {
      id: 'status',
      header: 'Record',
      meta: { label: 'Record status' },
      cell: ({ row }) => (
        <span className="flex flex-wrap items-center gap-1">
          <EnumBadge value={row.original.status} tones={RECORD_STATUS_TONE} />
          {row.original.legalHold ? <EnumBadge value="held" tones={{ held: 'warning' }} /> : null}
          {row.original.lockMode !== 'none' ? (
            <EnumBadge value={row.original.lockMode} tones={LOCK_TONE} />
          ) : null}
        </span>
      ),
    },
    {
      id: 'retainUntil',
      header: 'Retain until',
      meta: { label: 'Retain until', className: 'whitespace-nowrap' },
      cell: ({ row }) => <DateTime value={row.original.retainUntil} emptyLabel="None" />,
    },
    {
      id: 'attachments',
      header: 'Attachments',
      meta: { label: 'Attachments' },
      cell: ({ row }) => (
        <span className="text-xs">
          {row.original.attachmentCount}
          {row.original.attachmentNames.length > 0 ? (
            <span className="block max-w-48 truncate text-muted-foreground">
              <UntrustedText value={row.original.attachmentNames.join(', ')} maxLength={60} />
            </span>
          ) : null}
        </span>
      ),
    },
    {
      id: 'size',
      header: 'Size',
      meta: { label: 'Size', className: 'whitespace-nowrap' },
      cell: ({ row }) => formatBytes(row.original.sizeBytes),
    },
  ];
}

/** Mobile card of an archive row. */
export function ArchiveCard({
  row,
  revealed,
}: {
  row: ArchiveRow;
  revealed?: RevealedArchiveValues;
}) {
  return (
    <div className="grid gap-1 text-sm">
      <Link
        href={archiveMessageHref(row.messageId)}
        className="font-medium text-primary underline-offset-2 hover:underline"
      >
        <DateTime value={row.receivedAt} />
        <span className="sr-only">, open archived message</span>
      </Link>
      <UntrustedText value={row.envelopeFrom} maxLength={60} />
      <ArchiveSubject row={row} revealed={revealed} />
      <span className="flex flex-wrap gap-1">
        <DirectionBadge direction={row.direction} />
        <EnumBadge value={row.category} tones={CATEGORY_TONE} />
        <EnumBadge value={row.status} tones={RECORD_STATUS_TONE} />
        <IngestSourcesBadges sources={row.ingestSources} />
      </span>
    </div>
  );
}

/** Where a record's copies came from (step 8.6): words, never colour alone. */
export function IngestSourcesBadges({
  sources,
}: {
  sources: readonly ArchiveIngestSource[] | undefined;
}) {
  const list = sources && sources.length > 0 ? sources : (['gateway'] as const);
  return (
    <span className="flex flex-wrap items-center gap-1">
      {list.map((source) => (
        <ToneBadge key={source} tone={source === 'gateway' ? 'neutral' : 'info'}>
          {INGEST_SOURCE_LABEL[source]}
        </ToneBadge>
      ))}
    </span>
  );
}

/** A coloured notice (never colour alone: icon and words carry the meaning). */
export function Notice({
  tone = 'info',
  children,
  icon: Icon = InfoIcon,
}: {
  tone?: 'info' | 'warning' | 'danger';
  children: ReactNode;
  icon?: typeof InfoIcon;
}) {
  const classes =
    tone === 'warning'
      ? 'border-tone-warning bg-tone-warning text-tone-warning-foreground'
      : tone === 'danger'
        ? 'border-destructive/40 bg-tone-danger text-tone-danger-foreground'
        : 'bg-muted/40 text-muted-foreground';
  return (
    <div
      role="status"
      className={`flex items-start gap-2 rounded-md border px-3 py-2 text-xs ${classes}`}
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="grid gap-1">{children}</div>
    </div>
  );
}

/** The index-lag banner (A17 freshness: `X-EG-Index-Lag-Seconds`). */
export function IndexLagBanner({ seconds }: { seconds: number | null }) {
  if (seconds === null || seconds < 60) return null;
  const minutes = Math.round(seconds / 60);
  return (
    <Notice tone="warning" icon={ClockIcon}>
      <span>
        The search index is about{' '}
        {minutes < 60
          ? `${minutes} minute${minutes === 1 ? '' : 's'}`
          : `${Math.round(minutes / 60)} hour(s)`}{' '}
        behind: recently archived or changed records may be missing from the results. The archive
        itself (MySQL and the encrypted objects) is complete.
      </span>
    </Notice>
  );
}

/** `503 archive_search_unavailable`: the search is down, everything else keeps working. */
export function SearchUnavailable({ error, onRetry }: { error: ApiError; onRetry: () => void }) {
  return (
    <div role="alert" className="grid gap-2 rounded-lg border bg-card p-4 text-sm">
      <p className="flex items-center gap-2 font-semibold">
        <ServerCrashIcon className="size-4 text-destructive" aria-hidden />
        Archive search is temporarily unavailable
      </p>
      <p className="text-muted-foreground">
        The search index cannot be reached. Archived messages you open by link, their details,
        previews and downloads keep working from the archive itself.
      </p>
      <p className="text-xs text-muted-foreground">
        Code <span className="font-mono">{error.code}</span>
        {error.requestId ? (
          <>
            {' '}
            · Request ID <span className="font-mono">{error.requestId}</span>
          </>
        ) : null}
      </p>
      <Button variant="outline" size="sm" className="justify-self-start" onClick={onRetry}>
        Try again
      </Button>
    </div>
  );
}

/** A `429` with its countdown. */
export function RateLimited({ seconds, what = 'requests' }: { seconds: number; what?: string }) {
  return (
    <p role="alert" className="text-sm">
      {seconds > 0
        ? `Too many ${what} in the last minute. Try again in ${seconds} s.`
        : `Too many ${what} in the last minute. You can try again now.`}
    </p>
  );
}

/** An api error inside a dialog or panel: explained, with code and request id. */
export function ArchiveErrorSummary({ error }: { error: ApiError | null }) {
  if (!error) return null;
  return (
    <FormErrorSummary
      messages={[...explainArchiveError(error), `Code: ${error.code}`]}
      requestId={error.requestId}
    />
  );
}

/** Standard error state of a query, with the archive explanation on top for coded errors. */
export function ArchiveQueryError({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const explained =
    error instanceof ApiError && error.status !== 404 && error.code.includes('_')
      ? explainArchiveError(error)
      : [];
  return (
    <div className="grid gap-2">
      {explained.length > 0 && explained[0] !== (error as ApiError).messages[0] ? (
        <p className="text-sm">{explained.join(' ')}</p>
      ) : null}
      <ErrorState error={error} onRetry={onRetry} compact />
    </div>
  );
}

interface Outcome {
  readonly ok: boolean;
  readonly error?: ApiError;
}

/**
 * A confirmation with a required reason (audited actions: key rotation, disposal, hold release,
 * case close). Confirm submits a new intent (new Idempotency-Key); "Retry the same request"
 * repeats a failed intent with the same key.
 */
export function ReasonDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  destructive = false,
  maxChars = 1024,
  required = true,
  onSubmit,
  onRetry,
  pending = false,
  extra,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  maxChars?: number;
  required?: boolean;
  onSubmit: (reason: string) => Promise<Outcome>;
  onRetry?: () => Promise<Outcome>;
  pending?: boolean;
  extra?: ReactNode;
}) {
  const id = useId();
  const [reason, setReason] = useState('');
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<ApiError | null>(null);
  const reset = () => {
    setReason('');
    setFieldError(null);
    setApiError(null);
  };
  const handle = (outcome: Outcome) => {
    if (outcome.ok) {
      reset();
      return true;
    }
    setApiError(outcome.error ?? null);
    return false;
  };
  const confirm = async () => {
    const trimmed = reason.trim();
    if (required && !trimmed) {
      setFieldError('Enter a reason (it is recorded in the audit log)');
      return false;
    }
    if (trimmed.length > maxChars) {
      setFieldError(`Use at most ${maxChars} characters`);
      return false;
    }
    setFieldError(null);
    setApiError(null);
    return handle(await onSubmit(trimmed));
  };
  const retry = async () => {
    if (!onRetry) return;
    if (handle(await onRetry())) onOpenChange(false);
  };
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset();
        onOpenChange(next);
      }}
      title={title}
      description={description}
      confirmLabel={confirmLabel}
      destructive={destructive}
      pending={pending}
      onConfirm={confirm}
      error={
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor={id}>Reason{required ? ' (required)' : ' (optional)'}</Label>
            <Textarea
              id={id}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              maxLength={maxChars}
              rows={3}
              aria-invalid={fieldError ? true : undefined}
              aria-describedby={`${id}-help${fieldError ? ` ${id}-error` : ''}`}
            />
            <p id={`${id}-help`} className="text-xs text-muted-foreground">
              Recorded in the audit log (at most {maxChars} characters).
            </p>
            {fieldError ? (
              <p id={`${id}-error`} className="text-xs font-medium text-destructive">
                {fieldError}
              </p>
            ) : null}
          </div>
          {extra}
          {apiError ? (
            <div className="grid gap-2">
              <ArchiveErrorSummary error={apiError} />
              {onRetry && isRetryable(apiError) ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="justify-self-start"
                  disabled={pending}
                  onClick={() => void retry()}
                >
                  Retry the same request
                </Button>
              ) : null}
            </div>
          ) : null}
        </div>
      }
    />
  );
}

/**
 * The CAS conflict dialog (`409 *_conflict` with `currentRowVersion`): reload the current version
 * (discarding the edit) or overwrite it with the edit (resubmit against the current version).
 */
export function ConflictDialog({
  open,
  onOpenChange,
  what,
  onReload,
  onOverwrite,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  what: string;
  onReload: () => void;
  onOverwrite: () => Promise<unknown>;
}) {
  const [busy, setBusy] = useState(false);
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={`The ${what} changed`}
      description={
        <p>
          Someone else saved the {what} after you opened it. Reload to see their version (your edit
          is discarded), or overwrite their version with your edit.
        </p>
      }
      confirmLabel="Overwrite with my edit"
      pending={busy}
      onConfirm={async () => {
        setBusy(true);
        try {
          await onOverwrite();
        } finally {
          setBusy(false);
        }
      }}
      error={
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="justify-self-start"
          onClick={() => {
            onReload();
            onOpenChange(false);
          }}
        >
          Reload the current version
        </Button>
      }
    />
  );
}
