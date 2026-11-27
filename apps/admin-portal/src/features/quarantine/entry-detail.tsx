'use client';

import {
  DownloadIcon,
  InboxIcon,
  SendIcon,
  ShieldXIcon,
  Trash2Icon,
  UserCheckIcon,
} from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { toast } from 'sonner';
import { DateTime, UntrustedText } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import { Section } from '@/features/messages/controls';
import { DownloadDialog } from './download-dialog';
import {
  EntryMetadata,
  EntryStateNotices,
  ReleaseOutcomeNotice,
  ReleasesList,
} from './entry-parts';
import { deleteBody, rejectBody, releaseBody, requestReleaseBody } from './forms';
import { CONTAINER_TEXT, isMailboxEntry, mailboxLocation } from './location';
import { PreviewSection } from './preview-panel';
import { ReasonConfirm } from './reason-confirm';
import type { EntryAction, EntryDetailBody, ReleaseOutcome } from './types';
import { useQuarantineCatalog } from './use-catalog';

/** Queries a quarantine mutation makes stale (entry, history, lists, summary, approvals). */
export const ENTRY_QUERIES = [
  'QuarantineEntriesController_detail_v1',
  'QuarantineEntriesController_history_v1',
  'QuarantineEntriesController_search_v1',
  'QuarantineToolsController_summary_v1',
  'QuarantineApprovalsController_list_v1',
] as const;

/** Codes after which the entry is reloaded (it changed since it was read: 409 row version / state). */
const RELOAD_CODES = new Set(['quarantine_version_conflict', 'quarantine_state_conflict']);

export interface EntryActionFlags {
  readonly release: boolean;
  readonly request_release: boolean;
  readonly reject: boolean;
  readonly delete: boolean;
  readonly download: boolean;
  readonly preview: boolean;
}

/** What the caller may do with an entry: its permission and the entry's `allowedActions`. */
export function useEntryActions(entry: EntryDetailBody): EntryActionFlags {
  const allowed = new Set<EntryAction>(entry.allowedActions);
  return {
    release: useCan('QuarantineEntriesController_release_v1') && allowed.has('release'),
    request_release:
      useCan('QuarantineEntriesController_requestRelease_v1') && allowed.has('request_release'),
    reject: useCan('QuarantineEntriesController_reject_v1') && allowed.has('reject'),
    delete: useCan('QuarantineEntriesController_delete_v1') && allowed.has('delete'),
    download: useCan('QuarantineEntriesController_grant_v1') && allowed.has('download'),
    preview: useCan('QuarantineEntriesController_preview_v1') && allowed.has('preview'),
  };
}

/** The action buttons of an entry (release, request release, download, reject, delete). */
export function EntryActionButtons({
  can,
  onAction,
  label,
  mailbox = false,
}: {
  can: EntryActionFlags;
  onAction: (action: EntryAction) => void;
  /** Appended to each button's accessible name when several entries share a page. */
  label?: string;
  /** A mailbox-located entry: its release is "Restore to inbox" (step API-2 R15). */
  mailbox?: boolean;
}) {
  const suffix = label ? ` ${label}` : '';
  const releaseLabel = mailbox ? 'Restore to inbox' : 'Release';
  return (
    <>
      {can.release ? (
        <Button
          size="sm"
          onClick={() => onAction('release')}
          aria-label={label ? `${releaseLabel}${suffix}` : undefined}
        >
          {mailbox ? <InboxIcon aria-hidden /> : <SendIcon aria-hidden />}
          {releaseLabel}
        </Button>
      ) : null}
      {can.request_release ? (
        <Button
          size="sm"
          variant="outline"
          onClick={() => onAction('request_release')}
          aria-label={label ? `Request release${suffix}` : undefined}
        >
          <UserCheckIcon aria-hidden />
          Request release
        </Button>
      ) : null}
      {can.download ? (
        <Button
          size="sm"
          variant="outline"
          onClick={() => onAction('download')}
          aria-label={label ? `Download${suffix}` : undefined}
        >
          <DownloadIcon aria-hidden />
          Download
        </Button>
      ) : null}
      {can.reject ? (
        <Button
          size="sm"
          variant="outline"
          onClick={() => onAction('reject')}
          aria-label={label ? `Reject${suffix}` : undefined}
        >
          <ShieldXIcon aria-hidden />
          Reject
        </Button>
      ) : null}
      {can.delete ? (
        <Button
          size="sm"
          variant="destructive"
          onClick={() => onAction('delete')}
          aria-label={label ? `Delete${suffix}` : undefined}
        >
          <Trash2Icon aria-hidden />
          Delete
        </Button>
      ) : null}
    </>
  );
}

/** Quarantine entry detail (`/quarantine/[entryId]`, §1.3 row 12). */
export function EntryDetail({ entryId }: { entryId: string }) {
  return (
    <RouteGate gate={['QuarantineEntriesController_detail_v1']}>
      <EntryDetailContent entryId={entryId} />
    </RouteGate>
  );
}

function EntryDetailContent({ entryId }: { entryId: string }) {
  // Each detail read is audited by the api (`quarantine.entry_viewed`): no refetch on focus.
  const detail = useApiQuery(
    'QuarantineEntriesController_detail_v1',
    { path: { entryId } },
    { refetchOnWindowFocus: false },
  );
  const breadcrumbs = [{ label: 'Quarantine', href: '/quarantine' }, { label: 'Entry' }];
  if (detail.isLoading) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Quarantine entry" breadcrumbs={breadcrumbs} />
        <LoadingState label="Loading the entry" rows={8} />
      </div>
    );
  }
  if (detail.error || !detail.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Quarantine entry" breadcrumbs={breadcrumbs} />
        <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />
      </div>
    );
  }
  return <EntryView entry={detail.data} breadcrumbs={breadcrumbs} />;
}

function EntryView({
  entry,
  breadcrumbs,
}: {
  entry: EntryDetailBody;
  breadcrumbs: { label: string; href?: string }[];
}) {
  const actions = useEntryActions(entry);
  const { preview: canPreview, ...can } = actions;
  const [dialog, setDialog] = useState<EntryAction | null>(null);
  const [outcome, setOutcome] = useState<ReleaseOutcome | null>(null);
  const anyAction = Object.values(can).some(Boolean);
  const mailbox = isMailboxEntry(entry);
  return (
    <div className="grid gap-4">
      <PageHeader
        title="Quarantine entry"
        breadcrumbs={breadcrumbs}
        description={
          mailbox
            ? "One recipient's message, moved in their mailbox by API-mode remediation. Actions apply to this recipient only."
            : "One recipient's copy of a held message. Actions apply to this recipient only."
        }
        actions={<EntryActionButtons can={actions} onAction={setDialog} mailbox={mailbox} />}
      />
      <div role="status" aria-live="polite">
        {outcome ? <ReleaseOutcomeNotice outcome={outcome} mailbox={mailbox} /> : null}
      </div>
      <EntryStateNotices entry={entry} />
      {!anyAction ? (
        <p className="text-sm text-muted-foreground">
          No action is available to you for this entry in its current state ({humanize(entry.state)}
          ).
        </p>
      ) : null}
      <EntryMetadata entry={entry} />
      {canPreview ? <PreviewSection entryId={entry.id} /> : null}
      <Section title="Release attempts">
        <ReleasesList releases={entry.releases} />
      </Section>
      <Section title="History" description="Every action on this entry, oldest first.">
        <EntryHistory entryId={entry.id} />
      </Section>
      <OperatorDialogs
        entry={entry}
        dialog={dialog}
        onClose={() => setDialog(null)}
        onOutcome={setOutcome}
      />
    </div>
  );
}

/** The actions recorded on an entry (`QuarantineEntriesController_history`), oldest first. */
export function EntryHistory({ entryId }: { entryId: string }) {
  const history = useApiQuery('QuarantineEntriesController_history_v1', { path: { entryId } });
  return (
    <>
      {history.isLoading ? (
        <LoadingState label="Loading the history" rows={4} />
      ) : history.error ? (
        <ErrorState error={history.error} onRetry={() => void history.refetch()} compact />
      ) : (history.data?.actions.length ?? 0) === 0 ? (
        <p className="text-sm text-muted-foreground">No actions recorded yet.</p>
      ) : (
        <ol className="grid gap-2" aria-label="Entry history">
          {history.data?.actions.map((action, index) => (
            <li
              key={`${action.at}-${index}`}
              className="grid gap-0.5 rounded-md border p-2 text-sm"
            >
              <span className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{humanize(action.action)}</span>
                {action.result ? (
                  <span className="font-mono text-xs text-muted-foreground">{action.result}</span>
                ) : null}
                <span className="text-xs text-muted-foreground">
                  by {humanize(action.actor.type)}
                  {action.actor.id ? ` ${action.actor.id}` : ''} · <DateTime value={action.at} />
                </span>
              </span>
              {action.reason ? (
                <span className="text-xs">
                  Reason: <UntrustedText value={action.reason} maxLength={512} />
                </span>
              ) : null}
            </li>
          ))}
        </ol>
      )}
    </>
  );
}

/**
 * The 7.1 operator dialogs of an entry (reason dialogs with one Idempotency-Key per intent,
 * reused by "Retry the same request"; the download grant). A `409` row-version or state conflict
 * reloads the entry. Used by the entry page and the details page's quarantine section.
 */
export function OperatorDialogs({
  entry,
  dialog,
  onClose,
  onOutcome,
}: {
  entry: EntryDetailBody;
  dialog: EntryAction | null;
  onClose: () => void;
  onOutcome: (outcome: ReleaseOutcome) => void;
}) {
  const catalog = useQuarantineCatalog();
  const queryClient = useQueryClient();
  const maxChars = catalog.data?.limits.reasonMaxChars;
  const path = { entryId: entry.id };
  /** Reloads the entry after a conflict, so the next attempt uses its current row version. */
  const reloading = async <T extends { ok: boolean; error?: { code: string } }>(
    outcome: Promise<T>,
  ): Promise<T> => {
    const result = await outcome;
    if (!result.ok && result.error && RELOAD_CODES.has(result.error.code)) {
      for (const id of ENTRY_QUERIES) await queryClient.invalidateQueries({ queryKey: [id] });
    }
    return result;
  };
  const release = useApiMutation('QuarantineEntriesController_release_v1', {
    invalidates: ENTRY_QUERIES,
    successMessage: null,
    onSuccess: (data) => onOutcome(data),
  });
  const request = useApiMutation('QuarantineEntriesController_requestRelease_v1', {
    invalidates: ENTRY_QUERIES,
    successMessage: null,
    onSuccess: (data) => onOutcome(data),
  });
  const reject = useApiMutation('QuarantineEntriesController_reject_v1', {
    invalidates: ENTRY_QUERIES,
    successMessage: 'Entry rejected.',
  });
  const remove = useApiMutation('QuarantineEntriesController_delete_v1', {
    invalidates: ENTRY_QUERIES,
    successMessage: null,
    onSuccess: (data) =>
      void toast.success(
        mailboxLocation(entry.location)
          ? "Entry deleted. The message is moved to the mailbox's deleted items unless it is already there."
          : data.purge === 'retained'
            ? 'Entry deleted. The stored copy is kept until retention or other recipients allow purging it.'
            : 'Entry deleted. The stored copy will be purged.',
      ),
  });
  const [notify, setNotify] = useState(true);
  const mailbox = mailboxLocation(entry.location);
  const canNotify = entry.direction !== 'inbound' && !mailbox;
  const open = (kind: EntryAction) => dialog === kind;
  const onOpenChange = (next: boolean) => {
    if (!next) onClose();
  };
  return (
    <>
      <ReasonConfirm
        open={open('release')}
        onOpenChange={onOpenChange}
        title={mailbox ? 'Restore this message to the inbox?' : 'Release this message?'}
        description={
          mailbox ? (
            <p>
              The message is moved from the mailbox ({CONTAINER_TEXT[mailbox.container]}) back to
              the Inbox of <UntrustedText value={entry.recipient} /> through the provider API;
              nothing is delivered again. If approval reasons apply (hard block, failed scan), an
              approval request is created instead.
            </p>
          ) : (
            <p>
              The message is re-validated against the current policy before delivery to{' '}
              <UntrustedText value={entry.recipient} />. If approval reasons apply (hard block,
              engine failure, review), an approval request is created instead.
            </p>
          )
        }
        confirmLabel={mailbox ? 'Restore to inbox' : 'Release'}
        maxChars={maxChars}
        pending={release.isPending}
        onSubmit={(reason) =>
          reloading(release.submit({ path, body: releaseBody(reason, entry.rowVersion) }))
        }
        onRetry={() => reloading(release.retry())}
      />
      <ReasonConfirm
        open={open('request_release')}
        onOpenChange={onOpenChange}
        title="Request a release?"
        description={<p>An approver reviews the request; you are notified of the decision.</p>}
        confirmLabel="Request release"
        maxChars={maxChars}
        pending={request.isPending}
        onSubmit={(reason) => reloading(request.submit({ path, body: requestReleaseBody(reason) }))}
        onRetry={() => reloading(request.retry())}
      />
      <ReasonConfirm
        open={open('reject')}
        onOpenChange={onOpenChange}
        title="Reject this message?"
        description={
          mailbox ? (
            <p>
              The entry is closed and the message stays where it is (
              {CONTAINER_TEXT[mailbox.container]}). This cannot be undone.
            </p>
          ) : (
            <p>
              The message is not delivered to <UntrustedText value={entry.recipient} />. This cannot
              be undone.
            </p>
          )
        }
        confirmLabel="Reject"
        destructive
        maxChars={maxChars}
        pending={reject.isPending}
        extra={
          canNotify ? (
            <div className="flex items-center gap-2">
              <Checkbox
                id={`${entry.id}-notify`}
                checked={notify}
                onCheckedChange={(value) => setNotify(value === true)}
              />
              <Label htmlFor={`${entry.id}-notify`}>
                Notify the sender (outbound and internal mail)
              </Label>
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              Senders of inbound mail are never notified (no backscatter).
            </p>
          )
        }
        onSubmit={(reason) =>
          reloading(
            reject.submit({
              path,
              body: rejectBody(reason, {
                notifySender: canNotify ? notify : undefined,
                rowVersion: entry.rowVersion,
              }),
            }),
          )
        }
        onRetry={() => reloading(reject.retry())}
      />
      <ReasonConfirm
        open={open('delete')}
        onOpenChange={onOpenChange}
        title="Delete this entry?"
        description={
          mailbox ? (
            <p>
              The entry is deleted and the message is moved to the mailbox&apos;s deleted items
              (recoverable by the user) unless it is already there. This cannot be undone.
            </p>
          ) : (
            <p>
              The entry is deleted and the stored message is purged when no retention, legal hold or
              other recipient needs it. This cannot be undone.
            </p>
          )
        }
        confirmLabel="Delete"
        destructive
        maxChars={maxChars}
        pending={remove.isPending}
        onSubmit={(reason) =>
          reloading(remove.submit({ path, body: deleteBody(reason, entry.rowVersion) }))
        }
        onRetry={() => reloading(remove.retry())}
      />
      <DownloadDialog entryId={entry.id} open={open('download')} onOpenChange={onOpenChange} />
    </>
  );
}
