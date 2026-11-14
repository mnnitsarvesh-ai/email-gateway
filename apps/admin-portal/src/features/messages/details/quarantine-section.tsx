'use client';

import { ChevronDownIcon, ChevronRightIcon } from 'lucide-react';
import Link from 'next/link';
import { useId, useState } from 'react';
import { DateTime, QuarantineStateBadge, RiskScore, SensitiveValue } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { humanize } from '@/lib/format';
import {
  EntryActionButtons,
  EntryHistory,
  OperatorDialogs,
  useEntryActions,
} from '@/features/quarantine/entry-detail';
import {
  EntryStateNotices,
  ReleaseOutcomeNotice,
  ReleasesList,
} from '@/features/quarantine/entry-parts';
import { approvalHref, entryHref } from '@/features/quarantine/links';
import { PreviewSection } from '@/features/quarantine/preview-panel';
import type { EntryAction, EntryDetailBody, ReleaseOutcome } from '@/features/quarantine/types';
import { CodeList, CursorPager, DetailList, Section } from '../controls';
import { NoData } from './parts';
import type { MessageDetailBody } from './summary-section';

type EntrySummary = ListItem<'QuarantineEntriesController_search_v1'>;

/**
 * The entries of a message (shared by the quarantine and audit sections: one cached search):
 * every entry of the message, any recipient and round, whenever it was quarantined. The search
 * gives `messageId` and no range, so the api reads the message's entries by its unique key
 * (§2 E13 as amended in §13 closer): a manual quarantine or a rescan long after receipt is
 * found too, whatever `QUARANTINE_SEARCH_MAX_RANGE_DAYS` is.
 */
export function useMessageEntries(message: MessageDetailBody, limit = 10) {
  return useCursorList(
    'QuarantineEntriesController_search_v1',
    { messageId: message.id },
    {
      limit,
      // Every search is audited (`quarantine.searched`): never refetched on focus.
      queryOptions: { refetchOnWindowFocus: false },
    },
  );
}

/** Section 13: quarantine actions (§2 E13), one card per recipient's entry. */
export function QuarantineSection({ message }: { message: MessageDetailBody }) {
  const list = useMessageEntries(message);
  const { isLoading, error, isFetching } = list.query;
  return (
    <Section
      title="Quarantine actions"
      description="One entry per recipient and round. Details, history and actions load when you open an entry (opening it is recorded in the audit log); the sanitized preview loads only when you ask for it."
    >
      {isLoading ? (
        <LoadingState label="Loading quarantine entries" rows={3} />
      ) : error && list.rows.length === 0 ? (
        <ErrorState error={error} onRetry={() => void list.query.refetch()} compact />
      ) : list.rows.length === 0 ? (
        <EmptyState
          title="No quarantine entry"
          description="No recipient's copy of this message is held in quarantine or review, in any scan round (an entry created in the last few seconds may take a moment to appear). No preview: message bodies are shown only as the sanitized preview of a quarantined copy (step 5.3)."
        />
      ) : (
        <div className="grid gap-3">
          <ul className="grid gap-3" aria-label="Quarantine entries of this message">
            {list.rows.map((entry) => (
              <EntryCard key={entry.id} entry={entry} />
            ))}
          </ul>
          <CursorPager
            label="Quarantine entries"
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
        </div>
      )}
    </Section>
  );
}

function EntryCard({ entry }: { entry: EntrySummary }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  return (
    <li className="grid gap-3 rounded-md border p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="grid min-w-0 gap-1">
          <span className="flex flex-wrap items-center gap-2">
            <QuarantineStateBadge state={entry.state} />
            <span className="text-sm font-medium">
              {entry.kind === 'review' ? 'Review' : 'Quarantine'} · {humanize(entry.reason)}
            </span>
            <span className="text-xs text-muted-foreground">round {entry.lifecycleRound}</span>
          </span>
          <span className="flex min-w-0 flex-wrap items-center gap-1 text-sm">
            <span className="text-xs text-muted-foreground">Recipient</span>
            <SensitiveValue
              value={entry.recipient}
              masked={entry.recipientMasked}
              kind="address"
              copy={!entry.recipientMasked}
              copyLabel="Copy recipient"
              explanation="Masked for your role: quarantine deciders and message:reveal holders see recipients of entries in clear (every read is audited)."
            />
          </span>
        </div>
        <Button
          variant="outline"
          size="sm"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={() => setOpen((value) => !value)}
        >
          {open ? <ChevronDownIcon aria-hidden /> : <ChevronRightIcon aria-hidden />}
          {open ? 'Hide details' : 'Details and actions'}
          <span className="sr-only"> for the entry of {entry.recipient}</span>
        </Button>
      </div>
      <DetailList
        items={[
          {
            label: 'Risk',
            value: <RiskScore score={entry.riskScore} level={entry.riskLevel} />,
          },
          { label: 'Primary engine', value: humanize(entry.primaryEngine) },
          { label: 'Hard blocks', value: <CodeList codes={entry.hardBlocks} /> },
          { label: 'Quarantined', value: <DateTime value={entry.quarantinedAt} mode="absolute" /> },
          { label: 'Expires', value: <DateTime value={entry.expiresAt} mode="absolute" /> },
          {
            label: 'Approval',
            value: entry.approvalRequestId ? (
              <Link
                href={approvalHref(entry.approvalRequestId)}
                className="text-primary underline-offset-2 hover:underline"
              >
                Open the approval request
              </Link>
            ) : (
              <span className="text-muted-foreground">None</span>
            ),
          },
        ]}
      />
      <div id={panelId}>{open ? <EntryExpanded entryId={entry.id} /> : null}</div>
    </li>
  );
}

/** The audited entry detail (`quarantine.entry_viewed`): loaded on expand, never on focus. */
function EntryExpanded({ entryId }: { entryId: string }) {
  const detail = useApiQuery(
    'QuarantineEntriesController_detail_v1',
    { path: { entryId } },
    { refetchOnWindowFocus: false },
  );
  if (detail.isLoading) return <LoadingState label="Loading the entry" rows={4} />;
  if (detail.error || !detail.data) {
    return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} compact />;
  }
  return <EntryActionsPanel entry={detail.data} />;
}

function EntryActionsPanel({ entry }: { entry: EntryDetailBody }) {
  const actions = useEntryActions(entry);
  const { preview, ...can } = actions;
  const [dialog, setDialog] = useState<EntryAction | null>(null);
  const [outcome, setOutcome] = useState<ReleaseOutcome | null>(null);
  const anyAction = Object.values(can).some(Boolean);
  return (
    <div className="grid gap-3 border-t pt-3">
      <div role="status" aria-live="polite">
        {outcome ? <ReleaseOutcomeNotice outcome={outcome} /> : null}
      </div>
      <EntryStateNotices entry={entry} />
      {anyAction ? (
        <div className="flex flex-wrap gap-2" role="group" aria-label="Entry actions">
          <EntryActionButtons can={actions} onAction={setDialog} />
        </div>
      ) : (
        <NoData>
          No action is available to you for this entry in its current state ({humanize(entry.state)}
          ).
        </NoData>
      )}
      <div className="grid gap-1 text-sm">
        <h4 className="text-xs font-medium text-muted-foreground">Why it is held</h4>
        <p className="whitespace-pre-wrap">{entry.explanation.text}</p>
        <CodeList codes={entry.reasonCodes} />
      </div>
      {preview ? (
        <PreviewSection entryId={entry.id} headingLevel={3} />
      ) : (
        <NoData>
          {entry.contentAvailable
            ? 'The sanitized preview is not available to you for this entry.'
            : 'No preview: the stored copy was purged.'}
        </NoData>
      )}
      <div className="grid gap-1">
        <h4 className="text-xs font-medium text-muted-foreground">Release attempts</h4>
        <ReleasesList releases={entry.releases} />
      </div>
      <div className="grid gap-1">
        <h4 className="text-xs font-medium text-muted-foreground">History</h4>
        <EntryHistory entryId={entry.id} />
      </div>
      <Link
        href={entryHref(entry.id)}
        className="text-xs text-primary underline-offset-2 hover:underline"
      >
        Open the quarantine entry page
      </Link>
      <OperatorDialogs
        entry={entry}
        dialog={dialog}
        onClose={() => setDialog(null)}
        onOutcome={setOutcome}
      />
    </div>
  );
}
