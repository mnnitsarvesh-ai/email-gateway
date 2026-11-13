'use client';

import Link from 'next/link';
import { CopyableId, DateTime } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { useApiQuery } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge, Section } from '@/features/messages/controls';
import { DISPOSITION_TONE, RISK_LEVEL_TONE } from '@/features/messages/semantic';
import { approvalHref, entryHref } from './links';
import { RELEASE_STATUS_TONE } from './semantic';

/** Poll interval while the release executor has not run yet. */
export const RELEASE_POLL_MS = 5_000;

const STATUS_TEXT: Record<string, string> = {
  pending: 'Queued. Waiting for the release executor.',
  dispatched: 'Re-validated and handed to delivery.',
  delivered: 'Delivered.',
  failed: 'The release failed.',
  blocked_by_revalidation: 'Blocked: the re-validation no longer allows delivery.',
  approval_required: 'New approval reasons were found; a new approval request was created.',
  rescan_required: 'The verdict is stale; the message must be rescanned first.',
  refused: 'Refused (self-release no longer allowed or a hard block).',
  stale: 'Superseded by a later decision.',
  message_busy: 'The message was busy; the entry returned to held.',
};

/** Release status (`/quarantine/releases/[releaseId]`, linked from release e-mails). */
export function ReleaseStatus({ releaseId }: { releaseId: string }) {
  return (
    <RouteGate gate={['QuarantineToolsController_release_v1']}>
      <ReleaseStatusContent releaseId={releaseId} />
    </RouteGate>
  );
}

function ReleaseStatusContent({ releaseId }: { releaseId: string }) {
  const release = useApiQuery(
    'QuarantineToolsController_release_v1',
    { path: { releaseId } },
    {
      refetchInterval: (query) =>
        query.state.data?.status === 'pending' ? RELEASE_POLL_MS : false,
      refetchOnWindowFocus: false,
    },
  );
  const breadcrumbs = [{ label: 'Quarantine', href: '/quarantine' }, { label: 'Release' }];
  if (release.isLoading) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Release status" breadcrumbs={breadcrumbs} />
        <LoadingState label="Loading the release" rows={5} />
      </div>
    );
  }
  if (release.error || !release.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Release status" breadcrumbs={breadcrumbs} />
        <ErrorState error={release.error} onRetry={() => void release.refetch()} />
      </div>
    );
  }
  const r = release.data;
  const v = r.revalidation;
  return (
    <div className="grid gap-4">
      <PageHeader
        title="Release status"
        breadcrumbs={breadcrumbs}
        description="Releases are executed by the release executor (policy engine), which re-validates the message against the current policy before delivery."
      />
      <div role="status" aria-live="polite" className="flex flex-wrap items-center gap-2 text-sm">
        <EnumBadge value={r.status} tones={RELEASE_STATUS_TONE} />
        <span>{STATUS_TEXT[r.status] ?? humanize(r.status)}</span>
        {r.status === 'pending' ? (
          <span className="text-xs text-muted-foreground">
            Updates automatically every {RELEASE_POLL_MS / 1000} s.
          </span>
        ) : null}
      </div>
      <Section title="Release">
        <DetailList
          items={[
            { label: 'Mode', value: humanize(r.mode) },
            {
              label: 'Requested by',
              value: (
                <span>
                  {humanize(r.requestedBy.type)}
                  {r.requestedBy.id ? (
                    <span className="font-mono text-xs"> {r.requestedBy.id}</span>
                  ) : null}
                </span>
              ),
            },
            { label: 'Requested', value: <DateTime value={r.requestedAt} mode="absolute" /> },
            {
              label: 'Completed',
              value: <DateTime value={r.completedAt} mode="absolute" emptyLabel="Not yet" />,
            },
            {
              label: 'Delivered object',
              value: r.deliveredObject ? (
                humanize(r.deliveredObject)
              ) : (
                <span className="text-muted-foreground">Not yet</span>
              ),
            },
            {
              label: 'Approval request',
              value: r.approvalRequestId ? (
                <Link href={approvalHref(r.approvalRequestId)} className="text-primary underline">
                  Open the approval request
                </Link>
              ) : (
                <span className="text-muted-foreground">None</span>
              ),
            },
            { label: 'Release ID', value: <CopyableId value={r.id} label="release ID" max={40} /> },
          ]}
        />
      </Section>
      <Section title="Re-validation">
        {v ? (
          <DetailList
            items={[
              {
                label: 'Disposition',
                value: <EnumBadge value={v.disposition} tones={DISPOSITION_TONE} />,
              },
              {
                label: 'Decided by',
                value: (
                  <span className="text-xs">
                    {humanize(v.source)}
                    {v.decisiveRuleRef ? (
                      <span className="font-mono"> {v.decisiveRuleRef}</span>
                    ) : null}
                  </span>
                ),
              },
              {
                label: 'Risk level',
                value: (
                  <EnumBadge value={v.level} tones={RISK_LEVEL_TONE} emptyLabel="Not scored" />
                ),
              },
              { label: 'Hard blocks', value: <CodeList codes={v.hardBlocks} /> },
              { label: 'Floor reasons', value: <CodeList codes={v.floorReasons} /> },
              {
                label: 'Scan',
                value: v.scanCompletedAt ? (
                  <span className="text-xs">
                    completed <DateTime value={v.scanCompletedAt} />
                  </span>
                ) : (
                  <span className="text-muted-foreground">No completed scan</span>
                ),
              },
              {
                label: 'Policy generation',
                value: <span className="font-mono text-xs">{v.generation}</span>,
              },
            ]}
          />
        ) : (
          <p className="text-sm text-muted-foreground">Not re-validated yet.</p>
        )}
      </Section>
      <Section title={`Entries (${r.entryIds.length})`}>
        <ul className="grid gap-1 text-sm" aria-label="Released entries">
          {r.entryIds.map((id) => (
            <li key={id}>
              <Link href={entryHref(id)} className="font-mono text-xs text-primary underline">
                {id}
              </Link>
            </li>
          ))}
        </ul>
      </Section>
    </div>
  );
}
