'use client';

import { AlertTriangleIcon, CheckCircle2Icon, ClockIcon, LockIcon } from 'lucide-react';
import Link from 'next/link';
import type { ReactNode } from 'react';
import {
  CopyableId,
  DateTime,
  DirectionBadge,
  QuarantineStateBadge,
  RiskScore,
  UntrustedText,
} from '@/components/domain';
import { useCan } from '@/lib/auth/me';
import { formatBytes, formatNumber, humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge, Section } from '@/features/messages/controls';
import { messageHref } from '@/features/messages/links';
import { RISK_LEVEL_TONE } from '@/features/messages/semantic';
import { approvalHref, releaseHref } from './links';
import { RELEASE_STATUS_TONE } from './semantic';
import type { EntryDetailBody, ReleaseOutcome, ReleaseSummary, SelfEntryDetailBody } from './types';

type AnyDetail = EntryDetailBody | SelfEntryDetailBody;

/** Metadata of one entry (ids, addresses, reason, engines, risk, decisive rule); never content. */
export function EntryMetadata({ entry, self = false }: { entry: AnyDetail; self?: boolean }) {
  const canMessage = useCan('MessagesController_detail_v1');
  const canPolicy = useCan('PolicyManagementController_get_v1');
  return (
    <Section title="Entry">
      <DetailList
        items={[
          {
            label: 'Subject',
            value: (
              <UntrustedText
                value={entry.subject}
                maxLength={256}
                emptyLabel={self ? '(no subject)' : '(not shown: needs the preview permission)'}
              />
            ),
          },
          {
            label: 'Recipient',
            value: <UntrustedText value={entry.recipient} copy copyLabel="Copy recipient" />,
          },
          {
            label: 'Envelope sender',
            value: <UntrustedText value={entry.sender.envelope} emptyLabel="(null sender)" />,
          },
          {
            label: 'Header From',
            value: <UntrustedText value={entry.sender.headerFrom} emptyLabel="(none)" />,
          },
          { label: 'State', value: <QuarantineStateBadge state={entry.state} /> },
          { label: 'Reason', value: humanize(entry.reason) },
          {
            label: 'Kind',
            value:
              entry.kind === 'review' ? 'Review (the policy requires an approver)' : 'Quarantine',
          },
          { label: 'Origin', value: humanize(entry.origin) },
          { label: 'Direction', value: <DirectionBadge direction={entry.direction} /> },
          { label: 'Primary engine', value: humanize(entry.primaryEngine) },
          {
            label: 'Risk',
            value: (
              <span className="flex flex-wrap items-center gap-2">
                <RiskScore score={entry.riskScore} level={entry.riskLevel} />
                {entry.riskLevel ? (
                  <EnumBadge value={entry.riskLevel} tones={RISK_LEVEL_TONE} />
                ) : null}
              </span>
            ),
          },
          { label: 'Hard blocks', value: <CodeList codes={entry.hardBlocks} /> },
          {
            label: 'Decided by',
            hidden: self,
            value: entry.decisive.source ? (
              <span className="flex flex-wrap items-center gap-2 text-xs">
                <span>{humanize(entry.decisive.source)}</span>
                {entry.decisive.policyId ? (
                  canPolicy ? (
                    <Link
                      href={`/policies/${encodeURIComponent(entry.decisive.policyId)}`}
                      className="text-primary underline-offset-2 hover:underline"
                    >
                      Policy{entry.decisive.versionNo ? ` v${entry.decisive.versionNo}` : ''}
                    </Link>
                  ) : (
                    <CopyableId value={entry.decisive.policyId} label="policy ID" />
                  )
                ) : null}
                {entry.decisive.ruleId ? (
                  <span className="font-mono">rule {entry.decisive.ruleId}</span>
                ) : null}
              </span>
            ) : (
              <span className="text-muted-foreground">Not recorded</span>
            ),
          },
          { label: 'Received', value: <DateTime value={entry.receivedAt} mode="absolute" /> },
          { label: 'Quarantined', value: <DateTime value={entry.quarantinedAt} mode="absolute" /> },
          { label: 'Expires', value: <DateTime value={entry.expiresAt} mode="absolute" /> },
          {
            label: 'Attachments',
            value: entry.hasAttachments ? formatNumber(entry.attachmentCount) : 'None',
          },
          { label: 'Size', value: formatBytes(entry.sizeBytes) },
          {
            label: 'Content available',
            value: entry.contentAvailable ? 'Yes' : 'No (purged or not stored)',
          },
          { label: 'Entry ID', value: <CopyableId value={entry.id} label="entry ID" max={40} /> },
          {
            label: 'Message',
            hidden: self,
            value: canMessage ? (
              <Link
                href={messageHref(entry.messageId)}
                className="text-primary underline-offset-2 hover:underline"
              >
                Open message details
              </Link>
            ) : (
              <CopyableId value={entry.messageId} label="message ID" max={40} />
            ),
          },
          { label: 'Lifecycle round', value: formatNumber(entry.lifecycleRound), hidden: self },
        ]}
      />
      <div className="grid gap-2 border-t pt-3">
        <h3 className="text-xs font-medium text-muted-foreground">Why it is held</h3>
        <p className="text-sm whitespace-pre-wrap">{entry.explanation.text}</p>
        {entry.floorReasons.length > 0 ? (
          <div className="grid gap-1">
            <span className="text-xs text-muted-foreground">Strictness floor</span>
            <CodeList codes={entry.floorReasons} />
          </div>
        ) : null}
        {!self && entry.reasonCodes.length > 0 ? (
          <div className="grid gap-1">
            <span className="text-xs text-muted-foreground">Reason codes</span>
            <CodeList codes={entry.reasonCodes} />
          </div>
        ) : null}
      </div>
    </Section>
  );
}

function Notice({
  icon: Icon,
  tone,
  children,
}: {
  icon: typeof LockIcon;
  tone: 'warning' | 'info' | 'purple' | 'success';
  children: ReactNode;
}) {
  const classes = {
    warning: 'bg-tone-warning text-tone-warning-foreground',
    info: 'bg-tone-info text-tone-info-foreground',
    purple: 'bg-tone-purple text-tone-purple-foreground',
    success: 'bg-tone-success text-tone-success-foreground',
  }[tone];
  return (
    <div className={`flex items-start gap-2 rounded-md px-3 py-2 text-sm ${classes}`}>
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div>{children}</div>
    </div>
  );
}

/** Hard-block, approval and release states explained in words. */
export function EntryStateNotices({ entry, self = false }: { entry: AnyDetail; self?: boolean }) {
  const notices: ReactNode[] = [];
  if (entry.hardBlocks.length > 0) {
    notices.push(
      <Notice key="hb" icon={LockIcon} tone="warning">
        <strong>Hard block.</strong> The scan found {entry.hardBlocks.join(', ')}. A release needs
        an approver, and is refused when the organization does not allow releasing hard-blocked
        mail. Downloads are never possible.
      </Notice>,
    );
  }
  if (entry.state === 'pending_approval') {
    notices.push(
      <Notice key="approval" icon={ClockIcon} tone="purple">
        <strong>Waiting for approval.</strong>{' '}
        {entry.kind === 'review'
          ? 'The policy requires an approver before this message is delivered.'
          : 'A release was requested and needs an approver.'}{' '}
        {entry.approvalRequestId && !self ? (
          <Link href={approvalHref(entry.approvalRequestId)} className="font-medium underline">
            Open the approval request
          </Link>
        ) : null}
      </Notice>,
    );
  }
  if (entry.state === 'releasing') {
    notices.push(
      <Notice key="releasing" icon={ClockIcon} tone="info">
        <strong>Release queued.</strong> The release executor re-validates the message against the
        current policy and then delivers it; the entry changes to released when it ran.
      </Notice>,
    );
  }
  if (entry.state === 'released') {
    notices.push(
      <Notice key="released" icon={CheckCircle2Icon} tone="success">
        <strong>Released.</strong> The message was handed to delivery.
      </Notice>,
    );
  }
  if (entry.kind === 'review' && entry.state === 'held') {
    notices.push(
      <Notice key="review" icon={AlertTriangleIcon} tone="info">
        This entry was created by a policy that requires approval; releasing it creates an approval
        request.
      </Notice>,
    );
  }
  if (notices.length === 0) return null;
  return <div className="grid gap-2">{notices}</div>;
}

/** The result of a release or release request, with the link to follow it. */
export function ReleaseOutcomeNotice({
  outcome,
  self = false,
}: {
  outcome: ReleaseOutcome;
  self?: boolean;
}) {
  if (outcome.outcome === 'queued') {
    return (
      <Notice icon={CheckCircle2Icon} tone="success">
        <strong>Release queued.</strong> The release executor re-validates and delivers the message.{' '}
        {!self ? (
          <Link href={releaseHref(outcome.releaseId)} className="font-medium underline">
            Follow the release status
          </Link>
        ) : null}
      </Notice>
    );
  }
  return (
    <Notice icon={ClockIcon} tone="purple">
      <strong>Approval requested</strong>
      {outcome.approvalReasons.length > 0
        ? ` (${outcome.approvalReasons.map(humanize).join(', ')})`
        : ''}
      . An approver decides; you are notified of the decision.{' '}
      {!self ? (
        <Link href={approvalHref(outcome.approvalRequestId)} className="font-medium underline">
          Open the approval request
        </Link>
      ) : null}
    </Notice>
  );
}

export function ReleasesList({
  releases,
  linkReleases = true,
}: {
  releases: readonly ReleaseSummary[];
  linkReleases?: boolean;
}) {
  if (releases.length === 0)
    return <p className="text-sm text-muted-foreground">No release attempts.</p>;
  return (
    <ul className="grid gap-2" aria-label="Release attempts">
      {releases.map((release) => (
        <li
          key={release.id}
          className="flex flex-wrap items-center gap-2 rounded-md border p-2 text-sm"
        >
          <EnumBadge value={release.status} tones={RELEASE_STATUS_TONE} />
          <span>{humanize(release.mode)}</span>
          <span className="text-xs text-muted-foreground">
            requested <DateTime value={release.requestedAt} />
            {release.completedAt ? (
              <>
                {' '}
                · completed <DateTime value={release.completedAt} />
              </>
            ) : null}
          </span>
          {linkReleases ? (
            <Link href={releaseHref(release.id)} className="ml-auto text-xs text-primary underline">
              Release status
            </Link>
          ) : null}
        </li>
      ))}
    </ul>
  );
}
