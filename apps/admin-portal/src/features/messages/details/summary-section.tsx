'use client';

import {
  CopyableId,
  DateTime,
  DirectionBadge,
  RiskScore,
  SensitiveValue,
  UntrustedText,
  VerdictBadge,
} from '@/components/domain';
import { useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { formatBytes, formatNumber, humanize } from '@/lib/format';
import { DetailList, EnumBadge, Section, YesNo } from '../controls';
import { FINAL_ACTION_TONE, MESSAGE_STATUS_TONE } from '../semantic';
import { QueryBoundary } from './parts';
import { useRevealed } from './use-message-reveal';

export type MessageDetailBody = SuccessBody<'MessagesController_detail_v1'>;

/** The subject: masked for everyone, revealed by the page's audited reveal (ADR-0062). */
export function SubjectValue({ message }: { message: MessageDetailBody }) {
  const { values } = useRevealed();
  const revealed = values !== null && values.subject !== undefined;
  return (
    <SensitiveValue
      value={revealed ? values.subject : message.subject}
      masked={message.subjectMasked}
      revealed={revealed}
      maxLength={300}
      emptyLabel="(no subject)"
    />
  );
}

/** Section 1: message summary (`MessagesController_detail`, `MessageLifecycleController_lifecycle`). */
export function SummarySection({ message }: { message: MessageDetailBody }) {
  const m = message;
  return (
    <div className="grid gap-4">
      <Section
        title="Message summary"
        description="Metadata only: the message body and attachment content are never shown here."
      >
        <DetailList
          items={[
            { label: 'Subject', value: <SubjectValue message={m} /> },
            {
              label: 'Envelope sender',
              value: (
                <UntrustedText
                  value={m.envelopeFrom}
                  copy
                  copyLabel="Copy envelope sender"
                  emptyLabel="(null sender)"
                />
              ),
            },
            {
              label: 'Header From',
              value: (
                <UntrustedText
                  value={m.headerFrom}
                  copy
                  copyLabel="Copy header From"
                  emptyLabel="(none)"
                />
              ),
            },
            { label: 'Received', value: <DateTime value={m.receivedAt} mode="absolute" /> },
            { label: 'Direction', value: <DirectionBadge direction={m.direction} /> },
            {
              label: 'Status',
              value: (
                <span className="flex flex-wrap items-center gap-2">
                  <EnumBadge value={m.status} tones={MESSAGE_STATUS_TONE} />
                  <span className="text-xs text-muted-foreground">
                    since <DateTime value={m.statusChangedAt} />
                  </span>
                </span>
              ),
            },
            {
              label: 'Status reason',
              value: m.statusReason ? (
                <span className="font-mono text-xs">{m.statusReason}</span>
              ) : (
                <span className="text-muted-foreground">None</span>
              ),
            },
            { label: 'Final verdict', value: <VerdictBadge verdict={m.finalVerdict} /> },
            {
              label: 'Final action',
              value: (
                <EnumBadge value={m.finalAction} tones={FINAL_ACTION_TONE} emptyLabel="Pending" />
              ),
            },
            { label: 'Risk score', value: <RiskScore score={m.riskScore} /> },
            { label: 'Recipients', value: formatNumber(m.recipientCount) },
            { label: 'Attachments', value: formatNumber(m.attachmentCount) },
            { label: 'Size', value: formatBytes(m.sizeBytes) },
          ]}
        />
        <p className="text-xs text-muted-foreground">
          No preview here: message bodies are shown only as the sanitized preview of a quarantined
          copy (step 5.3), in the Quarantine actions section, after an explicit request.
        </p>
      </Section>
      <Section title="Identifiers and transport" headingLevel={3}>
        <DetailList
          items={[
            { label: 'Message ID', value: <CopyableId value={m.id} label="message ID" max={40} /> },
            {
              label: 'Internet Message-ID',
              value: (
                <UntrustedText
                  value={m.internetMessageId}
                  mono
                  copy
                  copyLabel="Copy Internet Message-ID"
                  emptyLabel="(none)"
                />
              ),
            },
            {
              label: 'Domain ID',
              value: m.domainId ? (
                <CopyableId value={m.domainId} label="domain ID" max={40} />
              ) : (
                <span className="text-muted-foreground">Not attributed to a domain</span>
              ),
            },
            { label: 'Lifecycle round', value: formatNumber(m.lifecycleRound) },
            { label: 'Version', value: formatNumber(m.version) },
            {
              label: 'Client IP',
              value: m.clientIp ? (
                <span className="font-mono text-xs">{m.clientIp}</span>
              ) : (
                <span className="text-muted-foreground">Unknown</span>
              ),
            },
            {
              label: 'Client HELO',
              value: <UntrustedText value={m.clientHelo} mono emptyLabel="Unknown" />,
            },
            {
              label: 'MTA queue ID',
              value: m.mtaQueueId ? (
                <CopyableId value={m.mtaQueueId} label="MTA queue ID" max={40} />
              ) : (
                <span className="text-muted-foreground">None</span>
              ),
            },
          ]}
        />
      </Section>
      <LifecycleBlock messageId={m.id} />
    </div>
  );
}

function LifecycleBlock({ messageId }: { messageId: string }) {
  const query = useApiQuery('MessageLifecycleController_lifecycle_v1', { path: { messageId } });
  return (
    <Section
      title="Lifecycle"
      headingLevel={3}
      description="The message's state machine (step 3.3): current state, parse result and recipient states."
    >
      <QueryBoundary query={query} label="Loading the lifecycle">
        {() => {
          const l = query.data;
          if (!l) return null;
          const byStatus = Object.entries(l.recipients.byStatus).filter(([, count]) => count > 0);
          return (
            <DetailList
              items={[
                {
                  label: 'State',
                  value: (
                    <span className="flex flex-wrap items-center gap-2">
                      <EnumBadge value={l.state} tones={MESSAGE_STATUS_TONE} />
                      <span className="text-xs text-muted-foreground">
                        since <DateTime value={l.statusChangedAt} />
                      </span>
                    </span>
                  ),
                },
                { label: 'Version', value: formatNumber(l.version) },
                { label: 'Lifecycle round', value: formatNumber(l.lifecycleRound) },
                {
                  label: 'MIME parse',
                  value: l.parse ? (
                    <span className="flex flex-wrap items-center gap-2">
                      <span>{humanize(l.parse.status)}</span>
                      {l.parse.completedAt ? (
                        <span className="text-xs text-muted-foreground">
                          <DateTime value={l.parse.completedAt} mode="absolute" />
                        </span>
                      ) : null}
                    </span>
                  ) : (
                    <span className="text-muted-foreground">No parse recorded</span>
                  ),
                },
                {
                  label: 'Recipients by status',
                  value:
                    byStatus.length === 0 ? (
                      <span className="text-muted-foreground">
                        {formatNumber(l.recipients.total)} recipients, no status recorded
                      </span>
                    ) : (
                      <ul
                        className="flex flex-wrap gap-2 text-xs"
                        aria-label="Recipients by status"
                      >
                        {byStatus.map(([status, count]) => (
                          <li key={status} className="rounded-sm bg-muted px-1.5 py-0.5">
                            {humanize(status)}: {formatNumber(count)}
                          </li>
                        ))}
                      </ul>
                    ),
                },
                {
                  label: 'Delivery sequence',
                  value:
                    l.deliverySeq === null ? (
                      <span className="text-muted-foreground">No delivery planned</span>
                    ) : (
                      formatNumber(l.deliverySeq)
                    ),
                },
                { label: 'Rescan possible now', value: <YesNo value={l.actions.rescan} /> },
                { label: 'Release possible now', value: <YesNo value={l.actions.release} /> },
              ]}
            />
          );
        }}
      </QueryBoundary>
    </Section>
  );
}
