'use client';

import { ScanSearchIcon, ShieldAlertIcon } from 'lucide-react';
import { z } from 'zod';
import Link from 'next/link';
import {
  CopyableId,
  DateTime,
  DirectionBadge,
  RiskScore,
  UntrustedText,
  VerdictBadge,
} from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { UnavailableState } from '@/components/states/unavailable-state';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery } from '@/lib/api/hooks';
import { Can } from '@/lib/auth/can';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatBytes, formatNumber } from '@/lib/format';
import { DetailList, EnumBadge, Section } from './controls';
import { scansHref } from './links';
import { FINAL_ACTION_TONE, MESSAGE_STATUS_TONE } from './semantic';

const DETAIL_TABS = ['recipients', 'deliveries', 'lifecycle', 'policy', 'risk'] as const;
const TAB_LABEL: Record<(typeof DETAIL_TABS)[number], string> = {
  recipients: 'Recipients',
  deliveries: 'Deliveries',
  lifecycle: 'Lifecycle history',
  policy: 'Policy evaluations',
  risk: 'Risk breakdown',
};
const DETAIL_URL_SHAPE = {
  tab: z.enum(DETAIL_TABS).default('recipients').catch('recipients'),
};

/** Email details (`/messages/[messageId]`, §1.3 row 10): the metadata summary of one message. */
export function MessageDetail({ messageId }: { messageId: string }) {
  return (
    <RouteGate gate={['MessagesController_detail_v1']}>
      <MessageDetailContent messageId={messageId} />
    </RouteGate>
  );
}

function MessageDetailContent({ messageId }: { messageId: string }) {
  const detail = useApiQuery('MessagesController_detail_v1', { path: { messageId } });
  const [state, setState] = useUrlState(DETAIL_URL_SHAPE);
  const breadcrumbs = [{ label: 'Email explorer', href: '/messages' }, { label: 'Message' }];

  if (detail.isLoading) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Email details" breadcrumbs={breadcrumbs} />
        <LoadingState label="Loading message" rows={8} />
      </div>
    );
  }
  if (detail.error || !detail.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Email details" breadcrumbs={breadcrumbs} />
        <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />
      </div>
    );
  }
  const m = detail.data;
  return (
    <div className="grid gap-4">
      <PageHeader
        title="Email details"
        breadcrumbs={breadcrumbs}
        description="Metadata only: the message body and attachment content are never shown here."
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <Link href={scansHref(m.id)}>
                <ScanSearchIcon aria-hidden />
                Security scan details
              </Link>
            </Button>
            <Can op="QuarantineEntriesController_search_v1">
              <Button asChild variant="outline" size="sm">
                <Link href={`/quarantine?messageId=${encodeURIComponent(m.id)}&range=30d`}>
                  <ShieldAlertIcon aria-hidden />
                  Quarantine entries
                </Link>
              </Button>
            </Can>
          </>
        }
      />
      <Section title="Summary">
        <DetailList
          items={[
            {
              label: 'Subject',
              value: <UntrustedText value={m.subject} maxLength={300} emptyLabel="(no subject)" />,
            },
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
      </Section>
      <Section title="Identifiers and transport">
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
      <Tabs
        value={state.tab}
        onValueChange={(tab) => setState({ tab: tab as typeof state.tab })}
        aria-label="Message detail views"
      >
        <TabsList>
          {DETAIL_TABS.map((tab) => (
            <TabsTrigger key={tab} value={tab}>
              {TAB_LABEL[tab]}
            </TabsTrigger>
          ))}
        </TabsList>
        {DETAIL_TABS.map((tab) => (
          <TabsContent key={tab} value={tab}>
            <UnavailableState
              step="7.2"
              title={TAB_LABEL[tab]}
              description={
                tab === 'policy' ? (
                  <>
                    Detailed view arrives in step 7.2. The stored policy evaluations are listed
                    today on the{' '}
                    <Link href={`${scansHref(m.id)}?tab=policy`} className="text-primary underline">
                      security scan details
                    </Link>
                    .
                  </>
                ) : (
                  'Detailed view arrives in step 7.2.'
                )
              }
            />
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
