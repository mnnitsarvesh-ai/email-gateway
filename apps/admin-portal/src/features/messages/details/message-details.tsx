'use client';

import { RefreshCwIcon, ScanSearchIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo, useState, type ReactNode } from 'react';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery } from '@/lib/api/hooks';
import { Can } from '@/lib/auth/can';
import { useCan, usePermissions } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { scansHref } from '../links';
import { AuditSection } from './audit-section';
import { AttachmentsSection, UrlsSection } from './content-sections';
import { DeliverySection } from './delivery-section';
import { DlpSection } from './dlp-section';
import { HeadersSection } from './headers-section';
import { SectionForbidden } from './parts';
import { PeopleSection } from './people-section';
import { PhishingSection } from './phishing-section';
import { PolicySection } from './policy-section';
import { QuarantineSection } from './quarantine-section';
import { RescanDialog } from './rescan-dialog';
import { RevealButton, RevealStatus } from './reveal-panel';
import { RiskSection } from './risk-section';
import { RoundScope } from './rounds';
import { AuthenticationSection, SpamSection } from './scan-sections';
import { SectionNav } from './section-nav';
import {
  DETAIL_URL_SHAPE,
  SECTIONS,
  sectionAllowed,
  sectionById,
  type SectionId,
} from './sections';
import { SummarySection, type MessageDetailBody } from './summary-section';
import { MessageRevealContext, useMessageReveal } from './use-message-reveal';

const BREADCRUMBS = [{ label: 'Email explorer', href: '/messages' }, { label: 'Message' }];

/**
 * Email details (`/messages/[messageId]`, step 7.2 §2 E11): 14 lazily loaded, permission-gated
 * sections in the URL (`?section=`, `?round=`), the audited reveal of masked metadata, rescan
 * and the link to every scan round. No body or attachment content is fetched by any section.
 */
export function MessageDetails({ messageId }: { messageId: string }) {
  return (
    <RouteGate gate={['MessagesController_detail_v1']}>
      <DetailsContent messageId={messageId} />
    </RouteGate>
  );
}

function DetailsContent({ messageId }: { messageId: string }) {
  const detail = useApiQuery('MessagesController_detail_v1', { path: { messageId } });
  if (detail.isLoading) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Email details" breadcrumbs={BREADCRUMBS} />
        <LoadingState label="Loading message" rows={8} />
      </div>
    );
  }
  if (detail.error || !detail.data) {
    // 404 message_not_found: unknown and other organizations' ids look the same (P8).
    return (
      <div className="grid gap-4">
        <PageHeader title="Email details" breadcrumbs={BREADCRUMBS} />
        <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />
      </div>
    );
  }
  return <DetailsView message={detail.data} />;
}

function DetailsView({ message }: { message: MessageDetailBody }) {
  const [state, setState] = useUrlState(DETAIL_URL_SHAPE);
  const permissions = usePermissions();
  const reveal = useMessageReveal(message.id);
  const canReveal = useCan('MessageRevealController_reveal_v1');
  const [rescanOpen, setRescanOpen] = useState(false);
  const visible = useMemo(
    () => SECTIONS.filter((section) => sectionAllowed(section, permissions)),
    [permissions],
  );
  const active = sectionById(state.section);
  const allowed = sectionAllowed(active, permissions);
  const changeSection = (section: SectionId) => {
    const next = sectionById(section);
    // The round stays while moving between round-scoped sections.
    setState(
      { section, round: next.roundScoped && active.roundScoped ? state.round : undefined },
      { push: true },
    );
  };

  let panel: ReactNode;
  if (!allowed) {
    panel = <SectionForbidden section={active} />;
  } else {
    panel = <SectionPanel id={active.id} message={message} />;
    if (active.roundScoped) {
      panel = (
        <RoundScope
          messageId={message.id}
          round={state.round}
          onRoundChange={(round) => setState({ round })}
        >
          {panel}
        </RoundScope>
      );
    }
  }

  return (
    <MessageRevealContext.Provider value={reveal}>
      <div className="grid gap-4">
        <PageHeader
          title="Email details"
          breadcrumbs={BREADCRUMBS}
          description="Metadata and scan results of one message. Subjects, recipient addresses and To/Cc/Subject values are masked for every user; the message body is never shown here."
          actions={
            <>
              {canReveal ? <RevealButton /> : null}
              <Can op="MessageLifecycleController_rescan_v1">
                <Button variant="outline" size="sm" onClick={() => setRescanOpen(true)}>
                  <RefreshCwIcon aria-hidden />
                  Rescan
                </Button>
              </Can>
              <Can op="MessageScansController_scansOf_v1">
                <Button asChild variant="outline" size="sm">
                  <Link href={scansHref(message.id)}>
                    <ScanSearchIcon aria-hidden />
                    All scan rounds
                  </Link>
                </Button>
              </Can>
            </>
          }
        />
        <RevealStatus />
        <SectionNav sections={visible} active={active} allowed={allowed} onChange={changeSection}>
          {panel}
        </SectionNav>
        <RescanDialog message={message} open={rescanOpen} onOpenChange={setRescanOpen} />
      </div>
    </MessageRevealContext.Provider>
  );
}

/** The active section only (its queries run only while it is mounted). */
function SectionPanel({ id, message }: { id: SectionId; message: MessageDetailBody }) {
  switch (id) {
    case 'summary':
      return <SummarySection message={message} />;
    case 'people':
      return <PeopleSection message={message} />;
    case 'headers':
      return <HeadersSection messageId={message.id} />;
    case 'authentication':
      return <AuthenticationSection messageId={message.id} />;
    case 'spam':
      return <SpamSection />;
    case 'phishing':
      return <PhishingSection />;
    case 'urls':
      return <UrlsSection messageId={message.id} />;
    case 'attachments':
      return <AttachmentsSection messageId={message.id} />;
    case 'dlp':
      return <DlpSection messageId={message.id} />;
    case 'risk':
      return <RiskSection />;
    case 'policy':
      return <PolicySection messageId={message.id} />;
    case 'delivery':
      return <DeliverySection messageId={message.id} />;
    case 'quarantine':
      return <QuarantineSection message={message} />;
    case 'audit':
      return <AuditSection message={message} />;
  }
}
