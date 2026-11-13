'use client';

import Link from 'next/link';
import { z } from 'zod';
import { CopyableId } from '@/components/domain/copyable-id';
import { DateTime } from '@/components/domain/date-time';
import { PageHeader } from '@/components/page-header';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery } from '@/lib/api/hooks';
import { Can } from '@/lib/auth/can';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import { DestinationsEditor } from './destinations-editor';
import { DkimPanel } from './dkim-panel';
import { DnsRecordsPanel } from './dns-records';
import { DetailList, QueryView, Section, isUuid } from './kit';
import { NotFoundView } from '@/components/not-found-view';
import { DomainStatusBadge, type DomainDetail } from './model';
import { RecipientRegistrySection, RecipientValidationSection } from './recipients-panel';
import { DeleteDomainButton, DomainStatusActions } from './status-actions';
import { VerificationPanel } from './verification-panel';

const TABS = ['overview', 'dns', 'recipients', 'destinations'] as const;
const URL_SHAPE = { tab: z.enum(TABS).default('overview').catch('overview') };

function Overview({ domain }: { domain: DomainDetail }) {
  return (
    <div className="grid min-w-0 gap-6 lg:grid-cols-2 [&>*]:min-w-0">
      <Section title="Domain">
        <DetailList
          items={[
            { label: 'Status', value: <DomainStatusBadge status={domain.status} /> },
            {
              label: 'Reason',
              value: domain.statusReason ? humanize(domain.statusReason) : 'None',
            },
            {
              label: 'Name (ASCII)',
              value: <code className="font-mono text-xs">{domain.name}</code>,
            },
            { label: 'Domain ID', value: <CopyableId value={domain.id} label="domain ID" /> },
            {
              label: 'Mail flow',
              value: `Inbound ${domain.inboundEnabled ? 'enabled' : 'disabled'} · outbound ${domain.outboundEnabled ? 'enabled' : 'disabled'}`,
            },
            { label: 'Added', value: <DateTime value={domain.createdAt} mode="absolute" /> },
            {
              label: 'Verified',
              value: <DateTime value={domain.verifiedAt} mode="absolute" emptyLabel="Not yet" />,
            },
            {
              label: 'Activated',
              value: <DateTime value={domain.activatedAt} mode="absolute" emptyLabel="Not yet" />,
            },
            {
              label: 'Status changed',
              value: <DateTime value={domain.statusChangedAt} emptyLabel="Never" />,
            },
            { label: 'Last DNS check', value: <DateTime value={domain.lastCheckedAt} /> },
            {
              label: 'Next DNS check',
              value: <DateTime value={domain.nextCheckAt} emptyLabel="Not scheduled" />,
            },
          ]}
        />
        <div className="flex flex-wrap items-center gap-2">
          <DomainStatusActions domain={domain} />
          <DeleteDomainButton domain={domain} />
        </div>
      </Section>
      <Section
        title="Verification"
        description={
          domain.verification
            ? `Ownership TXT record at ${domain.verification.host}; the challenge expires on ${new Date(domain.verification.expiresAt).toUTCString()}.`
            : undefined
        }
      >
        <VerificationPanel domainId={domain.id} />
      </Section>
    </div>
  );
}

function DomainDetailContent({ domain }: { domain: DomainDetail }) {
  const [state, setState] = useUrlState(URL_SHAPE);
  const incomplete = domain.status !== 'active' && domain.status !== 'suspended';
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title={domain.unicodeName}
        breadcrumbs={[{ label: 'Domains', href: '/domains' }, { label: domain.unicodeName }]}
        description={
          <span className="inline-flex flex-wrap items-center gap-2">
            <DomainStatusBadge status={domain.status} />
            {domain.statusReason ? <span>{humanize(domain.statusReason)}</span> : null}
          </span>
        }
        actions={
          incomplete ? (
            <Can op="DomainsController_create_v1">
              <Button asChild variant="outline">
                <Link href={`/domains/onboarding?domainId=${domain.id}`}>Continue onboarding</Link>
              </Button>
            </Can>
          ) : null
        }
      />
      <Tabs
        value={state.tab}
        onValueChange={(tab) => setState({ tab: tab as (typeof TABS)[number] })}
      >
        <TabsList aria-label="Domain sections">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="dns">DNS records</TabsTrigger>
          <TabsTrigger value="recipients">Recipients</TabsTrigger>
          <TabsTrigger value="destinations">Destinations</TabsTrigger>
        </TabsList>
        <TabsContent value="overview" className="min-w-0">
          <Overview domain={domain} />
        </TabsContent>
        <TabsContent value="dns" className="grid min-w-0 gap-6 [&>*]:min-w-0">
          <Section title="DNS records">
            <DnsRecordsPanel domainId={domain.id} />
          </Section>
          <Section
            title="DKIM signing keys"
            description="Outbound mail is signed with the active key. Rotation needs the new record published first."
          >
            <DkimPanel domain={domain} />
          </Section>
        </TabsContent>
        <TabsContent value="recipients" className="grid min-w-0 gap-6 [&>*]:min-w-0">
          <RecipientValidationSection domainId={domain.id} />
          <RecipientRegistrySection domainId={domain.id} />
        </TabsContent>
        <TabsContent value="destinations" className="min-w-0">
          <Section
            title="Destination servers"
            description="Where approved inbound and internal mail of this domain is delivered."
          >
            <DestinationsEditor domainId={domain.id} />
          </Section>
        </TabsContent>
      </Tabs>
    </div>
  );
}

/** `/domains/[domainId]` (linked from the DNS alert e-mails): a foreign or unknown id is a 404. */
export function DomainDetailPage({ domainId }: { domainId: string }) {
  return (
    <RouteGate gate={['DomainsController_get_v1']}>
      <DomainDetailLoader domainId={domainId} />
    </RouteGate>
  );
}

function DomainDetailLoader({ domainId }: { domainId: string }) {
  const valid = isUuid(domainId);
  const domain = useApiQuery(
    'DomainsController_get_v1',
    { path: { id: domainId } },
    { retry: false, enabled: valid },
  );
  if (!valid) return <NotFoundView />;
  return (
    <QueryView query={domain} label="domain">
      {(data) => <DomainDetailContent domain={data} />}
    </QueryView>
  );
}
