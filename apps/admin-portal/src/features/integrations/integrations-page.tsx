'use client';

import { CableIcon, KeyRoundIcon } from 'lucide-react';
import Link from 'next/link';
import { PageHeader } from '@/components/page-header';
import { UnavailableState } from '@/components/states/unavailable-state';
import { Button } from '@/components/ui/button';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { Section } from '@/features/domains/kit';
import { WebhooksSection } from './webhooks-section';

/**
 * `/integrations`: webhooks (full list), API keys and SMTP connectors (link cards), and the
 * honest unavailable states of the connectors later steps deliver.
 */
export function IntegrationsPage() {
  return (
    <RouteGate
      gate={[
        'WebhooksController_list_v1',
        'ApiKeysController_list_v1',
        'SmtpConnectorsController_list_v1',
      ]}
    >
      <Integrations />
    </RouteGate>
  );
}

function Integrations() {
  const canWebhooks = useCan('WebhooksController_list_v1');
  const canKeys = useCan('ApiKeysController_list_v1');
  const canConnectors = useCan('SmtpConnectorsController_list_v1');
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title="Integrations"
        description="Connect the gateway to your systems: webhooks for events, API keys for the REST API, SMTP connectors for relaying."
      />
      {canWebhooks ? <WebhooksSection /> : null}
      <div className="grid min-w-0 gap-6 md:grid-cols-2 [&>*]:min-w-0">
        {canKeys ? (
          <Section
            title="API keys"
            description="Keys for server-to-server access to the REST API, scoped to permissions you hold."
          >
            <Button asChild variant="outline" className="justify-self-start">
              <Link href="/integrations/api-keys">
                <KeyRoundIcon aria-hidden />
                Manage API keys
              </Link>
            </Button>
          </Section>
        ) : null}
        {canConnectors ? (
          <Section
            title="SMTP connectors"
            description="Let your own mail servers relay outbound mail through the gateway."
          >
            <Button asChild variant="outline" className="justify-self-start">
              <Link href="/mail-servers?tab=connectors">
                <CableIcon aria-hidden />
                Manage SMTP connectors
              </Link>
            </Button>
          </Section>
        ) : null}
        <UnavailableState
          step="8.2"
          title="Microsoft 365 and Google Workspace"
          description="API-based connectors for Microsoft 365 and Google Workspace mailboxes are not available yet."
        />
        <UnavailableState
          step="8.1"
          title="Archive and journaling"
          description="Journaling and compliance archive integrations are not available yet."
        />
      </div>
    </div>
  );
}
