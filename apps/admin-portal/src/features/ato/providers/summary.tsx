'use client';

import Link from 'next/link';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { formatNumber } from '@/lib/format';
import { DetailList, Section } from '@/features/messages/controls';
import type { AtoSettings } from '../model';
import { HealthBadge } from './components';
import { PROVIDER_LABELS, formatLag, providerHref, providersHref } from './model';

const HEALTH_ORDER = ['healthy', 'degraded', 'unhealthy', 'unknown'] as const;

/**
 * "Identity providers" monitoring card of the ATO dashboard (§7): integrations counted by health
 * and the worst stream lag, shown when the caller may list the integrations.
 */
export function IdentityProvidersCard() {
  const can = useCan('AtoProvidersController_list_v1');
  if (!can) return null;
  return <CardContent />;
}

function CardContent() {
  const list = useApiQuery('AtoProvidersController_list_v1');
  return (
    <Section
      title="Identity providers"
      description="Microsoft Entra ID / Microsoft 365 and Google Workspace telemetry for detection."
      actions={
        <Link
          href={providersHref}
          className="text-sm text-primary underline-offset-2 hover:underline"
        >
          Manage identity providers
        </Link>
      }
    >
      {list.isLoading ? (
        <LoadingState label="Loading identity providers" rows={2} />
      ) : list.error ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} compact />
      ) : !list.data || list.data.data.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No identity provider connected: detection sees only the gateway’s own sign-ins, SMTP
          authentication and outbound mail.
        </p>
      ) : (
        <DetailList
          items={[
            ...HEALTH_ORDER.map((health) => {
              const count = list.data.data.filter((p) => p.health.status === health).length;
              return {
                label:
                  health === 'unknown'
                    ? 'Not checked yet'
                    : `${health[0]!.toUpperCase()}${health.slice(1)}`,
                value: formatNumber(count),
                hidden: count === 0,
              };
            }),
            {
              label: 'Worst stream lag',
              value: formatLag(
                list.data.data.reduce<number | null>(
                  (worst, p) =>
                    p.streams.maxLagSeconds === null
                      ? worst
                      : Math.max(worst ?? 0, p.streams.maxLagSeconds),
                  null,
                ),
              ),
            },
          ]}
        />
      )}
    </Section>
  );
}

/**
 * "Identity providers" tab of `/ato/settings` (§7): the integrations of each provider with their
 * health (from `GET /ato/settings`) and a link to the identity-provider pages.
 */
export function IdentityProvidersSettingsSummary({ settings }: { settings: AtoSettings }) {
  const canList = useCan('AtoProvidersController_list_v1');
  const total = settings.identityProviders.reduce((sum, p) => sum + p.integrations.length, 0);
  return (
    <Section
      title="Identity providers"
      description="Provider sign-ins, risk events, OAuth consents, mailbox changes and provider-confirmed responses (revoke sessions, require MFA, suspend, remove forwarding)."
      actions={
        canList ? (
          <Button asChild size="sm" variant="outline">
            <Link href={providersHref}>Manage identity providers</Link>
          </Button>
        ) : null
      }
    >
      <ul className="grid gap-2" aria-label="Identity providers by provider">
        {settings.identityProviders.map((p) => (
          <li key={p.provider} className="grid gap-1 rounded-md border p-2 text-sm">
            <span className="font-medium">{PROVIDER_LABELS[p.provider]}</span>
            {p.integrations.length === 0 ? (
              <span className="text-muted-foreground">Not connected</span>
            ) : (
              <ul className="grid gap-1">
                {p.integrations.map((i) => (
                  <li key={i.id} className="flex flex-wrap items-center gap-2">
                    {canList ? (
                      <Link
                        href={providerHref(i.id)}
                        className="text-primary underline-offset-2 hover:underline"
                      >
                        Integration {i.id.slice(0, 8)}
                      </Link>
                    ) : (
                      <span>Integration {i.id.slice(0, 8)}</span>
                    )}
                    <HealthBadge status={i.health} />
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
      {total === 0 ? (
        <p className="text-xs text-muted-foreground">
          Connect a Microsoft 365 or Google Workspace connection with the account takeover
          permissions on the Identity providers page.
        </p>
      ) : null}
    </Section>
  );
}
