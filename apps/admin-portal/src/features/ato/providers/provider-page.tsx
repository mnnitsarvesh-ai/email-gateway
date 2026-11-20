'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useId, useState } from 'react';
import { DateTime, ToneBadge } from '@/components/domain';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatNumber, humanize } from '@/lib/format';
import { isUuid } from '@/features/domains/kit';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import { DetailList, EnumBadge, Section } from '@/features/messages/controls';
import { AtoReasonDialog, ScrollRegion } from '../components';
import { ACTION_LABELS, labelOf } from '../model';
import {
  CapabilityBadge,
  CodeText,
  HealthBadge,
  IntegrationStatusBadge,
  MfaPrompt,
  PermissionNames,
  ProfileTable,
  ProviderErrorSummary,
  useMfaSession,
} from './components';
import {
  PROVIDER_LABELS,
  PROVIDER_QUERIES,
  STREAM_LABELS,
  STREAM_STATUS_TONE,
  connectionHref,
  explainProviderError,
  formatLag,
  providersHref,
  type ProviderDetail,
  type ProviderStream,
} from './model';
import { ProviderSettingsForm } from './settings-form';

export const PROVIDER_TABS: readonly TabDefinition[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'streams', label: 'Streams' },
  { id: 'actions', label: 'Actions' },
  { id: 'permissions', label: 'Permissions' },
  { id: 'settings', label: 'Settings' },
];

/** `/ato/providers/[integrationId]`: one identity-provider integration (step 8.5 §7). */
export function AtoProviderPage({ integrationId }: { integrationId: string }) {
  return (
    <RouteGate gate={['AtoProvidersController_get_v1']}>
      {isUuid(integrationId) ? <ProviderContent integrationId={integrationId} /> : <NotFoundView />}
    </RouteGate>
  );
}

function ProviderContent({ integrationId }: { integrationId: string }) {
  const query = useApiQuery(
    'AtoProvidersController_get_v1',
    { path: { integrationId } },
    { retry: false, refetchInterval: 30_000 },
  );
  if (query.isLoading) return <LoadingState label="Loading the identity provider" />;
  if (query.error instanceof ApiError && query.error.status === 404) return <NotFoundView />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  const data = query.data;
  if (!data) return null;
  const name = data.displayName ?? data.connection?.displayName ?? PROVIDER_LABELS[data.provider];
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title={name}
        breadcrumbs={[
          { label: 'Account takeover', href: '/ato' },
          { label: 'Identity providers', href: providersHref },
          { label: name },
        ]}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-muted-foreground">{PROVIDER_LABELS[data.provider]}</span>
            <IntegrationStatusBadge status={data.status} />
            <HealthBadge status={data.health.status} stale={data.health.stale} />
          </span>
        }
      />
      <GatedTabs
        tabs={PROVIDER_TABS}
        label="Identity provider details"
        keepParams={[]}
        render={(tab) => {
          switch (tab) {
            case 'streams':
              return <StreamsTab provider={data} />;
            case 'actions':
              return <ActionsTab provider={data} />;
            case 'permissions':
              return <PermissionsTab provider={data} />;
            case 'settings':
              return (
                <ProviderSettingsForm
                  provider={data}
                  sections="all"
                  onReload={() => void query.refetch()}
                />
              );
            default:
              return <OverviewTab provider={data} />;
          }
        }}
      />
    </div>
  );
}

type Dialog = 'pause' | 'remove' | null;

function OverviewTab({ provider: p }: { provider: ProviderDetail }) {
  const router = useRouter();
  const canConfigure = useCan('AtoProvidersController_pause_v1');
  const canSeeConnection = useCan('ProviderConnectionsController_get_v1');
  const mfa = useMfaSession();
  const [dialog, setDialog] = useState<Dialog>(null);
  const path = { integrationId: p.id };
  const pause = useApiMutation('AtoProvidersController_pause_v1', {
    invalidates: PROVIDER_QUERIES,
    successMessage: 'Identity provider paused',
  });
  const resume = useApiMutation('AtoProvidersController_resume_v1', {
    invalidates: PROVIDER_QUERIES,
    successMessage: 'Identity provider resumed',
  });
  const check = useApiMutation('AtoProvidersController_healthCheck_v1', {
    invalidates: PROVIDER_QUERIES,
    successMessage: 'Health check requested: the worker probes the provider within a minute',
  });
  const remove = useApiMutation('AtoProvidersController_remove_v1', {
    invalidates: PROVIDER_QUERIES,
    successMessage: 'Identity provider removed',
  });
  const removed = p.status === 'disabled';
  const lastError = resume.error ?? check.error;
  return (
    <div className="grid min-w-0 gap-4">
      <Section
        title="Status"
        description="The worker checks the provider’s permissions, licences and directory every health interval."
        actions={
          canConfigure && !removed ? (
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={check.isPending}
                onClick={() => void check.submit({ path })}
              >
                Check now
              </Button>
              {p.status === 'paused' ? (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={resume.isPending}
                  onClick={() => void resume.submit({ path })}
                >
                  Resume
                </Button>
              ) : (
                <Button size="sm" variant="outline" onClick={() => setDialog('pause')}>
                  Pause
                </Button>
              )}
              <Button
                size="sm"
                variant="destructive"
                disabled={!mfa}
                onClick={() => setDialog('remove')}
              >
                Remove
              </Button>
            </div>
          ) : null
        }
      >
        <DetailList
          items={[
            { label: 'Status', value: <IntegrationStatusBadge status={p.status} /> },
            {
              label: 'Paused because',
              value: <CodeText code={p.pausedReason} />,
              hidden: p.status !== 'paused',
            },
            {
              label: 'Removed',
              value: (
                <span>
                  <DateTime value={p.disabledAt} /> · <CodeText code={p.disabledReason} />
                </span>
              ),
              hidden: !removed,
            },
            {
              label: 'Health',
              value: (
                <span className="grid gap-1">
                  <HealthBadge status={p.healthDetail.status} stale={p.healthDetail.stale} />
                  {p.healthDetail.code ? <CodeText code={p.healthDetail.code} /> : null}
                </span>
              ),
            },
            {
              label: 'Last health check',
              value: <DateTime value={p.healthDetail.checkedAt} emptyLabel="Never" />,
            },
            {
              label: 'Next health check',
              value: <DateTime value={p.healthDetail.nextCheckAt} emptyLabel="Not scheduled" />,
            },
            {
              label: 'Connection',
              value: p.connection ? (
                <span className="flex flex-wrap items-center gap-2">
                  {canSeeConnection && p.connection.status !== 'missing' ? (
                    <Link
                      href={connectionHref(p.connection.id)}
                      className="text-primary underline-offset-2 hover:underline"
                    >
                      {p.connection.displayName}
                    </Link>
                  ) : (
                    <span>{p.connection.displayName}</span>
                  )}
                  <EnumBadge
                    value={p.connection.status}
                    tones={{ active: 'success', error: 'danger', missing: 'danger' }}
                  />
                </span>
              ) : (
                'None'
              ),
            },
            {
              label: 'Linked directory domains',
              value: formatNumber(p.directory.domainCount),
            },
            {
              label: 'Grants',
              value:
                p.healthDetail.grants.length > 0 ? (
                  <ul className="grid gap-1">
                    {p.healthDetail.grants.map((g) => (
                      <li key={g.profile} className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs">{g.profile}</span>
                        <EnumBadge
                          value={g.status}
                          tones={{ active: 'success', pending: 'info', absent: 'neutral' }}
                        />
                        {g.missingPermissions.length > 0 ? (
                          <span className="text-xs text-destructive">
                            missing {g.missingPermissions.join(', ')}
                          </span>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                ) : (
                  'Not checked yet'
                ),
            },
            { label: 'Connected', value: <DateTime value={p.createdAt} mode="absolute" /> },
          ]}
        />
        {canConfigure && !removed && !mfa ? <MfaPrompt action="Removing" /> : null}
        {lastError ? <ProviderErrorSummary error={lastError} /> : null}
      </Section>
      <AtoReasonDialog
        open={dialog === 'pause'}
        onOpenChange={(open) => setDialog(open ? 'pause' : null)}
        title="Pause the identity provider?"
        description="Polling and health checks stop until you resume; provider actions of this integration fail while it is paused. Mail flow is not affected."
        confirmLabel="Pause"
        minChars={3}
        maxChars={512}
        explain={explainProviderError}
        pending={pause.isPending}
        onSubmit={(reason) => pause.submit({ path, body: { reason: reason ?? '' } })}
        onRetry={pause.retry}
      />
      <AtoReasonDialog
        open={dialog === 'remove'}
        onOpenChange={(open) => setDialog(open ? 'remove' : null)}
        title="Remove the identity provider?"
        description="Account takeover detection stops reading this directory, and pending provider actions of this integration end as failed. The Microsoft 365 / Google Workspace connection itself stays (manage it in Integrations)."
        confirmLabel="Remove"
        destructive
        minChars={3}
        maxChars={512}
        explain={explainProviderError}
        pending={remove.isPending}
        onSubmit={async (reason) => {
          const outcome = await remove.submit({ path, body: { reason: reason ?? '' } });
          if (outcome.ok) router.push(providersHref);
          return outcome;
        }}
        onRetry={remove.retry}
      />
    </div>
  );
}

function StreamsTab({ provider: p }: { provider: ProviderDetail }) {
  const canBackfill = useCan('AtoProvidersController_backfill_v1');
  const [open, setOpen] = useState(false);
  const streams = p.streamDetails.filter((s) => s.role !== 'unsupported');
  const unsupported = p.streamDetails.filter((s) => s.role === 'unsupported');
  return (
    <Section
      title="Streams"
      description="What the worker reads from the provider, how far it is behind (lag) and the last results. Companion streams are read together with their primary stream."
      actions={
        canBackfill && p.status !== 'disabled' ? (
          <Button size="sm" variant="outline" onClick={() => setOpen(true)}>
            Backfill
          </Button>
        ) : null
      }
    >
      <ScrollRegion label="Streams of the identity provider">
        <table className="w-full min-w-[60rem] text-left text-sm">
          <caption className="sr-only">Streams of the identity provider</caption>
          <thead className="bg-muted/50 text-xs text-muted-foreground">
            <tr>
              {[
                'Stream',
                'Enabled',
                'Status',
                'Availability',
                'Watermark',
                'Lag',
                'Last event',
                'Last success',
                'Last error',
                'Failures',
                'Throttled until',
                'Backfill',
              ].map((h) => (
                <th key={h} scope="col" className="px-2 py-1.5 font-medium whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {streams.map((s) => (
              <tr key={s.stream} className="border-t align-top">
                <th scope="row" className="px-2 py-1.5 font-normal">
                  <span className="font-medium">{STREAM_LABELS[s.stream]}</span>
                  <span className="block text-xs text-muted-foreground">
                    {s.role === 'companion' && s.primary
                      ? `With ${STREAM_LABELS[s.primary].toLowerCase()}`
                      : 'Primary'}
                  </span>
                </th>
                <td className="px-2 py-1.5">{s.enabled ? 'Yes' : 'No'}</td>
                <td className="px-2 py-1.5">
                  <ToneBadge tone={STREAM_STATUS_TONE[s.status] ?? 'neutral'}>
                    {humanize(s.status)}
                  </ToneBadge>
                </td>
                <td className="px-2 py-1.5">
                  <CapabilityBadge value={s.capability} />
                  {s.availabilityCode ? (
                    <span className="block text-xs text-muted-foreground">
                      <CodeText code={s.availabilityCode} />
                    </span>
                  ) : null}
                </td>
                <td className="px-2 py-1.5 whitespace-nowrap">
                  <DateTime value={s.watermarkAt} emptyLabel="—" />
                </td>
                <td className="px-2 py-1.5 whitespace-nowrap">{formatLag(s.lagSeconds)}</td>
                <td className="px-2 py-1.5 whitespace-nowrap">
                  <DateTime value={s.lastEventAt} emptyLabel="None" />
                </td>
                <td className="px-2 py-1.5 whitespace-nowrap">
                  <DateTime value={s.lastSuccessAt} emptyLabel="Never" />
                </td>
                <td className="px-2 py-1.5">
                  <CodeText code={s.lastErrorCode} />
                </td>
                <td className="px-2 py-1.5 tabular-nums">{s.consecutiveFailures}</td>
                <td className="px-2 py-1.5 whitespace-nowrap">
                  <DateTime value={s.throttledUntil} emptyLabel="—" />
                </td>
                <td className="px-2 py-1.5">
                  {s.backfill.active ? (
                    <span className="grid gap-0.5">
                      <ToneBadge tone="info">Running</ToneBadge>
                      <span className="text-xs text-muted-foreground">
                        from <DateTime value={s.backfill.from} mode="absolute" />
                      </span>
                    </span>
                  ) : s.backfill.completedAt ? (
                    <span className="text-xs">
                      Completed <DateTime value={s.backfill.completedAt} />
                    </span>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </ScrollRegion>
      {unsupported.length > 0 ? (
        <p className="text-xs text-muted-foreground">
          Not offered by {PROVIDER_LABELS[p.provider]}:{' '}
          {unsupported.map((s) => STREAM_LABELS[s.stream]).join(', ')}.
        </p>
      ) : null}
      <p className="text-xs text-muted-foreground">
        Events processed: {formatNumber(p.streamDetails.reduce((sum, s) => sum + s.eventsTotal, 0))}{' '}
        in {formatNumber(p.streamDetails.reduce((sum, s) => sum + s.pagesTotal, 0))} pages.
      </p>
      {canBackfill ? <BackfillDialog provider={p} open={open} onOpenChange={setOpen} /> : null}
    </Section>
  );
}

function BackfillDialog({
  provider: p,
  open,
  onOpenChange,
}: {
  provider: ProviderDetail;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const daysId = useId();
  const primaries = p.streamDetails.filter((s) => s.role === 'primary' && s.enabled);
  const [days, setDays] = useState('7');
  const [chosen, setChosen] = useState<ProviderStream[]>([]);
  const backfill = useApiMutation('AtoProvidersController_backfill_v1', {
    invalidates: PROVIDER_QUERIES,
    successMessage: 'Backfill requested',
  });
  const n = Number(days);
  const daysOk = days.trim() !== '' && Number.isInteger(n) && n >= 1 && n <= 30;
  return (
    <AtoReasonDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Backfill history"
      description="The worker reads the selected streams again from the start date in historical mode: signals are informational and baselines learn, but no incident or alert is raised. Duplicates are skipped."
      confirmLabel="Start backfill"
      required={false}
      minChars={1}
      reasonLabel="Note"
      explain={explainProviderError}
      disabled={!daysOk}
      pending={backfill.isPending}
      extra={
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor={daysId}>Days back</Label>
            <Input
              id={daysId}
              type="number"
              inputMode="numeric"
              className="w-32"
              min={1}
              max={30}
              value={days}
              aria-invalid={daysOk ? undefined : true}
              onChange={(e) => setDays(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              1–30 days, limited by the provider’s retention (the api refuses a start outside it).
            </p>
          </div>
          <fieldset className="grid gap-1.5">
            <legend className="text-sm font-medium">Streams (none selected = every enabled)</legend>
            {primaries.map((s) => {
              const id = `backfill-${s.stream}`;
              return (
                <div key={s.stream} className="flex items-center gap-2">
                  <Checkbox
                    id={id}
                    checked={chosen.includes(s.stream)}
                    onCheckedChange={(checked) =>
                      setChosen((prev) =>
                        checked === true ? [...prev, s.stream] : prev.filter((x) => x !== s.stream),
                      )
                    }
                  />
                  <Label htmlFor={id} className="text-sm font-normal">
                    {STREAM_LABELS[s.stream]}
                  </Label>
                </div>
              );
            })}
          </fieldset>
        </div>
      }
      onSubmit={() => {
        const from = new Date(Date.now() - n * 86_400_000).toISOString();
        return backfill.submit({
          path: { integrationId: p.id },
          body: { from, ...(chosen.length > 0 ? { streams: chosen } : {}) },
        });
      }}
      onRetry={backfill.retry}
    />
  );
}

function ActionsTab({ provider: p }: { provider: ProviderDetail }) {
  return (
    <div className="grid min-w-0 gap-4">
      <Section
        title="Provider actions"
        description="Responses the gateway can ask the identity provider to carry out. Medium and high impact actions need a second analyst’s approval (ATO settings → Automated responses); an action counts as done only when the provider confirms it."
      >
        <ScrollRegion label="Provider action capabilities">
          <table className="w-full min-w-[40rem] text-left text-sm">
            <caption className="sr-only">Provider action capabilities</caption>
            <thead className="bg-muted/50 text-xs text-muted-foreground">
              <tr>
                {['Action', 'Enabled', 'Availability', 'Roll back', 'Confirmation', 'Needs'].map(
                  (h) => (
                    <th key={h} scope="col" className="px-2 py-1.5 font-medium">
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {p.actions.map((a) => (
                <tr key={a.action} className="border-t align-top">
                  <th scope="row" className="px-2 py-1.5 font-normal">
                    {labelOf(ACTION_LABELS, a.action)}
                  </th>
                  <td className="px-2 py-1.5">{a.enabled ? 'Yes' : 'No'}</td>
                  <td className="px-2 py-1.5">
                    <CapabilityBadge value={a.capability} />
                    {a.code ? (
                      <span className="block text-xs text-muted-foreground">
                        <CodeText code={a.code} />
                      </span>
                    ) : null}
                  </td>
                  <td className="px-2 py-1.5">{a.rollback ? 'Yes' : 'No'}</td>
                  <td className="px-2 py-1.5">
                    {a.confirmation === 'polling' ? 'Read back until confirmed' : 'Immediate'}
                  </td>
                  <td className="px-2 py-1.5 text-xs">
                    {a.requiresConfiguration ? (
                      <code className="font-mono">{a.requiresConfiguration}</code>
                    ) : (
                      '—'
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </ScrollRegion>
        <ul className="grid gap-1 text-xs text-muted-foreground">
          <li>
            Revoking sessions also revokes the user’s refresh and OAuth tokens: users sign in and
            authorize their applications again.
          </li>
          {p.provider === 'microsoft_entra' ? (
            <li>
              Mailbox-level forwarding cannot be removed through Microsoft Graph: remove it in the
              Exchange admin center. Inbox-rule forwarding is handled.
            </li>
          ) : (
            <li>
              Google auto-forwarding and filters that forward cannot be restored after removal.
            </li>
          )}
        </ul>
      </Section>
      <ProviderSettingsForm provider={p} sections="actions" />
    </div>
  );
}

function PermissionsTab({ provider: p }: { provider: ProviderDetail }) {
  return (
    <div className="grid min-w-0 gap-4">
      <Section
        title="Permissions"
        description="Required permissions or scopes per profile, what the connection’s grant has and what is missing. Copy the names into the provider’s admin consent or domain-wide delegation."
      >
        <ProfileTable profiles={p.permissions.profiles} caption="Permissions per profile" />
      </Section>
      <Section title="Granted when connected" headingLevel={3}>
        <PermissionNames names={p.permissions.granted} emptyLabel="Not verified by step 8.2" />
      </Section>
    </div>
  );
}
