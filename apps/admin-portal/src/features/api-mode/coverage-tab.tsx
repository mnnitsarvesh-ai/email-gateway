'use client';

import { RefreshCwIcon } from 'lucide-react';
import Link from 'next/link';
import { useId, type ReactNode } from 'react';
import { DateTime } from '@/components/domain/date-time';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { MutationError, Section } from '@/features/domains/kit';
import { PROVIDER_LABEL } from '@/features/integrations/providers/model';
import {
  ApiModeHealthBadge,
  MailboxGrantBadge,
  checkTitle,
  coverageText,
  formatLagSeconds,
  type ApiModeConnection,
  type FeedMode,
  type Overview,
  type OverviewConnection,
} from './model';

export const API_MODE_QUERIES: readonly OperationId[] = [
  'ApiModeController_overview_v1',
  'ApiModeController_listConnections_v1',
  'ApiModeController_getConnection_v1',
  'ApiModeController_listMailboxes_v1',
];

/** Link to the 8.2 connection page's mailbox-access grant card (D14). */
export function grantHref(connectionId: string): string {
  return `/integrations/providers/${connectionId}?tab=settings#mailbox-access`;
}

function Tile({ label, value, detail }: { label: string; value: ReactNode; detail?: ReactNode }) {
  return (
    <Card className="gap-1 px-4 py-4">
      <h3 className="text-sm font-medium text-muted-foreground">{label}</h3>
      <p className="text-xl font-semibold tabular-nums">{value}</p>
      {detail ? <div className="text-xs text-muted-foreground">{detail}</div> : null}
    </Card>
  );
}

/** The overview tiles (D12 #4): coverage, connections by health, lag, throttling, copies. */
export function CoverageTiles({ overview }: { overview: Overview }) {
  const { coverage, connectionsByHealth: health, lag, throttling } = overview;
  return (
    <ul
      className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5"
      aria-label="Mailbox protection summary"
    >
      <li>
        <Tile
          label="Mailboxes covered"
          value={
            coverage.total === null
              ? `${formatNumber(coverage.covered)} covered`
              : `${formatNumber(coverage.covered)} / ${formatNumber(coverage.total)}`
          }
          detail={
            coverage.total === null
              ? 'Total unknown: connect mailbox access to count every mailbox.'
              : `${coverageText(coverage)}; ${formatNumber(coverage.gap)} with a gap`
          }
        />
      </li>
      <li>
        <Tile
          label="Connections by health"
          value={`${formatNumber(health.healthy)} healthy`}
          detail={`${formatNumber(health.degraded)} degraded · ${formatNumber(health.failing)} failing · ${formatNumber(health.unknown)} not evaluated`}
        />
      </li>
      <li>
        <Tile
          label="Detection lag, last hour"
          value={`p95 ${formatLagSeconds(lag.p95Seconds1h)}`}
          detail={`p50 ${formatLagSeconds(lag.p50Seconds1h)} (provider delivery to verdict)`}
        />
      </li>
      <li>
        <Tile
          label="Detection lag, last 24 hours"
          value={`p95 ${formatLagSeconds(lag.p95Seconds24h)}`}
          detail={`p50 ${formatLagSeconds(lag.p50Seconds24h)}`}
        />
      </li>
      <li>
        <Tile
          label="Provider throttling"
          value={`${formatNumber(throttling.events1h)} in 1 h`}
          detail={`${formatNumber(throttling.events24h)} in 24 h · ${formatNumber(overview.copiesToday)} copies scanned today`}
        />
      </li>
    </ul>
  );
}

function settingsErrorText(error: ApiError | null): string | null {
  if (!error) return null;
  switch (error.code) {
    case 'api_mode_mailbox_access_required':
      return 'Grant mailbox access for API mode on the connection first; feeds and inventory need it.';
    case 'api_mode_connection_conflict':
      return 'The settings were changed by someone else; the current values were reloaded. Try again.';
    case 'api_mode_notifications_unavailable':
      return error.details.reason === 'provider'
        ? 'Change notifications exist for Microsoft 365 only; Google Workspace always polls.'
        : 'Change notifications are not configured on this gateway; use polling.';
    default:
      return null;
  }
}

/** Feeds toggle and mode of one connection (`PUT …/settings`, CAS on `rowVersion`; D10.1). */
export function FeedsControl({ connection }: { connection: ApiModeConnection }) {
  const switchId = useId();
  const modeId = useId();
  const canWrite = useCan('ApiModeController_updateSettings_v1');
  const update = useApiMutation('ApiModeController_updateSettings_v1', {
    invalidates: API_MODE_QUERIES,
    successMessage: null,
  });
  const notifyAllowed = connection.provider === 'microsoft_365';
  const save = (feedsEnabled: boolean, feedMode: FeedMode) =>
    void update.submit({
      path: { connectionId: connection.id },
      body: { feedsEnabled, feedMode, expectedRowVersion: connection.rowVersion },
    });
  if (!canWrite) {
    return (
      <span className="text-sm">
        {connection.feedsEnabled ? `On (${humanize(connection.feedMode)})` : 'Off'}
      </span>
    );
  }
  const text = settingsErrorText(update.error);
  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Switch
          id={switchId}
          checked={connection.feedsEnabled}
          disabled={update.isPending || connection.status === 'disabled'}
          onCheckedChange={(checked) => save(checked, connection.feedMode)}
        />
        <Label htmlFor={switchId} className="font-normal">
          Mailbox feeds for {connection.displayName}
        </Label>
      </div>
      <div className="grid gap-1">
        <Label htmlFor={modeId} className="text-xs text-muted-foreground">
          Feed mode
        </Label>
        <Select
          value={connection.feedMode}
          disabled={update.isPending || !connection.feedsEnabled || !notifyAllowed}
          onValueChange={(value) => save(connection.feedsEnabled, value as FeedMode)}
        >
          <SelectTrigger id={modeId} size="sm" className="w-44">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="poll">Poll</SelectItem>
            <SelectItem value="notify">Notify (with safety poll)</SelectItem>
          </SelectContent>
        </Select>
      </div>
      {update.error ? (
        <div className="grid gap-1" role="alert">
          {text ? <p className="text-xs font-medium text-destructive">{text}</p> : null}
          <MutationError error={update.error} />
        </div>
      ) : null}
    </div>
  );
}

/** `POST …/inventory-sync` (D11.1): the worker lists the provider's users on its next run. */
export function InventorySyncButton({ connection }: { connection: ApiModeConnection }) {
  const canWrite = useCan('ApiModeController_inventorySync_v1');
  const sync = useApiMutation('ApiModeController_inventorySync_v1', {
    invalidates: API_MODE_QUERIES,
    successMessage: 'Inventory sync requested; the mailbox list updates when the worker has run.',
  });
  if (!canWrite) return null;
  const text = settingsErrorText(sync.error);
  return (
    <div className="grid gap-1">
      <Button
        size="sm"
        variant="outline"
        disabled={sync.isPending || connection.status === 'disabled'}
        onClick={() => void sync.submit({ path: { connectionId: connection.id } })}
      >
        <RefreshCwIcon aria-hidden />
        Sync inventory <span className="sr-only">of {connection.displayName}</span>
      </Button>
      {sync.error ? (
        <div className="grid gap-1" role="alert">
          {text ? <p className="text-xs font-medium text-destructive">{text}</p> : null}
          <MutationError error={sync.error} />
        </div>
      ) : null}
    </div>
  );
}

function ConnectionsTable({
  connections,
  metrics,
}: {
  connections: readonly ApiModeConnection[];
  metrics: ReadonlyMap<string, OverviewConnection>;
}) {
  if (connections.length === 0) {
    return (
      <EmptyState
        title="No provider connection"
        description="Connect Microsoft 365 or Google Workspace under Integrations first; API mode uses that connection."
        action={
          <Button asChild size="sm" variant="outline">
            <Link href="/integrations">Open integrations</Link>
          </Button>
        }
      />
    );
  }
  return (
    // `relative`: the sr-only labels and the feed-mode select's hidden native control are
    // positioned absolutely; contained here, they cannot widen the page on phones and tablets.
    <div className="relative overflow-x-auto">
      <Table>
        <TableCaption className="sr-only">Provider connections used for API mode</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead>Connection</TableHead>
            <TableHead>Health</TableHead>
            <TableHead>Failing checks</TableHead>
            <TableHead>Coverage</TableHead>
            <TableHead>Mailbox access</TableHead>
            <TableHead>Feeds</TableHead>
            <TableHead>Inventory</TableHead>
            <TableHead>Lag p95 (1 h)</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {connections.map((connection) => {
            const m = metrics.get(connection.id);
            return (
              <TableRow key={connection.id}>
                <TableCell className="align-top">
                  <div className="grid gap-0.5">
                    <Link
                      href={`/integrations/providers/${connection.id}`}
                      className="font-medium text-primary hover:underline"
                    >
                      {connection.displayName}
                    </Link>
                    <span className="text-xs text-muted-foreground">
                      {PROVIDER_LABEL[connection.provider]} · {humanize(connection.status)}
                      {connection.bound ? '' : ' · not bound'}
                    </span>
                  </div>
                </TableCell>
                <TableCell className="align-top">
                  <ApiModeHealthBadge health={connection.health.status} />
                  {connection.throttledUntil ? (
                    <p className="mt-1 text-xs text-muted-foreground">
                      Throttled until <DateTime value={connection.throttledUntil} />
                    </p>
                  ) : null}
                </TableCell>
                <TableCell className="align-top">
                  {m && m.failingChecks.length > 0 ? (
                    <ul className="grid gap-0.5 text-xs">
                      {m.failingChecks.map((code) => (
                        <li key={code}>{checkTitle(code)}</li>
                      ))}
                    </ul>
                  ) : (
                    <span className="text-xs text-muted-foreground">None</span>
                  )}
                </TableCell>
                <TableCell className="align-top text-sm">
                  {m ? coverageText(m.coverage) : 'Not evaluated yet'}
                </TableCell>
                <TableCell className="align-top">
                  <div className="grid justify-items-start gap-1">
                    <MailboxGrantBadge status={connection.grant?.status ?? null} />
                    <Link
                      href={grantHref(connection.id)}
                      className="text-xs text-primary underline underline-offset-2"
                    >
                      {connection.grant?.status === 'active' ? 'Manage' : 'Grant mailbox access'}{' '}
                      <span className="sr-only">for {connection.displayName}</span>
                    </Link>
                  </div>
                </TableCell>
                <TableCell className="min-w-56 align-top">
                  <FeedsControl connection={connection} />
                </TableCell>
                <TableCell className="align-top">
                  <div className="grid justify-items-start gap-1 text-xs">
                    <span>
                      {humanize(connection.inventoryStatus)}
                      {connection.mailboxesTotal !== null
                        ? ` · ${formatNumber(connection.mailboxesTotal)} in scope`
                        : ''}
                    </span>
                    {connection.inventorySyncedAt ? (
                      <span className="text-muted-foreground">
                        Synced <DateTime value={connection.inventorySyncedAt} />
                      </span>
                    ) : null}
                    <InventorySyncButton connection={connection} />
                  </div>
                </TableCell>
                <TableCell className="align-top text-sm tabular-nums">
                  {m ? formatLagSeconds(m.lag.p95Seconds1h) : 'No copies'}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

/** Tab "Coverage" (D14): tiles and the per-connection table. */
export function CoverageTab() {
  const overview = useApiQuery('ApiModeController_overview_v1', undefined, {
    refetchInterval: 60_000,
  });
  const connections = useApiQuery('ApiModeController_listConnections_v1');
  if (overview.isLoading || connections.isLoading)
    return <LoadingState label="Loading mailbox protection" rows={6} />;
  if (overview.error)
    return <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />;
  if (connections.error)
    return <ErrorState error={connections.error} onRetry={() => void connections.refetch()} />;
  if (!overview.data || !connections.data) return null;
  const metrics = new Map(overview.data.connections.map((c) => [c.id, c]));
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <CoverageTiles overview={overview.data} />
      <p className="text-xs text-muted-foreground">
        Updated <DateTime value={overview.data.generatedAt} />. Lag is measured from the
        provider&apos;s delivery to the verdict; coverage counts in-scope mailboxes of domains in
        API or Hybrid mode.
      </p>
      <Section
        title="Connections"
        description="Each Microsoft 365 or Google Workspace connection: health, coverage, mailbox access, change feeds and mailbox inventory."
      >
        <ConnectionsTable connections={connections.data.data} metrics={metrics} />
      </Section>
    </div>
  );
}
