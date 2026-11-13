'use client';

import Link from 'next/link';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { formatNumber, humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge, Section, YesNo } from '@/features/messages/controls';
import { FINAL_ACTION_TONE } from '@/features/messages/semantic';
import { VERSION_STATUS_TONE } from './semantic';

/** Policy settings (`GET /policy-settings`), read-only in 7.1. */
export function PolicySettingsTab() {
  const settings = useApiQuery('PolicySettingsController_get_v1');
  if (settings.isLoading) return <LoadingState label="Loading policy settings" rows={6} />;
  if (settings.error || !settings.data) {
    return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  }
  const s = settings.data;
  const e = s.effective;
  return (
    <div className="grid gap-4">
      <Section title="Effective policy settings" description="What applies to the next evaluation.">
        <DetailList
          items={[
            {
              label: 'Recommendation overrides',
              value: <YesNo value={e.allowRecommendationOverrides} />,
            },
            {
              label: 'Per-recipient evaluation',
              value:
                e.recipientSplit === undefined ? (
                  <span className="text-muted-foreground">Platform default</span>
                ) : (
                  <YesNo value={e.recipientSplit} />
                ),
            },
            {
              label: 'Sender non-delivery notices',
              value: <YesNo value={e.notices.senderNonDelivery} />,
            },
            { label: 'Policy alerts', value: <YesNo value={e.alerts.enabled} /> },
            { label: 'Platform tag header', value: <YesNo value={e.tagging.platformTagHeader} /> },
            {
              label: 'Platform tag on outbound mail',
              value: <YesNo value={e.tagging.platformTagOutbound} />,
            },
          ]}
        />
      </Section>
      <Section title="Version">
        <DetailList
          items={[
            {
              label: 'Generation',
              value: <span className="font-mono text-xs">{s.generation}</span>,
            },
            { label: 'Row version', value: formatNumber(s.rowVersion) },
            {
              label: 'Settings hash',
              value: s.settingsSha256 ? (
                <span className="font-mono text-xs break-all">{s.settingsSha256}</span>
              ) : (
                <span className="text-muted-foreground">Defaults (nothing stored)</span>
              ),
            },
            {
              label: 'Updated',
              value: <DateTime value={s.updatedAt} mode="absolute" emptyLabel="Never" />,
            },
            {
              label: 'Violations',
              value:
                s.violations.length === 0 ? (
                  'None'
                ) : (
                  <ul className="grid gap-1 text-xs">
                    {s.violations.map((v, i) => (
                      <li key={i}>
                        <span className="font-mono">{v.path}</span>: {v.message}
                      </li>
                    ))}
                  </ul>
                ),
            },
          ]}
        />
      </Section>
    </div>
  );
}

type RiskVersion = ListItem<'RiskProfilesController_listVersions_v1'>;

const RISK_VERSION_COLUMNS: DataTableColumn<RiskVersion>[] = [
  {
    id: 'versionNo',
    header: 'Version',
    meta: { label: 'Version', className: 'tabular-nums' },
    cell: ({ row }) => (
      <span>
        v{row.original.versionNo}
        {row.original.active ? <span className="ml-2 text-xs font-medium">(active)</span> : null}
      </span>
    ),
  },
  {
    id: 'status',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => <EnumBadge value={row.original.status} tones={VERSION_STATUS_TONE} />,
  },
  {
    id: 'note',
    header: 'Change note',
    meta: { label: 'Change note', className: 'max-w-80' },
    cell: ({ row }) =>
      row.original.changeNote ?? <span className="text-muted-foreground">None</span>,
  },
  {
    id: 'publishedAt',
    header: 'Published',
    meta: { label: 'Published', className: 'whitespace-nowrap' },
    cell: ({ row }) => <DateTime value={row.original.publishedAt} emptyLabel="Not published" />,
  },
];

/** Risk scoring profile and versions (`GET /risk-scoring/profile`, `…/versions`), read-only. */
export function RiskTab() {
  const profile = useApiQuery('RiskProfilesController_profile_v1');
  const versions = useCursorList('RiskProfilesController_listVersions_v1', undefined, {
    limit: 25,
  });
  return (
    <div className="grid gap-4">
      {profile.isLoading ? (
        <LoadingState label="Loading the risk profile" rows={6} />
      ) : profile.error || !profile.data ? (
        <ErrorState error={profile.error} onRetry={() => void profile.refetch()} />
      ) : (
        <>
          <Section
            title="Active risk profile"
            description="Engineering defaults calibrated on synthetic data; a recommendation that the policy decides on."
          >
            <DetailList
              items={[
                {
                  label: 'Source',
                  value:
                    profile.data.active.source === 'platform'
                      ? `Platform default (${profile.data.platformProfile})`
                      : `Tenant version v${profile.data.active.versionNo ?? '?'}`,
                },
                {
                  label: 'Profile',
                  value: <span className="font-mono text-xs">{profile.data.active.profileId}</span>,
                },
                {
                  label: 'Fallback',
                  value: profile.data.active.fallback
                    ? humanize(profile.data.active.fallback)
                    : 'None',
                },
                {
                  label: 'Versions',
                  value: `${formatNumber(profile.data.counts.published)} published, ${formatNumber(profile.data.counts.drafts)} drafts (limit ${formatNumber(profile.data.counts.limit)})`,
                },
                {
                  label: 'Updated',
                  value: (
                    <DateTime value={profile.data.updatedAt} mode="absolute" emptyLabel="Never" />
                  ),
                },
              ]}
            />
          </Section>
          <Section title="Levels and actions">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <caption className="sr-only">Risk level thresholds and recommended actions</caption>
                <thead className="text-left text-xs text-muted-foreground">
                  <tr>
                    <th scope="col" className="py-1 pr-4 font-semibold">
                      Level
                    </th>
                    <th scope="col" className="py-1 pr-4 font-semibold">
                      From score
                    </th>
                    <th scope="col" className="py-1 font-semibold">
                      Recommended action
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {(['none', 'low', 'medium', 'high', 'critical'] as const).map((level) => (
                    <tr key={level} className="border-t">
                      <th scope="row" className="py-1 pr-4 text-left font-medium">
                        {humanize(level)}
                      </th>
                      <td className="py-1 pr-4 tabular-nums">
                        {level === 'none'
                          ? '0'
                          : formatNumber(profile.data.effectiveProfile.thresholds[level])}
                      </td>
                      <td className="py-1">
                        <EnumBadge
                          value={profile.data.effectiveProfile.actions[level]}
                          tones={FINAL_ACTION_TONE}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="grid gap-1">
              <h3 className="text-xs font-medium text-muted-foreground">Hard blocks</h3>
              <ul className="grid gap-1 text-sm sm:grid-cols-2">
                {Object.entries(profile.data.effectiveProfile.hardBlocks).map(([id, block]) => (
                  <li key={id} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs">{id}</span>
                    <span className="text-xs">
                      {block.enabled ? humanize(block.action) : 'Off'}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </Section>
        </>
      )}
      <DataTable
        tableId="risk-versions"
        caption="Risk profile versions"
        columns={RISK_VERSION_COLUMNS}
        list={versions}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `risk profile version ${row.versionNo}`}
        emptyState={
          <EmptyState
            title="No tenant versions"
            description="The platform default profile applies."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <span>v{row.versionNo}</span>
            <EnumBadge value={row.status} tones={VERSION_STATUS_TONE} />
          </div>
        )}
      />
    </div>
  );
}

type ScanSetting = ListItem<'ScanSettingsController_list_v1'>;

/** Scan settings summary (`GET /scan-settings`); editing lives in Settings → Scanning. */
export function ScanningTab() {
  const settings = useApiQuery('ScanSettingsController_list_v1');
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          Per-engine thresholds and options; tenant overrides stay within platform bounds.
        </p>
        <Button asChild variant="outline" size="sm">
          <Link href="/settings?tab=scanning">Open scan settings</Link>
        </Button>
      </div>
      {settings.isLoading ? (
        <LoadingState label="Loading scan settings" rows={6} variant="table" />
      ) : settings.error ? (
        <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />
      ) : (settings.data?.data.length ?? 0) === 0 ? (
        <EmptyState title="No scan engines reported" />
      ) : (
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full text-sm">
            <caption className="sr-only">Scan engines</caption>
            <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
              <tr>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Engine
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Required
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Tenant may disable
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Tenant override
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Violations
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Updated
                </th>
              </tr>
            </thead>
            <tbody>
              {settings.data?.data.map((engine: ScanSetting) => (
                <tr key={engine.engine} className="border-t">
                  <th scope="row" className="px-3 py-2 text-left font-medium">
                    {humanize(engine.engine)}
                  </th>
                  <td className="px-3 py-2">
                    <YesNo value={engine.required} />
                  </td>
                  <td className="px-3 py-2">
                    <YesNo value={engine.tenantMayDisable} />
                  </td>
                  <td className="px-3 py-2">
                    {engine.overrideApplied
                      ? `Applied (version ${engine.version})`
                      : 'Platform defaults'}
                  </td>
                  <td className="px-3 py-2">
                    <CodeList codes={engine.violations.map((v) => `${v.path}: ${v.code}`)} />
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap">
                    <DateTime value={engine.updatedAt} emptyLabel="Never" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {settings.data?.note ? (
        <p className="text-xs text-muted-foreground">{settings.data.note}</p>
      ) : null}
    </div>
  );
}
