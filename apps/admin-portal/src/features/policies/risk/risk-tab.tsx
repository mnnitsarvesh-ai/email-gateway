'use client';

import { PlusIcon, RotateCcwIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type ReactNode } from 'react';
import { DataTable, type DataTableColumn, type RowAction } from '@/components/data-table';
import { DateTime } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { DetailList, EnumBadge, Section } from '@/features/messages/controls';
import { FINAL_ACTION_TONE } from '@/features/messages/semantic';
import { riskProfileVersionHref } from '../links';
import { VERSION_STATUS_TONE } from '../semantic';
import {
  DeleteRiskDraftDialog,
  NewRiskDraftDialog,
  RiskActivateDialog,
  RiskPublishDialog,
  RiskResetDialog,
  riskActivationLabel,
} from './risk-dialogs';

type Profile = SuccessBody<'RiskProfilesController_profile_v1'>;
type RiskVersion = ListItem<'RiskProfilesController_listVersions_v1'>;

type Dialog =
  | { kind: 'new' }
  | { kind: 'reset' }
  | { kind: 'publish'; version: RiskVersion }
  | { kind: 'activate'; version: RiskVersion }
  | { kind: 'delete'; version: RiskVersion };

/**
 * Risk scoring (page 13 risk tab; step 7.3 design B13): the active profile, risk-profile drafts
 * (new from the active version or the platform profile), publish, activate an older version
 * (rollback), delete drafts and reset to the platform profile. Not in 7.3: the risk dry-run UI.
 */
export function RiskTab() {
  const router = useRouter();
  const profile = useApiQuery('RiskProfilesController_profile_v1');
  const versions = useCursorList('RiskProfilesController_listVersions_v1', undefined, {
    limit: 25,
  });
  const canCreate = useCan('RiskProfilesController_createDraft_v1');
  const canPublish = useCan('RiskProfilesController_publish_v1');
  const canActivate = useCan('RiskProfilesController_activate_v1');
  const canReset = useCan('RiskProfilesController_reset_v1');
  const canDelete = useCan('RiskProfilesController_deleteDraft_v1');
  const canEdit = useCan('RiskProfilesController_updateDraft_v1');
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const p = profile.data;
  const activeNo = p?.active.versionNo ?? null;

  const columns: DataTableColumn<RiskVersion>[] = [
    {
      id: 'versionNo',
      header: 'Version',
      meta: { label: 'Version' },
      cell: ({ row }) => (
        <span className="flex flex-wrap items-center gap-1.5">
          <Link
            href={riskProfileVersionHref(row.original.id)}
            className="font-medium text-primary underline-offset-2 hover:underline"
          >
            {`v${row.original.versionNo}`}
          </Link>
          {row.original.active ? <EnumBadge value="active" tones={{ active: 'success' }} /> : null}
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

  const rowActions = (row: RiskVersion): RowAction[] => {
    const actions: RowAction[] = [
      {
        label: row.status === 'draft' && canEdit ? 'Edit draft' : 'Open',
        onSelect: () => router.push(riskProfileVersionHref(row.id)),
      },
    ];
    if (row.status === 'draft' && canPublish) {
      actions.push({
        label: 'Publish…',
        onSelect: () => setDialog({ kind: 'publish', version: row }),
      });
    }
    if (row.status === 'published' && !row.active && canActivate) {
      actions.push({
        label: `${riskActivationLabel(row.versionNo, activeNo)}…`,
        onSelect: () => setDialog({ kind: 'activate', version: row }),
      });
    }
    if (row.status === 'draft' && canDelete) {
      actions.push({
        label: 'Delete draft…',
        destructive: true,
        onSelect: () => setDialog({ kind: 'delete', version: row }),
      });
    }
    return actions;
  };

  return (
    <div className="grid gap-4">
      {profile.isLoading ? (
        <LoadingState label="Loading the risk profile" rows={6} />
      ) : profile.error || !p ? (
        <ErrorState error={profile.error} onRetry={() => void profile.refetch()} />
      ) : (
        <ActiveProfile
          profile={p}
          actions={
            <>
              {canCreate ? (
                <Button size="sm" onClick={() => setDialog({ kind: 'new' })}>
                  <PlusIcon aria-hidden />
                  New draft
                </Button>
              ) : null}
              {canReset && p.active.source === 'tenant' ? (
                <Button size="sm" variant="outline" onClick={() => setDialog({ kind: 'reset' })}>
                  <RotateCcwIcon aria-hidden />
                  Reset to the platform profile
                </Button>
              ) : null}
            </>
          }
        />
      )}
      <DataTable
        tableId="risk-versions"
        caption="Risk profile versions"
        columns={columns}
        list={versions}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `risk profile version ${row.versionNo}`}
        rowActions={rowActions}
        emptyState={
          <EmptyState
            title="No tenant versions"
            description="The platform default profile applies."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <Link
              href={riskProfileVersionHref(row.id)}
              className="font-medium text-primary hover:underline"
            >
              {`v${row.versionNo}${row.active ? ' (active)' : ''}`}
            </Link>
            <EnumBadge value={row.status} tones={VERSION_STATUS_TONE} />
          </div>
        )}
      />
      {dialog?.kind === 'new' && p ? (
        <NewRiskDraftDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null);
          }}
          activeVersionId={p.active.versionId}
          activeVersionNo={p.active.versionNo}
        />
      ) : null}
      {dialog?.kind === 'reset' && p ? (
        <RiskResetDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null);
          }}
          profileVersion={p.profileVersion}
        />
      ) : null}
      {dialog?.kind === 'publish' ? (
        <RiskPublishDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null);
          }}
          versionId={dialog.version.id}
          versionNo={dialog.version.versionNo}
          rowVersion={dialog.version.rowVersion}
        />
      ) : null}
      {dialog?.kind === 'activate' && p ? (
        <RiskActivateDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null);
          }}
          versionId={dialog.version.id}
          versionNo={dialog.version.versionNo}
          activeVersionNo={activeNo}
          profileVersion={p.profileVersion}
        />
      ) : null}
      {dialog?.kind === 'delete' ? (
        <DeleteRiskDraftDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null);
          }}
          versionId={dialog.version.id}
          versionNo={dialog.version.versionNo}
          rowVersion={dialog.version.rowVersion}
        />
      ) : null}
    </div>
  );
}

function ActiveProfile({ profile, actions }: { profile: Profile; actions: ReactNode }) {
  return (
    <>
      <Section
        title="Active risk profile"
        description="Engineering defaults calibrated on synthetic data; a recommendation that the policy decides on."
        actions={actions}
      >
        <DetailList
          items={[
            {
              label: 'Source',
              value:
                profile.active.source === 'platform'
                  ? `Platform default (${profile.platformProfile})`
                  : `Tenant version v${profile.active.versionNo ?? '?'}`,
            },
            {
              label: 'Profile',
              value: <span className="font-mono text-xs">{profile.active.profileId}</span>,
            },
            {
              label: 'Fallback',
              value: profile.active.fallback ? humanize(profile.active.fallback) : 'None',
            },
            {
              label: 'Versions',
              value: `${formatNumber(profile.counts.published)} published, ${formatNumber(profile.counts.drafts)} drafts (limit ${formatNumber(profile.counts.limit)})`,
            },
            {
              label: 'Updated',
              value: <DateTime value={profile.updatedAt} mode="absolute" emptyLabel="Never" />,
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
              {Object.entries(profile.effectiveProfile.actions).map(([level, action]) => (
                <tr key={level} className="border-t">
                  <th scope="row" className="py-1 pr-4 text-left font-medium">
                    {humanize(level)}
                  </th>
                  <td className="py-1 pr-4 tabular-nums">
                    {level in profile.effectiveProfile.thresholds
                      ? formatNumber(
                          profile.effectiveProfile.thresholds[
                            level as keyof Profile['effectiveProfile']['thresholds']
                          ],
                        )
                      : '0'}
                  </td>
                  <td className="py-1">
                    <EnumBadge value={action} tones={FINAL_ACTION_TONE} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="grid gap-1">
          <h3 className="text-xs font-medium text-muted-foreground">Hard blocks</h3>
          <ul className="grid gap-1 text-sm sm:grid-cols-2">
            {Object.entries(profile.effectiveProfile.hardBlocks).map(([id, block]) => (
              <li key={id} className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs">{id}</span>
                <span className="text-xs">{block.enabled ? humanize(block.action) : 'Off'}</span>
              </li>
            ))}
          </ul>
        </div>
      </Section>
    </>
  );
}
