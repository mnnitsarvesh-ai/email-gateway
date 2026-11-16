'use client';

import { GitCompareIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { DataTable, type DataTableColumn, type RowAction } from '@/components/data-table';
import { CopyableId, DateTime } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { useApiMutation, useCursorList } from '@/lib/api/hooks';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber } from '@/lib/format';
import { EnumBadge } from '@/features/messages/controls';
import type { DirectoryNames } from '../builder';
import { ActivateDialog, activationLabel } from '../lifecycle/activate-dialog';
import { DeleteDraftDialog } from '../lifecycle/policy-controls';
import { PublishDialog } from '../lifecycle/publish-dialog';
import { policyCompareHref, policyVersionHref } from '../links';
import { detailNumber, POLICY_QUERIES } from '../queries';
import { VERSION_STATUS_TONE } from '../semantic';

type Policy = SuccessBody<'PolicyManagementController_get_v1'>;
type VersionRow = ListItem<'PolicyManagementController_listVersions_v1'>;

type Dialog =
  | { kind: 'publish'; versionNo: number }
  | { kind: 'activate'; versionNo: number }
  | { kind: 'delete'; versionNo: number; rowVersion: number };

function person(names: DirectoryNames, id: string | null) {
  if (!id) return <span className="text-muted-foreground">None</span>;
  const name = names.users?.get(id);
  return name ? <span>{name}</span> : <CopyableId value={id} label="user ID" max={12} />;
}

/**
 * The versions of a policy, newest first (design B10): status, active marker, rules, override
 * flag, change note, author, publisher, published time and the actions the user may take; two
 * selected rows open the comparison.
 */
export function VersionsTable({
  policy,
  names,
  onGeneration,
}: {
  policy: Policy;
  names: DirectoryNames;
  onGeneration: (generation: string | null) => void;
}) {
  const router = useRouter();
  const list = useCursorList('PolicyManagementController_listVersions_v1', undefined, {
    path: { policyId: policy.id },
    limit: 25,
  });
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const canUpdateDraft = useCan('PolicyManagementController_updateDraft_v1');
  const canCreateDraft = useCan('PolicyManagementController_createDraft_v1');
  const canPublish = useCan('PolicyManagementController_publish_v1');
  const canActivate = useCan('PolicyManagementController_activate_v1');
  const canDeleteDraft = useCan('PolicyManagementController_deleteDraft_v1');
  const createDraft = useApiMutation('PolicyManagementController_createDraft_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: null,
  });
  const activeNo = policy.activeVersionNo;

  const newDraftFrom = async (versionNo: number) => {
    const outcome = await createDraft.submit({
      path: { policyId: policy.id },
      body: { basedOnVersionNo: versionNo },
    });
    if (outcome.ok) {
      toast.success(`Draft v${outcome.data.versionNo} created from v${versionNo}`);
      router.push(policyVersionHref(policy.id, outcome.data.versionNo));
    } else if (outcome.error.code === 'policy_version_limit_reached') {
      toast.error(
        `This policy reached its limit of ${detailNumber(outcome.error, 'limit') ?? '?'} versions; delete unused drafts first.`,
      );
    } else if (outcome.error.status !== 429) {
      toast.error(`The draft could not be created (${outcome.error.code}).`);
    }
  };

  const columns = useMemo<DataTableColumn<VersionRow>[]>(
    () => [
      {
        id: 'versionNo',
        header: 'Version',
        meta: { label: 'Version' },
        cell: ({ row }) => (
          <span className="flex flex-wrap items-center gap-1.5">
            <Link
              href={policyVersionHref(policy.id, row.original.versionNo)}
              className="font-medium text-primary underline-offset-2 hover:underline"
            >
              {`v${row.original.versionNo}`}
            </Link>
            {row.original.active ? (
              <EnumBadge value="active" tones={{ active: 'success' }} />
            ) : null}
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
        id: 'rules',
        header: 'Rules',
        meta: { label: 'Rules', className: 'tabular-nums' },
        cell: ({ row }) => (
          <span>
            {formatNumber(row.original.ruleCount)}
            {row.original.hasOverrideRules ? (
              <span className="ml-1 text-xs text-muted-foreground">(override rules)</span>
            ) : null}
          </span>
        ),
      },
      {
        id: 'note',
        header: 'Change note',
        meta: { label: 'Change note', className: 'max-w-64' },
        cell: ({ row }) =>
          row.original.changeNote ? (
            <span className="line-clamp-2 break-words" title={row.original.changeNote}>
              {row.original.changeNote}
            </span>
          ) : (
            <span className="text-muted-foreground">None</span>
          ),
      },
      {
        id: 'author',
        header: 'Author',
        meta: { label: 'Author' },
        cell: ({ row }) => person(names, row.original.createdByUserId),
      },
      {
        id: 'publisher',
        header: 'Publisher',
        meta: { label: 'Publisher' },
        cell: ({ row }) => person(names, row.original.publishedByUserId),
      },
      {
        id: 'publishedAt',
        header: 'Published',
        meta: { label: 'Published', className: 'whitespace-nowrap' },
        cell: ({ row }) => <DateTime value={row.original.publishedAt} emptyLabel="Not published" />,
      },
    ],
    [names, policy.id],
  );

  const rowActions = (row: VersionRow): RowAction[] => {
    const actions: RowAction[] = [
      {
        label: row.status === 'draft' && canUpdateDraft ? 'Edit draft' : 'Open',
        onSelect: () => router.push(policyVersionHref(policy.id, row.versionNo)),
      },
    ];
    if (row.status !== 'draft' && canCreateDraft) {
      actions.push({
        label: 'New draft from this version',
        onSelect: () => void newDraftFrom(row.versionNo),
        disabled: createDraft.isPending,
      });
    }
    if (row.status === 'draft' && canPublish) {
      actions.push({
        label: 'Publish…',
        onSelect: () => setDialog({ kind: 'publish', versionNo: row.versionNo }),
      });
    }
    if (row.status === 'published' && !row.active && canActivate) {
      actions.push({
        label: `${activationLabel(row.versionNo, activeNo)}…`,
        onSelect: () => setDialog({ kind: 'activate', versionNo: row.versionNo }),
      });
    }
    if (activeNo !== null && !row.active) {
      actions.push({
        label: 'Compare with active',
        onSelect: () => router.push(policyCompareHref(policy.id, activeNo, row.versionNo)),
      });
    }
    if (row.status === 'draft' && canDeleteDraft) {
      actions.push({
        label: 'Delete draft…',
        destructive: true,
        onSelect: () =>
          setDialog({ kind: 'delete', versionNo: row.versionNo, rowVersion: row.rowVersion }),
      });
    }
    return actions;
  };

  return (
    <>
      <DataTable
        tableId="policy-versions"
        caption="Policy versions"
        columns={columns}
        list={list}
        getRowId={(row) => String(row.versionNo)}
        getRowLabel={(row) => `version ${row.versionNo}`}
        rowActions={rowActions}
        enableSelection
        bulkActions={(rows) => {
          if (rows.length !== 2) {
            return (
              <span className="text-xs text-muted-foreground">
                Select two versions to compare them.
              </span>
            );
          }
          const [from, to] = rows.map((r) => r.versionNo).sort((a, b) => a - b);
          return (
            <Button asChild size="sm" variant="outline">
              <Link href={policyCompareHref(policy.id, from, to)}>
                <GitCompareIcon aria-hidden />
                {`Compare v${from} and v${to}`}
              </Link>
            </Button>
          );
        }}
        emptyState={<EmptyState title="No versions" />}
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <Link
              href={policyVersionHref(policy.id, row.versionNo)}
              className="font-medium text-primary hover:underline"
            >
              {`v${row.versionNo}${row.active ? ' (active)' : ''}`}
            </Link>
            <EnumBadge value={row.status} tones={VERSION_STATUS_TONE} />
            {row.changeNote ? (
              <span className="text-xs break-words text-muted-foreground">{row.changeNote}</span>
            ) : null}
          </div>
        )}
      />
      {dialog?.kind === 'publish' ? (
        <PublishDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null);
          }}
          policyId={policy.id}
          versionNo={dialog.versionNo}
          onPublished={(result) =>
            onGeneration(
              result.policy.activeVersionNo === dialog.versionNo ? result.generation : null,
            )
          }
        />
      ) : null}
      {dialog?.kind === 'activate' ? (
        <ActivateDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null);
          }}
          policyId={policy.id}
          versionNo={dialog.versionNo}
          onActivated={(result) => onGeneration(result.generation)}
        />
      ) : null}
      {dialog?.kind === 'delete' ? (
        <DeleteDraftDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null);
          }}
          policyId={policy.id}
          versionNo={dialog.versionNo}
          rowVersion={dialog.rowVersion}
          onDeleted={() => setDialog(null)}
        />
      ) : null}
    </>
  );
}
