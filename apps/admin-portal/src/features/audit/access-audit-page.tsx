'use client';

import { useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable } from '@/components/data-table';
import { ForbiddenView } from '@/components/forbidden-view';
import { PageHeader } from '@/components/page-header';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { EmptyState } from '@/components/states/empty-state';
import { LoadingState } from '@/components/states/loading-state';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { useHasPermission, useMe } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatUtc } from '@/lib/format';
import { AuditDetailSheet, auditColumns } from './audit-logs-page';

type AuditRow = ListItem<'AuditLogsController_search_v1'>;

/**
 * The audit rows of archive use (step 8.6 D14): the api filters by one action prefix or one exact
 * action per request, so each category is its own view.
 */
export const ACCESS_AUDIT_CATEGORIES = [
  {
    id: 'archive',
    label: 'Archive use',
    description: 'Searches, record views, reveals, previews, downloads, settings and disposal.',
    filter: { actionPrefix: 'archive.' },
  },
  {
    id: 'ediscovery',
    label: 'eDiscovery',
    description: 'Cases, custodians, searches, review and exports.',
    filter: { actionPrefix: 'ediscovery.' },
  },
  {
    id: 'legal_hold',
    label: 'Legal holds',
    description: 'Holds placed and released.',
    filter: { actionPrefix: 'legal_hold.' },
  },
  {
    id: 'granted',
    label: 'Access granted',
    description: 'A role with archive access was assigned to a user.',
    filter: { action: 'rbac.archive_access_granted' },
  },
  {
    id: 'revoked',
    label: 'Access removed',
    description: 'A role with archive access was removed from a user.',
    filter: { action: 'rbac.archive_access_revoked' },
  },
  {
    id: 'migrated',
    label: 'Access migrated',
    description:
      'Archive access kept by existing organization administrators when the Journaling / Archive split was introduced (step 8.6).',
    filter: { action: 'rbac.archive_access_migrated' },
  },
] as const;

type CategoryId = (typeof ACCESS_AUDIT_CATEGORIES)[number]['id'];

const URL_SHAPE = {
  category: z
    .enum(ACCESS_AUDIT_CATEGORIES.map((c) => c.id) as [CategoryId, ...CategoryId[]])
    .default('archive')
    .catch('archive'),
  sort: z.enum(['-createdAt', 'createdAt']).optional().catch(undefined),
};

/**
 * Archive → Access audit (`/archive/access-audit`, step 8.6 D14): who searched, viewed,
 * revealed, downloaded or exported archived mail, placed holds, and who was given or lost
 * archive access. Needs the audit log (`audit:read`) and archive access (`archive:search`).
 */
export function AccessAuditPage() {
  return (
    <RouteGate gate={['AuditLogsController_search_v1']}>
      <ArchiveAudienceGate />
    </RouteGate>
  );
}

function ArchiveAudienceGate() {
  const me = useMe();
  const archiveSearch = useHasPermission('archive:search');
  if (me.isLoading) return <LoadingState label="Checking access" rows={4} />;
  if (!archiveSearch) return <ForbiddenView gate={['ArchiveMessagesController_list_v1']} />;
  return <AccessAudit />;
}

function AccessAudit() {
  const [range] = useRangeState();
  const [state, setState] = useUrlState(URL_SHAPE);
  const [open, setOpen] = useState<AuditRow | null>(null);
  const category =
    ACCESS_AUDIT_CATEGORIES.find((c) => c.id === state.category) ?? ACCESS_AUDIT_CATEGORIES[0];
  const list = useCursorList('AuditLogsController_search_v1', {
    from: range.from,
    to: range.to,
    ...category.filter,
    ...(state.sort ? { sort: state.sort } : {}),
  });
  const columns = useMemo(() => auditColumns(setOpen), []);
  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Access audit"
        breadcrumbs={[{ label: 'Archive', href: '/archive' }, { label: 'Access audit' }]}
        description="Every use of the archive is recorded: searches, views, reveals, previews, downloads, exports, holds and changes of who may access archived mail. Searching this log is itself audited."
        actions={<RangePicker />}
      />
      <fieldset className="grid gap-2">
        <legend className="text-sm font-semibold">Category</legend>
        <RadioGroup
          value={category.id}
          onValueChange={(value) => setState({ category: value as CategoryId })}
          className="flex flex-wrap gap-x-5 gap-y-2"
          aria-label="Category"
        >
          {ACCESS_AUDIT_CATEGORIES.map((c) => (
            <div key={c.id} className="flex min-h-7 items-center gap-2">
              <RadioGroupItem value={c.id} id={`access-audit-${c.id}`} />
              <Label htmlFor={`access-audit-${c.id}`} className="font-normal">
                {c.label}
              </Label>
            </div>
          ))}
        </RadioGroup>
        <p className="text-xs text-muted-foreground">
          {category.description}{' '}
          <code className="font-mono">
            {'actionPrefix' in category.filter
              ? `${category.filter.actionPrefix}*`
              : category.filter.action}
          </code>
        </p>
      </fieldset>
      <DataTable<AuditRow>
        tableId="archive-access-audit"
        caption={`Access audit: ${category.label}`}
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `${row.action} at ${formatUtc(row.createdAt)}`}
        sort={{
          operationId: 'AuditLogsController_search_v1',
          columnId: 'createdAt',
          value: state.sort ?? '-createdAt',
          onChange: (sort) => setState({ sort: sort as '-createdAt' | 'createdAt' | undefined }),
        }}
        emptyState={
          <EmptyState
            title="No entries in this range"
            description="Nothing of this category was recorded in the selected range."
          />
        }
      />
      <AuditDetailSheet row={open} onClose={() => setOpen(null)} />
    </div>
  );
}
