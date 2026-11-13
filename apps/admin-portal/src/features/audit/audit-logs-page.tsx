'use client';

import { useMemo, useState } from 'react';
import { z } from 'zod';
import { Combobox } from '@/components/combobox';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { CopyableId } from '@/components/domain/copyable-id';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { UntrustedText, sanitizeDisplay } from '@/components/domain/untrusted-text';
import { PageHeader } from '@/components/page-header';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Switch } from '@/components/ui/switch';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import { ApiError } from '@/lib/api/errors';
import type { ListItem } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatUtc, humanize } from '@/lib/format';
import { cn } from '@/lib/utils';
import { SelectFilter, TextFilter, validateUuid } from '@/features/reports/filters';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import { navGate } from '@/features/reports/nav-gate';

type AuditRow = ListItem<'AuditLogsController_search_v1'>;
type LoginRow = ListItem<'LoginEventsController_list_v1'>;

const TABS: readonly TabDefinition[] = [
  { id: 'activity', label: 'Activity', ops: ['AuditLogsController_search_v1'] },
  { id: 'sign-in', label: 'Sign-in events', ops: ['LoginEventsController_list_v1'] },
  { id: 'platform', label: 'Platform', ops: ['PlatformAuditLogsController_search_v1'] },
];

const text = (max: number) => z.string().max(max).optional().catch(undefined);
export const AUDIT_URL_SHAPE = {
  action: text(100),
  actionPrefix: z
    .string()
    .regex(/^[a-z_]+\.$/)
    .max(64)
    .optional()
    .catch(undefined),
  resourceType: text(64),
  resourceId: text(64),
  actorType: z.enum(['user', 'system', 'api_key']).optional().catch(undefined),
  actorId: text(64),
  sort: z.enum(['-createdAt', 'createdAt']).optional().catch(undefined),
  organizationId: z.string().uuid().optional().catch(undefined),
  scope: z.enum(['platform']).optional().catch(undefined),
  userId: z.string().uuid().optional().catch(undefined),
  outcome: z
    .enum(['success', 'failure', 'locked', 'mfa_required', 'mfa_failure', 'rate_limited'])
    .optional()
    .catch(undefined),
};

/** `/audit-logs` (design §1.3 row 19): organization activity, sign-in events, platform trail. */
export function AuditLogsPage() {
  return (
    <RouteGate gate={navGate('audit-logs')}>
      <div className="flex flex-col gap-4">
        <PageHeader
          title="Audit logs"
          description="Who changed what, and every sign-in attempt. Searches of the activity log are themselves audited."
          actions={<RangePicker />}
        />
        <GatedTabs
          tabs={TABS}
          label="Audit logs"
          render={(tab) =>
            tab === 'activity' ? (
              <ActivityLog mode="tenant" />
            ) : tab === 'sign-in' ? (
              <SignInEvents />
            ) : (
              <PlatformLog />
            )
          }
        />
      </div>
    </RouteGate>
  );
}

/** `quarantine` → `quarantine.`; the api accepts `[a-z_]+.` prefixes only. */
export function normalizePrefix(value: string): string {
  const trimmed = value.trim();
  return trimmed && !trimmed.endsWith('.') ? `${trimmed}.` : trimmed;
}

function validatePrefix(value: string): string | null {
  return /^[a-z_]+\.$/.test(value)
    ? null
    : 'Use lower-case letters and underscores, e.g. quarantine.';
}

function ActorCell({ actor }: { actor: AuditRow['actor'] }) {
  return (
    <span className="flex min-w-0 flex-col gap-0.5">
      <span className="text-xs text-muted-foreground">{humanize(actor.type)}</span>
      {actor.id ? <CopyableId value={actor.id} label="actor ID" /> : null}
    </span>
  );
}

const auditColumns = (onOpen: (row: AuditRow) => void): DataTableColumn<AuditRow>[] => [
  {
    id: 'createdAt',
    header: 'Time',
    meta: { label: 'Time', className: 'whitespace-nowrap' },
    cell: ({ row }) => <DateTime value={row.original.createdAt} />,
  },
  {
    id: 'action',
    header: 'Action',
    meta: { label: 'Action' },
    cell: ({ row }) => <span className="font-mono text-xs">{row.original.action}</span>,
  },
  {
    id: 'actor',
    header: 'Actor',
    meta: { label: 'Actor' },
    cell: ({ row }) => <ActorCell actor={row.original.actor} />,
  },
  {
    id: 'resource',
    header: 'Resource',
    meta: { label: 'Resource' },
    cell: ({ row }) => (
      <span className="flex min-w-0 flex-col gap-0.5">
        <span className="font-mono text-xs">{row.original.resourceType}</span>
        {row.original.resourceId ? (
          <CopyableId value={row.original.resourceId} label="resource ID" />
        ) : null}
      </span>
    ),
  },
  {
    id: 'sourceIp',
    header: 'Source IP',
    meta: { label: 'Source IP' },
    cell: ({ row }) =>
      row.original.sourceIp ? (
        <span className="font-mono text-xs">{row.original.sourceIp}</span>
      ) : (
        <span className="text-muted-foreground">None</span>
      ),
  },
  {
    id: 'details',
    header: () => <span className="sr-only">Details</span>,
    meta: { label: 'Details', hideable: false },
    cell: ({ row }) => (
      <Button
        variant="outline"
        size="sm"
        onClick={() => onOpen(row.original)}
        aria-label={`Details of ${row.original.action} at ${formatUtc(row.original.createdAt)}`}
      >
        Details
      </Button>
    ),
  },
];

/** Activity of the organization (`GET /audit/logs`) or the platform trail (`GET /platform/audit/logs`). */
function ActivityLog({
  mode,
  target,
}: {
  mode: 'tenant' | 'platform';
  target?: { organizationId?: string; scope?: 'platform' };
}) {
  const [range] = useRangeState();
  const [state, setState] = useUrlState(AUDIT_URL_SHAPE);
  const [open, setOpen] = useState<AuditRow | null>(null);
  const filters = {
    from: range.from,
    to: range.to,
    ...(state.action ? { action: state.action } : {}),
    ...(state.actionPrefix && !state.action ? { actionPrefix: state.actionPrefix } : {}),
    ...(state.resourceType ? { resourceType: state.resourceType } : {}),
    ...(state.resourceId ? { resourceId: state.resourceId } : {}),
    ...(state.actorType ? { actorType: state.actorType } : {}),
    ...(state.actorId ? { actorId: state.actorId } : {}),
    ...(state.sort ? { sort: state.sort } : {}),
  };
  const tenantList = useCursorList('AuditLogsController_search_v1', filters, {
    enabled: mode === 'tenant',
  });
  const platformList = useCursorList(
    'PlatformAuditLogsController_search_v1',
    { ...filters, ...(target ?? {}) },
    { enabled: mode === 'platform' && Boolean(target?.organizationId || target?.scope) },
  );
  const list = mode === 'tenant' ? tenantList : platformList;
  const isFiltered = Boolean(
    state.action ||
    state.actionPrefix ||
    state.resourceType ||
    state.resourceId ||
    state.actorType ||
    state.actorId,
  );
  const columns = useMemo(() => auditColumns(setOpen), []);
  const mfaRequired =
    list.query.error instanceof ApiError &&
    list.query.error.status === 403 &&
    list.query.error.code === 'mfa_required';

  return (
    <div className="grid gap-3">
      {mfaRequired ? (
        <p
          role="note"
          className="rounded-md border border-input bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground"
        >
          The platform audit trail needs a session signed in with MFA. Sign out and sign in again
          with your authenticator code, then retry.
        </p>
      ) : null}
      <DataTable<AuditRow>
        tableId={mode === 'tenant' ? 'audit-activity' : 'audit-platform'}
        caption={mode === 'tenant' ? 'Audit log entries' : 'Platform audit log entries'}
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `${row.action} at ${formatUtc(row.createdAt)}`}
        sort={{
          operationId:
            mode === 'tenant'
              ? 'AuditLogsController_search_v1'
              : 'PlatformAuditLogsController_search_v1',
          columnId: 'createdAt',
          value: state.sort ?? '-createdAt',
          onChange: (sort) => setState({ sort: sort as '-createdAt' | 'createdAt' | undefined }),
        }}
        isFiltered={isFiltered}
        onClearFilters={() =>
          setState({
            action: undefined,
            actionPrefix: undefined,
            resourceType: undefined,
            resourceId: undefined,
            actorType: undefined,
            actorId: undefined,
          })
        }
        emptyState={
          <EmptyState
            title="No audit entries in this range"
            description="Nothing was recorded in the selected range."
          />
        }
        filters={
          <>
            <TextFilter
              label="Action (exact)"
              value={state.action}
              onChange={(action) => setState({ action })}
              placeholder="domain.created"
              mono
            />
            <TextFilter
              label="Action prefix"
              value={state.actionPrefix}
              onChange={(actionPrefix) => setState({ actionPrefix })}
              placeholder="quarantine."
              normalize={normalizePrefix}
              validate={validatePrefix}
              mono
            />
            <TextFilter
              label="Resource type"
              value={state.resourceType}
              onChange={(resourceType) => setState({ resourceType })}
              placeholder="domain"
              mono
            />
            <TextFilter
              label="Resource ID"
              value={state.resourceId}
              onChange={(resourceId) => setState({ resourceId })}
              mono
            />
            <SelectFilter
              label="Actor type"
              value={state.actorType}
              onChange={(actorType) => setState({ actorType })}
              options={[
                { value: 'user', label: 'User' },
                { value: 'system', label: 'System' },
                { value: 'api_key', label: 'API key' },
              ]}
            />
            <TextFilter
              label="Actor ID"
              value={state.actorId}
              onChange={(actorId) => setState({ actorId })}
              mono
            />
          </>
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <span className="font-mono text-xs">{row.action}</span>
            <DateTime value={row.createdAt} />
            <span className="text-xs text-muted-foreground">
              {humanize(row.actor.type)} · {row.resourceType}
            </span>
            <Button
              variant="outline"
              size="sm"
              className="justify-self-start"
              onClick={() => setOpen(row)}
            >
              Details
            </Button>
          </div>
        )}
      />
      {state.action && state.actionPrefix ? (
        <p className="text-xs text-muted-foreground">
          The exact action wins; the prefix is not sent while an exact action is set.
        </p>
      ) : null}
      <AuditDetailSheet row={open} onClose={() => setOpen(null)} />
    </div>
  );
}

/** Row detail: every field as text; metadata as JSON text (never HTML). */
export function AuditDetailSheet({ row, onClose }: { row: AuditRow | null; onClose: () => void }) {
  return (
    <Sheet open={row !== null} onOpenChange={(next) => (!next ? onClose() : undefined)}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        {row ? (
          <>
            <SheetHeader>
              <SheetTitle className="font-mono text-sm">{row.action}</SheetTitle>
              <SheetDescription>{formatUtc(row.createdAt)}</SheetDescription>
            </SheetHeader>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-2 px-4 text-sm">
              <dt className="text-muted-foreground">Entry ID</dt>
              <dd>
                <CopyableId value={row.id} label="entry ID" max={28} />
              </dd>
              <dt className="text-muted-foreground">Actor</dt>
              <dd>
                <ActorCell actor={row.actor} />
              </dd>
              <dt className="text-muted-foreground">Resource</dt>
              <dd className="grid gap-0.5">
                <span className="font-mono text-xs">{row.resourceType}</span>
                {row.resourceId ? (
                  <CopyableId value={row.resourceId} label="resource ID" max={28} />
                ) : null}
              </dd>
              <dt className="text-muted-foreground">Source IP</dt>
              <dd className="font-mono text-xs">{row.sourceIp ?? 'None'}</dd>
              <dt className="text-muted-foreground">Correlation ID</dt>
              <dd>
                {row.correlationId ? (
                  <CopyableId value={row.correlationId} label="correlation ID" max={28} />
                ) : (
                  'None'
                )}
              </dd>
            </dl>
            <div className="grid gap-1 px-4 pb-4">
              <h3 className="text-sm font-semibold">Metadata</h3>
              {row.metadata ? (
                <pre
                  className="max-h-96 overflow-auto rounded-md border bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all"
                  data-testid="audit-metadata"
                >
                  {sanitizeDisplay(JSON.stringify(row.metadata, null, 2))}
                </pre>
              ) : (
                <p className="text-sm text-muted-foreground">No metadata.</p>
              )}
            </div>
          </>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}

const OUTCOME_TONE: Record<
  LoginRow['outcome'],
  'success' | 'danger' | 'warning' | 'orange' | 'info'
> = {
  success: 'success',
  failure: 'danger',
  locked: 'orange',
  mfa_required: 'info',
  mfa_failure: 'danger',
  rate_limited: 'warning',
};

const loginColumns: DataTableColumn<LoginRow>[] = [
  {
    id: 'occurredAt',
    header: 'Time',
    meta: { label: 'Time' },
    cell: ({ row }) => <DateTime value={row.original.occurredAt} />,
  },
  {
    id: 'email',
    header: 'Email',
    meta: { label: 'Email' },
    cell: ({ row }) => <UntrustedText value={row.original.email} maxLength={60} />,
  },
  {
    id: 'outcome',
    header: 'Outcome',
    meta: { label: 'Outcome' },
    cell: ({ row }) => (
      <ToneBadge tone={OUTCOME_TONE[row.original.outcome]}>
        {humanize(row.original.outcome)}
      </ToneBadge>
    ),
  },
  {
    id: 'failureReason',
    header: 'Reason',
    meta: { label: 'Reason' },
    cell: ({ row }) =>
      row.original.failureReason ? (
        <span className="font-mono text-xs">{row.original.failureReason}</span>
      ) : (
        <span className="text-muted-foreground">None</span>
      ),
  },
  {
    id: 'ipAddress',
    header: 'IP address',
    meta: { label: 'IP address' },
    cell: ({ row }) => (
      <span className="font-mono text-xs">{row.original.ipAddress ?? 'Unknown'}</span>
    ),
  },
  {
    id: 'userAgent',
    header: 'User agent',
    meta: { label: 'User agent' },
    cell: ({ row }) => (
      <UntrustedText value={row.original.userAgent} maxLength={48} emptyLabel="Unknown" />
    ),
  },
  {
    id: 'userId',
    header: 'User',
    meta: { label: 'User' },
    cell: ({ row }) =>
      row.original.userId ? (
        <CopyableId value={row.original.userId} label="user ID" />
      ) : (
        <span className="text-muted-foreground">No account</span>
      ),
  },
];

function SignInEvents() {
  const [range] = useRangeState();
  const [state, setState] = useUrlState(AUDIT_URL_SHAPE);
  const list = useCursorList('LoginEventsController_list_v1', {
    from: range.from,
    to: range.to,
    ...(state.userId ? { userId: state.userId } : {}),
    ...(state.outcome ? { outcome: state.outcome } : {}),
  });
  return (
    <DataTable<LoginRow>
      tableId="audit-sign-in"
      caption="Sign-in events"
      columns={loginColumns}
      list={list}
      getRowId={(row) => row.id}
      getRowLabel={(row) => `sign-in at ${formatUtc(row.occurredAt)}`}
      isFiltered={Boolean(state.userId || state.outcome)}
      onClearFilters={() => setState({ userId: undefined, outcome: undefined })}
      emptyState={<EmptyState title="No sign-in events in this range" />}
      filters={
        <>
          <TextFilter
            label="User ID"
            value={state.userId}
            onChange={(userId) => setState({ userId })}
            validate={validateUuid}
            mono
          />
          <SelectFilter
            label="Outcome"
            value={state.outcome}
            onChange={(outcome) => setState({ outcome })}
            options={(
              [
                'success',
                'failure',
                'locked',
                'mfa_required',
                'mfa_failure',
                'rate_limited',
              ] as const
            ).map((value) => ({ value, label: humanize(value) }))}
          />
        </>
      }
      mobileCard={(row) => (
        <div className="grid gap-1 text-sm">
          <UntrustedText value={row.email} maxLength={48} />
          <span className="flex items-center gap-2">
            <ToneBadge tone={OUTCOME_TONE[row.outcome]}>{humanize(row.outcome)}</ToneBadge>
            <DateTime value={row.occurredAt} />
          </span>
        </div>
      )}
    />
  );
}

/** Platform trail: exactly one target, an organization (picked from `GET /organizations`) or the platform scope. */
function PlatformLog() {
  const [state, setState] = useUrlState(AUDIT_URL_SHAPE);
  const [search, setSearch] = useState('');
  const organizations = useApiQuery('OrganizationsController_list_v1', {
    query: { limit: 25, ...(search ? { q: search } : {}) },
  });
  const inList = Boolean(organizations.data?.data.some((o) => o.id === state.organizationId));
  // The chosen organization's name when it is not on the current search page (shared link).
  const selected = useApiQuery(
    'OrganizationsController_get_v1',
    { path: { id: state.organizationId ?? '' } },
    { enabled: Boolean(state.organizationId) && organizations.isSuccess && !inList },
  );
  const options = useMemo(() => {
    const rows = organizations.data?.data ?? [];
    const list = rows.map((o) => ({ value: o.id, label: o.name, description: o.slug }));
    if (selected.data && !list.some((o) => o.value === selected.data.id)) {
      list.unshift({
        value: selected.data.id,
        label: selected.data.name,
        description: selected.data.slug,
      });
    }
    return list;
  }, [organizations.data, selected.data]);
  const platformScope = state.scope === 'platform';
  const target = platformScope
    ? { scope: 'platform' as const }
    : state.organizationId
      ? { organizationId: state.organizationId }
      : undefined;
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-end gap-4 rounded-lg border bg-card p-3">
        <div className="grid min-w-64 gap-1">
          <Label className="text-xs" htmlFor="platform-audit-org">
            Organization
          </Label>
          <Combobox
            id="platform-audit-org"
            label="Organization to search"
            options={options}
            value={state.organizationId ?? null}
            onChange={(organizationId) =>
              setState({ organizationId: organizationId ?? undefined, scope: undefined })
            }
            onSearch={(q) => setSearch(q.trim().slice(0, 63))}
            loading={organizations.isFetching}
            disabled={platformScope}
            placeholder="Choose an organization …"
            searchPlaceholder="Search organizations"
          />
        </div>
        <div className="flex items-center gap-2 pb-1">
          <Switch
            id="platform-audit-scope"
            checked={platformScope}
            onCheckedChange={(checked) =>
              setState({ scope: checked ? 'platform' : undefined, organizationId: undefined })
            }
          />
          <Label htmlFor="platform-audit-scope">
            Platform scope (rows without an organization)
          </Label>
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        Platform searches need <code className="font-mono">platform:operations</code> and{' '}
        <code className="font-mono">audit:read</code> and an MFA session; each search is audited in
        the searched trail.
      </p>
      {target ? (
        <ActivityLog mode="platform" target={target} />
      ) : (
        <div className={cn('rounded-lg border bg-card')}>
          <EmptyState
            title="Choose what to search"
            description="Pick an organization, or switch on the platform scope."
          />
        </div>
      )}
    </div>
  );
}
