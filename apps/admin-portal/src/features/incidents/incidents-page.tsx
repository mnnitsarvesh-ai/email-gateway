'use client';

import { SirenIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useId, useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useCursorList } from '@/lib/api/hooks';
import { useCan, useMe } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { EnumBadge, FilterMultiSelect, FilterSelect } from '@/features/messages/controls';
import { AtoReasonDialog } from '@/features/ato/components';
import {
  categoryLabel,
  categoryUi,
  useManageableCategories,
  useReadableCategories,
} from './categories';
import {
  INCIDENT_SEVERITIES,
  INCIDENT_STATUSES,
  SEVERITY_TONE,
  STATUS_LABELS,
  STATUS_TONE,
  incidentHref,
  type IncidentSeverity,
  type IncidentSummary,
} from './model';

export const INCIDENTS_URL_SHAPE = {
  category: z
    .array(z.string().regex(/^[a-z][a-z0-9_]{0,47}$/))
    .max(10)
    .default([]),
  status: z.array(z.enum(INCIDENT_STATUSES)).max(6).default([]),
  severity: z.array(z.enum(INCIDENT_SEVERITIES)).max(4).default([]),
  assignee: z.enum(['me', 'unassigned']).optional(),
  sort: z.enum(['-detectedAt', '-severity']).default('-detectedAt'),
};

/** `/incidents`: the generic security incident list (step 8.4 §6, D24). */
export function IncidentsPage() {
  return (
    <RouteGate gate={['IncidentsController_list_v1']}>
      <IncidentsContent />
    </RouteGate>
  );
}

function IncidentsContent() {
  const [state, setState] = useUrlState(INCIDENTS_URL_SHAPE);
  const readable = useReadableCategories();
  const me = useMe();
  // Only readable categories are offered; an unreadable one in the URL is dropped (the api would
  // answer nothing for it anyway).
  const categories = state.category.filter((c) => readable.some((r) => r.id === c));
  const filters = useMemo(
    () => ({
      sort: state.sort,
      ...(categories.length ? { category: categories.join(',') } : {}),
      ...(state.status.length ? { status: state.status.join(',') } : {}),
      ...(state.severity.length ? { severity: state.severity.join(',') } : {}),
      ...(state.assignee ? { assignee: state.assignee } : {}),
    }),
    [state.sort, categories, state.status, state.severity, state.assignee],
  );
  const list = useCursorList('IncidentsController_list_v1', filters, { limit: 25 });
  const myId = me.data?.user.id;
  const columns: DataTableColumn<IncidentSummary>[] = [
    {
      id: 'incident',
      header: 'Incident',
      meta: { label: 'Incident', hideable: false },
      cell: ({ row }) => (
        <div className="grid gap-0.5">
          <Link
            href={incidentHref(row.original.id)}
            className="font-medium text-primary underline-offset-2 hover:underline"
          >
            {row.original.subject.display ?? row.original.subject.id}
          </Link>
          <span className="text-xs text-muted-foreground">
            {categoryLabel(row.original.category)}
            {row.original.titleCode ? ` · ${row.original.titleCode}` : ''}
          </span>
        </div>
      ),
    },
    {
      id: 'severity',
      header: 'Severity',
      meta: { label: 'Severity' },
      cell: ({ row }) => <EnumBadge value={row.original.severity} tones={SEVERITY_TONE} />,
    },
    {
      id: 'status',
      header: 'Status',
      meta: { label: 'Status' },
      cell: ({ row }) => <EnumBadge value={row.original.status} tones={STATUS_TONE} />,
    },
    {
      id: 'detected',
      header: 'Detected',
      meta: { label: 'Detected' },
      cell: ({ row }) => (
        <span className="grid gap-0.5">
          <DateTime value={row.original.detectedAt} />
          <span className="text-xs text-muted-foreground">
            {row.original.origin === 'manual' ? 'Opened manually' : 'Detection'}
          </span>
        </span>
      ),
    },
    {
      id: 'assignee',
      header: 'Assignee',
      meta: { label: 'Assignee' },
      cell: ({ row }) =>
        !row.original.assigneeId ? (
          <span className="text-muted-foreground">Unassigned</span>
        ) : row.original.assigneeId === myId ? (
          'You'
        ) : (
          <span className="text-xs">Another analyst</span>
        ),
    },
    {
      id: 'evidence',
      header: 'Evidence',
      meta: { label: 'Evidence' },
      cell: ({ row }) => (
        <span className="grid gap-0.5 text-xs">
          <span>{row.original.evidenceCount} items</span>
          {row.original.lastEvidenceAt ? (
            <span className="text-muted-foreground">
              Last <DateTime value={row.original.lastEvidenceAt} />
            </span>
          ) : null}
        </span>
      ),
    },
  ];
  const filtered =
    categories.length > 0 ||
    state.status.length > 0 ||
    state.severity.length > 0 ||
    state.assignee !== undefined;
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="Incidents"
        description="Security incidents of every category you may read, with their investigation state. Account takeover is the first category."
        actions={<NewIncidentButton />}
      />
      <DataTable
        tableId="incidents"
        caption="Security incidents"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.subject.display ?? row.id}
        filters={
          <div className="flex flex-wrap items-end gap-3">
            {readable.length > 1 ? (
              <FilterMultiSelect
                label="Category"
                values={categories}
                options={readable.map((c) => ({ value: c.id, label: c.label }))}
                onChange={(category) => setState({ category })}
              />
            ) : (
              <FilterSelect
                label="Category"
                value={categories[0]}
                anyLabel="Every category you can read"
                options={readable.map((c) => ({ value: c.id, label: c.label }))}
                onChange={(category) => setState({ category: category ? [category] : [] })}
              />
            )}
            <FilterMultiSelect
              label="Status"
              values={state.status}
              options={INCIDENT_STATUSES.map((s) => ({ value: s, label: STATUS_LABELS[s] }))}
              onChange={(status) => setState({ status: status as typeof state.status })}
            />
            <FilterMultiSelect
              label="Severity"
              values={state.severity}
              options={INCIDENT_SEVERITIES.map((s) => ({
                value: s,
                label: s.charAt(0).toUpperCase() + s.slice(1),
              }))}
              onChange={(severity) => setState({ severity: severity as typeof state.severity })}
            />
            <FilterSelect
              label="Assignee"
              value={state.assignee}
              options={[
                { value: 'me', label: 'Assigned to me' },
                { value: 'unassigned', label: 'Unassigned' },
              ]}
              onChange={(assignee) =>
                setState({ assignee: assignee as 'me' | 'unassigned' | undefined })
              }
            />
            <FilterSelect
              label="Sort by"
              allowAny={false}
              value={state.sort}
              options={[
                { value: '-detectedAt', label: 'Newest first' },
                { value: '-severity', label: 'Most severe first' },
              ]}
              onChange={(sort) =>
                setState({ sort: (sort as '-detectedAt' | '-severity') ?? '-detectedAt' })
              }
            />
          </div>
        }
        isFiltered={filtered}
        onClearFilters={() =>
          setState({ category: [], status: [], severity: [], assignee: undefined })
        }
        emptyState={
          <EmptyState
            icon={SirenIcon}
            title="No incidents"
            description="Incidents open when detection finds a compromised account, or when an analyst opens one."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <Link href={incidentHref(row.id)} className="font-medium text-primary hover:underline">
              {row.subject.display ?? row.subject.id}
            </Link>
            <span className="flex gap-1.5">
              <EnumBadge value={row.severity} tones={SEVERITY_TONE} />
              <EnumBadge value={row.status} tones={STATUS_TONE} />
            </span>
          </div>
        )}
      />
    </div>
  );
}

/** "New incident": a manual incident of a manageable category (§5.2 I2). */
function NewIncidentButton() {
  const can = useCan('IncidentsController_create_v1');
  const manageable = useManageableCategories();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [category, setCategory] = useState<string>(manageable[0]?.id ?? '');
  const [subject, setSubject] = useState<{ id: string; label: string } | null>(null);
  const [severity, setSeverity] = useState<IncidentSeverity>('medium');
  const categoryId = useId();
  const severityId = useId();
  const create = useApiMutation('IncidentsController_create_v1', {
    invalidates: ['IncidentsController_list_v1'],
    successMessage: 'Incident opened',
    onSuccess: (data) => router.push(incidentHref(data.id)),
  });
  if (!can || manageable.length === 0) return null;
  const ui = categoryUi(category);
  return (
    <>
      <Button onClick={() => setOpen(true)}>New incident</Button>
      <AtoReasonDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) setSubject(null);
        }}
        title="Open an incident"
        description="Open an incident manually, for example after a user reported suspicious activity. The subject may have at most one active incident."
        confirmLabel="Open incident"
        reasonLabel="Why"
        maxChars={4000}
        disabled={!subject || !ui}
        pending={create.isPending}
        extra={
          <div className="grid gap-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label htmlFor={categoryId}>Category</Label>
                <Select
                  value={category}
                  onValueChange={(v) => {
                    setCategory(v);
                    setSubject(null);
                  }}
                >
                  <SelectTrigger id={categoryId}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {manageable.map((c) => (
                      <SelectItem key={c.id} value={c.id}>
                        {c.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor={severityId}>Severity</Label>
                <Select value={severity} onValueChange={(v) => setSeverity(v as IncidentSeverity)}>
                  <SelectTrigger id={severityId}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {INCIDENT_SEVERITIES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s.charAt(0).toUpperCase() + s.slice(1)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            {ui ? <ui.SubjectPicker value={subject} onChange={setSubject} /> : null}
          </div>
        }
        onSubmit={(reason) =>
          create.submit({
            body: {
              category,
              subject: { type: ui?.subjectType ?? '', id: subject?.id ?? '' },
              severity,
              reason: reason ?? '',
            },
          })
        }
        onRetry={create.retry}
      />
    </>
  );
}
