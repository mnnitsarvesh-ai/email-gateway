'use client';

import { BriefcaseIcon, PlusIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMemo, useState } from 'react';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime, UntrustedText } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useApiMutation, useCursorList } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { FormDialog, splitList } from '@/features/domains/kit';
import { EnumBadge, FilterSelect } from '@/features/messages/controls';
import { ArchiveErrorSummary, Notice } from '@/features/archive/components';
import {
  CASE_STATUS_TONE,
  caseHref,
  type EdiscoveryCaseSummary,
  useArchiveAccess,
} from '@/features/archive/model';

const EMAIL = /^[^\s@<>()",;]+@[^\s@<>()",;]+\.[^\s@<>()",;]+$/;

export interface CaseDraft {
  name: string;
  description: string;
  matterReference: string;
  custodians: string;
}

/** Validation of a case draft (`field → message`). */
export function caseDraftErrors(draft: CaseDraft): Record<string, string> {
  const errors: Record<string, string> = {};
  const name = draft.name.trim();
  if (!name) errors.name = 'Enter a case name';
  else if (name.length > 200) errors.name = 'Use at most 200 characters';
  if (draft.description.length > 4096) errors.description = 'Use at most 4 096 characters';
  if (draft.matterReference.trim().length > 200)
    errors.matterReference = 'Use at most 200 characters';
  const custodians = splitList(draft.custodians);
  const bad = custodians.filter((c) => !EMAIL.test(c));
  if (bad.length > 0) errors.custodians = `Not an email address: ${bad.slice(0, 3).join(', ')}`;
  else if (custodians.length > 10_000) errors.custodians = 'At most 10 000 custodians';
  return errors;
}

/** Normalized custodian addresses (lower case, unique). */
export function custodianList(text: string): string[] {
  return [...new Set(splitList(text).map((c) => c.toLowerCase()))];
}

export function caseCreateBody(
  draft: CaseDraft,
): RequestBody<'EdiscoveryCasesController_create_v1'> {
  const custodians = custodianList(draft.custodians);
  return {
    name: draft.name.trim(),
    ...(draft.description.trim() ? { description: draft.description.trim() } : {}),
    ...(draft.matterReference.trim() ? { matterReference: draft.matterReference.trim() } : {}),
    ...(custodians.length > 0 ? { custodians } : {}),
  };
}

/** eDiscovery cases (`/ediscovery`, step 8.1 A18, A28). */
export function CasesPage() {
  return (
    <RouteGate gate={['EdiscoveryCasesController_list_v1']}>
      <CasesContent />
    </RouteGate>
  );
}

function CasesContent() {
  const [status, setStatus] = useState<string | undefined>('open');
  const filters = useMemo(
    () => ({ sort: '-id' as const, ...(status ? { status } : {}) }),
    [status],
  );
  const list = useCursorList('EdiscoveryCasesController_list_v1', filters, { limit: 25 });
  const [creating, setCreating] = useState(false);
  const columns: DataTableColumn<EdiscoveryCaseSummary>[] = [
    {
      id: 'name',
      header: 'Case',
      meta: { label: 'Case', hideable: false },
      cell: ({ row }) => (
        <Link
          href={caseHref(row.original.id)}
          className="font-medium text-primary underline-offset-2 hover:underline"
        >
          <UntrustedText value={row.original.name} maxLength={80} />
        </Link>
      ),
    },
    {
      id: 'matter',
      header: 'Matter',
      meta: { label: 'Matter reference' },
      cell: ({ row }) => (
        <UntrustedText value={row.original.matterReference} emptyLabel="—" maxLength={60} />
      ),
    },
    {
      id: 'status',
      header: 'Status',
      meta: { label: 'Status' },
      cell: ({ row }) => <EnumBadge value={row.original.status} tones={CASE_STATUS_TONE} />,
    },
    {
      id: 'createdAt',
      header: 'Opened',
      meta: { label: 'Opened' },
      cell: ({ row }) => <DateTime value={row.original.createdAt} />,
    },
    {
      id: 'updatedAt',
      header: 'Updated',
      meta: { label: 'Updated' },
      cell: ({ row }) => <DateTime value={row.original.updatedAt} />,
    },
  ];
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="eDiscovery"
        description="Cases group custodians, legal holds, searches of the archive, review and exports with a signed chain-of-custody manifest. Every action is audited."
        actions={
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon aria-hidden />
            New case
          </Button>
        }
      />
      <Notice>
        <span>
          Everyone with ediscovery:manage sees every case of the organization. Holds need
          archive:legal_hold as well; exports need archive:export.
        </span>
      </Notice>
      <DataTable
        tableId="ediscovery-cases"
        caption="eDiscovery cases"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        filters={
          <FilterSelect
            label="Status"
            value={status}
            anyLabel="All"
            options={[
              { value: 'open', label: 'Open' },
              { value: 'closed', label: 'Closed' },
            ]}
            onChange={setStatus}
          />
        }
        isFiltered={status !== 'open'}
        onClearFilters={() => setStatus('open')}
        emptyState={
          <EmptyState
            icon={BriefcaseIcon}
            title="No case"
            description="Open a case to place holds, search and export."
          />
        }
      />
      {creating ? <CreateCaseDialog onClose={() => setCreating(false)} /> : null}
    </div>
  );
}

function CreateCaseDialog({ onClose }: { onClose: () => void }) {
  const router = useRouter();
  // Custodian addresses drive case searches and holds: writing them needs message:reveal.
  const canWriteCustodians = useArchiveAccess().reveal;
  const [draft, setDraft] = useState<CaseDraft>({
    name: '',
    description: '',
    matterReference: '',
    custodians: '',
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const create = useApiMutation('EdiscoveryCasesController_create_v1', {
    successMessage: 'Case opened',
    invalidates: ['EdiscoveryCasesController_list_v1'],
  });
  const set = (patch: Partial<CaseDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const submit = async () => {
    const found = caseDraftErrors(draft);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    const outcome = await create.submit({ body: caseCreateBody(draft) });
    if (outcome.ok) {
      onClose();
      router.push(caseHref(outcome.data.id));
    } else if (outcome.error.code === 'ediscovery_case_name_taken') {
      setErrors({ name: 'A case with this name already exists.' });
    }
  };
  return (
    <FormDialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title="New eDiscovery case"
      wide
    >
      <form
        className="grid gap-4"
        noValidate
        aria-label="New eDiscovery case"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <ArchiveErrorSummary
          error={
            create.error && create.error.code !== 'ediscovery_case_name_taken' ? create.error : null
          }
        />
        <CaseFields draft={draft} set={set} errors={errors} withCustodians={canWriteCustodians} />
        {canWriteCustodians ? null : <CustodiansNeedReveal />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={create.isPending}>
            {create.isPending ? 'Opening …' : 'Open case'}
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

/** Why the custodian editor is not offered to a caller without `message:reveal`. */
export function CustodiansNeedReveal() {
  return (
    <p className="text-xs text-muted-foreground">
      Custodian addresses can be set only by users who may reveal recipients (message:reveal): a
      custodian search or hold would confirm which messages an address received.
    </p>
  );
}

/** Name, matter, description (and optionally custodians) of a case form. */
export function CaseFields({
  draft,
  set,
  errors,
  withCustodians = false,
}: {
  draft: CaseDraft;
  set: (patch: Partial<CaseDraft>) => void;
  errors: Record<string, string>;
  withCustodians?: boolean;
}) {
  return (
    <>
      <div className="grid gap-1">
        <Label htmlFor="case-name">Case name (required)</Label>
        <Input
          id="case-name"
          value={draft.name}
          maxLength={200}
          onChange={(e) => set({ name: e.target.value })}
          aria-invalid={errors.name ? true : undefined}
        />
        {errors.name ? <p className="text-xs font-medium text-destructive">{errors.name}</p> : null}
      </div>
      <div className="grid gap-1">
        <Label htmlFor="case-matter">Matter reference</Label>
        <Input
          id="case-matter"
          value={draft.matterReference}
          maxLength={200}
          onChange={(e) => set({ matterReference: e.target.value })}
          aria-invalid={errors.matterReference ? true : undefined}
        />
        {errors.matterReference ? (
          <p className="text-xs font-medium text-destructive">{errors.matterReference}</p>
        ) : null}
      </div>
      <div className="grid gap-1">
        <Label htmlFor="case-description">Description</Label>
        <Textarea
          id="case-description"
          rows={3}
          value={draft.description}
          onChange={(e) => set({ description: e.target.value })}
          aria-invalid={errors.description ? true : undefined}
        />
        {errors.description ? (
          <p className="text-xs font-medium text-destructive">{errors.description}</p>
        ) : null}
      </div>
      {withCustodians ? (
        <div className="grid gap-1">
          <Label htmlFor="case-custodians">Custodians (email addresses, one per line)</Label>
          <Textarea
            id="case-custodians"
            rows={4}
            value={draft.custodians}
            onChange={(e) => set({ custodians: e.target.value })}
            aria-invalid={errors.custodians ? true : undefined}
            aria-describedby="case-custodians-help"
          />
          <p id="case-custodians-help" className="text-xs text-muted-foreground">
            The people whose mail the case concerns (sender or recipient). Can be changed later.
          </p>
          {errors.custodians ? (
            <p className="text-xs font-medium text-destructive">{errors.custodians}</p>
          ) : null}
        </div>
      ) : null}
    </>
  );
}
