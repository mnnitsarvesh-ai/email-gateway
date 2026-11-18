'use client';

import {
  CheckCircle2Icon,
  DownloadIcon,
  GavelIcon,
  LockIcon,
  PackageIcon,
  PencilIcon,
  SaveIcon,
  SearchIcon,
  TriangleAlertIcon,
} from 'lucide-react';
import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { CopyableId, DateTime, UntrustedText } from '@/components/domain';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatBytes, formatNumber, humanize } from '@/lib/format';
import { FormDialog, isUuid } from '@/features/domains/kit';
import { DetailList, EnumBadge, Section } from '@/features/messages/controls';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import {
  ArchiveErrorSummary,
  ArchiveQueryError,
  ConflictDialog,
  Notice,
} from '@/features/archive/components';
import { GrantDownloadDialog } from '@/features/archive/download-dialog';
import {
  ARCHIVE_DIRECTIONS,
  CASE_SEARCH_MAX_RANGE_DAYS,
  CASE_STATUS_TONE,
  DEFAULT_EXPORT_TAGS,
  HOLD_STATUS_TONE,
  JOB_STATUS_TONE,
  REVIEW_TAGS,
  caseSearchHref,
  conflictVersion,
  contentBlocker,
  legalHoldHref,
  stringList,
  useArchiveAccess,
  type EdiscoveryCase,
  type EdiscoveryExport,
  type EdiscoverySearch,
  type ReviewTag,
} from '@/features/archive/model';
import { ArchiveFilters, DayRangeFields } from '@/features/archive/search-filters';
import {
  DEFAULT_ARCHIVE_STATE,
  caseSearchCriteria,
  customRangeError,
  riskError,
  type ArchiveSearchPatch,
  type ArchiveSearchState,
} from '@/features/archive/search-state';
import {
  CaseFields,
  caseDraftErrors,
  CustodiansNeedReveal,
  custodianList,
  type CaseDraft,
} from './cases-page';
import { ReleaseHoldDialog } from './legal-holds';
import { JOB_POLL_MS, completenessOf, isActiveJob } from './model';

export const CASE_TABS: readonly TabDefinition[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'custodians', label: 'Custodians' },
  { id: 'holds', label: 'Legal holds', ops: ['LegalHoldsController_list_v1'] },
  { id: 'searches', label: 'Searches', ops: ['EdiscoverySearchesController_list_v1'] },
  { id: 'exports', label: 'Exports', ops: ['EdiscoveryExportsController_list_v1'] },
];

/** One eDiscovery case (`/ediscovery/[caseId]`, step 8.1 A18, A28). */
export function CasePage({ caseId }: { caseId: string }) {
  return (
    <RouteGate gate={['EdiscoveryCasesController_get_v1']}>
      {isUuid(caseId) ? <CaseContent caseId={caseId} /> : <NotFoundView />}
    </RouteGate>
  );
}

function CaseContent({ caseId }: { caseId: string }) {
  const query = useApiQuery('EdiscoveryCasesController_get_v1', { path: { caseId } });
  const crumbs = [{ label: 'eDiscovery', href: '/ediscovery' }, { label: 'Case' }];
  if (query.isLoading) return <LoadingState label="Loading the case" rows={6} />;
  if (query.error || !query.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title="eDiscovery case" breadcrumbs={crumbs} />
        <ArchiveQueryError error={query.error} onRetry={() => void query.refetch()} />
      </div>
    );
  }
  const c = query.data;
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title={c.name}
        breadcrumbs={crumbs}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <EnumBadge value={c.status} tones={CASE_STATUS_TONE} />
            {c.matterReference ? (
              <span>
                Matter <UntrustedText value={c.matterReference} maxLength={80} />
              </span>
            ) : null}
            <span>
              {formatNumber(c.counts.custodians)} custodians · {formatNumber(c.counts.activeHolds)}{' '}
              active holds · {formatNumber(c.counts.searches)} searches ·{' '}
              {formatNumber(c.counts.exports)} exports
            </span>
          </span>
        }
      />
      {c.status === 'closed' ? (
        <Notice tone="warning" icon={LockIcon}>
          <span>This case is closed: it can be read but no longer changed.</span>
        </Notice>
      ) : null}
      <GatedTabs
        tabs={CASE_TABS}
        label="Case"
        keepParams={[]}
        render={(tab) => {
          switch (tab) {
            case 'custodians':
              return <CustodiansTab record={c} />;
            case 'holds':
              return <HoldsTab record={c} />;
            case 'searches':
              return <SearchesTab record={c} />;
            case 'exports':
              return <ExportsTab record={c} />;
            default:
              return <OverviewTab record={c} />;
          }
        }}
      />
    </div>
  );
}

// ---- overview ------------------------------------------------------------------------------

function OverviewTab({ record }: { record: EdiscoveryCase }) {
  const [editing, setEditing] = useState(false);
  const [closing, setClosing] = useState(false);
  const close = useApiMutation('EdiscoveryCasesController_close_v1', {
    successMessage: 'Case closed',
    invalidates: ['EdiscoveryCasesController_get_v1', 'EdiscoveryCasesController_list_v1'],
  });
  const open = record.status === 'open';
  return (
    <Section
      title="Case"
      actions={
        open ? (
          <>
            <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
              <PencilIcon aria-hidden />
              Edit
            </Button>
            <Button variant="outline" size="sm" onClick={() => setClosing(true)}>
              <LockIcon aria-hidden />
              Close case
            </Button>
          </>
        ) : null
      }
    >
      <DetailList
        items={[
          { label: 'Case', value: <CopyableId value={record.id} label="case ID" /> },
          { label: 'Status', value: <EnumBadge value={record.status} tones={CASE_STATUS_TONE} /> },
          {
            label: 'Matter reference',
            value: <UntrustedText value={record.matterReference} emptyLabel="None" />,
          },
          {
            label: 'Description',
            value: <UntrustedText value={record.description} emptyLabel="None" maxLength={2000} />,
          },
          { label: 'Opened', value: <DateTime value={record.createdAt} mode="absolute" /> },
          { label: 'Updated', value: <DateTime value={record.updatedAt} mode="absolute" /> },
          {
            label: 'Closed',
            value: <DateTime value={record.closedAt} mode="absolute" emptyLabel="Open" />,
          },
        ]}
      />
      {editing ? <EditCaseDialog record={record} onClose={() => setEditing(false)} /> : null}
      <ConfirmDialog
        open={closing}
        onOpenChange={(next) => {
          setClosing(next);
          if (!next) close.reset();
        }}
        title="Close this case?"
        description={
          <p>
            A closed case keeps its searches, exports and audit trail but can no longer be changed.
            Release its active legal holds first. Closing needs a session signed in with MFA.
          </p>
        }
        confirmLabel="Close case"
        pending={close.isPending}
        error={<ArchiveErrorSummary error={close.error} />}
        onConfirm={async () => (await close.submit({ path: { caseId: record.id } })).ok}
      />
    </Section>
  );
}

type CasePatch = RequestBody<'EdiscoveryCasesController_update_v1'>;

/** A CAS `PATCH /ediscovery/cases/{caseId}` with the reload/overwrite conflict dialog. */
function useCasePatch(record: EdiscoveryCase, onDone: () => void) {
  const [conflict, setConflict] = useState<{
    version: number;
    body: Omit<CasePatch, 'expectedRowVersion'>;
  } | null>(null);
  const patch = useApiMutation('EdiscoveryCasesController_update_v1', {
    successMessage: 'Case saved',
    invalidates: ['EdiscoveryCasesController_get_v1', 'EdiscoveryCasesController_list_v1'],
  });
  const save = async (body: Omit<CasePatch, 'expectedRowVersion'>, version = record.rowVersion) => {
    const outcome = await patch.submit({
      path: { caseId: record.id },
      body: { ...body, expectedRowVersion: version },
    });
    if (outcome.ok) {
      onDone();
      return outcome;
    }
    const current = conflictVersion(outcome.error);
    if (outcome.error.code === 'ediscovery_case_conflict' && current !== null) {
      setConflict({ version: current, body });
    }
    return outcome;
  };
  const dialog = (
    <ConflictDialog
      open={conflict !== null}
      onOpenChange={(next) => {
        if (!next) setConflict(null);
      }}
      what="case"
      onReload={() => {
        setConflict(null);
        patch.reset();
        onDone();
      }}
      onOverwrite={async () => {
        if (!conflict) return;
        const { version, body } = conflict;
        setConflict(null);
        await save(body, version);
      }}
    />
  );
  return { save, mutation: patch, dialog };
}

function EditCaseDialog({ record, onClose }: { record: EdiscoveryCase; onClose: () => void }) {
  const [draft, setDraft] = useState<CaseDraft>({
    name: record.name,
    description: record.description ?? '',
    matterReference: record.matterReference ?? '',
    custodians: '',
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const { save, mutation, dialog } = useCasePatch(record, onClose);
  const set = (patch: Partial<CaseDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const submit = async () => {
    const found = caseDraftErrors(draft);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    await save({
      name: draft.name.trim(),
      description: draft.description.trim() ? draft.description.trim() : null,
      matterReference: draft.matterReference.trim() ? draft.matterReference.trim() : null,
    });
  };
  return (
    <FormDialog open onOpenChange={(next) => (next ? undefined : onClose())} title="Edit case" wide>
      <form
        className="grid gap-4"
        noValidate
        aria-label="Edit case"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <ArchiveErrorSummary
          error={
            mutation.error && mutation.error.code !== 'ediscovery_case_conflict'
              ? mutation.error
              : null
          }
        />
        <CaseFields draft={draft} set={set} errors={errors} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={mutation.isPending}>
            <SaveIcon aria-hidden />
            {mutation.isPending ? 'Saving …' : 'Save case'}
          </Button>
        </div>
      </form>
      {dialog}
    </FormDialog>
  );
}

// ---- custodians ----------------------------------------------------------------------------

function CustodiansTab({ record }: { record: EdiscoveryCase }) {
  // Writing custodian addresses needs message:reveal (the api refuses it otherwise).
  const canWrite = useArchiveAccess().reveal;
  const initial = useMemo(
    () => record.custodians.map((c) => c.address).join('\n'),
    [record.custodians],
  );
  const [text, setText] = useState(initial);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => setText(initial), [initial]);
  const { save, mutation, dialog } = useCasePatch(record, () => undefined);
  const open = record.status === 'open';
  const next = custodianList(text);
  const dirty = next.join('\n') !== record.custodians.map((c) => c.address).join('\n');
  const submit = async () => {
    const found = caseDraftErrors({
      name: record.name,
      description: '',
      matterReference: '',
      custodians: text,
    });
    setError(found.custodians ?? null);
    if (found.custodians) return;
    await save({ custodians: next });
  };
  return (
    <Section
      title="Custodians"
      description="The people whose mail the case concerns. Saving replaces the whole list; holds keep the custodians they snapshotted when they were placed."
    >
      {open && !canWrite ? <CustodiansNeedReveal /> : null}
      {open && canWrite ? (
        <form
          className="grid gap-3"
          noValidate
          aria-label="Custodians"
          onSubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          <ArchiveErrorSummary
            error={
              mutation.error && mutation.error.code !== 'ediscovery_case_conflict'
                ? mutation.error
                : null
            }
          />
          <Label htmlFor="case-custodian-list">Custodian addresses (one per line)</Label>
          <Textarea
            id="case-custodian-list"
            rows={8}
            value={text}
            onChange={(e) => setText(e.target.value)}
            aria-invalid={error ? true : undefined}
          />
          {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
          <p className="text-xs text-muted-foreground">
            {next.length} custodian{next.length === 1 ? '' : 's'} after saving.
          </p>
          <div>
            <Button type="submit" disabled={!dirty || mutation.isPending}>
              <SaveIcon aria-hidden />
              {mutation.isPending ? 'Saving …' : 'Save custodians'}
            </Button>
          </div>
        </form>
      ) : record.custodians.length === 0 ? (
        <p className="text-sm text-muted-foreground">No custodian.</p>
      ) : (
        <ul className="grid gap-1 text-sm">
          {record.custodians.map((c) => (
            <li key={c.id}>
              <UntrustedText value={c.address} mono />
            </li>
          ))}
        </ul>
      )}
      {dialog}
    </Section>
  );
}

// ---- holds ---------------------------------------------------------------------------------

function HoldsTab({ record }: { record: EdiscoveryCase }) {
  const access = useArchiveAccess();
  const holds = useApiQuery('LegalHoldsController_list_v1', {
    query: { caseId: record.id, limit: '100', sort: '-id' },
  });
  const [creating, setCreating] = useState(false);
  const [releasing, setReleasing] = useState<string | null>(null);
  const canCreate = access.legalHold && access.ediscovery && record.status === 'open';
  return (
    <Section
      title="Legal holds of this case"
      description="A hold keeps the archived mail of its custodians (in its time range and directions) from being disposed. Holds are immutable."
      actions={
        canCreate ? (
          <Button size="sm" onClick={() => setCreating(true)}>
            <GavelIcon aria-hidden />
            Place a hold
          </Button>
        ) : null
      }
    >
      {!access.legalHold ? (
        <p className="text-xs text-muted-foreground">
          Placing and releasing holds needs the archive:legal_hold permission.
        </p>
      ) : null}
      {holds.isLoading ? (
        <LoadingState label="Loading holds" rows={2} />
      ) : holds.error ? (
        <ErrorState error={holds.error} onRetry={() => void holds.refetch()} compact />
      ) : (holds.data?.data ?? []).length === 0 ? (
        <EmptyState
          icon={GavelIcon}
          title="No hold"
          description="No legal hold has been placed in this case."
        />
      ) : (
        <ul className="grid gap-2">
          {(holds.data?.data ?? []).map((hold) => (
            <li
              key={hold.id}
              className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3"
            >
              <div className="grid gap-0.5">
                <Link
                  href={legalHoldHref(hold.id)}
                  className="font-medium text-primary underline-offset-2 hover:underline"
                >
                  <UntrustedText value={hold.name} maxLength={80} />
                </Link>
                <span className="text-xs text-muted-foreground">
                  {stringList((hold.criteria as Record<string, unknown>).custodians).length}{' '}
                  custodians · placed <DateTime value={hold.createdAt} />
                </span>
              </div>
              <div className="flex items-center gap-2">
                <EnumBadge value={hold.status} tones={HOLD_STATUS_TONE} />
                {access.legalHold && hold.status === 'active' ? (
                  <Button variant="outline" size="sm" onClick={() => setReleasing(hold.id)}>
                    Release
                  </Button>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      )}
      {creating ? <CreateHoldDialog record={record} onClose={() => setCreating(false)} /> : null}
      {releasing ? (
        <ReleaseHoldDialog
          holdId={releasing}
          open
          onOpenChange={(next) => {
            if (!next) setReleasing(null);
          }}
        />
      ) : null}
    </Section>
  );
}

export interface HoldDraft {
  name: string;
  reason: string;
  useCaseCustodians: boolean;
  custodians: string;
  range: ArchiveSearchState['range'] | 'all';
  from?: string;
  to?: string;
  directions: string[];
}

type HoldBody = RequestBody<'EdiscoveryCasesController_createHold_v1'>;

/** The `POST …/holds` body (`archive-hold/1`, A12). */
export function holdBody(draft: HoldDraft): HoldBody {
  const criteria: NonNullable<HoldBody['criteria']> = {};
  if (!draft.useCaseCustodians) criteria.custodians = custodianList(draft.custodians);
  if (draft.range === 'custom' && draft.from && draft.to) {
    criteria.from = draft.from;
    criteria.to = draft.to;
  }
  if (draft.directions.length > 0 && draft.directions.length < 3) {
    criteria.directions = draft.directions as NonNullable<typeof criteria.directions>;
  }
  return {
    name: draft.name.trim(),
    reason: draft.reason.trim(),
    useCaseCustodians: draft.useCaseCustodians,
    ...(Object.keys(criteria).length > 0 ? { criteria } : {}),
  };
}

export function holdDraftErrors(draft: HoldDraft): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!draft.name.trim()) errors.name = 'Enter a hold name';
  if (!draft.reason.trim()) errors.reason = 'Enter a reason (it is recorded in the audit log)';
  if (!draft.useCaseCustodians) {
    const list = custodianList(draft.custodians);
    if (list.length === 0) errors.custodians = 'Enter at least one custodian address';
    else if (
      caseDraftErrors({
        name: 'x',
        description: '',
        matterReference: '',
        custodians: draft.custodians,
      }).custodians
    ) {
      errors.custodians = 'Enter valid email addresses';
    }
  }
  if (draft.range === 'custom') {
    const problem = customRangeError(draft.from, draft.to, CASE_SEARCH_MAX_RANGE_DAYS);
    if (problem) errors.range = problem;
  }
  return errors;
}

function CreateHoldDialog({ record, onClose }: { record: EdiscoveryCase; onClose: () => void }) {
  // Explicit custodian addresses need message:reveal; without it only the case's list is held.
  const canWriteCustodians = useArchiveAccess().reveal;
  const [draft, setDraft] = useState<HoldDraft>({
    name: '',
    reason: '',
    useCaseCustodians: true,
    custodians: '',
    range: 'all',
    directions: [],
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const create = useApiMutation('EdiscoveryCasesController_createHold_v1', {
    successMessage: 'Legal hold placed',
    invalidates: ['LegalHoldsController_list_v1', 'EdiscoveryCasesController_get_v1'],
  });
  const set = (patch: Partial<HoldDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const submit = async () => {
    const found = holdDraftErrors(draft);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    const outcome = await create.submit({ path: { caseId: record.id }, body: holdBody(draft) });
    if (outcome.ok) onClose();
  };
  return (
    <FormDialog
      open
      onOpenChange={(next) => (next ? undefined : onClose())}
      title="Place a legal hold"
      wide
    >
      <form
        className="grid gap-4"
        noValidate
        aria-label="Place a legal hold"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <ArchiveErrorSummary error={create.error} />
        <div className="grid gap-1">
          <Label htmlFor="hold-name">Hold name (required)</Label>
          <Input
            id="hold-name"
            value={draft.name}
            maxLength={200}
            onChange={(e) => set({ name: e.target.value })}
          />
          {errors.name ? (
            <p className="text-xs font-medium text-destructive">{errors.name}</p>
          ) : null}
        </div>
        <div className="grid gap-1">
          <Label htmlFor="hold-reason">Reason (required)</Label>
          <Textarea
            id="hold-reason"
            rows={2}
            maxLength={4096}
            value={draft.reason}
            onChange={(e) => set({ reason: e.target.value })}
          />
          {errors.reason ? (
            <p className="text-xs font-medium text-destructive">{errors.reason}</p>
          ) : null}
        </div>
        <div className="flex items-start gap-2">
          <Checkbox
            id="hold-use-case"
            checked={draft.useCaseCustodians}
            disabled={!canWriteCustodians}
            onCheckedChange={(next) => set({ useCaseCustodians: next === true })}
          />
          <div className="grid gap-0.5">
            <Label htmlFor="hold-use-case">
              Hold the case’s custodians ({record.counts.custodians})
            </Label>
            <p className="text-xs text-muted-foreground">
              The list is copied into the hold now; later changes to the case do not change the
              hold.
            </p>
            {canWriteCustodians ? null : <CustodiansNeedReveal />}
          </div>
        </div>
        {!draft.useCaseCustodians ? (
          <div className="grid gap-1">
            <Label htmlFor="hold-custodians">Custodian addresses (one per line)</Label>
            <Textarea
              id="hold-custodians"
              rows={4}
              value={draft.custodians}
              onChange={(e) => set({ custodians: e.target.value })}
            />
            {errors.custodians ? (
              <p className="text-xs font-medium text-destructive">{errors.custodians}</p>
            ) : null}
          </div>
        ) : null}
        <div className="grid gap-1">
          <div className="flex items-center gap-2">
            <Checkbox
              id="hold-range"
              checked={draft.range === 'custom'}
              onCheckedChange={(next) => {
                if (next === true) {
                  const today = new Date().toISOString().slice(0, 10);
                  set({ range: 'custom', from: draft.from ?? '2020-01-01', to: draft.to ?? today });
                } else set({ range: 'all', from: undefined, to: undefined });
              }}
            />
            <Label htmlFor="hold-range">Only mail received in a date range</Label>
          </div>
          {draft.range === 'custom' ? (
            <DayRangeFields
              state={{ range: 'custom', from: draft.from, to: draft.to }}
              setState={(patch: ArchiveSearchPatch) =>
                set({ from: patch.from ?? draft.from, to: patch.to ?? draft.to })
              }
              maxDays={CASE_SEARCH_MAX_RANGE_DAYS}
            />
          ) : null}
          {errors.range ? (
            <p className="text-xs font-medium text-destructive">{errors.range}</p>
          ) : null}
        </div>
        <fieldset className="grid gap-1">
          <legend className="text-sm font-medium">
            Directions (none chosen = every direction)
          </legend>
          <div className="flex flex-wrap gap-4">
            {ARCHIVE_DIRECTIONS.map((direction) => (
              <div key={direction} className="flex items-center gap-2">
                <Checkbox
                  id={`hold-dir-${direction}`}
                  checked={draft.directions.includes(direction)}
                  onCheckedChange={(next) =>
                    set({
                      directions:
                        next === true
                          ? [...draft.directions, direction]
                          : draft.directions.filter((d) => d !== direction),
                    })
                  }
                />
                <Label htmlFor={`hold-dir-${direction}`} className="font-normal">
                  {humanize(direction)}
                </Label>
              </div>
            ))}
          </div>
        </fieldset>
        <p className="text-xs text-muted-foreground">
          Placing a hold needs a session signed in with MFA and is recorded in the audit log.
        </p>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={create.isPending}>
            <GavelIcon aria-hidden />
            {create.isPending ? 'Placing …' : 'Place hold'}
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

// ---- searches ------------------------------------------------------------------------------

/** The completeness flags of a search (A18). */
export function CompletenessBanner({ search }: { search: EdiscoverySearch }) {
  if (search.status === 'failed') {
    return (
      <Notice tone="danger" icon={TriangleAlertIcon}>
        <span>
          The search failed{search.errorCode ? ` (${search.errorCode})` : ''}. Run it again; no
          partial results are kept.
        </span>
      </Notice>
    );
  }
  if (isActiveJob(search.status)) {
    return (
      <Notice>
        <span>
          The search is {humanize(search.status).toLowerCase()}; this page updates on its own.
        </span>
      </Notice>
    );
  }
  const { complete, lines } = completenessOf(search);
  if (complete) {
    return (
      <Notice icon={CheckCircle2Icon}>
        <span>
          Complete: the index was current and every day of the range was verified against the
          archive. {formatNumber(search.hitCount)} hits, each checked against the archive database.
        </span>
      </Notice>
    );
  }
  return (
    <Notice tone="warning" icon={TriangleAlertIcon}>
      {lines.map((line) => (
        <span key={line}>{line}</span>
      ))}
    </Notice>
  );
}

function SearchesTab({ record }: { record: EdiscoveryCase }) {
  const access = useArchiveAccess();
  const searches = useApiQuery(
    'EdiscoverySearchesController_list_v1',
    { path: { caseId: record.id }, query: { limit: '100', sort: '-id' } },
    {
      refetchInterval: (query) =>
        (query.state.data?.data ?? []).some((s) => isActiveJob(s.status)) ? JOB_POLL_MS : false,
    },
  );
  const [creating, setCreating] = useState(false);
  const canCreate = access.search && record.status === 'open';
  return (
    <Section
      title="Searches"
      description="Searches run in the background over the archive’s index; every hit is verified against the archive database. Completeness is reported, never assumed."
      actions={
        canCreate ? (
          <Button size="sm" onClick={() => setCreating((v) => !v)}>
            <SearchIcon aria-hidden />
            {creating ? 'Hide the search form' : 'New search'}
          </Button>
        ) : null
      }
    >
      {creating ? <CreateSearchForm record={record} onDone={() => setCreating(false)} /> : null}
      {searches.isLoading ? (
        <LoadingState label="Loading searches" rows={2} />
      ) : searches.error ? (
        <ErrorState error={searches.error} onRetry={() => void searches.refetch()} compact />
      ) : (searches.data?.data ?? []).length === 0 ? (
        <EmptyState
          icon={SearchIcon}
          title="No search"
          description="Run a search to find the case’s archived mail."
        />
      ) : (
        <ul className="grid gap-2">
          {(searches.data?.data ?? []).map((search) => {
            const completeness = completenessOf(search);
            return (
              <li key={search.id} className="grid gap-1 rounded-md border p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <Link
                    href={caseSearchHref(record.id, search.id)}
                    className="font-medium text-primary underline-offset-2 hover:underline"
                  >
                    Search of <DateTime value={search.createdAt} mode="absolute" />
                  </Link>
                  <span className="flex flex-wrap items-center gap-2">
                    <EnumBadge value={search.status} tones={JOB_STATUS_TONE} />
                    {search.status === 'completed' ? (
                      <EnumBadge
                        value={completeness.complete ? 'complete' : 'possibly_incomplete'}
                        tones={{ complete: 'success', possibly_incomplete: 'warning' }}
                      />
                    ) : null}
                  </span>
                </div>
                <span className="text-xs text-muted-foreground">
                  {formatNumber(search.hitCount)} hits
                  {search.truncated ? ' (truncated)' : ''}
                  {search.incompleteReason ? ` · ${humanize(search.incompleteReason)}` : ''}
                  {search.errorCode ? ` · ${search.errorCode}` : ''}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </Section>
  );
}

function CreateSearchForm({ record, onDone }: { record: EdiscoveryCase; onDone: () => void }) {
  const access = useArchiveAccess();
  const [state, setState] = useState<ArchiveSearchState>({
    ...DEFAULT_ARCHIVE_STATE,
    range: '365d',
  });
  const [useCaseCustodians, setUseCaseCustodians] = useState(record.counts.custodians > 0);
  const create = useApiMutation('EdiscoverySearchesController_create_v1', {
    successMessage: 'Search queued',
    invalidates: ['EdiscoverySearchesController_list_v1', 'EdiscoveryCasesController_get_v1'],
  });
  const holds = useApiQuery('LegalHoldsController_list_v1', {
    query: { caseId: record.id, status: 'active', limit: '100' },
  });
  const patch = (p: ArchiveSearchPatch) => setState((s) => ({ ...s, ...p }));
  const invalid =
    riskError(state) !== null ||
    (state.range === 'custom' &&
      customRangeError(state.from, state.to, CASE_SEARCH_MAX_RANGE_DAYS) !== null);
  return (
    <form
      className="grid gap-3 rounded-md border bg-muted/20 p-3"
      noValidate
      aria-label="New case search"
      onSubmit={(event) => {
        event.preventDefault();
        if (invalid) return;
        void create
          .submit({
            path: { caseId: record.id },
            body: { criteria: caseSearchCriteria(state, { useCaseCustodians, now: Date.now() }) },
          })
          .then((outcome) => {
            if (outcome.ok) onDone();
          });
      }}
    >
      <ArchiveErrorSummary error={create.error} />
      <div className="flex items-start gap-2">
        <Checkbox
          id="search-case-custodians"
          checked={useCaseCustodians}
          disabled={record.counts.custodians === 0}
          onCheckedChange={(next) => setUseCaseCustodians(next === true)}
        />
        <div className="grid gap-0.5">
          <Label htmlFor="search-case-custodians">
            Mail of the case’s custodians ({record.counts.custodians})
          </Label>
          <p className="text-xs text-muted-foreground">
            Sent or received by a custodian. Off: the whole archive matching the filters below.
          </p>
        </div>
      </div>
      <ArchiveFilters
        state={state}
        setState={patch}
        can={{ reveal: access.reveal, holds: true }}
        maxDays={CASE_SEARCH_MAX_RANGE_DAYS}
        holdOptions={(holds.data?.data ?? []).map((h) => ({ id: h.id, name: h.name }))}
        idPrefix="case-search"
      />
      <div className="flex flex-wrap items-center gap-2">
        <Button
          type="submit"
          disabled={invalid || create.isPending || create.retryAfterSeconds > 0}
        >
          <SearchIcon aria-hidden />
          {create.isPending
            ? 'Queuing …'
            : create.retryAfterSeconds > 0
              ? `Try again in ${create.retryAfterSeconds} s`
              : 'Run search'}
        </Button>
        <span className="text-xs text-muted-foreground">
          The search is recorded in the audit log (criteria as hashes).
        </span>
      </div>
    </form>
  );
}

// ---- exports -------------------------------------------------------------------------------

function ExportsTab({ record }: { record: EdiscoveryCase }) {
  const access = useArchiveAccess();
  const exports = useApiQuery(
    'EdiscoveryExportsController_list_v1',
    { path: { caseId: record.id }, query: { limit: '100', sort: '-id' } },
    {
      refetchInterval: (query) =>
        (query.state.data?.data ?? []).some((e) => isActiveJob(e.status)) ? JOB_POLL_MS : false,
    },
  );
  const [creating, setCreating] = useState(false);
  const [downloading, setDownloading] = useState<EdiscoveryExport | null>(null);
  const canCreate = access.export && record.status === 'open';
  const blocker = contentBlocker(access);
  return (
    <Section
      title="Exports"
      description="Encrypted ZIP packages of the original messages of a completed search, with a signed manifest (SHA-256 per item). Packages expire after the configured time."
      actions={
        canCreate ? (
          <Button size="sm" onClick={() => setCreating(true)}>
            <PackageIcon aria-hidden />
            New export
          </Button>
        ) : null
      }
    >
      {!access.export ? (
        <p className="text-xs text-muted-foreground">
          Creating and downloading exports needs archive:export.
        </p>
      ) : null}
      {exports.isLoading ? (
        <LoadingState label="Loading exports" rows={2} />
      ) : exports.error ? (
        <ErrorState error={exports.error} onRetry={() => void exports.refetch()} compact />
      ) : (exports.data?.data ?? []).length === 0 ? (
        <EmptyState
          icon={PackageIcon}
          title="No export"
          description="Export the reviewed results of a completed search."
        />
      ) : (
        <ul className="grid gap-2">
          {(exports.data?.data ?? []).map((item) => (
            <li key={item.id} className="grid gap-2 rounded-md border p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium">
                  Export of <DateTime value={item.createdAt} mode="absolute" />
                </span>
                <span className="flex items-center gap-2">
                  <EnumBadge value={item.status} tones={JOB_STATUS_TONE} />
                  {access.export && item.status === 'completed' ? (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={blocker !== null}
                      title={blocker ?? undefined}
                      onClick={() => setDownloading(item)}
                    >
                      <DownloadIcon aria-hidden />
                      Download
                    </Button>
                  ) : null}
                </span>
              </div>
              <DetailList
                items={[
                  {
                    label: 'Items',
                    value: `${formatNumber(item.itemCount)}${item.maliciousCount > 0 ? ` (${formatNumber(item.maliciousCount)} malicious, under malicious/)` : ''}`,
                  },
                  { label: 'Review tags', value: item.reviewTags.map(humanize).join(', ') },
                  {
                    label: 'Package',
                    value: item.packageBytes === null ? '—' : formatBytes(item.packageBytes),
                  },
                  {
                    label: 'Package SHA-256',
                    hidden: !item.packageSha256,
                    value: (
                      <span className="font-mono text-xs break-all">{item.packageSha256}</span>
                    ),
                  },
                  {
                    label: 'Manifest SHA-256',
                    hidden: !item.manifestSha256,
                    value: (
                      <span className="font-mono text-xs break-all">{item.manifestSha256}</span>
                    ),
                  },
                  {
                    label: 'Signing key',
                    hidden: !item.signingKeyId,
                    value: <span className="font-mono text-xs">{item.signingKeyId}</span>,
                  },
                  {
                    label: 'Expires',
                    value: <DateTime value={item.expiresAt} mode="absolute" emptyLabel="—" />,
                  },
                  {
                    label: 'Error',
                    hidden: !item.errorCode,
                    value: <span className="font-mono text-xs">{item.errorCode}</span>,
                  },
                ]}
              />
            </li>
          ))}
        </ul>
      )}
      {blocker && access.export ? <p className="text-xs text-muted-foreground">{blocker}</p> : null}
      {creating ? <CreateExportDialog record={record} onClose={() => setCreating(false)} /> : null}
      {downloading ? (
        <GrantDownloadDialog
          target={{ kind: 'export', caseId: record.id, exportId: downloading.id }}
          open
          onOpenChange={(next) => {
            if (!next) setDownloading(null);
          }}
          title="Download the export package"
          description="Confirm your identity to create a single-use download link. The ZIP holds the original messages, manifest.json, its Ed25519 signature manifest.sig and a README; the download is recorded in the audit log."
        />
      ) : null}
    </Section>
  );
}

export function exportBody(
  searchId: string,
  tags: readonly ReviewTag[],
  acknowledgeMalicious: boolean,
): RequestBody<'EdiscoveryExportsController_create_v1'> {
  return {
    searchId,
    reviewTags: [...tags],
    ...(acknowledgeMalicious ? { acknowledgeMalicious: true } : {}),
  };
}

function CreateExportDialog({ record, onClose }: { record: EdiscoveryCase; onClose: () => void }) {
  const searches = useApiQuery('EdiscoverySearchesController_list_v1', {
    path: { caseId: record.id },
    query: { status: 'completed', limit: '100', sort: '-id' },
  });
  const [searchId, setSearchId] = useState<string>('');
  const [tags, setTags] = useState<ReviewTag[]>([...DEFAULT_EXPORT_TAGS]);
  const [acknowledge, setAcknowledge] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const create = useApiMutation('EdiscoveryExportsController_create_v1', {
    successMessage: 'Export queued',
    invalidates: ['EdiscoveryExportsController_list_v1', 'EdiscoveryCasesController_get_v1'],
  });
  const completed = useMemo(() => searches.data?.data ?? [], [searches.data]);
  useEffect(() => {
    if (!searchId && completed[0]) setSearchId(completed[0].id);
  }, [completed, searchId]);
  const needsAck = create.error?.code === 'ediscovery_export_malicious_ack_required';
  const submit = async () => {
    if (!searchId) return setError('Choose a completed search');
    if (tags.length === 0) return setError('Choose at least one review tag');
    setError(null);
    const outcome = await create.submit({
      path: { caseId: record.id },
      body: exportBody(searchId, tags, acknowledge),
    });
    if (outcome.ok) onClose();
  };
  return (
    <FormDialog
      open
      onOpenChange={(next) => (next ? undefined : onClose())}
      title="New export"
      wide
    >
      <form
        className="grid gap-4"
        noValidate
        aria-label="New export"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <ArchiveErrorSummary error={create.error} />
        {error ? (
          <p role="alert" className="text-sm font-medium text-destructive">
            {error}
          </p>
        ) : null}
        <fieldset className="grid gap-1">
          <legend className="text-sm font-medium">Completed search</legend>
          {searches.isLoading ? (
            <LoadingState label="Loading searches" rows={1} />
          ) : completed.length === 0 ? (
            <p className="text-sm text-muted-foreground">No completed search yet.</p>
          ) : (
            completed.map((search) => (
              <div key={search.id} className="flex items-center gap-2">
                <input
                  type="radio"
                  id={`export-search-${search.id}`}
                  name="export-search"
                  className="size-4 accent-primary"
                  checked={searchId === search.id}
                  onChange={() => setSearchId(search.id)}
                />
                <Label htmlFor={`export-search-${search.id}`} className="font-normal">
                  Search of{' '}
                  {new Date(search.createdAt).toISOString().slice(0, 16).replace('T', ' ')} UTC ·{' '}
                  {formatNumber(search.hitCount)} hits
                  {completenessOf(search).complete ? '' : ' (possibly incomplete)'}
                </Label>
              </div>
            ))
          )}
        </fieldset>
        <fieldset className="grid gap-1">
          <legend className="text-sm font-medium">Include hits tagged</legend>
          <div className="flex flex-wrap gap-4">
            {REVIEW_TAGS.map((tag) => (
              <div key={tag} className="flex items-center gap-2">
                <Checkbox
                  id={`export-tag-${tag}`}
                  checked={tags.includes(tag)}
                  onCheckedChange={(next) =>
                    setTags(next === true ? [...tags, tag] : tags.filter((t) => t !== tag))
                  }
                />
                <Label htmlFor={`export-tag-${tag}`} className="font-normal">
                  {humanize(tag)}
                </Label>
              </div>
            ))}
          </div>
        </fieldset>
        <div
          className={`flex items-start gap-2 rounded-md border p-3 ${needsAck ? 'border-tone-warning bg-tone-warning' : ''}`}
        >
          <Checkbox
            id="export-ack-malicious"
            checked={acknowledge}
            onCheckedChange={(next) => setAcknowledge(next === true)}
          />
          <div className="grid gap-0.5">
            <Label htmlFor="export-ack-malicious">Include malicious messages</Label>
            <p className="text-xs text-muted-foreground">
              Messages classified as malicious are placed under malicious/ with a warning README.
              Required when the selection contains any.
            </p>
          </div>
        </div>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            disabled={create.isPending || completed.length === 0 || create.retryAfterSeconds > 0}
          >
            <PackageIcon aria-hidden />
            {create.isPending ? 'Queuing …' : 'Create export'}
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}
