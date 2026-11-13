'use client';

import { PlusIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { CopyableId } from '@/components/domain/copyable-id';
import { DateTime } from '@/components/domain/date-time';
import { SeverityBadge } from '@/components/domain/badges';
import { ToneBadge } from '@/components/domain/tone-badge';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { UnavailableState } from '@/components/states/unavailable-state';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Form } from '@/components/ui/form';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem, QueryParams } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatUtc, humanize } from '@/lib/format';
import { ReasonConfirmDialog } from '@/features/organizations/reason-confirm-dialog';
import { SelectFilter, TextFilter } from '@/features/reports/filters';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import { navGate } from '@/features/reports/nav-gate';
import { ReportSection } from '@/features/reports/report-state';
import { SelectField, TextField } from './form-fields';
import {
  CATEGORIES,
  INDICATOR_TYPES,
  LOOKUP_TYPES,
  SEVERITIES,
  addHashBody,
  addHashSchema,
  addIndicatorBody,
  addIndicatorSchema,
  lookupSchema,
} from './schemas';

type HashRow = ListItem<'ThreatHashesController_list_v1'>;
type IndicatorRow = ListItem<'ThreatIndicatorsController_list_v1'>;

const TABS: readonly TabDefinition[] = [
  { id: 'lookup', label: 'Lookup', ops: ['ThreatIntelligenceController_lookup_v1'] },
  { id: 'hashes', label: 'Hash catalogue', ops: ['ThreatHashesController_list_v1'] },
  { id: 'indicators', label: 'Indicators', ops: ['ThreatIndicatorsController_list_v1'] },
];

export const NOT_OFFERED =
  'Tenant-owned indicators, reputation lists and brand lists are not offered: no scanning engine reads them, so a list here would have no effect.';

/** `/threat-intelligence` (design §1.3 row 15). */
export function ThreatIntelligencePage() {
  return (
    <RouteGate gate={navGate('threat-intelligence')}>
      <div className="flex flex-col gap-4">
        <PageHeader
          title="Threat intelligence"
          description="Check a hash, URL, domain or IP address against the platform's threat intelligence."
        />
        <GatedTabs
          tabs={TABS}
          label="Threat intelligence"
          keepParams={[]}
          render={(tab) =>
            tab === 'lookup' ? <Lookup /> : tab === 'hashes' ? <Hashes /> : <Indicators />
          }
        />
        <UnavailableState
          step={null}
          title="Your own indicators and reputation lists"
          description={NOT_OFFERED}
        />
      </div>
    </RouteGate>
  );
}

/* ------------------------------------------------------------------------------------------ */

function Lookup() {
  const [submitted, setSubmitted] = useState<{
    type: (typeof LOOKUP_TYPES)[number];
    value: string;
  } | null>(null);
  const form = useZodForm(lookupSchema, { defaultValues: { type: 'domain', value: '' } });
  const result = useApiQuery(
    'ThreatIntelligenceController_lookup_v1',
    { query: submitted ?? { type: 'domain', value: '' } },
    {
      enabled: submitted !== null,
      staleTime: 0,
      gcTime: 0,
    },
  );
  const submit = form.handleSubmit((values) => setSubmitted(values));
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <ReportSection
        title="Look up an indicator"
        description="Lookups are audited (the value is stored as a SHA-256) and rate limited."
      >
        <Form {...form}>
          <form
            onSubmit={(event) => void submit(event)}
            className="grid gap-4"
            noValidate
            aria-label="Threat lookup"
          >
            <SelectField
              control={form.control}
              name="type"
              label="Type"
              options={LOOKUP_TYPES}
              labels={{ sha256: 'SHA-256 hash', url: 'URL', domain: 'Domain', ip: 'IP address' }}
              required
            />
            <TextField control={form.control} name="value" label="Value" required mono />
            <Button type="submit" className="justify-self-start" disabled={result.isFetching}>
              {result.isFetching ? 'Looking up …' : 'Look up'}
            </Button>
          </form>
        </Form>
      </ReportSection>
      <ReportSection title="Result">
        {!submitted ? (
          <p className="text-sm text-muted-foreground">Enter a value to look it up.</p>
        ) : result.isLoading ? (
          <LoadingState label="Looking up" rows={3} />
        ) : result.error ? (
          <ErrorState error={result.error} onRetry={() => void result.refetch()} compact />
        ) : result.data ? (
          <div className="grid gap-3 text-sm">
            <p className="flex flex-wrap items-center gap-2">
              {result.data.known ? (
                <ToneBadge tone="danger">Known threat</ToneBadge>
              ) : (
                <ToneBadge tone="success">Not known</ToneBadge>
              )}
              <span className="text-muted-foreground">{humanize(result.data.type)}</span>
              <UntrustedText value={submitted.value} maxLength={80} />
            </p>
            <p className="text-xs text-muted-foreground">
              Normalized value hash:{' '}
              <CopyableId value={result.data.valueSha256} label="value hash" />
            </p>
            {result.data.matches.length === 0 ? (
              <p className="text-muted-foreground">
                No platform indicator or catalogued hash matches. “Not known” is not a verdict that
                the value is safe.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-sm">
                  <caption className="sr-only">Matches</caption>
                  <thead>
                    <tr className="border-b text-xs text-muted-foreground">
                      {['Source', 'Severity', 'Category', 'First seen', 'Last seen', 'Expires'].map(
                        (h) => (
                          <th key={h} scope="col" className="px-2 py-1.5 text-left font-semibold">
                            {h}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {result.data.matches.map((m, i) => (
                      <tr key={i} className="border-b last:border-0">
                        <td className="px-2 py-1.5">
                          {m.source === 'hash_catalog' ? 'Hash catalogue' : 'Platform indicator'}
                        </td>
                        <td className="px-2 py-1.5">
                          <SeverityBadge severity={m.severity} />
                        </td>
                        <td className="px-2 py-1.5">
                          {m.category ? humanize(m.category) : 'None'}
                        </td>
                        <td className="px-2 py-1.5">{formatUtc(m.firstSeenAt)}</td>
                        <td className="px-2 py-1.5">{formatUtc(m.lastSeenAt)}</td>
                        <td className="px-2 py-1.5">
                          {m.expiresAt ? formatUtc(m.expiresAt) : 'Never'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ) : null}
      </ReportSection>
    </div>
  );
}

/* ------------------------------------------------------------------------------------------ */

const SOURCE = /^(analyst|sandbox|feed:[a-z0-9][a-z0-9_.-]{0,58})$/;
export const HASHES_URL_SHAPE = {
  source: z.string().regex(SOURCE).optional().catch(undefined),
  sha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional()
    .catch(undefined),
  type: z.enum(INDICATOR_TYPES).optional().catch(undefined),
  value: z.string().min(1).max(4096).optional().catch(undefined),
};

function Hashes() {
  const [state, setState] = useUrlState(HASHES_URL_SHAPE);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<HashRow | null>(null);
  const canRemove = useCan('ThreatHashesController_remove_v1');
  const list = useCursorList('ThreatHashesController_list_v1', {
    ...(state.source ? { source: state.source } : {}),
    ...(state.sha256 ? { sha256: state.sha256 } : {}),
  });
  const remove = useApiMutation('ThreatHashesController_remove_v1', {
    successMessage: 'Hash removed from the catalogue.',
    invalidates: ['ThreatHashesController_list_v1'],
  });
  const columns = useMemo<DataTableColumn<HashRow>[]>(
    () => [
      {
        id: 'sha256',
        header: 'SHA-256',
        meta: { label: 'SHA-256' },
        cell: ({ row }) => <CopyableId value={row.original.sha256} label="SHA-256" max={24} />,
      },
      {
        id: 'severity',
        header: 'Severity',
        meta: { label: 'Severity' },
        cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      },
      {
        id: 'family',
        header: 'Family',
        meta: { label: 'Family' },
        cell: ({ row }) => (
          <UntrustedText value={row.original.family} emptyLabel="None" maxLength={40} />
        ),
      },
      {
        id: 'source',
        header: 'Source',
        meta: { label: 'Source' },
        cell: ({ row }) => <span className="font-mono text-xs">{row.original.source}</span>,
      },
      {
        id: 'reason',
        header: 'Reason',
        meta: { label: 'Reason' },
        cell: ({ row }) => (
          <UntrustedText value={row.original.reason} emptyLabel="None" maxLength={60} />
        ),
      },
      {
        id: 'lastSeenAt',
        header: 'Last seen',
        meta: { label: 'Last seen' },
        cell: ({ row }) => <DateTime value={row.original.lastSeenAt} />,
      },
      {
        id: 'expiresAt',
        header: 'Expires',
        meta: { label: 'Expires' },
        cell: ({ row }) => <DateTime value={row.original.expiresAt} emptyLabel="Never" />,
      },
    ],
    [],
  );
  return (
    <div className="grid gap-3">
      <div className="flex justify-end">
        <Can op="ThreatHashesController_add_v1">
          <Button onClick={() => setAdding(true)}>
            <PlusIcon aria-hidden />
            Add hash
          </Button>
        </Can>
      </div>
      <DataTable<HashRow>
        tableId="threat-hashes"
        caption="Known-threat hash catalogue"
        columns={columns}
        list={list}
        getRowId={(row) => row.sha256}
        getRowLabel={(row) => `hash ${row.sha256.slice(0, 12)}`}
        rowActions={
          canRemove
            ? (row) => [{ label: 'Remove', destructive: true, onSelect: () => setRemoving(row) }]
            : undefined
        }
        isFiltered={Boolean(state.source || state.sha256)}
        onClearFilters={() => setState({ source: undefined, sha256: undefined })}
        emptyState={<EmptyState title="The catalogue is empty" />}
        filters={
          <>
            <TextFilter
              label="SHA-256"
              value={state.sha256}
              onChange={(sha256) => setState({ sha256 })}
              normalize={(v) => v.trim().toLowerCase()}
              validate={(v) => (/^[0-9a-f]{64}$/.test(v) ? null : '64 hexadecimal characters')}
              mono
            />
            <TextFilter
              label="Source"
              value={state.source}
              onChange={(source) => setState({ source })}
              placeholder="analyst, sandbox, feed:name"
              validate={(v) => (SOURCE.test(v) ? null : 'analyst, sandbox or feed:<name>')}
              mono
            />
          </>
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <CopyableId value={row.sha256} label="SHA-256" />
            <span className="flex items-center gap-2">
              <SeverityBadge severity={row.severity} /> {row.source}
            </span>
          </div>
        )}
      />
      <AddHashDialog open={adding} onOpenChange={setAdding} />
      <ReasonConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRemoving(null);
            remove.reset();
          }
        }}
        title="Remove this hash from the catalogue?"
        description={
          removing ? <span className="break-all font-mono text-xs">{removing.sha256}</span> : null
        }
        confirmLabel="Remove hash"
        destructive
        onConfirm={async (reason) => {
          if (!removing) return false;
          const outcome = await remove.submit({
            path: { sha256: removing.sha256 },
            query: { reason },
          });
          return outcome.ok;
        }}
        error={remove.error ? <ErrorState error={remove.error} compact /> : null}
      />
    </div>
  );
}

function AddHashDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [messages, setMessages] = useState<string[]>([]);
  const form = useZodForm(addHashSchema, {
    defaultValues: { sha256: '', md5: '', severity: 'high', family: '', reason: '', expiresOn: '' },
  });
  const mutation = useApiMutation('ThreatHashesController_add_v1', {
    successMessage: 'Hash added to the catalogue.',
    invalidates: ['ThreatHashesController_list_v1'],
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await mutation.submit({ body: addHashBody(values) });
    if (outcome.ok) {
      form.reset();
      onOpenChange(false);
    } else setMessages(applyApiErrors(form, outcome.error));
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Add a known-threat hash</DialogTitle>
          <DialogDescription>
            The attachment engine treats matching attachments as malicious for every organization.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form
            onSubmit={(event) => void submit(event)}
            className="grid gap-4"
            noValidate
            aria-label="Add hash"
          >
            <FormErrorSummary messages={messages} requestId={mutation.error?.requestId} />
            <TextField control={form.control} name="sha256" label="SHA-256" required mono />
            <TextField control={form.control} name="md5" label="MD5" mono hint="Optional." />
            <div className="grid gap-4 sm:grid-cols-2">
              <SelectField
                control={form.control}
                name="severity"
                label="Severity"
                options={SEVERITIES}
                required
              />
              <TextField
                control={form.control}
                name="family"
                label="Family"
                hint="Optional, e.g. a malware family."
              />
            </div>
            <TextField
              control={form.control}
              name="reason"
              label="Reason"
              required
              multiline
              hint="Recorded with the entry and in the audit log."
            />
            <TextField
              control={form.control}
              name="expiresOn"
              label="Expires on (UTC)"
              type="date"
              hint="Optional; never expires when empty."
            />
            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={mutation.isPending || mutation.retryAfterSeconds > 0}>
                {mutation.isPending ? 'Adding …' : 'Add hash'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------------------------------------------------------------------ */

function Indicators() {
  const [state, setState] = useUrlState(HASHES_URL_SHAPE);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<IndicatorRow | null>(null);
  const canRemove = useCan('ThreatIndicatorsController_remove_v1');
  const filters: QueryParams<'ThreatIndicatorsController_list_v1'> = {
    ...(state.type ? { type: state.type } : {}),
    ...(state.source && !state.source.startsWith('sandbox') ? { source: state.source } : {}),
    ...(state.value && state.type ? { value: state.value } : {}),
  };
  const list = useCursorList('ThreatIndicatorsController_list_v1', filters);
  const remove = useApiMutation('ThreatIndicatorsController_remove_v1', {
    successMessage: 'Indicator removed.',
    invalidates: ['ThreatIndicatorsController_list_v1'],
  });
  const columns = useMemo<DataTableColumn<IndicatorRow>[]>(
    () => [
      {
        id: 'value',
        header: 'Value',
        meta: { label: 'Value' },
        cell: ({ row }) => (
          <UntrustedText
            value={row.original.value}
            maxLength={60}
            copy
            copyLabel="Copy indicator"
            mono
          />
        ),
      },
      {
        id: 'type',
        header: 'Type',
        meta: { label: 'Type' },
        cell: ({ row }) => humanize(row.original.type),
      },
      {
        id: 'severity',
        header: 'Severity',
        meta: { label: 'Severity' },
        cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      },
      {
        id: 'category',
        header: 'Category',
        meta: { label: 'Category' },
        cell: ({ row }) => (row.original.category ? humanize(row.original.category) : 'None'),
      },
      {
        id: 'source',
        header: 'Source',
        meta: { label: 'Source' },
        cell: ({ row }) => <span className="font-mono text-xs">{row.original.source}</span>,
      },
      {
        id: 'reason',
        header: 'Reason',
        meta: { label: 'Reason' },
        cell: ({ row }) => (
          <UntrustedText value={row.original.reason} emptyLabel="None" maxLength={60} />
        ),
      },
      {
        id: 'expiresAt',
        header: 'Expires',
        meta: { label: 'Expires' },
        cell: ({ row }) => <DateTime value={row.original.expiresAt} emptyLabel="Never" />,
      },
    ],
    [],
  );
  return (
    <div className="grid gap-3">
      <div className="flex justify-end">
        <Can op="ThreatIndicatorsController_add_v1">
          <Button onClick={() => setAdding(true)}>
            <PlusIcon aria-hidden />
            Add indicator
          </Button>
        </Can>
      </div>
      <DataTable<IndicatorRow>
        tableId="threat-indicators"
        caption="Platform threat indicators"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `${row.type} indicator ${row.value.slice(0, 40)}`}
        rowActions={
          canRemove
            ? (row) => [{ label: 'Remove', destructive: true, onSelect: () => setRemoving(row) }]
            : undefined
        }
        isFiltered={Boolean(state.type || state.source || state.value)}
        onClearFilters={() => setState({ type: undefined, source: undefined, value: undefined })}
        emptyState={<EmptyState title="No platform indicators" />}
        filters={
          <>
            <SelectFilter
              label="Type"
              value={state.type}
              onChange={(type) => setState({ type })}
              options={INDICATOR_TYPES.map((value) => ({ value, label: humanize(value) }))}
            />
            <TextFilter
              label="Value (needs a type)"
              value={state.value}
              onChange={(value) => setState({ value })}
              mono
            />
            <TextFilter
              label="Source"
              value={state.source}
              onChange={(source) => setState({ source })}
              placeholder="analyst, feed:name"
              validate={(v) =>
                /^(analyst|feed:[a-z0-9][a-z0-9_.-]{0,58})$/.test(v)
                  ? null
                  : 'analyst or feed:<name>'
              }
              mono
            />
          </>
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <UntrustedText value={row.value} maxLength={48} mono />
            <span className="flex items-center gap-2">
              <SeverityBadge severity={row.severity} /> {humanize(row.type)}
            </span>
          </div>
        )}
      />
      <AddIndicatorDialog open={adding} onOpenChange={setAdding} />
      <ReasonConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRemoving(null);
            remove.reset();
          }
        }}
        title="Remove this indicator?"
        description={removing ? <UntrustedText value={removing.value} maxLength={80} mono /> : null}
        confirmLabel="Remove indicator"
        destructive
        onConfirm={async (reason) => {
          if (!removing) return false;
          const outcome = await remove.submit({ path: { id: removing.id }, query: { reason } });
          return outcome.ok;
        }}
        error={remove.error ? <ErrorState error={remove.error} compact /> : null}
      />
    </div>
  );
}

function AddIndicatorDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [messages, setMessages] = useState<string[]>([]);
  const form = useZodForm(addIndicatorSchema, {
    defaultValues: {
      type: 'domain',
      value: '',
      severity: 'high',
      category: 'phishing',
      reason: '',
      expiresOn: '',
    },
  });
  const mutation = useApiMutation('ThreatIndicatorsController_add_v1', {
    successMessage: 'Indicator added.',
    invalidates: ['ThreatIndicatorsController_list_v1'],
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await mutation.submit({ body: addIndicatorBody(values) });
    if (outcome.ok) {
      form.reset();
      onOpenChange(false);
    } else setMessages(applyApiErrors(form, outcome.error));
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Add a platform indicator</DialogTitle>
          <DialogDescription>
            The URL engine and the click service match it for every organization.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form
            onSubmit={(event) => void submit(event)}
            className="grid gap-4"
            noValidate
            aria-label="Add indicator"
          >
            <FormErrorSummary messages={messages} requestId={mutation.error?.requestId} />
            <div className="grid gap-4 sm:grid-cols-3">
              <SelectField
                control={form.control}
                name="type"
                label="Type"
                options={INDICATOR_TYPES}
                required
              />
              <SelectField
                control={form.control}
                name="severity"
                label="Severity"
                options={SEVERITIES}
                required
              />
              <SelectField
                control={form.control}
                name="category"
                label="Category"
                options={CATEGORIES}
                required
                labels={{ c2: 'Command and control' }}
              />
            </div>
            <TextField control={form.control} name="value" label="Value" required mono />
            <TextField
              control={form.control}
              name="reason"
              label="Reason"
              required
              multiline
              hint="Recorded with the indicator and in the audit log."
            />
            <TextField
              control={form.control}
              name="expiresOn"
              label="Expires on (UTC)"
              type="date"
              hint="Optional; never expires when empty."
            />
            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={mutation.isPending || mutation.retryAfterSeconds > 0}>
                {mutation.isPending ? 'Adding …' : 'Add indicator'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
