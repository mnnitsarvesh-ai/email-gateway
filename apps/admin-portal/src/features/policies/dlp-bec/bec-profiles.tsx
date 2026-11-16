'use client';

import { PlusIcon } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn, type RowAction } from '@/components/data-table';
import { useZodForm } from '@/components/form';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Form } from '@/components/ui/form';
import { useApiMutation, useCursorList } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { CodeList, YesNo } from '@/features/messages/controls';
import {
  executiveCreateBody,
  executiveDefaults,
  executiveSchema,
  executiveUpdateBody,
  vendorCreateBody,
  vendorDefaults,
  vendorSchema,
  vendorUpdateBody,
  type ExecutiveInput,
  type VendorInput,
} from './bec-schemas';
import { enabledBadge } from './dlp-policies';
import {
  applyServerError,
  confirmProblem,
  indexDetail,
  type Explain,
  type FieldRule,
  type Problem,
} from './errors';
import {
  EditorSheet,
  FormAlert,
  LinesField,
  SectionToolbar,
  SubmitRow,
  SwitchField,
  TextField,
  useEntryEditor,
  useEntryTarget,
} from './kit';
import { lineOfEntry, type Executive, type Vendor } from './model';

/**
 * Protected executives and vendors of the BEC engine (step 4.4 B5, B6, B18): names are compared
 * after the engine's normalization (`409 executive_exists` / `vendor_exists`); vendor domains are
 * registrable domains, never free-mail (`422 vendor_domain_freemail`).
 */

export const BEC_CACHE_NOTE =
  'Changes apply to messages scanned after the BEC engine’s cache refresh (30 seconds by default).';

const EXECUTIVE_QUERIES: readonly OperationId[] = [
  'BecExecutivesController_list_v1',
  'BecExecutivesController_get_v1',
];
const VENDOR_QUERIES: readonly OperationId[] = [
  'BecVendorsController_list_v1',
  'BecVendorsController_get_v1',
];

const EXECUTIVE_COLUMNS: DataTableColumn<Executive>[] = [
  {
    id: 'name',
    header: 'Executive',
    meta: { label: 'Executive' },
    cell: ({ row }) => row.original.displayName,
  },
  {
    id: 'title',
    header: 'Title',
    meta: { label: 'Title' },
    cell: ({ row }) => row.original.title ?? <span className="text-muted-foreground">None</span>,
  },
  {
    id: 'addresses',
    header: 'Known addresses',
    meta: { label: 'Known addresses', className: 'max-w-72' },
    cell: ({ row }) => <CodeList codes={row.original.knownAddresses} />,
  },
  {
    id: 'aliases',
    header: 'Aliases',
    meta: { label: 'Aliases' },
    cell: ({ row }) => <CodeList codes={row.original.aliases} />,
  },
  {
    id: 'enabled',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => enabledBadge(row.original.enabled),
  },
];

const VENDOR_COLUMNS: DataTableColumn<Vendor>[] = [
  { id: 'name', header: 'Vendor', meta: { label: 'Vendor' }, cell: ({ row }) => row.original.name },
  {
    id: 'domains',
    header: 'Domains',
    meta: { label: 'Domains' },
    cell: ({ row }) => <CodeList codes={row.original.domains} />,
  },
  {
    id: 'senders',
    header: 'Known senders',
    meta: { label: 'Known senders' },
    cell: ({ row }) => <CodeList codes={row.original.knownSenders} />,
  },
  {
    id: 'payment',
    header: 'Payment-change sensitive',
    meta: { label: 'Payment-change sensitive' },
    cell: ({ row }) => <YesNo value={row.original.paymentChangeSensitive} />,
  },
  {
    id: 'enabled',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => enabledBadge(row.original.enabled),
  },
];

// ---------------------------------------------------------------------------------------------
// Executives
// ---------------------------------------------------------------------------------------------

function executiveFields(text: () => ExecutiveInput): FieldRule<keyof ExecutiveInput>[] {
  return [
    { path: 'displayName', field: 'displayName' },
    { path: 'title', field: 'title' },
    { path: 'aliases', field: 'aliases', line: (index) => lineOfEntry(text().aliases, index) },
    {
      path: 'knownAddresses',
      field: 'knownAddresses',
      line: (index) => lineOfEntry(text().knownAddresses, index),
    },
    { path: 'enabled', field: 'enabled' },
  ];
}

const explainExecutive: Explain<keyof ExecutiveInput> = (error) =>
  error.code === 'executive_exists'
    ? {
        field: 'displayName',
        message:
          'An executive with this name exists (names are compared after normalization: case, accents and punctuation do not count).',
      }
    : null;

function ExecutiveForm({
  executive,
  onDone,
  onReload,
}: {
  executive?: Executive;
  onDone: () => void;
  onReload: () => void;
}) {
  const [problem, setProblem] = useState<Problem | null>(null);
  const create = useApiMutation('BecExecutivesController_create_v1', {
    invalidates: EXECUTIVE_QUERIES,
    successMessage: 'Executive added.',
  });
  const update = useApiMutation('BecExecutivesController_update_v1', {
    invalidates: EXECUTIVE_QUERIES,
    successMessage: 'Executive saved.',
  });
  const form = useZodForm(executiveSchema, { defaultValues: executiveDefaults(executive) });
  const submit = form.handleSubmit(async (values) => {
    setProblem(null);
    let outcome;
    if (executive) {
      const body = executiveUpdateBody(executive, values);
      if (Object.keys(body).length === 1) {
        toast.info('Nothing changed.');
        return onDone();
      }
      outcome = await update.submit({ path: { id: executive.id }, body });
    } else {
      outcome = await create.submit({ body: executiveCreateBody(values) });
    }
    if (outcome.ok) return onDone();
    setProblem(
      applyServerError(
        form,
        outcome.error,
        executiveFields(() => form.getValues()),
        explainExecutive,
      ),
    );
  });
  const mutation = executive ? update : create;
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label={executive ? `Edit executive ${executive.displayName}` : 'New executive'}
        onSubmit={(event) => void submit(event)}
      >
        <FormAlert problem={problem} onReload={onReload} />
        <TextField
          control={form.control}
          name="displayName"
          label="Display name"
          required
          maxLength={128}
          hint="2 to 128 characters; a sender display name close to it is flagged as impersonation."
        />
        <TextField
          control={form.control}
          name="title"
          label="Job title (optional)"
          maxLength={128}
        />
        <LinesField
          control={form.control}
          name="aliases"
          label="Aliases (optional)"
          max={10}
          noun="aliases"
          hint="Other names the executive is known by, 2 to 128 characters each."
        />
        <LinesField
          control={form.control}
          name="knownAddresses"
          label="Known addresses (optional)"
          max={20}
          noun="addresses"
          mono
          hint="Addresses the executive really uses; mail from them is not impersonation."
        />
        <SwitchField control={form.control} name="enabled" label="Enabled" />
        <SubmitRow
          label={executive ? 'Save executive' : 'Add executive'}
          pending={mutation.isPending}
          retryAfterSeconds={mutation.retryAfterSeconds}
          onCancel={onDone}
        />
      </form>
    </Form>
  );
}

/** The "Executives" section of the BEC tab. */
export function ExecutivesSection() {
  const canCreate = useCan('BecExecutivesController_create_v1');
  const canUpdate = useCan('BecExecutivesController_update_v1');
  const canDelete = useCan('BecExecutivesController_remove_v1');
  const list = useCursorList('BecExecutivesController_list_v1', undefined, { limit: 25 });
  const { editor, setEditor, reload, close } = useEntryEditor<Executive>(list.query.refetch);
  const {
    target: deleting,
    setTarget: setDeleting,
    refresh: refreshDeleting,
  } = useEntryTarget<Executive>(list.query.refetch);
  const remove = useApiMutation('BecExecutivesController_remove_v1', {
    invalidates: EXECUTIVE_QUERIES,
    successMessage: 'Executive removed.',
  });
  const rowActions =
    canUpdate || canDelete
      ? (row: Executive): RowAction[] => [
          ...(canUpdate
            ? [{ label: 'Edit', onSelect: () => setEditor({ mode: 'edit', row }) }]
            : []),
          ...(canDelete
            ? [{ label: 'Delete', destructive: true, onSelect: () => setDeleting(row) }]
            : []),
        ]
      : undefined;
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <SectionToolbar
        actions={
          canCreate ? (
            <Button size="sm" onClick={() => setEditor({ mode: 'create' })}>
              <PlusIcon aria-hidden />
              New executive
            </Button>
          ) : null
        }
      >
        Protected executives: mail that impersonates them (display name, free-mail, reply-to) is
        flagged.
      </SectionToolbar>
      <DataTable
        tableId="bec-executives"
        caption="Protected executives"
        columns={EXECUTIVE_COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.displayName}
        rowActions={rowActions}
        emptyState={<EmptyState title="No protected executives" />}
        mobileCard={(row) => row.displayName}
      />
      <EditorSheet
        open={editor !== null}
        onOpenChange={(open) => !open && setEditor(null)}
        title={editor?.mode === 'edit' ? `Edit ${editor.row.displayName}` : 'New executive'}
        description={BEC_CACHE_NOTE}
      >
        {editor?.mode === 'create' ? (
          <ExecutiveForm onDone={close} onReload={() => undefined} />
        ) : editor ? (
          <ExecutiveForm
            key={`${editor.row.id}:${editor.row.version}`}
            executive={editor.row}
            onDone={close}
            onReload={() => void reload()}
          />
        ) : null}
      </EditorSheet>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
            remove.reset();
          }
        }}
        title={`Remove ${deleting?.displayName ?? 'the executive'}?`}
        description="Mail impersonating this person is no longer flagged as executive impersonation."
        confirmLabel="Remove executive"
        destructive
        error={<FormAlert problem={remove.error ? confirmProblem(remove.error) : null} />}
        onConfirm={async () => {
          if (!deleting) return false;
          const outcome = await remove.submit({
            path: { id: deleting.id },
            query: { version: deleting.version },
          });
          if (!outcome.ok && outcome.error.code === 'version_conflict') {
            void refreshDeleting();
          }
          return outcome.ok;
        }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Vendors
// ---------------------------------------------------------------------------------------------

function vendorFields(text: () => VendorInput): FieldRule<keyof VendorInput>[] {
  return [
    { path: 'name', field: 'name' },
    { path: 'aliases', field: 'aliases', line: (index) => lineOfEntry(text().aliases, index) },
    { path: 'domains', field: 'domains', line: (index) => lineOfEntry(text().domains, index) },
    {
      path: 'knownSenders',
      field: 'knownSenders',
      line: (index) => lineOfEntry(text().knownSenders, index),
    },
    { path: 'paymentChangeSensitive', field: 'paymentChangeSensitive' },
    { path: 'enabled', field: 'enabled' },
  ];
}

function vendorExplain(text: () => VendorInput): Explain<keyof VendorInput> {
  return (error) => {
    if (error.code === 'vendor_exists') {
      return {
        field: 'name',
        message: 'A vendor with this name exists (names are compared after normalization).',
      };
    }
    if (error.code === 'vendor_domain_freemail') {
      const index = indexDetail(error);
      const line = index === null ? null : lineOfEntry(text().domains, index);
      return {
        field: 'domains',
        message: `${line !== null ? `Line ${line}: a` : 'A'} free-mail domain cannot be a vendor domain; list the vendor's addresses as known senders instead.`,
      };
    }
    return null;
  };
}

function VendorForm({
  vendor,
  onDone,
  onReload,
}: {
  vendor?: Vendor;
  onDone: () => void;
  onReload: () => void;
}) {
  const [problem, setProblem] = useState<Problem | null>(null);
  const create = useApiMutation('BecVendorsController_create_v1', {
    invalidates: VENDOR_QUERIES,
    successMessage: 'Vendor added.',
  });
  const update = useApiMutation('BecVendorsController_update_v1', {
    invalidates: VENDOR_QUERIES,
    successMessage: 'Vendor saved.',
  });
  const form = useZodForm(vendorSchema, { defaultValues: vendorDefaults(vendor) });
  const submit = form.handleSubmit(async (values) => {
    setProblem(null);
    let outcome;
    if (vendor) {
      const body = vendorUpdateBody(vendor, values);
      if (Object.keys(body).length === 1) {
        toast.info('Nothing changed.');
        return onDone();
      }
      outcome = await update.submit({ path: { id: vendor.id }, body });
    } else {
      outcome = await create.submit({ body: vendorCreateBody(values) });
    }
    if (outcome.ok) return onDone();
    const text = () => form.getValues();
    setProblem(applyServerError(form, outcome.error, vendorFields(text), vendorExplain(text)));
  });
  const mutation = vendor ? update : create;
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label={vendor ? `Edit vendor ${vendor.name}` : 'New vendor'}
        onSubmit={(event) => void submit(event)}
      >
        <FormAlert problem={problem} onReload={onReload} />
        <TextField
          control={form.control}
          name="name"
          label="Vendor name"
          required
          maxLength={128}
        />
        <LinesField
          control={form.control}
          name="domains"
          label="Domains"
          required
          max={20}
          noun="domains"
          mono
          hint="The vendor's registrable domains; public suffixes and free-mail domains are refused."
        />
        <LinesField
          control={form.control}
          name="knownSenders"
          label="Known sender addresses (optional)"
          max={50}
          noun="addresses"
          mono
          hint="Mail from other addresses of the vendor's domains is flagged."
        />
        <LinesField
          control={form.control}
          name="aliases"
          label="Aliases (optional)"
          max={10}
          noun="aliases"
        />
        <SwitchField
          control={form.control}
          name="paymentChangeSensitive"
          label="Flag payment-change wording from this vendor"
        />
        <SwitchField control={form.control} name="enabled" label="Enabled" />
        <SubmitRow
          label={vendor ? 'Save vendor' : 'Add vendor'}
          pending={mutation.isPending}
          retryAfterSeconds={mutation.retryAfterSeconds}
          onCancel={onDone}
        />
      </form>
    </Form>
  );
}

/** The "Vendors" section of the BEC tab. */
export function VendorsSection() {
  const canCreate = useCan('BecVendorsController_create_v1');
  const canUpdate = useCan('BecVendorsController_update_v1');
  const canDelete = useCan('BecVendorsController_remove_v1');
  const list = useCursorList('BecVendorsController_list_v1', undefined, { limit: 25 });
  const { editor, setEditor, reload, close } = useEntryEditor<Vendor>(list.query.refetch);
  const {
    target: deleting,
    setTarget: setDeleting,
    refresh: refreshDeleting,
  } = useEntryTarget<Vendor>(list.query.refetch);
  const remove = useApiMutation('BecVendorsController_remove_v1', {
    invalidates: VENDOR_QUERIES,
    successMessage: 'Vendor removed.',
  });
  const rowActions =
    canUpdate || canDelete
      ? (row: Vendor): RowAction[] => [
          ...(canUpdate
            ? [{ label: 'Edit', onSelect: () => setEditor({ mode: 'edit', row }) }]
            : []),
          ...(canDelete
            ? [{ label: 'Delete', destructive: true, onSelect: () => setDeleting(row) }]
            : []),
        ]
      : undefined;
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <SectionToolbar
        actions={
          canCreate ? (
            <Button size="sm" onClick={() => setEditor({ mode: 'create' })}>
              <PlusIcon aria-hidden />
              New vendor
            </Button>
          ) : null
        }
      >
        Vendors you pay: lookalike domains, unknown sender addresses and payment-change requests are
        flagged.
      </SectionToolbar>
      <DataTable
        tableId="bec-vendors"
        caption="Vendors"
        columns={VENDOR_COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        rowActions={rowActions}
        emptyState={<EmptyState title="No vendors" />}
        mobileCard={(row) => row.name}
      />
      <EditorSheet
        open={editor !== null}
        onOpenChange={(open) => !open && setEditor(null)}
        title={editor?.mode === 'edit' ? `Edit ${editor.row.name}` : 'New vendor'}
        description={BEC_CACHE_NOTE}
      >
        {editor?.mode === 'create' ? (
          <VendorForm onDone={close} onReload={() => undefined} />
        ) : editor ? (
          <VendorForm
            key={`${editor.row.id}:${editor.row.version}`}
            vendor={editor.row}
            onDone={close}
            onReload={() => void reload()}
          />
        ) : null}
      </EditorSheet>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
            remove.reset();
          }
        }}
        title={`Remove ${deleting?.name ?? 'the vendor'}?`}
        description="Mail from or imitating this vendor is no longer checked against its profile."
        confirmLabel="Remove vendor"
        destructive
        error={<FormAlert problem={remove.error ? confirmProblem(remove.error) : null} />}
        onConfirm={async () => {
          if (!deleting) return false;
          const outcome = await remove.submit({
            path: { id: deleting.id },
            query: { version: deleting.version },
          });
          if (!outcome.ok && outcome.error.code === 'version_conflict') {
            void refreshDeleting();
          }
          return outcome.ok;
        }}
      />
    </div>
  );
}
