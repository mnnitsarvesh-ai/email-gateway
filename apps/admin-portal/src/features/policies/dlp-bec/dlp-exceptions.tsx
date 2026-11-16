'use client';

import { PlusIcon } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useWatch, type Control, type FieldPath } from 'react-hook-form';
import { toast } from 'sonner';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn, type RowAction } from '@/components/data-table';
import { CopyableId, DateTime, UntrustedText } from '@/components/domain';
import { useZodForm } from '@/components/form';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { Button } from '@/components/ui/button';
import { Form } from '@/components/ui/form';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge } from '@/features/messages/controls';
import { ENABLED_TONE } from '../semantic';
import {
  EXCEPTION_TARGETS,
  dlpExceptionCreateBody,
  dlpExceptionDefaults,
  dlpExceptionEditDefaults,
  dlpExceptionEditSchema,
  dlpExceptionSchema,
  dlpExceptionUpdateBody,
  type DlpExceptionEditInput,
  type DlpExceptionInput,
  type ExceptionTarget,
} from './dlp-schemas';
import { enabledBadge } from './dlp-policies';
import {
  applyServerError,
  confirmProblem,
  type Explain,
  type FieldRule,
  type Problem,
} from './errors';
import {
  ChecklistField,
  EditorSheet,
  FieldGroup,
  FormAlert,
  SectionToolbar,
  SelectField,
  SubmitRow,
  SwitchField,
  TextField,
  TextareaField,
  type ChoiceOption,
  useEntryEditor,
  useEntryTarget,
} from './kit';
import {
  CATEGORY_LABELS,
  DETECTOR_LABELS,
  DLP_CATEGORIES,
  DLP_DETECTORS,
  DLP_EXCEPTION_SCOPES,
  EXCEPTION_SCOPE_LABELS,
  type DlpExceptionRow,
} from './model';

/**
 * DLP exceptions (step 4.5 D12): a sender or recipient address or domain, optionally for one
 * policy or rule and some detectors or categories, with a required reason and expiry.
 */

const EXCEPTION_QUERIES: readonly OperationId[] = ['DlpExceptionsController_list_v1'];

const DETECTOR_OPTIONS: ChoiceOption[] = DLP_DETECTORS.map((value) => ({
  value,
  label: DETECTOR_LABELS[value],
  code: value,
}));
const CATEGORY_OPTIONS: ChoiceOption[] = DLP_CATEGORIES.map((value) => ({
  value,
  label: CATEGORY_LABELS[value],
}));

const TARGET_LABELS: Record<ExceptionTarget, string> = {
  all: 'Every DLP rule',
  policy: 'The rules of one policy',
  rule: 'One rule',
};

export const SENDER_WARNING =
  'Sender exceptions match the envelope sender (MAIL FROM), which is not bound to an authenticated user: anyone who can submit through your connectors, or any inbound sender, can set it. Prefer recipient or domain exceptions where possible.';

function targetOf(row: DlpExceptionRow) {
  if (row.ruleId) return { label: 'One rule', id: row.ruleId };
  if (row.policyId) return { label: 'One policy', id: row.policyId };
  return { label: 'Every rule', id: null };
}

function filterCodes(row: Pick<DlpExceptionRow, 'filters'>): string[] {
  return [...(row.filters?.categories ?? []), ...(row.filters?.detectors ?? [])];
}

const EXCEPTION_COLUMNS: DataTableColumn<DlpExceptionRow>[] = [
  {
    id: 'scope',
    header: 'Scope',
    meta: { label: 'Scope' },
    cell: ({ row }) => humanize(row.original.scope),
  },
  {
    id: 'value',
    header: 'Value',
    meta: { label: 'Value' },
    cell: ({ row }) => <UntrustedText value={row.original.value} maxLength={60} />,
  },
  {
    id: 'target',
    header: 'Applies to',
    meta: { label: 'Applies to' },
    cell: ({ row }) => {
      const target = targetOf(row.original);
      return target.id ? (
        <span className="inline-flex flex-wrap items-center gap-1">
          {target.label} <CopyableId value={target.id} label="target ID" max={12} />
        </span>
      ) : (
        target.label
      );
    },
  },
  {
    id: 'filters',
    header: 'Only',
    meta: { label: 'Only' },
    cell: ({ row }) => <CodeList codes={filterCodes(row.original)} emptyLabel="Every finding" />,
  },
  {
    id: 'reason',
    header: 'Reason',
    meta: { label: 'Reason', className: 'max-w-72' },
    cell: ({ row }) => <UntrustedText value={row.original.reason} maxLength={80} />,
  },
  {
    id: 'expires',
    header: 'Expires',
    meta: { label: 'Expires' },
    cell: ({ row }) => <DateTime value={row.original.expiresAt} />,
  },
  {
    id: 'status',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) =>
      row.original.expired ? (
        <EnumBadge value="expired" tones={ENABLED_TONE} />
      ) : (
        enabledBadge(row.original.enabled)
      ),
  },
];

const explainException: Explain<keyof DlpExceptionInput> = (error) => {
  if (error.code === 'dlp_exception_exists') {
    return {
      field: 'value',
      message: 'An exception for this scope, value and target exists. Edit that one instead.',
    };
  }
  if (error.code === 'dlp_reference_invalid') {
    const field = typeof error.details.field === 'string' ? error.details.field : '';
    return field === 'ruleId'
      ? { field: 'ruleId', message: 'This rule is not one of your organization’s DLP rules.' }
      : {
          field: 'policyId',
          message: 'This policy is not one of your organization’s DLP policies.',
        };
  }
  return null;
};

const CREATE_FIELDS: readonly FieldRule<keyof DlpExceptionInput>[] = [
  { path: 'scope', field: 'scope' },
  { path: 'value', field: 'value' },
  { path: 'policyId', field: 'policyId' },
  { path: 'ruleId', field: 'ruleId' },
  { path: 'filters.detectors', field: 'detectors' },
  { path: 'filters.categories', field: 'categories' },
  { path: 'filters', field: 'categories' },
  { path: 'reason', field: 'reason' },
  { path: 'expiresAt', field: 'expiresOn' },
  { path: 'enabled', field: 'enabled' },
];

const EDIT_FIELDS: readonly FieldRule<keyof DlpExceptionEditInput>[] = [
  { path: 'filters.detectors', field: 'detectors' },
  { path: 'filters.categories', field: 'categories' },
  { path: 'filters', field: 'categories' },
  { path: 'reason', field: 'reason' },
  { path: 'expiresAt', field: 'expiresOn' },
  { path: 'enabled', field: 'enabled' },
];

interface FilterValues {
  detectors: string[];
  categories: string[];
  [key: string]: unknown;
}

function FilterChoices<T extends FilterValues>({ control }: { control: Control<T> }) {
  return (
    <FieldGroup
      legend="Only these findings (optional)"
      description="Nothing selected: the exception removes every finding (sender) or the recipient from every finding (recipient)."
    >
      <ChecklistField
        control={control}
        name={'categories' as FieldPath<T>}
        legend="Data categories"
        options={CATEGORY_OPTIONS}
      />
      <ChecklistField
        control={control}
        name={'detectors' as FieldPath<T>}
        legend="Detectors"
        options={DETECTOR_OPTIONS}
      />
    </FieldGroup>
  );
}

/** Target pickers: the policies (and a policy's rules) are read only when a target is chosen. */
function TargetPickers({
  control,
  target,
  policyId,
}: {
  control: Control<DlpExceptionInput>;
  target: ExceptionTarget;
  policyId: string;
}) {
  const policies = useApiQuery(
    'DlpPoliciesController_list_v1',
    { query: { limit: 100 } },
    { enabled: target !== 'all' },
  );
  const detail = useApiQuery(
    'DlpPoliciesController_get_v1',
    { path: { id: policyId } },
    { enabled: target === 'rule' && policyId !== '' },
  );
  if (target === 'all') return null;
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {policies.error ? (
        <ErrorState error={policies.error} onRetry={() => void policies.refetch()} compact />
      ) : (
        <SelectField
          control={control}
          name="policyId"
          label="Policy"
          required
          emptyOption={policies.isLoading ? 'Loading policies …' : 'Choose a policy'}
          options={(policies.data?.data ?? []).map((p) => ({ value: p.id, label: p.name }))}
        />
      )}
      {target === 'rule' ? (
        detail.error ? (
          <ErrorState error={detail.error} onRetry={() => void detail.refetch()} compact />
        ) : (
          <SelectField
            control={control}
            name="ruleId"
            label="Rule"
            required
            disabled={!policyId}
            emptyOption={
              !policyId
                ? 'Choose a policy first'
                : detail.isLoading
                  ? 'Loading rules …'
                  : 'Choose a rule'
            }
            options={(detail.data?.rules ?? []).map((r) => ({ value: r.id, label: r.name }))}
          />
        )
      ) : null}
    </div>
  );
}

function NewExceptionForm({ onDone }: { onDone: () => void }) {
  const [problem, setProblem] = useState<Problem | null>(null);
  const create = useApiMutation('DlpExceptionsController_create_v1', {
    invalidates: EXCEPTION_QUERIES,
    successMessage: 'DLP exception added.',
  });
  const form = useZodForm(dlpExceptionSchema, { defaultValues: dlpExceptionDefaults() });
  const [scope, target, policyId] = useWatch({
    control: form.control,
    name: ['scope', 'target', 'policyId'],
  });
  // A rule belongs to one policy: choosing another policy clears the rule.
  const { setValue } = form;
  useEffect(() => setValue('ruleId', ''), [policyId, setValue]);
  const submit = form.handleSubmit(async (values) => {
    setProblem(null);
    const outcome = await create.submit({ body: dlpExceptionCreateBody(values) });
    if (outcome.ok) return onDone();
    setProblem(applyServerError(form, outcome.error, CREATE_FIELDS, explainException));
  });
  const address = scope.endsWith('_address');
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label="New DLP exception"
        onSubmit={(event) => void submit(event)}
      >
        <FormAlert problem={problem} />
        <div className="grid gap-4 sm:grid-cols-2">
          <SelectField
            control={form.control}
            name="scope"
            label="Scope"
            required
            options={DLP_EXCEPTION_SCOPES.map((value) => ({
              value,
              label: EXCEPTION_SCOPE_LABELS[value],
            }))}
          />
          <TextField
            control={form.control}
            name="value"
            label={address ? 'Address' : 'Domain'}
            required
            mono
            maxLength={320}
            hint={
              address
                ? 'Normalized by the API (lower case, international domain names).'
                : 'Public suffixes and IP literals are refused.'
            }
          />
        </div>
        {scope.startsWith('sender_') ? (
          <p
            role="note"
            className="rounded-md bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground"
          >
            {SENDER_WARNING}
          </p>
        ) : null}
        <SelectField
          control={form.control}
          name="target"
          label="Applies to"
          required
          options={EXCEPTION_TARGETS.map((value) => ({ value, label: TARGET_LABELS[value] }))}
          hint="The target cannot be changed later (delete the exception and add a new one)."
        />
        <TargetPickers control={form.control} target={target} policyId={policyId} />
        <FilterChoices control={form.control} />
        <TextareaField control={form.control} name="reason" label="Reason" required />
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            control={form.control}
            name="expiresOn"
            label="Expires"
            type="date"
            required
            hint="At the end of this day (UTC); the platform allows at most 365 days ahead by default."
          />
        </div>
        <SwitchField control={form.control} name="enabled" label="Enabled" />
        <SubmitRow
          label="Add exception"
          pending={create.isPending}
          retryAfterSeconds={create.retryAfterSeconds}
          onCancel={onDone}
        />
      </form>
    </Form>
  );
}

function EditExceptionForm({
  exception,
  onDone,
  onReload,
}: {
  exception: DlpExceptionRow;
  onDone: () => void;
  onReload: () => void;
}) {
  const [problem, setProblem] = useState<Problem | null>(null);
  const update = useApiMutation('DlpExceptionsController_update_v1', {
    invalidates: EXCEPTION_QUERIES,
    successMessage: 'DLP exception saved.',
  });
  const schema = useMemo(() => dlpExceptionEditSchema(exception), [exception]);
  const form = useZodForm(schema, { defaultValues: dlpExceptionEditDefaults(exception) });
  const submit = form.handleSubmit(async (values) => {
    setProblem(null);
    const body = dlpExceptionUpdateBody(exception, values);
    if (Object.keys(body).length === 1) {
      toast.info('Nothing changed.');
      return onDone();
    }
    const outcome = await update.submit({ path: { id: exception.id }, body });
    if (outcome.ok) return onDone();
    setProblem(applyServerError(form, outcome.error, EDIT_FIELDS));
  });
  const target = targetOf(exception);
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label="Edit DLP exception"
        onSubmit={(event) => void submit(event)}
      >
        <FormAlert problem={problem} onReload={onReload} />
        <DetailList
          items={[
            { label: 'Scope', value: EXCEPTION_SCOPE_LABELS[exception.scope] },
            { label: 'Value', value: <UntrustedText value={exception.value} /> },
            {
              label: 'Applies to',
              value: target.id ? (
                <span className="inline-flex flex-wrap items-center gap-1">
                  {target.label} <CopyableId value={target.id} label="target ID" />
                </span>
              ) : (
                target.label
              ),
            },
          ]}
        />
        <p className="text-xs text-muted-foreground">
          Scope, value and target are fixed: to change them, delete this exception and add a new
          one.
        </p>
        <FilterChoices control={form.control} />
        <TextareaField control={form.control} name="reason" label="Reason" required />
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            control={form.control}
            name="expiresOn"
            label="Expires"
            type="date"
            required
            hint="At the end of this day (UTC)."
          />
        </div>
        <SwitchField control={form.control} name="enabled" label="Enabled" />
        <SubmitRow
          label="Save exception"
          pending={update.isPending}
          retryAfterSeconds={update.retryAfterSeconds}
          onCancel={onDone}
        />
      </form>
    </Form>
  );
}

/** The "Exceptions" section of the DLP tab. */
export function DlpExceptionsSection() {
  const canCreate = useCan('DlpExceptionsController_create_v1');
  const canUpdate = useCan('DlpExceptionsController_update_v1');
  const canDelete = useCan('DlpExceptionsController_remove_v1');
  const list = useCursorList('DlpExceptionsController_list_v1', undefined, { limit: 25 });
  const { editor, setEditor, reload, close } = useEntryEditor<DlpExceptionRow>(list.query.refetch);
  const {
    target: deleting,
    setTarget: setDeleting,
    refresh: refreshDeleting,
  } = useEntryTarget<DlpExceptionRow>(list.query.refetch);
  const remove = useApiMutation('DlpExceptionsController_remove_v1', {
    invalidates: EXCEPTION_QUERIES,
    successMessage: 'DLP exception removed.',
  });
  const rowActions =
    canUpdate || canDelete
      ? (row: DlpExceptionRow): RowAction[] => [
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
              New exception
            </Button>
          ) : null
        }
      >
        Exceptions remove findings (sender) or recipients (recipient) from the rules they target
        until they expire; investigators see which exception applied.
      </SectionToolbar>
      <DataTable
        tableId="dlp-exceptions"
        caption="DLP exceptions"
        columns={EXCEPTION_COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `${humanize(row.scope)} ${row.value}`}
        rowActions={rowActions}
        emptyState={<EmptyState title="No exceptions" />}
        mobileCard={(row) => (
          <div className="grid gap-0.5">
            <UntrustedText value={row.value} />
            <span className="text-xs text-muted-foreground">{humanize(row.scope)}</span>
          </div>
        )}
      />
      <EditorSheet
        open={editor !== null}
        onOpenChange={(open) => !open && setEditor(null)}
        title={editor?.mode === 'edit' ? 'Edit DLP exception' : 'New DLP exception'}
        description="Exceptions apply to messages scanned after the DLP engine's cache refresh (30 seconds by default)."
      >
        {editor?.mode === 'create' ? (
          <NewExceptionForm onDone={close} />
        ) : editor ? (
          <EditExceptionForm
            key={`${editor.row.id}:${editor.row.version}`}
            exception={editor.row}
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
        title="Remove this DLP exception?"
        description={
          deleting ? (
            <p>
              {humanize(deleting.scope)} <UntrustedText value={deleting.value} />: the targeted
              rules apply to it again for messages scanned after the DLP engine&apos;s cache
              refresh.
            </p>
          ) : null
        }
        confirmLabel="Remove exception"
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
