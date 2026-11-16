'use client';

import { PlusIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useWatch } from 'react-hook-form';
import { toast } from 'sonner';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn, type RowAction } from '@/components/data-table';
import { DateTime, UntrustedText } from '@/components/domain';
import { useZodForm } from '@/components/form';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Form } from '@/components/ui/form';
import { useApiMutation, useCursorList } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { DetailList } from '@/features/messages/controls';
import { BEC_CACHE_NOTE } from './bec-profiles';
import {
  TRUSTED_DEFAULTS,
  trustedSenderCreateBody,
  trustedSenderEditDefaults,
  trustedSenderEditSchema,
  trustedSenderSchema,
  trustedSenderUpdateBody,
  type TrustedSenderEditInput,
  type TrustedSenderInput,
} from './bec-schemas';
import {
  applyServerError,
  confirmProblem,
  problemOf,
  type Explain,
  type FieldRule,
  type Problem,
} from './errors';
import {
  EditorSheet,
  FormAlert,
  SectionToolbar,
  SelectField,
  SubmitRow,
  TextField,
  TextareaField,
  useEntryEditor,
  useEntryTarget,
} from './kit';
import { TRUSTED_KINDS, TRUSTED_KIND_LABELS, type Suppression, type TrustedSender } from './model';

/**
 * Trusted senders (step 4.4 B7) and suppressions created from false-positive feedback (B11). Trust
 * applies only when a message authenticates as its From domain and never neutralizes
 * authentication, lookalike, executive impersonation or link findings. Lifting a suppression is
 * the only suppression write here (feedback and its export are data operations, not in 7.3).
 */

const TRUSTED_QUERIES: readonly OperationId[] = ['BecTrustedSendersController_list_v1'];
const SUPPRESSION_QUERIES: readonly OperationId[] = ['BecFeedbackController_listSuppressions_v1'];

const TRUSTED_COLUMNS: DataTableColumn<TrustedSender>[] = [
  {
    id: 'kind',
    header: 'Kind',
    meta: { label: 'Kind' },
    cell: ({ row }) => humanize(row.original.kind),
  },
  {
    id: 'value',
    header: 'Value',
    meta: { label: 'Value' },
    cell: ({ row }) => <UntrustedText value={row.original.value} mono />,
  },
  {
    id: 'reason',
    header: 'Reason',
    meta: { label: 'Reason' },
    cell: ({ row }) => <UntrustedText value={row.original.reason} maxLength={80} />,
  },
  {
    id: 'expires',
    header: 'Expires',
    meta: { label: 'Expires' },
    cell: ({ row }) => (
      <span className="inline-flex flex-wrap items-center gap-1">
        <DateTime value={row.original.expiresAt} emptyLabel="Never" />
        {row.original.expired ? (
          <span className="text-xs text-muted-foreground">(expired)</span>
        ) : null}
      </span>
    ),
  },
];

const SUPPRESSION_COLUMNS: DataTableColumn<Suppression>[] = [
  {
    id: 'code',
    header: 'Reason code',
    meta: { label: 'Reason code' },
    cell: ({ row }) => <span className="font-mono text-xs">{row.original.reasonCode}</span>,
  },
  {
    id: 'scope',
    header: 'Sender scope',
    meta: { label: 'Sender scope' },
    cell: ({ row }) => humanize(row.original.senderScope),
  },
  {
    id: 'value',
    header: 'Sender',
    meta: { label: 'Sender' },
    cell: ({ row }) => <UntrustedText value={row.original.senderValue} mono />,
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
    cell: ({ row }) => (row.original.expired ? 'Expired' : 'Active'),
  },
];

// ---------------------------------------------------------------------------------------------
// Trusted senders
// ---------------------------------------------------------------------------------------------

const CREATE_FIELDS: readonly FieldRule<keyof TrustedSenderInput>[] = [
  { path: 'kind', field: 'kind' },
  { path: 'value', field: 'value' },
  { path: 'reason', field: 'reason' },
  { path: 'expiresAt', field: 'expiresOn' },
];
const EDIT_FIELDS: readonly FieldRule<keyof TrustedSenderEditInput>[] = [
  { path: 'reason', field: 'reason' },
  { path: 'expiresAt', field: 'expiresOn' },
];

const explainTrusted: Explain<keyof TrustedSenderInput> = (error) => {
  if (error.code === 'trusted_sender_exists') {
    return { field: 'value', message: 'This sender is already trusted.' };
  }
  if (error.code === 'trusted_domain_freemail') {
    return {
      field: 'value',
      message: 'A free-mail domain cannot be trusted; trust the exact address instead.',
    };
  }
  return null;
};

export const TRUST_NOTE =
  'Trust applies only when the message authenticates as its From domain. It never neutralizes authentication, lookalike, executive impersonation or link findings.';

function NewTrustedSenderForm({ onDone }: { onDone: () => void }) {
  const [problem, setProblem] = useState<Problem | null>(null);
  const create = useApiMutation('BecTrustedSendersController_create_v1', {
    invalidates: TRUSTED_QUERIES,
    successMessage: 'Trusted sender added.',
  });
  const form = useZodForm(trustedSenderSchema, { defaultValues: TRUSTED_DEFAULTS });
  const kind = useWatch({ control: form.control, name: 'kind' });
  const submit = form.handleSubmit(async (values) => {
    setProblem(null);
    const outcome = await create.submit({ body: trustedSenderCreateBody(values) });
    if (outcome.ok) return onDone();
    setProblem(applyServerError(form, outcome.error, CREATE_FIELDS, explainTrusted));
  });
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label="New trusted sender"
        onSubmit={(event) => void submit(event)}
      >
        <FormAlert problem={problem} />
        <p className="text-xs text-muted-foreground">{TRUST_NOTE}</p>
        <div className="grid gap-4 sm:grid-cols-2">
          <SelectField
            control={form.control}
            name="kind"
            label="Kind"
            required
            options={TRUSTED_KINDS.map((value) => ({ value, label: TRUSTED_KIND_LABELS[value] }))}
          />
          <TextField
            control={form.control}
            name="value"
            label={kind === 'address' ? 'Address' : 'Registrable domain'}
            required
            mono
            maxLength={320}
            hint={
              kind === 'address'
                ? 'An exact address (compared case-insensitively).'
                : 'The registrable domain of From; subdomains, public suffixes and free-mail domains are refused.'
            }
          />
        </div>
        <TextareaField control={form.control} name="reason" label="Reason" required />
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            control={form.control}
            name="expiresOn"
            label="Expires (optional)"
            type="date"
            hint="At the end of this day (UTC), at most 365 days ahead. Empty: no expiry."
          />
        </div>
        <SubmitRow
          label="Add trusted sender"
          pending={create.isPending}
          retryAfterSeconds={create.retryAfterSeconds}
          onCancel={onDone}
        />
      </form>
    </Form>
  );
}

function EditTrustedSenderForm({
  sender,
  onDone,
  onReload,
}: {
  sender: TrustedSender;
  onDone: () => void;
  onReload: () => void;
}) {
  const [problem, setProblem] = useState<Problem | null>(null);
  const update = useApiMutation('BecTrustedSendersController_update_v1', {
    invalidates: TRUSTED_QUERIES,
    successMessage: 'Trusted sender saved.',
  });
  const schema = useMemo(() => trustedSenderEditSchema(sender), [sender]);
  const form = useZodForm(schema, { defaultValues: trustedSenderEditDefaults(sender) });
  const submit = form.handleSubmit(async (values) => {
    setProblem(null);
    const body = trustedSenderUpdateBody(sender, values);
    if (Object.keys(body).length === 1) {
      toast.info('Nothing changed.');
      return onDone();
    }
    const outcome = await update.submit({ path: { id: sender.id }, body });
    if (outcome.ok) return onDone();
    setProblem(applyServerError(form, outcome.error, EDIT_FIELDS));
  });
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label="Edit trusted sender"
        onSubmit={(event) => void submit(event)}
      >
        <FormAlert problem={problem} onReload={onReload} />
        <DetailList
          items={[
            { label: 'Kind', value: TRUSTED_KIND_LABELS[sender.kind] },
            { label: 'Value', value: <UntrustedText value={sender.value} mono /> },
          ]}
        />
        <p className="text-xs text-muted-foreground">
          Kind and value are fixed: to change them, delete this entry and add a new one.
        </p>
        <TextareaField control={form.control} name="reason" label="Reason" required />
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            control={form.control}
            name="expiresOn"
            label="Expires (optional)"
            type="date"
            hint="At the end of this day (UTC). Empty: no expiry."
          />
        </div>
        <SubmitRow
          label="Save trusted sender"
          pending={update.isPending}
          retryAfterSeconds={update.retryAfterSeconds}
          onCancel={onDone}
        />
      </form>
    </Form>
  );
}

/** The "Trusted senders" section of the BEC tab. */
export function TrustedSendersSection() {
  const canCreate = useCan('BecTrustedSendersController_create_v1');
  const canUpdate = useCan('BecTrustedSendersController_update_v1');
  const canDelete = useCan('BecTrustedSendersController_remove_v1');
  const list = useCursorList('BecTrustedSendersController_list_v1', undefined, { limit: 25 });
  const { editor, setEditor, reload, close } = useEntryEditor<TrustedSender>(list.query.refetch);
  const {
    target: deleting,
    setTarget: setDeleting,
    refresh: refreshDeleting,
  } = useEntryTarget<TrustedSender>(list.query.refetch);
  const remove = useApiMutation('BecTrustedSendersController_remove_v1', {
    invalidates: TRUSTED_QUERIES,
    successMessage: 'Trusted sender removed.',
  });
  const rowActions =
    canUpdate || canDelete
      ? (row: TrustedSender): RowAction[] => [
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
              New trusted sender
            </Button>
          ) : null
        }
      >
        {TRUST_NOTE}
      </SectionToolbar>
      <DataTable
        tableId="bec-trusted"
        caption="Trusted senders"
        columns={TRUSTED_COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.value}
        rowActions={rowActions}
        emptyState={<EmptyState title="No trusted senders" />}
        mobileCard={(row) => <UntrustedText value={row.value} />}
      />
      <EditorSheet
        open={editor !== null}
        onOpenChange={(open) => !open && setEditor(null)}
        title={editor?.mode === 'edit' ? 'Edit trusted sender' : 'New trusted sender'}
        description={BEC_CACHE_NOTE}
      >
        {editor?.mode === 'create' ? (
          <NewTrustedSenderForm onDone={close} />
        ) : editor ? (
          <EditTrustedSenderForm
            key={`${editor.row.id}:${editor.row.version}`}
            sender={editor.row}
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
        title="Remove this trusted sender?"
        description={
          deleting ? (
            <p>
              <UntrustedText value={deleting.value} mono /> is no longer trusted for messages
              scanned after the BEC engine&apos;s cache refresh.
            </p>
          ) : null
        }
        confirmLabel="Remove trusted sender"
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
// Suppressions (lift only)
// ---------------------------------------------------------------------------------------------

/** The "Suppressions" section of the BEC tab: rules from false-positive feedback; lift only. */
export function SuppressionsSection() {
  const canLift = useCan('BecFeedbackController_deleteSuppression_v1');
  const list = useCursorList('BecFeedbackController_listSuppressions_v1', undefined, {
    limit: 25,
  });
  const [liftingId, setLiftingId] = useState<string | null>(null);
  const lift = useApiMutation('BecFeedbackController_deleteSuppression_v1', {
    invalidates: SUPPRESSION_QUERIES,
    successMessage: 'Suppression lifted.',
  });
  const lifting = liftingId ? list.rows.find((r) => r.id === liftingId) : undefined;
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <SectionToolbar>
        Suppressions silence one reason code for one sender for a bounded time; they are created
        from false-positive feedback on a message.
      </SectionToolbar>
      <DataTable
        tableId="bec-suppressions"
        caption="Suppressions"
        columns={SUPPRESSION_COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `${row.reasonCode} for ${row.senderValue}`}
        rowActions={
          canLift
            ? (row): RowAction[] => [
                {
                  label: 'Lift suppression',
                  destructive: true,
                  onSelect: () => setLiftingId(row.id),
                },
              ]
            : undefined
        }
        emptyState={<EmptyState title="No suppressions" />}
        mobileCard={(row) => row.reasonCode}
      />
      <ConfirmDialog
        open={liftingId !== null}
        onOpenChange={(open) => {
          if (!open) {
            setLiftingId(null);
            lift.reset();
          }
        }}
        title="Lift this suppression?"
        description={
          lifting ? (
            <p>
              <span className="font-mono text-xs">{lifting.reasonCode}</span> applies again to{' '}
              <UntrustedText value={lifting.senderValue} mono /> for messages scanned after the BEC
              engine&apos;s cache refresh (30 seconds by default). Lifting is audited and cannot be
              undone; a new suppression needs new feedback.
            </p>
          ) : null
        }
        confirmLabel="Lift suppression"
        destructive
        error={<FormAlert problem={lift.error ? problemOf(lift.error) : null} />}
        onConfirm={async () => {
          if (!lifting) return false;
          const outcome = await lift.submit({ path: { id: lifting.id } });
          if (!outcome.ok && outcome.error.status === 404) void list.query.refetch();
          return outcome.ok;
        }}
      />
    </div>
  );
}
