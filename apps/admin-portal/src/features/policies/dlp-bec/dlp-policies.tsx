'use client';

import { PlusIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn, type RowAction } from '@/components/data-table';
import { DateTime, UntrustedText } from '@/components/domain';
import { useZodForm } from '@/components/form';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Form } from '@/components/ui/form';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { DetailList, EnumBadge } from '@/features/messages/controls';
import { ENABLED_TONE } from '../semantic';
import {
  dlpPolicyCreateBody,
  dlpPolicyDefaults,
  dlpPolicySchema,
  dlpPolicyUpdateBody,
  type DlpPolicyInput,
} from './dlp-schemas';
import { DlpRuleForm } from './dlp-rule-form';
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
  FormAlert,
  SectionToolbar,
  SelectField,
  SubmitRow,
  SwitchField,
  TextField,
  TextareaField,
  staticList,
  useEntryEditor,
  useEntryTarget,
} from './kit';
import {
  ACTION_LABELS,
  CATEGORY_LABELS,
  DIRECTION_LABELS,
  DLP_DIRECTIONS,
  DLP_MODES,
  MODE_LABELS,
  type DlpPolicyDetail,
  type DlpPolicyRow,
  type DlpRule,
} from './model';

/** DLP policies and their rules (step 4.5 D11): list, create, edit, delete; rules per policy. */

const POLICY_QUERIES: readonly OperationId[] = [
  'DlpPoliciesController_list_v1',
  'DlpPoliciesController_get_v1',
];

export const enabledBadge = (enabled: boolean) => (
  <EnumBadge value={enabled ? 'enabled' : 'disabled'} tones={ENABLED_TONE} />
);

const POLICY_COLUMNS: DataTableColumn<DlpPolicyRow>[] = [
  { id: 'name', header: 'Policy', meta: { label: 'Policy' }, cell: ({ row }) => row.original.name },
  {
    id: 'enabled',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => enabledBadge(row.original.enabled),
  },
  {
    id: 'mode',
    header: 'Mode',
    meta: { label: 'Mode' },
    cell: ({ row }) => humanize(row.original.mode),
  },
  {
    id: 'directions',
    header: 'Directions',
    meta: { label: 'Directions' },
    cell: ({ row }) => row.original.directions.map(humanize).join(', '),
  },
  {
    id: 'rules',
    header: 'Rules',
    meta: { label: 'Rules', className: 'tabular-nums' },
    cell: ({ row }) => formatNumber(row.original.ruleCount),
  },
  {
    id: 'priority',
    header: 'Priority',
    meta: { label: 'Priority', className: 'tabular-nums' },
    cell: ({ row }) => formatNumber(row.original.priority),
  },
  {
    id: 'updated',
    header: 'Updated',
    meta: { label: 'Updated' },
    cell: ({ row }) => <DateTime value={row.original.updatedAt} />,
  },
];

const POLICY_FIELDS: readonly FieldRule<keyof DlpPolicyInput>[] = [
  { path: 'name', field: 'name' },
  { path: 'description', field: 'description' },
  { path: 'enabled', field: 'enabled' },
  { path: 'mode', field: 'mode' },
  { path: 'priority', field: 'priority' },
  { path: 'directions', field: 'directions' },
];

const explainPolicy: Explain<keyof DlpPolicyInput> = (error) => {
  if (error.code === 'dlp_policy_exists') {
    return { field: 'name', message: 'A DLP policy with this name exists. Choose another name.' };
  }
  if (error.code === 'dlp_directions_invalid') {
    const references = error.details.references;
    return {
      field: 'directions',
      message: `${typeof references === 'number' ? `${references} rule(s)` : 'Rules'} of this policy use a direction you removed. Change those rules first.`,
    };
  }
  return null;
};

const DIRECTION_OPTIONS = DLP_DIRECTIONS.map((value) => ({
  value,
  label: DIRECTION_LABELS[value],
}));

function DlpPolicyForm({
  policy,
  onDone,
  onReload,
}: {
  policy?: DlpPolicyRow;
  onDone: () => void;
  onReload: () => void;
}) {
  const [problem, setProblem] = useState<Problem | null>(null);
  const create = useApiMutation('DlpPoliciesController_create_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'DLP policy created.',
  });
  const update = useApiMutation('DlpPoliciesController_update_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'DLP policy saved.',
  });
  const form = useZodForm(dlpPolicySchema, { defaultValues: dlpPolicyDefaults(policy) });
  const submit = form.handleSubmit(async (values) => {
    setProblem(null);
    let outcome;
    if (policy) {
      const body = dlpPolicyUpdateBody(policy, values);
      if (Object.keys(body).length === 1) {
        toast.info('Nothing changed.');
        return onDone();
      }
      outcome = await update.submit({ path: { id: policy.id }, body });
    } else {
      outcome = await create.submit({ body: dlpPolicyCreateBody(values) });
    }
    if (outcome.ok) return onDone();
    setProblem(applyServerError(form, outcome.error, POLICY_FIELDS, explainPolicy));
  });
  const mutation = policy ? update : create;
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label={policy ? `Edit DLP policy ${policy.name}` : 'New DLP policy'}
        onSubmit={(event) => void submit(event)}
      >
        <FormAlert problem={problem} onReload={onReload} />
        <TextField control={form.control} name="name" label="Name" required maxLength={128} />
        <TextareaField
          control={form.control}
          name="description"
          label="Description (optional)"
          hint="At most 512 characters."
        />
        <div className="grid gap-4 sm:grid-cols-2">
          <SelectField
            control={form.control}
            name="mode"
            label="Mode"
            required
            options={DLP_MODES.map((value) => ({ value, label: MODE_LABELS[value] }))}
            hint="Monitor records matches and never changes the message's action."
          />
          <TextField
            control={form.control}
            name="priority"
            label="Priority"
            required
            inputMode="numeric"
            hint="0 to 1000; lower runs first."
          />
        </div>
        <ChecklistField
          control={form.control}
          name="directions"
          legend="Directions (required)"
          hint="Inbound applies only when your organization scans inbound mail."
          options={DIRECTION_OPTIONS}
          columns={3}
        />
        <SwitchField
          control={form.control}
          name="enabled"
          label="Enabled"
          hint="A disabled policy is kept but never evaluated. Without an enabled policy for a direction, the platform default DLP policy applies."
        />
        <SubmitRow
          label={policy ? 'Save DLP policy' : 'Create DLP policy'}
          pending={mutation.isPending}
          retryAfterSeconds={mutation.retryAfterSeconds}
          onCancel={onDone}
        />
      </form>
    </Form>
  );
}

/** The "Policies" section of the DLP tab (`dlp:read` lists; `dlp:manage` edits). */
export function DlpPoliciesSection() {
  const canCreate = useCan('DlpPoliciesController_create_v1');
  const canUpdate = useCan('DlpPoliciesController_update_v1');
  const canDelete = useCan('DlpPoliciesController_remove_v1');
  const list = useCursorList('DlpPoliciesController_list_v1', undefined, { limit: 25 });
  const { editor, setEditor, reload, close } = useEntryEditor<DlpPolicyRow>(list.query.refetch);
  const [rulesOf, setRulesOf] = useState<string | null>(null);
  const {
    target: deleting,
    setTarget: setDeleting,
    refresh: refreshDeleting,
  } = useEntryTarget<DlpPolicyRow>(list.query.refetch);
  const remove = useApiMutation('DlpPoliciesController_remove_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'DLP policy deleted.',
  });
  const rulesPolicy = rulesOf ? list.rows.find((r) => r.id === rulesOf) : undefined;
  const deleteProblem = remove.error
    ? confirmProblem(remove.error, 'Exceptions target this policy or one of its rules')
    : null;

  const rowActions = (row: DlpPolicyRow): RowAction[] => [
    { label: 'Rules', onSelect: () => setRulesOf(row.id) },
    ...(canUpdate ? [{ label: 'Edit', onSelect: () => setEditor({ mode: 'edit', row }) }] : []),
    ...(canDelete
      ? [{ label: 'Delete', destructive: true, onSelect: () => setDeleting(row) }]
      : []),
  ];

  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <SectionToolbar
        actions={
          canCreate ? (
            <Button size="sm" onClick={() => setEditor({ mode: 'create' })}>
              <PlusIcon aria-hidden />
              New DLP policy
            </Button>
          ) : null
        }
      >
        Enabled policies whose directions include a message&apos;s direction are evaluated; the
        strongest action of their matched rules wins.
      </SectionToolbar>
      <DataTable
        tableId="dlp-policies"
        caption="DLP policies"
        columns={POLICY_COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        rowActions={rowActions}
        emptyState={
          <EmptyState
            title="No DLP policies"
            description="Without an enabled policy, the platform default DLP policy applies."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-0.5">
            <span className="font-medium">{row.name}</span>
            <span className="text-xs text-muted-foreground">
              {humanize(row.mode)} · {formatNumber(row.ruleCount)} rules
            </span>
          </div>
        )}
      />
      <EditorSheet
        open={editor !== null}
        onOpenChange={(open) => !open && setEditor(null)}
        title={editor?.mode === 'edit' ? `Edit ${editor.row.name}` : 'New DLP policy'}
        description="Rules are added to a policy after it is created (row action Rules)."
      >
        {editor?.mode === 'create' ? (
          <DlpPolicyForm onDone={close} onReload={() => undefined} />
        ) : editor ? (
          <DlpPolicyForm
            key={`${editor.row.id}:${editor.row.version}`}
            policy={editor.row}
            onDone={close}
            onReload={() => void reload()}
          />
        ) : null}
      </EditorSheet>
      <EditorSheet
        open={rulesOf !== null}
        onOpenChange={(open) => !open && setRulesOf(null)}
        title={`Rules of ${rulesPolicy?.name ?? 'the DLP policy'}`}
        description="Rules run by priority (lower first). The strongest action of the matched rules of enforcing policies applies to the message."
        wide
      >
        {rulesOf ? <DlpRulesPanel policyId={rulesOf} /> : null}
      </EditorSheet>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
            remove.reset();
          }
        }}
        title={`Delete ${deleting?.name ?? 'the DLP policy'}?`}
        description={
          <p>
            The policy and its {formatNumber(deleting?.ruleCount ?? 0)} rules are deleted. Messages
            scanned after the DLP engine&apos;s cache refresh (30 seconds by default) no longer use
            them; finished scans keep their result. This cannot be undone.
          </p>
        }
        confirmLabel="Delete DLP policy"
        destructive
        typedConfirmation={deleting?.name}
        error={<FormAlert problem={deleteProblem} />}
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
// The rules of one policy (GET /dlp/policies/{id}; fetched only while the panel is open)
// ---------------------------------------------------------------------------------------------

function selectorSummary(rule: DlpRule): string {
  const s = rule.conditions.selectors;
  const parts = [
    ...(s.categories ?? []).map((c) => CATEGORY_LABELS[c] ?? humanize(c)),
    ...(s.detectors ?? []),
    ...(s.customPatternIds?.length ? [`${s.customPatternIds.length} custom pattern(s)`] : []),
    ...(s.dictionaryIds?.length ? [`${s.dictionaryIds.length} dictionary(ies)`] : []),
    ...(s.coverageReasons?.length ? [`${s.coverageReasons.length} coverage reason(s)`] : []),
  ];
  return parts.join(', ');
}

const RULE_COLUMNS: DataTableColumn<DlpRule>[] = [
  { id: 'name', header: 'Rule', meta: { label: 'Rule' }, cell: ({ row }) => row.original.name },
  {
    id: 'action',
    header: 'Action',
    meta: { label: 'Action' },
    cell: ({ row }) => humanize(row.original.action),
  },
  {
    id: 'selects',
    header: 'Looks for',
    meta: { label: 'Looks for', className: 'max-w-80 whitespace-normal' },
    cell: ({ row }) => <UntrustedText value={selectorSummary(row.original)} maxLength={120} />,
  },
  {
    id: 'priority',
    header: 'Priority',
    meta: { label: 'Priority', className: 'tabular-nums' },
    cell: ({ row }) => formatNumber(row.original.priority),
  },
  {
    id: 'enabled',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => enabledBadge(row.original.enabled),
  },
];

function PolicySummary({ policy }: { policy: DlpPolicyDetail }) {
  return (
    <DetailList
      items={[
        { label: 'Status', value: enabledBadge(policy.enabled) },
        { label: 'Mode', value: MODE_LABELS[policy.mode] ?? humanize(policy.mode) },
        {
          label: 'Directions',
          value: policy.directions.map((d) => DIRECTION_LABELS[d] ?? humanize(d)).join(', '),
        },
        { label: 'Priority', value: formatNumber(policy.priority) },
        {
          label: 'Description',
          value: <UntrustedText value={policy.description} emptyLabel="None" maxLength={300} />,
        },
        { label: 'Updated', value: <DateTime value={policy.updatedAt} /> },
      ]}
    />
  );
}

const rulesOfDetail = (data: unknown): readonly DlpRule[] =>
  (data as DlpPolicyDetail | undefined)?.rules ?? [];

function DlpRulesPanel({ policyId }: { policyId: string }) {
  const canCreate = useCan('DlpPoliciesController_createRule_v1');
  const canUpdate = useCan('DlpPoliciesController_updateRule_v1');
  const canDelete = useCan('DlpPoliciesController_removeRule_v1');
  const detail = useApiQuery('DlpPoliciesController_get_v1', { path: { id: policyId } });
  const { editor, setEditor, reload, close } = useEntryEditor<DlpRule>(
    detail.refetch,
    rulesOfDetail,
  );
  const {
    target: deleting,
    setTarget: setDeleting,
    refresh: refreshDeleting,
  } = useEntryTarget<DlpRule>(detail.refetch, rulesOfDetail);
  const remove = useApiMutation('DlpPoliciesController_removeRule_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'DLP rule deleted.',
  });
  const rules = useMemo(() => detail.data?.rules ?? [], [detail.data]);
  if (detail.isLoading) return <LoadingState label="Loading the rules" rows={4} />;
  if (detail.error || !detail.data) {
    return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />;
  }
  const policy = detail.data;
  const deleteProblem = remove.error
    ? confirmProblem(remove.error, 'Exceptions target this rule')
    : null;
  const rowActions =
    canUpdate || canDelete
      ? (row: DlpRule): RowAction[] => [
          ...(canUpdate
            ? [{ label: 'Edit', onSelect: () => setEditor({ mode: 'edit', row }) }]
            : []),
          ...(canDelete
            ? [{ label: 'Delete', destructive: true, onSelect: () => setDeleting(row) }]
            : []),
        ]
      : undefined;
  return (
    <>
      <PolicySummary policy={policy} />
      <SectionToolbar
        actions={
          canCreate ? (
            <Button size="sm" onClick={() => setEditor({ mode: 'create' })}>
              <PlusIcon aria-hidden />
              Add rule
            </Button>
          ) : null
        }
      >
        Actions, weakest first: {Object.values(ACTION_LABELS).join(' < ')}.
      </SectionToolbar>
      <DataTable
        tableId="dlp-rules"
        caption={`Rules of ${policy.name}`}
        columns={RULE_COLUMNS}
        list={staticList(rules, detail)}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        rowActions={rowActions}
        emptyState={
          <EmptyState
            title="No rules yet"
            description="A policy without rules never matches. Add a rule to choose what it looks for and which action applies."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-0.5">
            <span className="font-medium">{row.name}</span>
            <span className="text-xs text-muted-foreground">
              {humanize(row.action)} · priority {formatNumber(row.priority)}
            </span>
          </div>
        )}
      />
      <EditorSheet
        open={editor !== null}
        onOpenChange={(open) => !open && setEditor(null)}
        title={
          editor?.mode === 'edit' ? `Edit rule ${editor.row.name}` : `New rule in ${policy.name}`
        }
        description="A rule matches when enough findings of the selected kinds remain after exceptions and its scope matches."
        wide
      >
        {editor?.mode === 'create' ? (
          <DlpRuleForm policy={policy} onDone={close} onReload={() => undefined} />
        ) : editor ? (
          <DlpRuleForm
            key={`${editor.row.id}:${editor.row.version}`}
            policy={policy}
            rule={editor.row}
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
        title={`Delete rule ${deleting?.name ?? ''}?`}
        description="Messages scanned after the DLP engine's cache refresh no longer use this rule; finished scans keep their result."
        confirmLabel="Delete rule"
        destructive
        error={<FormAlert problem={deleteProblem} />}
        onConfirm={async () => {
          if (!deleting) return false;
          const outcome = await remove.submit({
            path: { id: policy.id, ruleId: deleting.id },
            query: { version: deleting.version },
          });
          if (!outcome.ok && outcome.error.code === 'version_conflict') {
            void refreshDeleting();
          }
          return outcome.ok;
        }}
      />
    </>
  );
}
