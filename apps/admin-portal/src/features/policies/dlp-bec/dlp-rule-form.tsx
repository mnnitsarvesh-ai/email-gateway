'use client';

import { useState } from 'react';
import type { Control } from 'react-hook-form';
import { toast } from 'sonner';
import { useZodForm } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { Form } from '@/components/ui/form';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import {
  dlpRuleCreateBody,
  dlpRuleDefaults,
  dlpRuleSchema,
  dlpRuleUpdateBody,
  type DlpRuleInput,
} from './dlp-schemas';
import { applyServerError, type Explain, type FieldRule, type Problem } from './errors';
import {
  CheckboxField,
  ChecklistField,
  FieldGroup,
  FormAlert,
  LinesField,
  SelectField,
  SubmitRow,
  SwitchField,
  TextField,
  type ChoiceOption,
} from './kit';
import {
  ACTION_LABELS,
  CATEGORY_LABELS,
  COVERAGE_LABELS,
  DETECTOR_LABELS,
  DIRECTION_LABELS,
  DLP_ACTIONS,
  DLP_CATEGORIES,
  DLP_COVERAGE_REASONS,
  DLP_DETECTORS,
  DLP_MIN_SEVERITIES,
  MIN_SEVERITY_LABELS,
  lineOfEntry,
  type DlpPolicyDetail,
  type DlpRule,
} from './model';

/**
 * The editor of one DLP rule (step 4.5 D11 `conditions`, strict): what it looks for (at least one
 * selector), thresholds, scope and the action. The custom pattern and dictionary choices are read
 * when the editor opens. The API re-validates everything (references, directions ⊆ the policy's).
 */

const RULE_QUERIES: readonly OperationId[] = [
  'DlpPoliciesController_get_v1',
  'DlpPoliciesController_list_v1',
];

const CATEGORY_OPTIONS: ChoiceOption[] = DLP_CATEGORIES.map((value) => ({
  value,
  label: CATEGORY_LABELS[value],
}));
const DETECTOR_OPTIONS: ChoiceOption[] = DLP_DETECTORS.map((value) => ({
  value,
  label: DETECTOR_LABELS[value],
  code: value,
}));
const COVERAGE_OPTIONS: ChoiceOption[] = DLP_COVERAGE_REASONS.map((value) => ({
  value,
  label: COVERAGE_LABELS[value],
}));

type Field = keyof DlpRuleInput;

function ruleFields(text: () => DlpRuleInput): FieldRule<Field>[] {
  const lineIn =
    (field: 'senderAddresses' | 'senderDomains' | 'recipientAddresses' | 'recipientDomains') =>
    (index: number) =>
      lineOfEntry(text()[field], index);
  return [
    { path: 'name', field: 'name' },
    { path: 'enabled', field: 'enabled' },
    { path: 'priority', field: 'priority' },
    { path: 'action', field: 'action' },
    { path: 'conditions.selectors.categories', field: 'categories' },
    { path: 'conditions.selectors.detectors', field: 'detectors' },
    { path: 'conditions.selectors.customPatternIds', field: 'customPatternIds' },
    { path: 'conditions.selectors.dictionaryIds', field: 'dictionaryIds' },
    { path: 'conditions.selectors.coverageReasons', field: 'coverageReasons' },
    { path: 'conditions.selectors', field: 'categories' },
    { path: 'conditions.minCount', field: 'minCount' },
    { path: 'conditions.minConfidence', field: 'minConfidence' },
    { path: 'conditions.minSeverity', field: 'minSeverity' },
    { path: 'conditions.directions', field: 'directions' },
    {
      path: 'conditions.sender.addresses',
      field: 'senderAddresses',
      line: lineIn('senderAddresses'),
    },
    { path: 'conditions.sender.domains', field: 'senderDomains', line: lineIn('senderDomains') },
    { path: 'conditions.sender', field: 'senderAddresses' },
    {
      path: 'conditions.recipients.addresses',
      field: 'recipientAddresses',
      line: lineIn('recipientAddresses'),
    },
    {
      path: 'conditions.recipients.domains',
      field: 'recipientDomains',
      line: lineIn('recipientDomains'),
    },
    { path: 'conditions.recipients.externalOnly', field: 'externalOnly' },
    { path: 'conditions.recipients', field: 'recipientAddresses' },
    { path: 'conditions.attachmentsOnly', field: 'attachmentsOnly' },
  ];
}

const explainRule: Explain<Field> = (error) => {
  if (error.code === 'dlp_rule_exists') {
    return { field: 'name', message: 'This policy already has a rule with this name.' };
  }
  if (error.code === 'dlp_reference_invalid') {
    const field = typeof error.details.field === 'string' ? error.details.field : '';
    if (field.endsWith('customPatternIds')) {
      return {
        field: 'customPatternIds',
        message:
          'A selected custom pattern is not one of your organization’s patterns (it may have been deleted). Uncheck it.',
      };
    }
    if (field.endsWith('dictionaryIds')) {
      return {
        field: 'dictionaryIds',
        message:
          'A selected dictionary is not one of your organization’s dictionaries (it may have been deleted). Uncheck it.',
      };
    }
  }
  if (error.code === 'dlp_directions_invalid') {
    return {
      field: 'directions',
      message: 'Rule directions must be within the policy’s directions.',
    };
  }
  return null;
};

function ReferenceChoices({
  control,
  name,
  legend,
  emptyText,
  query,
}: {
  control: Control<DlpRuleInput>;
  name: 'customPatternIds' | 'dictionaryIds';
  legend: string;
  emptyText: string;
  query: {
    isLoading: boolean;
    error: unknown;
    refetch: () => unknown;
    options: ChoiceOption[];
  };
}) {
  if (query.isLoading) {
    return (
      <p className="text-sm text-muted-foreground" role="status">
        Loading {legend.toLowerCase()} …
      </p>
    );
  }
  return (
    <div className="grid gap-2">
      {query.error ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} compact />
      ) : null}
      <ChecklistField
        control={control}
        name={name}
        legend={legend}
        hint={query.options.length === 0 && !query.error ? emptyText : 'At most 20.'}
        options={query.options}
      />
    </div>
  );
}

export function DlpRuleForm({
  policy,
  rule,
  onDone,
  onReload,
}: {
  policy: DlpPolicyDetail;
  rule?: DlpRule;
  onDone: () => void;
  onReload: () => void;
}) {
  const [problem, setProblem] = useState<Problem | null>(null);
  const patterns = useApiQuery('DlpPatternsController_list_v1', { query: { limit: 100 } });
  const dictionaries = useApiQuery('DlpDictionariesController_list_v1', { query: { limit: 100 } });
  const create = useApiMutation('DlpPoliciesController_createRule_v1', {
    invalidates: RULE_QUERIES,
    successMessage: 'DLP rule added.',
  });
  const update = useApiMutation('DlpPoliciesController_updateRule_v1', {
    invalidates: RULE_QUERIES,
    successMessage: 'DLP rule saved.',
  });
  const form = useZodForm(dlpRuleSchema, { defaultValues: dlpRuleDefaults(rule) });
  const submit = form.handleSubmit(async (values) => {
    setProblem(null);
    let outcome;
    if (rule) {
      const body = dlpRuleUpdateBody(rule, values);
      if (Object.keys(body).length === 1) {
        toast.info('Nothing changed.');
        return onDone();
      }
      outcome = await update.submit({ path: { id: policy.id, ruleId: rule.id }, body });
    } else {
      outcome = await create.submit({ path: { id: policy.id }, body: dlpRuleCreateBody(values) });
    }
    if (outcome.ok) return onDone();
    setProblem(
      applyServerError(
        form,
        outcome.error,
        ruleFields(() => form.getValues()),
        explainRule,
      ),
    );
  });
  const mutation = rule ? update : create;
  const directionOptions = policy.directions.map((value) => ({
    value,
    label: DIRECTION_LABELS[value],
  }));
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label={rule ? `Edit DLP rule ${rule.name}` : `New DLP rule in ${policy.name}`}
        onSubmit={(event) => void submit(event)}
      >
        <FormAlert problem={problem} onReload={onReload} />
        <TextField control={form.control} name="name" label="Name" required maxLength={128} />
        <div className="grid gap-4 sm:grid-cols-2">
          <SelectField
            control={form.control}
            name="action"
            label="Action"
            required
            options={DLP_ACTIONS.map((value) => ({ value, label: ACTION_LABELS[value] }))}
            hint="The strongest action of the matched rules wins; Allow only records the match."
          />
          <TextField
            control={form.control}
            name="priority"
            label="Priority"
            required
            inputMode="numeric"
            hint="0 to 1000; lower runs first within the policy."
          />
        </div>
        <SwitchField control={form.control} name="enabled" label="Enabled" />
        <FieldGroup
          legend="What the rule looks for"
          description="Choose at least one. Findings of any selected kind count towards the rule."
        >
          <ChecklistField
            control={form.control}
            name="categories"
            legend="Data categories"
            options={CATEGORY_OPTIONS}
          />
          <ChecklistField
            control={form.control}
            name="detectors"
            legend="Detectors"
            hint="NI2 (Aadhaar number) runs only while your organization has recorded an Aadhaar compliance basis (Compliance section)."
            options={DETECTOR_OPTIONS}
          />
          <ReferenceChoices
            control={form.control}
            name="customPatternIds"
            legend="Custom patterns"
            emptyText="Your organization has no custom patterns yet (Patterns section)."
            query={{
              isLoading: patterns.isLoading,
              error: patterns.error,
              refetch: patterns.refetch,
              options: (patterns.data?.data ?? []).map((p) => ({ value: p.id, label: p.name })),
            }}
          />
          <ReferenceChoices
            control={form.control}
            name="dictionaryIds"
            legend="Keyword dictionaries"
            emptyText="Your organization has no keyword dictionaries yet (Dictionaries section)."
            query={{
              isLoading: dictionaries.isLoading,
              error: dictionaries.error,
              refetch: dictionaries.refetch,
              options: (dictionaries.data?.data ?? []).map((d) => ({ value: d.id, label: d.name })),
            }}
          />
          <ChecklistField
            control={form.control}
            name="coverageReasons"
            legend="Incomplete coverage"
            hint="Matches when content could not be fully scanned for one of these reasons, for example to hold encrypted attachments."
            options={COVERAGE_OPTIONS}
          />
        </FieldGroup>
        <FieldGroup
          legend="Thresholds (optional)"
          description="Empty values use the defaults: at least one finding, the category’s confidence threshold and severity low."
        >
          <div className="grid gap-4 sm:grid-cols-3">
            <TextField
              control={form.control}
              name="minCount"
              label="Minimum findings"
              inputMode="numeric"
              hint="1 to 10 000 distinct values."
            />
            <TextField
              control={form.control}
              name="minConfidence"
              label="Minimum confidence"
              inputMode="decimal"
              hint="0.5 to 1."
            />
            <SelectField
              control={form.control}
              name="minSeverity"
              label="Minimum severity"
              emptyOption="Default (low)"
              options={DLP_MIN_SEVERITIES.map((value) => ({
                value,
                label: MIN_SEVERITY_LABELS[value],
              }))}
            />
          </div>
        </FieldGroup>
        <FieldGroup
          legend="Scope (optional)"
          description="Empty lists match every sender and recipient. Addresses are compared in lower case; domains by registrable domain or exact domain."
        >
          <ChecklistField
            control={form.control}
            name="directions"
            legend="Directions"
            hint="None selected: every direction of the policy."
            options={directionOptions}
            columns={3}
          />
          <div className="grid gap-4 sm:grid-cols-2">
            <LinesField
              control={form.control}
              name="senderAddresses"
              label="Sender addresses"
              max={100}
              noun="addresses"
              mono
            />
            <LinesField
              control={form.control}
              name="senderDomains"
              label="Sender domains"
              max={100}
              noun="domains"
              mono
            />
            <LinesField
              control={form.control}
              name="recipientAddresses"
              label="Recipient addresses"
              max={100}
              noun="addresses"
              mono
            />
            <LinesField
              control={form.control}
              name="recipientDomains"
              label="Recipient domains"
              max={100}
              noun="domains"
              mono
            />
          </div>
          <CheckboxField
            control={form.control}
            name="externalOnly"
            label="Only recipients outside your organization’s active domains"
          />
          <CheckboxField
            control={form.control}
            name="attachmentsOnly"
            label="Only findings in attachments"
          />
        </FieldGroup>
        <SubmitRow
          label={rule ? 'Save rule' : 'Add rule'}
          pending={mutation.isPending}
          retryAfterSeconds={mutation.retryAfterSeconds}
          onCancel={onDone}
        />
      </form>
    </Form>
  );
}
