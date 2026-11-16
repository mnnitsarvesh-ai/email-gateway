'use client';

import { FlaskConicalIcon, PlusIcon } from 'lucide-react';
import { useId, useState } from 'react';
import { useWatch, type Control } from 'react-hook-form';
import { toast } from 'sonner';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn, type RowAction } from '@/components/data-table';
import { UntrustedText } from '@/components/domain';
import { useZodForm } from '@/components/form';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Form } from '@/components/ui/form';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation, useCursorList } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { YesNo } from '@/features/messages/controls';
import {
  SAMPLE_MAX,
  TEST_PATTERN_MAX,
  dlpPatternCreateBody,
  dlpPatternDefaults,
  dlpPatternSchema,
  dlpPatternUpdateBody,
  patternTestBody,
  type DlpPatternInput,
} from './dlp-schemas';
import { enabledBadge } from './dlp-policies';
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
  ErrorCodes,
  FormAlert,
  LinesField,
  SectionToolbar,
  SelectField,
  SubmitRow,
  SwitchField,
  TextField,
  TextareaField,
  useEntryEditor,
  useEntryTarget,
} from './kit';
import {
  DLP_MASK_STYLES,
  DLP_SEVERITIES,
  DLP_VALIDATORS,
  MASK_STYLE_LABELS,
  SEVERITY_LABELS,
  VALIDATOR_LABELS,
  isPatternCode,
  lineOfEntry,
  patternCodeText,
  type DlpPatternRow,
  type PatternTestResult,
} from './model';

/**
 * Custom patterns (step 4.5 D9): RE2 syntax validated and compiled by the server only. The portal
 * never evaluates a pattern and never builds a regular expression from one: "Test pattern" sends
 * the pattern and a typed sample to `POST /dlp/patterns/test` and shows the server's answer
 * (design §2 B13, §7).
 */

const PATTERN_QUERIES: readonly OperationId[] = [
  'DlpPatternsController_list_v1',
  'DlpPatternsController_get_v1',
];

const PATTERN_COLUMNS: DataTableColumn<DlpPatternRow>[] = [
  {
    id: 'name',
    header: 'Pattern',
    meta: { label: 'Pattern' },
    cell: ({ row }) => row.original.name,
  },
  {
    id: 'pattern',
    header: 'Expression',
    meta: { label: 'Expression', className: 'max-w-72' },
    cell: ({ row }) => <UntrustedText value={row.original.pattern} mono maxLength={60} />,
  },
  {
    id: 'validator',
    header: 'Validator',
    meta: { label: 'Validator' },
    cell: ({ row }) => humanize(row.original.validator),
  },
  {
    id: 'severity',
    header: 'Severity',
    meta: { label: 'Severity' },
    cell: ({ row }) => humanize(row.original.severity),
  },
  {
    id: 'enabled',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => enabledBadge(row.original.enabled),
  },
];

function complexityText(details: Readonly<Record<string, unknown>>): string {
  const length = details.length;
  const product = details.repetitionProduct;
  return typeof length === 'number' && typeof product === 'number'
    ? ` (length ${formatNumber(length)}, repetition product ${formatNumber(product)})`
    : '';
}

const explainPattern: Explain<keyof DlpPatternInput> = (error) => {
  if (error.code === 'dlp_pattern_exists') {
    return {
      field: 'name',
      message: 'A custom pattern with this name exists. Choose another name.',
    };
  }
  if (error.status === 400 && isPatternCode(error.code)) {
    return {
      field: 'pattern',
      message: `${patternCodeText(error.code)}${complexityText(error.details)} Code: ${error.code}.`,
    };
  }
  return null;
};

function patternFields(text: () => DlpPatternInput): FieldRule<keyof DlpPatternInput>[] {
  return [
    { path: 'name', field: 'name' },
    { path: 'pattern', field: 'pattern' },
    { path: 'caseInsensitive', field: 'caseInsensitive' },
    { path: 'validator', field: 'validator' },
    {
      path: 'contextKeywords',
      field: 'contextKeywords',
      line: (index) => lineOfEntry(text().contextKeywords, index),
    },
    { path: 'requireContext', field: 'requireContext' },
    { path: 'severity', field: 'severity' },
    { path: 'baseConfidence', field: 'baseConfidence' },
    { path: 'maskStyle', field: 'maskStyle' },
    { path: 'enabled', field: 'enabled' },
  ];
}

// ---------------------------------------------------------------------------------------------
// Test pattern (POST /dlp/patterns/test: 30 per caller per minute, nothing stored or logged)
// ---------------------------------------------------------------------------------------------

function TestFailure({ error }: { error: ApiError }) {
  const lines =
    error.status === 429
      ? ['Too many pattern tests: the API allows 30 per minute for each user.']
      : error.status === 400
        ? isPatternCode(error.code)
          ? [patternCodeText(error.code)]
          : error.messages.map((line) => {
              const index = line.indexOf(': ');
              const path = index > 0 ? line.slice(0, index) : '';
              const issue = index > 0 ? line.slice(index + 2) : line;
              return path === 'pattern'
                ? `Pattern: ${issue}`
                : path === 'sample'
                  ? `Sample: ${issue}`
                  : line;
            })
        : [...problemOf(error).messages];
  return (
    <div
      role="alert"
      className="grid gap-2 rounded-md border border-destructive/40 bg-tone-danger px-3 py-2 text-sm text-tone-danger-foreground"
    >
      <p className="font-medium">
        {error.status === 400 ? 'The server did not accept the test' : 'The test did not run'}
      </p>
      {lines.map((line, index) => (
        <p key={index}>{line}</p>
      ))}
      <ErrorCodes code={error.code} requestId={error.requestId} />
    </div>
  );
}

function TestResult({ result, stale }: { result: PatternTestResult; stale: boolean }) {
  const captionId = useId();
  return (
    <div className="grid gap-2 text-sm">
      {stale ? (
        <p className="text-xs text-muted-foreground">
          The pattern, its options or the sample changed since this result. Test again to see the
          current result.
        </p>
      ) : null}
      {result.valid ? (
        <p>
          <span className="font-medium">The server accepted the pattern.</span>{' '}
          {result.matches.length === 0
            ? 'No match in the sample.'
            : `${formatNumber(result.matches.length)} ${result.matches.length === 1 ? 'match' : 'matches'} in the sample${result.matches.length >= 50 ? ' (the first 50)' : ''}.`}
        </p>
      ) : (
        <p>
          <span className="font-medium">The server refused the pattern:</span>{' '}
          {patternCodeText(result.code ?? '')}{' '}
          {result.code ? <span className="font-mono text-xs">({result.code})</span> : null}
        </p>
      )}
      <p className="text-xs text-muted-foreground">
        Complexity: length {formatNumber(result.complexity.length)}, repetition product{' '}
        {formatNumber(result.complexity.repetitionProduct)}.
      </p>
      {result.matches.length > 0 ? (
        <div
          className="overflow-x-auto"
          role="group"
          aria-labelledby={captionId}
          // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable region
          tabIndex={0}
        >
          <table className="w-full border-collapse text-sm">
            <caption id={captionId} className="sr-only">
              Matches of the pattern in the sample (masked by the server)
            </caption>
            <thead>
              <tr className="border-b text-xs text-muted-foreground">
                {['Position', 'Masked match', 'Checksum valid', 'Context keyword nearby'].map(
                  (heading) => (
                    <th key={heading} scope="col" className="px-2 py-1.5 text-left font-semibold">
                      {heading}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {result.matches.map((match, index) => (
                <tr key={`${match.start}:${index}`} className="border-b last:border-0">
                  <td className="px-2 py-1.5 tabular-nums">
                    {match.start}–{match.end}
                  </td>
                  <td className="px-2 py-1.5">
                    <UntrustedText value={match.masked} mono maxLength={80} />
                  </td>
                  <td className="px-2 py-1.5">
                    <YesNo value={match.validated} />
                  </td>
                  <td className="px-2 py-1.5">
                    <YesNo value={match.contextMatched} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

const TEST_OPTION_NAMES = [
  'pattern',
  'caseInsensitive',
  'validator',
  'contextKeywords',
  'requireContext',
  'maskStyle',
] as const;

/** The server-side test of the pattern being edited (explicit button, never automatic). */
export function PatternTestPanel({ control }: { control: Control<DlpPatternInput> }) {
  const headingId = useId();
  const sampleId = useId();
  const countId = useId();
  const [pattern, caseInsensitive, validator, contextKeywords, requireContext, maskStyle] =
    useWatch({ control, name: TEST_OPTION_NAMES });
  const [sample, setSample] = useState('');
  const [testedKey, setTestedKey] = useState<string | null>(null);
  const [hint, setHint] = useState<string | null>(null);
  const test = useApiMutation('DlpPatternsController_test_v1', { successMessage: null });
  const options = {
    pattern,
    caseInsensitive,
    validator,
    contextKeywords,
    requireContext,
    maskStyle,
  };
  const key = JSON.stringify([options, sample]);
  const waiting = test.retryAfterSeconds;
  const run = async () => {
    if (!pattern) return setHint('Enter a pattern above first.');
    if (pattern.length > TEST_PATTERN_MAX) {
      return setHint(`The pattern is longer than ${TEST_PATTERN_MAX} characters.`);
    }
    if (sample.length > SAMPLE_MAX) {
      return setHint(`The sample is longer than ${formatNumber(SAMPLE_MAX)} characters.`);
    }
    setHint(null);
    setTestedKey(key);
    await test.submit({ body: patternTestBody(options, sample) });
  };
  return (
    <section
      aria-labelledby={headingId}
      className="grid min-w-0 gap-3 rounded-md border bg-muted/30 p-3 [&>*]:min-w-0"
    >
      <div className="grid gap-1">
        <h3 id={headingId} className="flex items-center gap-2 text-sm font-semibold">
          <FlaskConicalIcon className="size-4" aria-hidden />
          Test pattern
        </h3>
        <p className="text-xs text-muted-foreground">
          Sends the pattern and options above with your sample to the server, which validates the
          pattern and returns at most 50 masked matches. Nothing is stored or logged. Use synthetic
          samples only; 30 tests per minute.
        </p>
      </div>
      <div className="grid gap-2">
        <Label htmlFor={sampleId}>Synthetic sample text</Label>
        <Textarea
          id={sampleId}
          value={sample}
          rows={4}
          spellCheck={false}
          aria-describedby={countId}
          onChange={(event) => setSample(event.target.value)}
          className="font-mono text-xs"
        />
        <p id={countId} className="text-xs text-muted-foreground">
          {formatNumber(sample.length)} of {formatNumber(SAMPLE_MAX)} characters.
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={() => void run()}
          disabled={test.isPending || waiting > 0}
        >
          {test.isPending ? 'Testing …' : 'Test pattern'}
        </Button>
        {waiting > 0 ? (
          <p className="text-xs text-muted-foreground" aria-live="polite">
            Try again in {waiting} s.
          </p>
        ) : null}
      </div>
      <div aria-live="polite" className="grid gap-2">
        {hint ? <p className="text-sm text-destructive">{hint}</p> : null}
        {test.error ? (
          <TestFailure error={test.error} />
        ) : test.data && !test.isPending ? (
          <TestResult result={test.data} stale={testedKey !== key} />
        ) : null}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------------------------
// Editor and section
// ---------------------------------------------------------------------------------------------

function DlpPatternForm({
  pattern,
  canTest,
  onDone,
  onReload,
}: {
  pattern?: DlpPatternRow;
  canTest: boolean;
  onDone: () => void;
  onReload: () => void;
}) {
  const [problem, setProblem] = useState<Problem | null>(null);
  const create = useApiMutation('DlpPatternsController_create_v1', {
    invalidates: PATTERN_QUERIES,
    successMessage: 'Custom pattern created.',
  });
  const update = useApiMutation('DlpPatternsController_update_v1', {
    invalidates: PATTERN_QUERIES,
    successMessage: 'Custom pattern saved.',
  });
  const form = useZodForm(dlpPatternSchema, { defaultValues: dlpPatternDefaults(pattern) });
  const submit = form.handleSubmit(async (values) => {
    setProblem(null);
    let outcome;
    if (pattern) {
      const body = dlpPatternUpdateBody(pattern, values);
      if (Object.keys(body).length === 1) {
        toast.info('Nothing changed.');
        return onDone();
      }
      outcome = await update.submit({ path: { id: pattern.id }, body });
    } else {
      outcome = await create.submit({ body: dlpPatternCreateBody(values) });
    }
    if (outcome.ok) return onDone();
    setProblem(
      applyServerError(
        form,
        outcome.error,
        patternFields(() => form.getValues()),
        explainPattern,
      ),
    );
  });
  const mutation = pattern ? update : create;
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label={pattern ? `Edit custom pattern ${pattern.name}` : 'New custom pattern'}
        onSubmit={(event) => void submit(event)}
      >
        <FormAlert problem={problem} onReload={onReload} />
        <TextField control={form.control} name="name" label="Name" required maxLength={128} />
        <TextareaField
          control={form.control}
          name="pattern"
          label="Pattern"
          required
          mono
          rows={2}
          hint="RE2 syntax: no backreferences, lookaround or possessive constructs. The server checks length, repetition, breadth and speed."
        />
        <div className="grid gap-4 sm:grid-cols-2">
          <SelectField
            control={form.control}
            name="validator"
            label="Checksum validator"
            required
            options={DLP_VALIDATORS.map((value) => ({ value, label: VALIDATOR_LABELS[value] }))}
          />
          <SelectField
            control={form.control}
            name="severity"
            label="Severity"
            required
            options={DLP_SEVERITIES.map((value) => ({ value, label: SEVERITY_LABELS[value] }))}
          />
          <TextField
            control={form.control}
            name="baseConfidence"
            label="Base confidence"
            required
            inputMode="decimal"
            hint="0.5 to 1; a nearby context keyword adds 0.30."
          />
          <SelectField
            control={form.control}
            name="maskStyle"
            label="Masking"
            required
            options={DLP_MASK_STYLES.map((value) => ({ value, label: MASK_STYLE_LABELS[value] }))}
            hint="How matches appear everywhere outside the encrypted evidence."
          />
        </div>
        <LinesField
          control={form.control}
          name="contextKeywords"
          label="Context keywords (optional)"
          max={20}
          noun="keywords"
          hint="1 to 64 characters each."
        />
        <SwitchField
          control={form.control}
          name="requireContext"
          label="Report only matches with a context keyword nearby"
        />
        <SwitchField control={form.control} name="caseInsensitive" label="Case-insensitive" />
        <SwitchField control={form.control} name="enabled" label="Enabled" />
        {canTest ? <PatternTestPanel control={form.control} /> : null}
        <SubmitRow
          label={pattern ? 'Save pattern' : 'Create pattern'}
          pending={mutation.isPending}
          retryAfterSeconds={mutation.retryAfterSeconds}
          onCancel={onDone}
        />
      </form>
    </Form>
  );
}

/** The "Patterns" section of the DLP tab. */
export function DlpPatternsSection() {
  const canCreate = useCan('DlpPatternsController_create_v1');
  const canUpdate = useCan('DlpPatternsController_update_v1');
  const canDelete = useCan('DlpPatternsController_remove_v1');
  const canTest = useCan('DlpPatternsController_test_v1');
  const list = useCursorList('DlpPatternsController_list_v1', undefined, { limit: 25 });
  const { editor, setEditor, reload, close } = useEntryEditor<DlpPatternRow>(list.query.refetch);
  const {
    target: deleting,
    setTarget: setDeleting,
    refresh: refreshDeleting,
  } = useEntryTarget<DlpPatternRow>(list.query.refetch);
  const remove = useApiMutation('DlpPatternsController_remove_v1', {
    invalidates: PATTERN_QUERIES,
    successMessage: 'Custom pattern deleted.',
  });
  const rowActions =
    canUpdate || canDelete
      ? (row: DlpPatternRow): RowAction[] => [
          ...(canUpdate
            ? [{ label: 'Edit and test', onSelect: () => setEditor({ mode: 'edit', row }) }]
            : []),
          ...(canDelete
            ? [{ label: 'Delete', destructive: true, onSelect: () => setDeleting(row) }]
            : []),
        ]
      : undefined;
  const deleteProblem = remove.error
    ? confirmProblem(remove.error, 'Rules select this custom pattern')
    : null;
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <SectionToolbar
        actions={
          canCreate ? (
            <Button size="sm" onClick={() => setEditor({ mode: 'create' })}>
              <PlusIcon aria-hidden />
              New pattern
            </Button>
          ) : null
        }
      >
        Your own patterns (detector CU1), selected by rules. Matches are masked everywhere outside
        the encrypted evidence.
      </SectionToolbar>
      <DataTable
        tableId="dlp-patterns"
        caption="DLP patterns"
        columns={PATTERN_COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        rowActions={rowActions}
        emptyState={<EmptyState title="No custom patterns" />}
        mobileCard={(row) => (
          <div className="grid gap-0.5">
            <span className="font-medium">{row.name}</span>
            <UntrustedText value={row.pattern} mono maxLength={40} />
          </div>
        )}
      />
      <EditorSheet
        open={editor !== null}
        onOpenChange={(open) => !open && setEditor(null)}
        title={editor?.mode === 'edit' ? `Edit ${editor.row.name}` : 'New custom pattern'}
        description="Changes apply to messages scanned after the DLP engine's cache refresh (30 seconds by default)."
        wide
      >
        {editor?.mode === 'create' ? (
          <DlpPatternForm canTest={canTest} onDone={close} onReload={() => undefined} />
        ) : editor ? (
          <DlpPatternForm
            key={`${editor.row.id}:${editor.row.version}`}
            pattern={editor.row}
            canTest={canTest}
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
        title={`Delete ${deleting?.name ?? 'the custom pattern'}?`}
        description="A pattern that a rule selects cannot be deleted; remove it from those rules first."
        confirmLabel="Delete pattern"
        destructive
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
