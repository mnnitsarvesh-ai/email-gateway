'use client';

import { PlusIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn, type RowAction } from '@/components/data-table';
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
import {
  dlpDictionaryCreateBody,
  dlpDictionaryDefaults,
  dlpDictionarySchema,
  dlpDictionaryUpdateBody,
  type DlpDictionaryInput,
} from './dlp-schemas';
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
  SelectField,
  SubmitRow,
  SwitchField,
  TextField,
  useEntryTarget,
} from './kit';
import {
  DICTIONARY_CATEGORY_LABELS,
  DLP_DICTIONARY_CATEGORIES,
  DLP_SEVERITIES,
  SEVERITY_LABELS,
  lineOfEntry,
  type DlpDictionary,
  type DlpDictionaryRow,
} from './model';

/**
 * Keyword dictionaries (step 4.5 D8): token phrases matched on normalized text. Terms are tenant
 * configuration (possibly confidential names): read with `GET /dlp/dictionaries/{id}` only when
 * the editor opens, never listed.
 */

const DICTIONARY_QUERIES: readonly OperationId[] = [
  'DlpDictionariesController_list_v1',
  'DlpDictionariesController_get_v1',
];

const DICTIONARY_COLUMNS: DataTableColumn<DlpDictionaryRow>[] = [
  {
    id: 'name',
    header: 'Dictionary',
    meta: { label: 'Dictionary' },
    cell: ({ row }) => row.original.name,
  },
  {
    id: 'category',
    header: 'Category',
    meta: { label: 'Category' },
    cell: ({ row }) => humanize(row.original.category),
  },
  {
    id: 'terms',
    header: 'Terms',
    meta: { label: 'Terms', className: 'tabular-nums' },
    cell: ({ row }) => formatNumber(row.original.termCount),
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

const TERM_RULES =
  '1 to 64 characters and 1 to 8 words each, unique after normalization (case and character forms do not count).';

function dictionaryExplain(text: () => DlpDictionaryInput): Explain<keyof DlpDictionaryInput> {
  return (error) => {
    if (error.code === 'dlp_dictionary_exists') {
      return { field: 'name', message: 'A dictionary with this name exists. Choose another name.' };
    }
    if (error.code === 'dictionary_terms_count') {
      return {
        field: 'terms',
        message: 'The number of terms is outside the platform limit for one dictionary.',
      };
    }
    if (error.code === 'dictionary_term_invalid') {
      const index = indexDetail(error);
      const line = index === null ? null : lineOfEntry(text().terms, index);
      return {
        field: 'terms',
        message: `${line !== null ? `Line ${line}: this` : 'A'} term was refused. Terms must be ${TERM_RULES}`,
      };
    }
    return null;
  };
}

function dictionaryFields(text: () => DlpDictionaryInput): FieldRule<keyof DlpDictionaryInput>[] {
  return [
    { path: 'name', field: 'name' },
    { path: 'category', field: 'category' },
    { path: 'terms', field: 'terms', line: (index) => lineOfEntry(text().terms, index) },
    { path: 'severity', field: 'severity' },
    { path: 'baseConfidence', field: 'baseConfidence' },
    { path: 'minMatches', field: 'minMatches' },
    { path: 'enabled', field: 'enabled' },
  ];
}

function DlpDictionaryForm({
  dictionary,
  onDone,
  onReload,
}: {
  dictionary?: DlpDictionary;
  onDone: () => void;
  onReload: () => void;
}) {
  const [problem, setProblem] = useState<Problem | null>(null);
  const create = useApiMutation('DlpDictionariesController_create_v1', {
    invalidates: DICTIONARY_QUERIES,
    successMessage: 'Keyword dictionary created.',
  });
  const update = useApiMutation('DlpDictionariesController_update_v1', {
    invalidates: DICTIONARY_QUERIES,
    successMessage: 'Keyword dictionary saved.',
  });
  const form = useZodForm(dlpDictionarySchema, {
    defaultValues: dlpDictionaryDefaults(dictionary),
  });
  const submit = form.handleSubmit(async (values) => {
    setProblem(null);
    let outcome;
    if (dictionary) {
      const body = dlpDictionaryUpdateBody(dictionary, values);
      if (Object.keys(body).length === 1) {
        toast.info('Nothing changed.');
        return onDone();
      }
      outcome = await update.submit({ path: { id: dictionary.id }, body });
    } else {
      outcome = await create.submit({ body: dlpDictionaryCreateBody(values) });
    }
    if (outcome.ok) return onDone();
    const text = () => form.getValues();
    setProblem(
      applyServerError(form, outcome.error, dictionaryFields(text), dictionaryExplain(text)),
    );
  });
  const mutation = dictionary ? update : create;
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label={dictionary ? `Edit dictionary ${dictionary.name}` : 'New keyword dictionary'}
        onSubmit={(event) => void submit(event)}
      >
        <FormAlert problem={problem} onReload={onReload} />
        <TextField control={form.control} name="name" label="Name" required maxLength={128} />
        <div className="grid gap-4 sm:grid-cols-2">
          <SelectField
            control={form.control}
            name="category"
            label="Category"
            required
            options={DLP_DICTIONARY_CATEGORIES.map((value) => ({
              value,
              label: DICTIONARY_CATEGORY_LABELS[value],
            }))}
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
            hint="0.5 to 1."
          />
          <TextField
            control={form.control}
            name="minMatches"
            label="Minimum distinct terms"
            required
            inputMode="numeric"
            hint="1 to 100 distinct terms a text segment needs."
          />
        </div>
        <LinesField
          control={form.control}
          name="terms"
          label="Terms"
          required
          max={10_000}
          noun="terms"
          rows={8}
          hint={`Terms are ${TERM_RULES} The platform limits the number of terms per dictionary.`}
        />
        <SwitchField control={form.control} name="enabled" label="Enabled" />
        <SubmitRow
          label={dictionary ? 'Save dictionary' : 'Create dictionary'}
          pending={mutation.isPending}
          retryAfterSeconds={mutation.retryAfterSeconds}
          onCancel={onDone}
        />
      </form>
    </Form>
  );
}

/** Loads the dictionary with its terms (only while the editor is open). */
function EditDictionary({ id, onDone }: { id: string; onDone: () => void }) {
  const detail = useApiQuery('DlpDictionariesController_get_v1', { path: { id } });
  // The editor works on the version loaded when it opened; only "Load the current version"
  // replaces it (a background refetch never swaps what the user is editing).
  const [snapshot, setSnapshot] = useState<DlpDictionary | null>(null);
  const loaded = detail.data ?? null;
  useEffect(() => {
    if (!snapshot && loaded) setSnapshot(loaded);
  }, [loaded, snapshot]);
  const current = snapshot ?? loaded;
  if (detail.isLoading && !current) {
    return <LoadingState label="Loading the dictionary" rows={4} />;
  }
  if (!current) {
    return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />;
  }
  return (
    <DlpDictionaryForm
      key={`${current.id}:${current.version}`}
      dictionary={current}
      onDone={onDone}
      onReload={() =>
        void detail.refetch().then((result) => {
          if (result.data) setSnapshot(result.data);
        })
      }
    />
  );
}

type Editor = { mode: 'create' } | { mode: 'edit'; id: string; name: string } | null;

/** The "Dictionaries" section of the DLP tab. */
export function DlpDictionariesSection() {
  const canCreate = useCan('DlpDictionariesController_create_v1');
  const canUpdate = useCan('DlpDictionariesController_update_v1');
  const canDelete = useCan('DlpDictionariesController_remove_v1');
  const list = useCursorList('DlpDictionariesController_list_v1', undefined, { limit: 25 });
  const [editor, setEditor] = useState<Editor>(null);
  const {
    target: deleting,
    setTarget: setDeleting,
    refresh: refreshDeleting,
  } = useEntryTarget<DlpDictionaryRow>(list.query.refetch);
  const remove = useApiMutation('DlpDictionariesController_remove_v1', {
    invalidates: DICTIONARY_QUERIES,
    successMessage: 'Keyword dictionary deleted.',
  });
  const rowActions =
    canUpdate || canDelete
      ? (row: DlpDictionaryRow): RowAction[] => [
          ...(canUpdate
            ? [
                {
                  label: 'Edit',
                  onSelect: () => setEditor({ mode: 'edit', id: row.id, name: row.name }),
                },
              ]
            : []),
          ...(canDelete
            ? [{ label: 'Delete', destructive: true, onSelect: () => setDeleting(row) }]
            : []),
        ]
      : undefined;
  const deleteProblem = remove.error
    ? confirmProblem(remove.error, 'Rules select this dictionary')
    : null;
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <SectionToolbar
        actions={
          canCreate ? (
            <Button size="sm" onClick={() => setEditor({ mode: 'create' })}>
              <PlusIcon aria-hidden />
              New dictionary
            </Button>
          ) : null
        }
      >
        Lists of words and phrases (detector DC1), selected by rules. Terms are visible only to
        holders of dlp:read.
      </SectionToolbar>
      <DataTable
        tableId="dlp-dictionaries"
        caption="DLP dictionaries"
        columns={DICTIONARY_COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        rowActions={rowActions}
        emptyState={<EmptyState title="No dictionaries" />}
        mobileCard={(row) => (
          <div className="grid gap-0.5">
            <span className="font-medium">{row.name}</span>
            <span className="text-xs text-muted-foreground">
              {humanize(row.category)} · {formatNumber(row.termCount)} terms
            </span>
          </div>
        )}
      />
      <EditorSheet
        open={editor !== null}
        onOpenChange={(open) => !open && setEditor(null)}
        title={editor?.mode === 'edit' ? `Edit ${editor.name}` : 'New keyword dictionary'}
        description="Changes apply to messages scanned after the DLP engine's cache refresh (30 seconds by default)."
      >
        {editor?.mode === 'create' ? (
          <DlpDictionaryForm onDone={() => setEditor(null)} onReload={() => undefined} />
        ) : editor ? (
          <EditDictionary id={editor.id} onDone={() => setEditor(null)} />
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
        title={`Delete ${deleting?.name ?? 'the dictionary'}?`}
        description="A dictionary that a rule selects cannot be deleted; remove it from those rules first."
        confirmLabel="Delete dictionary"
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
