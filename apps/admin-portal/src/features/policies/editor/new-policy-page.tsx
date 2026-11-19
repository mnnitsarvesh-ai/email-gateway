'use client';

import { CheckCheckIcon, FlaskConicalIcon, HistoryIcon, SaveIcon } from 'lucide-react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useMemo, useRef, useState } from 'react';
import { z } from 'zod';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { PageHeader } from '@/components/page-header';
import { Button } from '@/components/ui/button';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { useUnsavedChanges } from '@/hooks/use-unsaved-changes';
import { useApiMutation } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { Section } from '@/features/messages/controls';
import {
  BuilderProvider,
  buildDefinition,
  canonicalJson,
  documentBytes,
  emptyDefinition,
  factPresetById,
  PolicyBuilderEditor,
  useBuilderState,
  ViolationList,
  type BuilderCatalog,
  type PolicyDslDocument,
  type Violation,
} from '../builder';
import { summarizeModel } from '../builder/summary';
import { CatalogGate } from '../catalog-state';
import { policyVersionHref, policiesTabHref } from '../links';
import { PolicyDryRunPanel, useDryRunPanelState } from '../panels/dry-run-panel';
import { PolicyTestPanel, useTestPanelState } from '../panels/test-panel';
import {
  ACTIVE_TARGET,
  INLINE_TARGET_POLICY_ID,
  PLATFORM_TARGET,
  refPrefixOf,
  type TargetOption,
} from '../panels/targets';
import { detailNumber, violationsOf } from '../queries';
import { exceedsDocumentLimit, isTooLarge, sizeAgainstLimit, TOO_LARGE_MESSAGE } from '../size';
import { useBuilderCatalog } from '../use-builder-catalog';
import { useDirectoryOptions } from '../use-directory-options';
import { useServerValidation, type ValidationOutcome } from '../use-server-validation';
import { EditorLayout, SummaryAside, Toolbar, UnsavedChangesDialog } from './layout';
import { EMPTY_VIOLATIONS, ValidationStatus, type ServerCheck } from './validation-status';

/** The header of a new policy (mirrors `POST /policies`: name, description, change note). */
export const newPolicySchema = z
  .object({
    name: z.string().trim().min(1, 'Enter a name').max(128, 'At most 128 characters'),
    description: z.string().trim().max(512, 'At most 512 characters'),
    changeNote: z.string().trim().max(512, 'At most 512 characters'),
  })
  .strict();

export type NewPolicyValues = z.output<typeof newPolicySchema>;

export function createPolicyBody(
  values: NewPolicyValues,
  definition: PolicyDslDocument,
): RequestBody<'PolicyManagementController_create_v1'> {
  return {
    name: values.name,
    ...(values.description ? { description: values.description } : {}),
    definition,
    ...(values.changeNote ? { changeNote: values.changeNote } : {}),
  };
}

export const checkOfOutcome = (outcome: ValidationOutcome): ServerCheck => ({
  key: outcome.key,
  valid: outcome.response.valid,
  violations: outcome.response.violations,
  referenceViolations: outcome.response.referenceViolations,
  source: 'validate',
});

/** `/policies/new` (design B6, B17): the builder for a new policy, saved as draft version 1. */
export function NewPolicyPage() {
  return (
    <RouteGate gate={['PolicyManagementController_create_v1']}>
      <NewPolicyContent />
    </RouteGate>
  );
}

function NewPolicyContent() {
  const catalog = useBuilderCatalog();
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="New policy"
        breadcrumbs={[{ label: 'Policy management', href: '/policies' }, { label: 'New policy' }]}
        description="Build the policy from the catalogue’s fields and actions. It is saved as draft version 1; publishing makes it effective."
      />
      <CatalogGate state={catalog}>
        {(builderCatalog) => <NewPolicyWorkspace catalog={builderCatalog} />}
      </CatalogGate>
    </div>
  );
}

function NewPolicyWorkspace({ catalog }: { catalog: BuilderCatalog }) {
  const router = useRouter();
  const { directory, names } = useDirectoryOptions();
  const [initial] = useState(() => emptyDefinition());
  const { state, dispatch } = useBuilderState(initial);
  const { definition, paths } = useMemo(() => buildDefinition(state), [state]);
  const key = useMemo(() => canonicalJson(definition), [definition]);
  const [baselineKey] = useState(() => canonicalJson(buildDefinition(initial).definition));
  const bytes = useMemo(() => documentBytes(definition), [definition]);
  const summary = useMemo(() => summarizeModel(state, catalog, names), [state, catalog, names]);
  const form = useZodForm(newPolicySchema, {
    defaultValues: { name: '', description: '', changeNote: '' },
  });
  const [saved, setSaved] = useState(false);
  const dirty = !saved && (form.formState.isDirty || key !== baselineKey);
  const guard = useUnsavedChanges(dirty, (href) => router.push(href));
  const canValidate = useCan('PolicyToolsController_validate_v1');
  const canTest = useCan('PolicyToolsController_test_v1');
  const canSampleDryRun = useCan('PolicyToolsController_sampleDryRun_v1');
  const canMessageDryRun = useCan('PolicyMessagesController_dryRun_v1');
  const canDryRun = canSampleDryRun || canMessageDryRun;
  const [check, setCheck] = useState<ServerCheck | null>(null);
  const validation = useServerValidation(definition, {
    auto: canValidate,
    onOutcome: (outcome) => setCheck(checkOfOutcome(outcome)),
  });
  const [highlight, setHighlight] = useState<string | null>(null);
  // `?testPreset=<example id>` (step 8.4 D23: the ATO recommendation and settings link here)
  // starts the test panel from that example and opens it when the user may test.
  const testPreset = useSearchParams().get('testPreset');
  const [panel, setPanel] = useState<'test' | 'dry-run' | null>(() =>
    canTest && factPresetById(testPreset) ? 'test' : null,
  );
  const [testState, setTestState] = useTestPanelState('inline', testPreset);
  const [dryRunState, setDryRunState] = useDryRunPanelState('inline');
  const [messages, setMessages] = useState<string[]>([]);
  const create = useApiMutation('PolicyManagementController_create_v1', {
    invalidates: ['PolicyManagementController_list_v1'],
    successMessage: 'Policy saved as draft version 1',
  });

  const latest = useRef({ definition, key });
  latest.current = { definition, key };
  const inlineKey = useRef<string | null>(null);
  const targets = useMemo<TargetOption[]>(
    () => [
      {
        id: 'inline',
        label: 'This new policy (unsaved)',
        description: 'The definition in the editor, added to the active policies.',
        resolve: () => {
          inlineKey.current = latest.current.key;
          return Promise.resolve({ definition: latest.current.definition });
        },
        editorRefPrefix: refPrefixOf(INLINE_TARGET_POLICY_ID, 1),
      },
      ACTIVE_TARGET,
      PLATFORM_TARGET,
    ],
    [],
  );
  const onInlineViolations = (violations: Violation[]) =>
    setCheck({
      key: inlineKey.current ?? key,
      valid: false,
      violations,
      referenceViolations: [],
      source: 'save',
    });
  const showPath = (path: string) => {
    setPanel(null);
    setHighlight(path);
  };

  const violations = useMemo(
    () => (check && check.key === key ? [...check.violations] : (EMPTY_VIOLATIONS as Violation[])),
    [check, key],
  );

  const save = form.handleSubmit(async (values) => {
    setMessages([]);
    const sentKey = key;
    const outcome = await create.submit({ body: createPolicyBody(values, definition) });
    if (outcome.ok) {
      setSaved(true);
      router.push(policyVersionHref(outcome.data.policy.id, outcome.data.version.versionNo));
      return;
    }
    const error = outcome.error;
    if (error.code === 'policy_name_taken') {
      form.setError('name', {
        type: 'server',
        message: 'Another policy of your organization (possibly a deleted one) has this name.',
      });
    } else if (error.code === 'policy_limit_reached') {
      const limit = detailNumber(error, 'limit');
      setMessages([
        `Your organization has reached its limit of ${limit ?? 'its'} policies. Delete a policy you no longer need first.`,
      ]);
    } else if (error.code === 'policy_definition_invalid') {
      setCheck({
        key: sentKey,
        valid: false,
        violations: violationsOf(error),
        referenceViolations: [],
        source: 'save',
      });
      setMessages([
        'The server refused the definition; fix the problems listed below and save again.',
      ]);
    } else if (isTooLarge(error)) {
      setMessages([
        `${TOO_LARGE_MESSAGE} Document size: ${sizeAgainstLimit(bytes, catalog.limits.documentBytes)}.`,
      ]);
    } else {
      setMessages(applyApiErrors(form, error));
    }
  });

  return (
    <div className="grid min-w-0 gap-4">
      <UnsavedChangesDialog guard={guard} />
      <Form {...form}>
        <form
          id="new-policy-form"
          onSubmit={(event) => void save(event)}
          noValidate
          aria-label="New policy"
        >
          <Section title="Policy">
            <div className="grid min-w-0 gap-4 md:grid-cols-2">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel required>Name</FormLabel>
                    <FormControl>
                      <Input {...field} maxLength={128} autoComplete="off" />
                    </FormControl>
                    <FormDescription>Unique in your organization.</FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="changeNote"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Change note</FormLabel>
                    <FormControl>
                      <Input {...field} maxLength={512} autoComplete="off" />
                    </FormControl>
                    <FormDescription>Why this version exists (optional).</FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="description"
                render={({ field }) => (
                  <FormItem className="md:col-span-2">
                    <FormLabel>Description</FormLabel>
                    <FormControl>
                      <Textarea {...field} maxLength={512} rows={2} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
          </Section>
        </form>
      </Form>
      <Toolbar label="Policy actions">
        {canValidate ? (
          <Button
            variant="outline"
            onClick={() => void validation.validateNow()}
            disabled={validation.pending || validation.pausedUntil !== null}
          >
            <CheckCheckIcon aria-hidden />
            Validate
          </Button>
        ) : null}
        <Button
          type="submit"
          form="new-policy-form"
          disabled={create.isPending || create.retryAfterSeconds > 0}
        >
          <SaveIcon aria-hidden />
          {create.isPending ? 'Saving …' : 'Save draft'}
        </Button>
        {canTest ? (
          <Button variant="outline" onClick={() => setPanel('test')}>
            <FlaskConicalIcon aria-hidden />
            Test
          </Button>
        ) : null}
        {canDryRun ? (
          <Button variant="outline" onClick={() => setPanel('dry-run')}>
            <HistoryIcon aria-hidden />
            Dry run
          </Button>
        ) : null}
        <Button
          variant="ghost"
          onClick={() => guard.guard(() => router.push(policiesTabHref('email')))}
        >
          Cancel
        </Button>
      </Toolbar>
      <FormErrorSummary messages={messages} requestId={create.error?.requestId} />
      {exceedsDocumentLimit(bytes, catalog.limits.documentBytes) ? (
        <p role="alert" className="text-sm text-destructive">
          {`${TOO_LARGE_MESSAGE} Document size: ${sizeAgainstLimit(bytes, catalog.limits.documentBytes)}.`}
        </p>
      ) : null}
      <BuilderProvider
        catalog={catalog}
        readOnly={false}
        violations={violations}
        paths={paths}
        highlightPath={highlight}
        directory={directory}
      >
        <EditorLayout summary={<SummaryAside summary={summary} />}>
          <div className="grid min-w-0 gap-4">
            <ValidationStatus
              check={check}
              currentKey={key}
              pending={validation.pending}
              error={validation.error}
              pausedUntil={validation.pausedUntil}
              auto={canValidate}
              documentBytes={bytes}
            />
            <ViolationList violations={violations} onSelect={setHighlight} />
            <PolicyBuilderEditor state={state} dispatch={dispatch} />
          </div>
        </EditorLayout>
        <PolicyTestPanel
          open={panel === 'test'}
          onOpenChange={(open) => setPanel(open ? 'test' : null)}
          catalog={catalog}
          targets={targets}
          state={testState}
          onStateChange={setTestState}
          onShowPath={showPath}
          onInlineViolations={onInlineViolations}
        />
        <PolicyDryRunPanel
          open={panel === 'dry-run'}
          onOpenChange={(open) => setPanel(open ? 'dry-run' : null)}
          catalog={catalog}
          targets={targets}
          state={dryRunState}
          onStateChange={setDryRunState}
          onShowPath={showPath}
        />
      </BuilderProvider>
    </div>
  );
}
