'use client';

import { useQueryClient } from '@tanstack/react-query';
import {
  CheckCheckIcon,
  CopyPlusIcon,
  FlaskConicalIcon,
  GitCompareIcon,
  HistoryIcon,
  RotateCcwIcon,
  SaveIcon,
  SendIcon,
  Trash2Icon,
} from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useId, useMemo, useRef, useState, type ReactNode } from 'react';
import { toast } from 'sonner';
import { z } from 'zod';
import { CopyableId, DateTime } from '@/components/domain';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useUnsavedChanges } from '@/hooks/use-unsaved-changes';
import { useUrlState } from '@/hooks/use-url-state';
import { callOperation } from '@/lib/api/call';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatNumber } from '@/lib/format';
import { DetailList, EnumBadge, Section, YesNo } from '@/features/messages/controls';
import { isUuid } from '@/features/domains/kit';
import {
  BuilderProvider,
  buildDefinition,
  canonicalJson,
  documentBytes,
  parseDefinition,
  PolicyBuilderEditor,
  useBuilderState,
  ViolationList,
  type BuilderCatalog,
  type BuilderDefinition,
  type DirectoryNames,
  type ParseResult,
  type Violation,
} from '../builder';
import { summarizeModel } from '../builder/summary';
import { CatalogGate } from '../catalog-state';
import { ActivateDialog, activationLabel } from '../lifecycle/activate-dialog';
import { NextEvaluationNote } from '../lifecycle/dialog-shell';
import { DeleteDraftDialog } from '../lifecycle/policy-controls';
import { PublishDialog } from '../lifecycle/publish-dialog';
import { policyCompareHref, policyHref, policyVersionHref, type PolicyPanel } from '../links';
import { PolicyDryRunPanel, useDryRunPanelState } from '../panels/dry-run-panel';
import { PolicyTestPanel, useTestPanelState } from '../panels/test-panel';
import { ACTIVE_TARGET, PLATFORM_TARGET, refPrefixOf, type TargetOption } from '../panels/targets';
import { detailNumber, POLICY_QUERIES, violationsOf } from '../queries';
import { POLICY_STATUS_TONE, VERSION_STATUS_TONE } from '../semantic';
import { exceedsDocumentLimit, isTooLarge, sizeAgainstLimit, TOO_LARGE_MESSAGE } from '../size';
import { useBuilderCatalog, type BuilderCatalogState } from '../use-builder-catalog';
import { useDirectoryOptions } from '../use-directory-options';
import { useServerValidation } from '../use-server-validation';
import { ConflictDialog, ImmutableDialog } from './conflict-dialogs';
import { DefinitionJson, refusalText } from './json-view';
import { EditorLayout, SummaryAside, Toolbar, UnsavedChangesDialog, downloadJson } from './layout';
import { checkOfOutcome } from './new-policy-page';
import { EMPTY_VIOLATIONS, ValidationStatus, type ServerCheck } from './validation-status';

type Policy = SuccessBody<'PolicyManagementController_get_v1'>;
type Version = SuccessBody<'PolicyManagementController_getVersion_v1'>;

/** `?panel=test|dry-run` opens a panel, `?highlight=<dsl path>` outlines a node (design §4.6). */
export const VERSION_URL_SHAPE = {
  panel: z.enum(['test', 'dry-run']).optional().catch(undefined),
  highlight: z.string().max(512).optional().catch(undefined),
};

const versionNoOf = (raw: string): number | null => {
  if (!/^[1-9][0-9]{0,8}$/.test(raw)) return null;
  return Number(raw);
};

/**
 * `/policies/[policyId]/versions/[versionNo]` (design B6–B9, B14, B17): the builder in edit mode
 * for a draft when the user may update drafts, otherwise the same tree read-only; validate,
 * save, test, dry-run, publish, activate or roll back, new draft, delete draft, compare.
 */
export function PolicyVersionPage({
  policyId,
  versionNo,
}: {
  policyId: string;
  versionNo: string;
}) {
  return (
    <RouteGate gate={['PolicyManagementController_getVersion_v1']}>
      <VersionRoute policyId={policyId} versionNo={versionNo} />
    </RouteGate>
  );
}

function VersionRoute({ policyId, versionNo }: { policyId: string; versionNo: string }) {
  const n = versionNoOf(versionNo);
  // Ids that cannot exist look exactly like another tenant's ids: not found, no api call.
  if (!isUuid(policyId) || n === null) return <NotFoundView />;
  return <VersionLoader policyId={policyId} versionNo={n} />;
}

const isNotFound = (error: unknown) => error instanceof ApiError && error.status === 404;

function VersionLoader({ policyId, versionNo }: { policyId: string; versionNo: number }) {
  const policy = useApiQuery('PolicyManagementController_get_v1', { path: { policyId } });
  const version = useApiQuery('PolicyManagementController_getVersion_v1', {
    path: { policyId, versionNo },
  });
  const catalog = useBuilderCatalog();
  const [nonce, setNonce] = useState(0);
  const [generation, setGeneration] = useState<string | null>(null);
  const reload = useCallback(async () => {
    await Promise.all([policy.refetch(), version.refetch()]);
    setNonce((n) => n + 1);
  }, [policy, version]);
  const breadcrumbs = [
    { label: 'Policy management', href: '/policies' },
    { label: policy.data?.name ?? 'Policy', href: policyHref(policyId, 'versions') },
    { label: `Version ${versionNo}` },
  ];
  if (isNotFound(policy.error) || isNotFound(version.error)) return <NotFoundView />;
  if (policy.isLoading || version.isLoading) {
    return (
      <div className="grid gap-4">
        <PageHeader title={`Version ${versionNo}`} breadcrumbs={breadcrumbs} />
        <LoadingState label="Loading the policy version" rows={8} />
      </div>
    );
  }
  if (policy.error || version.error || !policy.data || !version.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title={`Version ${versionNo}`} breadcrumbs={breadcrumbs} />
        <ErrorState
          error={policy.error ?? version.error}
          onRetry={() => {
            void policy.refetch();
            void version.refetch();
          }}
        />
      </div>
    );
  }
  return (
    <VersionWorkspace
      key={nonce}
      policy={policy.data}
      version={version.data}
      catalogState={catalog}
      breadcrumbs={breadcrumbs}
      generation={generation}
      onGeneration={setGeneration}
      onReload={reload}
    />
  );
}

interface WorkspaceProps {
  policy: Policy;
  version: Version;
  catalogState: BuilderCatalogState;
  breadcrumbs: Array<{ label: string; href?: string }>;
  generation: string | null;
  onGeneration: (generation: string | null) => void;
  onReload: () => Promise<void>;
}

function VersionWorkspace(props: WorkspaceProps) {
  // The definition as loaded when this workspace mounted (a reload remounts it).
  const [parsed] = useState<ParseResult>(() => parseDefinition(props.version.definition));
  return (
    <CatalogGate state={props.catalogState}>
      {(catalog) =>
        parsed.ok ? (
          <BuilderWorkspace {...props} catalog={catalog} initialModel={parsed.model} />
        ) : (
          <LegacyWorkspace {...props} refusal={parsed} />
        )
      }
    </CatalogGate>
  );
}

/** Lifecycle capabilities of the loaded version for the current user (design B12). */
function useVersionCapabilities(policy: Policy, version: Version) {
  const canUpdateDraft = useCan('PolicyManagementController_updateDraft_v1');
  const canCreateDraft = useCan('PolicyManagementController_createDraft_v1');
  const canPublish = useCan('PolicyManagementController_publish_v1');
  const canActivate = useCan('PolicyManagementController_activate_v1');
  const canDeleteDraft = useCan('PolicyManagementController_deleteDraft_v1');
  const canValidate = useCan('PolicyToolsController_validate_v1');
  const canTest = useCan('PolicyToolsController_test_v1');
  const canSample = useCan('PolicyToolsController_sampleDryRun_v1');
  const canMessageDryRun = useCan('PolicyMessagesController_dryRun_v1');
  const draft = version.status === 'draft';
  return {
    edit: draft && canUpdateDraft,
    validate: draft && canUpdateDraft && canValidate,
    test: canTest,
    dryRun: canSample || canMessageDryRun,
    publish: draft && canPublish,
    deleteDraft: draft && canDeleteDraft,
    newDraft: !draft && canCreateDraft,
    activate:
      version.status === 'published' && policy.activeVersionNo !== version.versionNo && canActivate,
  };
}

function VersionHeader({
  policy,
  version,
  breadcrumbs,
  editing,
  dirty,
}: {
  policy: Policy;
  version: Version;
  breadcrumbs: Array<{ label: string; href?: string }>;
  editing: boolean;
  dirty: boolean;
}) {
  return (
    <PageHeader
      title={`${policy.name} · v${version.versionNo}`}
      breadcrumbs={breadcrumbs}
      description={
        <span className="flex flex-wrap items-center gap-2">
          <EnumBadge value={version.status} tones={VERSION_STATUS_TONE} />
          {version.active ? <EnumBadge value="active" tones={POLICY_STATUS_TONE} /> : null}
          <span>
            Policy <EnumBadge value={policy.status} tones={POLICY_STATUS_TONE} />
          </span>
          <span>{editing ? 'Edit mode' : 'View mode'}</span>
          {dirty ? <span className="font-medium text-foreground">Unsaved changes</span> : null}
        </span>
      }
    />
  );
}

function userName(names: DirectoryNames, id: string | null): ReactNode {
  if (!id) return <span className="text-muted-foreground">Unknown</span>;
  const name = names.users?.get(id);
  return name ?? <CopyableId value={id} label="user ID" max={14} />;
}

/** Created/updated/published by and when, hashes and references (design B11). */
function VersionDetails({
  version,
  names,
  changeNote,
}: {
  version: Version;
  names: DirectoryNames;
  changeNote: ReactNode;
}) {
  return (
    <Section title="Version details" headingLevel={2}>
      <DetailList
        items={[
          { label: 'Change note', value: changeNote },
          { label: 'Rules', value: formatNumber(version.ruleCount) },
          { label: 'Override rules', value: <YesNo value={version.hasOverrideRules} /> },
          { label: 'DSL version', value: version.dslVersion ?? 'Retired (legacy)' },
          {
            label: 'Created',
            value: (
              <span className="flex flex-wrap items-center gap-1">
                <DateTime value={version.createdAt} mode="absolute" /> by{' '}
                {userName(names, version.createdByUserId)}
              </span>
            ),
          },
          {
            label: 'Last updated',
            value: (
              <span className="flex flex-wrap items-center gap-1">
                <DateTime value={version.updatedAt} mode="absolute" /> by{' '}
                {userName(names, version.updatedByUserId)}
              </span>
            ),
          },
          {
            label: 'Published',
            value: version.publishedAt ? (
              <span className="flex flex-wrap items-center gap-1">
                <DateTime value={version.publishedAt} mode="absolute" /> by{' '}
                {userName(names, version.publishedByUserId)}
              </span>
            ) : (
              <span className="text-muted-foreground">Not published</span>
            ),
          },
          {
            label: 'Definition hash',
            value: <span className="font-mono text-xs break-all">{version.definitionSha256}</span>,
          },
          {
            label: 'Directory references',
            value: version.references
              ? `${version.references.departmentIds.length} departments, ${version.references.userIds.length} users`
              : 'Recorded when published',
          },
        ]}
      />
    </Section>
  );
}

/** Other drafts of the policy (design B6: several drafts may coexist). */
function OtherDrafts({ policyId, versionNo }: { policyId: string; versionNo: number }) {
  const drafts = useApiQuery('PolicyManagementController_listVersions_v1', {
    path: { policyId },
    query: { status: 'draft', limit: 25 },
  });
  const others = (drafts.data?.data ?? []).filter((v) => v.versionNo !== versionNo);
  if (others.length === 0) return null;
  return (
    <nav
      aria-label="Other drafts of this policy"
      className="flex flex-wrap items-center gap-2 text-sm"
    >
      <span className="text-muted-foreground">Other drafts:</span>
      {others.map((draft) => (
        <Link
          key={draft.versionNo}
          href={policyVersionHref(policyId, draft.versionNo)}
          className="text-primary underline-offset-2 hover:underline"
        >
          {`v${draft.versionNo}`}
          {draft.changeNote ? (
            <span className="text-muted-foreground">{` (${draft.changeNote})`}</span>
          ) : null}
        </Link>
      ))}
    </nav>
  );
}

function useNewDraftFromVersion(policyId: string) {
  const router = useRouter();
  const create = useApiMutation('PolicyManagementController_createDraft_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: null,
  });
  const fromVersion = async (basedOnVersionNo: number) => {
    const outcome = await create.submit({ path: { policyId }, body: { basedOnVersionNo } });
    if (outcome.ok) {
      toast.success(`Draft v${outcome.data.versionNo} created from v${basedOnVersionNo}`);
      router.push(policyVersionHref(policyId, outcome.data.versionNo));
    } else if (outcome.error.code === 'policy_version_limit_reached') {
      toast.error(
        `This policy reached its limit of ${detailNumber(outcome.error, 'limit') ?? '?'} versions; delete unused drafts first.`,
      );
    } else if (outcome.error.status !== 429) {
      toast.error(`The draft could not be created (${outcome.error.code}).`);
    }
  };
  return { fromVersion, pending: create.isPending };
}

/** Lifecycle actions shared by the builder and the legacy views. */
function LifecycleActions({
  policy,
  version,
  caps,
  dirty,
  onGeneration,
  onReload,
  extraStart,
}: {
  policy: Policy;
  version: Version;
  caps: ReturnType<typeof useVersionCapabilities>;
  dirty: boolean;
  onGeneration: (generation: string | null) => void;
  onReload: () => Promise<void>;
  extraStart?: ReactNode;
}) {
  const router = useRouter();
  const [dialog, setDialog] = useState<'publish' | 'activate' | 'delete' | null>(null);
  const newDraft = useNewDraftFromVersion(policy.id);
  const activeNo = policy.activeVersionNo;
  const hintId = useId();
  return (
    <>
      <Toolbar label="Version actions">
        {extraStart}
        {caps.publish ? (
          <Button
            variant="outline"
            onClick={() => setDialog('publish')}
            disabled={dirty}
            aria-describedby={dirty ? hintId : undefined}
          >
            <SendIcon aria-hidden />
            Publish…
          </Button>
        ) : null}
        {caps.activate ? (
          <Button variant="outline" onClick={() => setDialog('activate')}>
            <RotateCcwIcon aria-hidden />
            {activationLabel(version.versionNo, activeNo)}
          </Button>
        ) : null}
        {caps.newDraft ? (
          <Button
            variant="outline"
            onClick={() => void newDraft.fromVersion(version.versionNo)}
            disabled={newDraft.pending}
          >
            <CopyPlusIcon aria-hidden />
            New draft from this version
          </Button>
        ) : null}
        {activeNo !== null && activeNo !== version.versionNo ? (
          <Button asChild variant="ghost">
            <Link href={policyCompareHref(policy.id, activeNo, version.versionNo)}>
              <GitCompareIcon aria-hidden />
              Compare with active (v{activeNo})
            </Link>
          </Button>
        ) : null}
        {caps.deleteDraft ? (
          <Button variant="ghost" onClick={() => setDialog('delete')}>
            <Trash2Icon aria-hidden />
            Delete draft
          </Button>
        ) : null}
      </Toolbar>
      {dirty && caps.publish ? (
        <p id={hintId} className="text-xs text-muted-foreground">
          Save your changes before publishing: publishing publishes the saved draft.
        </p>
      ) : null}
      <PublishDialog
        open={dialog === 'publish'}
        onOpenChange={(open) => setDialog(open ? 'publish' : null)}
        policyId={policy.id}
        versionNo={version.versionNo}
        onPublished={(result) => {
          onGeneration(
            result.policy.activeVersionNo === version.versionNo ? result.generation : null,
          );
          void onReload();
        }}
      />
      <ActivateDialog
        open={dialog === 'activate'}
        onOpenChange={(open) => setDialog(open ? 'activate' : null)}
        policyId={policy.id}
        versionNo={version.versionNo}
        onActivated={(result) => {
          onGeneration(result.generation);
          void onReload();
        }}
      />
      <DeleteDraftDialog
        open={dialog === 'delete'}
        onOpenChange={(open) => setDialog(open ? 'delete' : null)}
        policyId={policy.id}
        versionNo={version.versionNo}
        rowVersion={version.rowVersion}
        onDeleted={() => router.push(policyHref(policy.id, 'versions'))}
      />
    </>
  );
}

function GenerationNote({ generation }: { generation: string | null }) {
  if (!generation) return null;
  return (
    <div className="rounded-md border bg-card p-3" role="status">
      <NextEvaluationNote generation={generation} />
    </div>
  );
}

function BuilderWorkspace({
  policy,
  version: initialVersion,
  catalog,
  initialModel,
  breadcrumbs,
  generation,
  onGeneration,
  onReload,
}: WorkspaceProps & { catalog: BuilderCatalog; initialModel: BuilderDefinition }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const policyId = policy.id;
  const versionNo = initialVersion.versionNo;
  const [url, setUrl] = useUrlState(VERSION_URL_SHAPE);
  /** The version as last read or saved here (never replaced by a background refetch). */
  const [loaded, setLoaded] = useState<Version>(initialVersion);
  const caps = useVersionCapabilities(policy, loaded);
  const editable = caps.edit;
  const { directory, names } = useDirectoryOptions();
  const { state, dispatch } = useBuilderState(initialModel);
  const { definition, paths } = useMemo(() => buildDefinition(state), [state]);
  const key = useMemo(() => canonicalJson(definition), [definition]);
  const [baselineKey, setBaselineKey] = useState(() =>
    canonicalJson(buildDefinition(initialModel).definition),
  );
  const [changeNote, setChangeNote] = useState(initialVersion.changeNote ?? '');
  const noteDirty = changeNote.trim() !== (loaded.changeNote ?? '');
  const dirty = editable && (key !== baselineKey || noteDirty);
  const guard = useUnsavedChanges(dirty, (href) => router.push(href));
  const bytes = useMemo(() => documentBytes(definition), [definition]);
  const summary = useMemo(() => summarizeModel(state, catalog, names), [state, catalog, names]);
  const [check, setCheck] = useState<ServerCheck | null>(() => ({
    key: canonicalJson(buildDefinition(initialModel).definition),
    valid: initialVersion.validation.valid,
    violations: initialVersion.validation.violations,
    referenceViolations: [],
    source: 'stored',
  }));
  const validation = useServerValidation(editable ? definition : null, {
    auto: caps.validate,
    onOutcome: (outcome) => setCheck(checkOfOutcome(outcome)),
  });
  const violations = useMemo(
    () => (check && check.key === key ? [...check.violations] : (EMPTY_VIOLATIONS as Violation[])),
    [check, key],
  );
  const [testState, setTestState] = useTestPanelState('version');
  const [dryRunState, setDryRunState] = useDryRunPanelState('version');
  const save = useApiMutation('PolicyManagementController_updateDraft_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'Draft saved',
  });
  const saveAsNew = useApiMutation('PolicyManagementController_createDraft_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: null,
  });
  const [conflict, setConflict] = useState<{ currentRowVersion: number | null } | null>(null);
  const [immutable, setImmutable] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  const saveDraft = async (expectedRowVersion: number = loaded.rowVersion): Promise<boolean> => {
    setSaveMessage(null);
    const sentKey = key;
    const note = changeNote.trim();
    const outcome = await save.submit({
      path: { policyId, versionNo },
      body: { definition, changeNote: note === '' ? null : note, expectedRowVersion },
    });
    if (outcome.ok) {
      setLoaded(outcome.data);
      setBaselineKey(sentKey);
      setConflict(null);
      setImmutable(false);
      setCheck((current) =>
        current && current.key === sentKey && current.source === 'validate'
          ? current
          : {
              key: sentKey,
              valid: outcome.data.validation.valid,
              violations: outcome.data.validation.violations,
              referenceViolations: [],
              source: 'save',
            },
      );
      return true;
    }
    const error = outcome.error;
    if (error.code === 'policy_conflict') {
      setConflict({ currentRowVersion: detailNumber(error, 'currentRowVersion') });
    } else if (error.code === 'policy_version_immutable') {
      setImmutable(true);
    } else if (error.code === 'policy_definition_invalid') {
      setCheck({
        key: sentKey,
        valid: false,
        violations: violationsOf(error),
        referenceViolations: [],
        source: 'save',
      });
      setSaveMessage(
        'The server refused the definition; fix the problems listed below and save again.',
      );
    } else if (isTooLarge(error)) {
      setSaveMessage(
        `${TOO_LARGE_MESSAGE} Document size: ${sizeAgainstLimit(bytes, catalog.limits.documentBytes)}.`,
      );
    }
    return false;
  };
  const saveRef = useRef(saveDraft);
  saveRef.current = saveDraft;
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;

  const overwrite = async () => {
    let current = conflict?.currentRowVersion ?? null;
    if (current === null) {
      try {
        current = (
          await callOperation('PolicyManagementController_getVersion_v1', {
            path: { policyId, versionNo },
          })
        ).rowVersion;
      } catch {
        return;
      }
    }
    await saveDraft(current);
  };

  const download = () =>
    downloadJson(
      `policy-${policyId}-v${versionNo}-local.json`,
      JSON.stringify(definition, null, 2),
    );

  const saveAsNewDraft = async () => {
    const note = changeNote.trim();
    const outcome = await saveAsNew.submit({
      path: { policyId },
      body: { definition, ...(note ? { changeNote: note } : {}) },
    });
    if (outcome.ok) {
      setImmutable(false);
      setBaselineKey(key);
      toast.success(`Saved as draft v${outcome.data.versionNo}`);
      router.push(policyVersionHref(policyId, outcome.data.versionNo));
    }
  };

  const targets = useMemo<TargetOption[]>(
    () => [
      {
        id: 'version',
        label: loaded.status === 'draft' ? 'This draft' : `This version (v${versionNo})`,
        description:
          loaded.status === 'draft'
            ? 'The saved draft in place of the policy’s active version (unsaved changes are saved first).'
            : 'This version in place of the policy’s active version.',
        needsSave: dirty,
        resolve: async () => {
          if (dirtyRef.current && !(await saveRef.current())) return null;
          return { policyId, versionNo };
        },
        editorRefPrefix: refPrefixOf(policyId, versionNo),
      },
      ACTIVE_TARGET,
      PLATFORM_TARGET,
    ],
    [dirty, loaded.status, policyId, versionNo],
  );

  const setPanel = (panel: PolicyPanel | undefined) => setUrl({ panel });
  const showPath = (path: string) => setUrl({ panel: undefined, highlight: path });

  return (
    <div className="grid min-w-0 gap-4">
      <VersionHeader
        policy={policy}
        version={loaded}
        breadcrumbs={breadcrumbs}
        editing={editable}
        dirty={dirty}
      />
      <UnsavedChangesDialog guard={guard} />
      <GenerationNote generation={generation} />
      <OtherDrafts policyId={policyId} versionNo={versionNo} />
      <LifecycleActions
        policy={policy}
        version={loaded}
        caps={caps}
        dirty={dirty}
        onGeneration={onGeneration}
        onReload={onReload}
        extraStart={
          <>
            {caps.validate ? (
              <Button
                variant="outline"
                onClick={() => void validation.validateNow()}
                disabled={validation.pending || validation.pausedUntil !== null}
              >
                <CheckCheckIcon aria-hidden />
                Validate
              </Button>
            ) : null}
            {editable ? (
              <Button
                onClick={() => void saveDraft()}
                disabled={!dirty || save.isPending || save.retryAfterSeconds > 0}
              >
                <SaveIcon aria-hidden />
                {save.isPending ? 'Saving …' : 'Save'}
              </Button>
            ) : null}
            {caps.test ? (
              <Button variant="outline" onClick={() => setPanel('test')}>
                <FlaskConicalIcon aria-hidden />
                Test
              </Button>
            ) : null}
            {caps.dryRun ? (
              <Button variant="outline" onClick={() => setPanel('dry-run')}>
                <HistoryIcon aria-hidden />
                Dry run
              </Button>
            ) : null}
          </>
        }
      />
      {saveMessage ? (
        <p role="alert" className="text-sm text-destructive">
          {saveMessage}
        </p>
      ) : null}
      {save.error &&
      !save.isPending &&
      !['policy_conflict', 'policy_version_immutable', 'policy_definition_invalid'].includes(
        save.error.code,
      ) &&
      !isTooLarge(save.error) ? (
        <ErrorState error={save.error} compact />
      ) : null}
      {editable && exceedsDocumentLimit(bytes, catalog.limits.documentBytes) ? (
        <p role="alert" className="text-sm text-destructive">
          {`${TOO_LARGE_MESSAGE} Document size: ${sizeAgainstLimit(bytes, catalog.limits.documentBytes)}.`}
        </p>
      ) : null}
      <BuilderProvider
        catalog={catalog}
        readOnly={!editable}
        violations={violations}
        paths={paths}
        highlightPath={url.highlight ?? null}
        directory={directory}
      >
        <EditorLayout summary={<SummaryAside summary={summary} />}>
          <div className="grid min-w-0 gap-4">
            {editable ? (
              <ValidationStatus
                check={check}
                currentKey={key}
                pending={validation.pending}
                error={validation.error}
                pausedUntil={validation.pausedUntil}
                auto={caps.validate}
                documentBytes={bytes}
              />
            ) : !loaded.validation.valid ? (
              <p role="alert" className="text-sm text-destructive">
                Today’s DSL no longer accepts this version; activating or copying it is refused
                until the problems below are fixed in a new draft.
              </p>
            ) : null}
            <ViolationList
              violations={violations}
              onSelect={(path) => setUrl({ highlight: path })}
            />
            <PolicyBuilderEditor state={state} dispatch={dispatch} />
            <VersionDetails
              version={loaded}
              names={names}
              changeNote={
                editable ? (
                  <ChangeNoteInput value={changeNote} onChange={setChangeNote} />
                ) : (
                  (loaded.changeNote ?? <span className="text-muted-foreground">None</span>)
                )
              }
            />
          </div>
        </EditorLayout>
        <PolicyTestPanel
          open={url.panel === 'test'}
          onOpenChange={(open) => setPanel(open ? 'test' : undefined)}
          catalog={catalog}
          targets={targets}
          state={testState}
          onStateChange={setTestState}
          onShowPath={showPath}
        />
        <PolicyDryRunPanel
          open={url.panel === 'dry-run'}
          onOpenChange={(open) => setPanel(open ? 'dry-run' : undefined)}
          catalog={catalog}
          targets={targets}
          state={dryRunState}
          onStateChange={setDryRunState}
          onShowPath={showPath}
        />
      </BuilderProvider>
      <ConflictDialog
        open={conflict !== null}
        onOpenChange={(open) => {
          if (!open) setConflict(null);
        }}
        currentRowVersion={conflict?.currentRowVersion ?? null}
        pending={save.isPending}
        error={save.error}
        onReload={() => {
          setConflict(null);
          void queryClient.invalidateQueries({
            queryKey: ['PolicyManagementController_listVersions_v1'],
          });
          void onReload();
        }}
        onOverwrite={() => void overwrite()}
        onDownload={download}
      />
      <ImmutableDialog
        open={immutable}
        onOpenChange={setImmutable}
        versionNo={versionNo}
        pending={saveAsNew.isPending}
        error={saveAsNew.error}
        onSaveAsNew={() => void saveAsNewDraft()}
        onDownload={download}
      />
    </div>
  );
}

function ChangeNoteInput({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  const id = useId();
  return (
    <div className="grid gap-1">
      <Label htmlFor={id} className="sr-only">
        Change note
      </Label>
      <Input
        id={id}
        value={value}
        maxLength={512}
        onChange={(event) => onChange(event.target.value)}
        placeholder="Why this version exists (optional)"
        autoComplete="off"
      />
    </div>
  );
}

/** A definition the builder cannot edit: the stored JSON with the reason (design B3). */
function LegacyWorkspace({
  policy,
  version,
  breadcrumbs,
  generation,
  onGeneration,
  onReload,
  refusal,
}: WorkspaceProps & { refusal: Extract<ParseResult, { ok: false }> }) {
  const caps = useVersionCapabilities(policy, version);
  const { names } = useDirectoryOptions();
  return (
    <div className="grid min-w-0 gap-4">
      <VersionHeader
        policy={policy}
        version={version}
        breadcrumbs={breadcrumbs}
        editing={false}
        dirty={false}
      />
      <GenerationNote generation={generation} />
      <LifecycleActions
        policy={policy}
        version={version}
        caps={{ ...caps, newDraft: false }}
        dirty={false}
        onGeneration={onGeneration}
        onReload={onReload}
      />
      <Section title="Definition (JSON)" description={refusalText(refusal)}>
        {version.validation.violations.length > 0 ? (
          <ViolationList violations={version.validation.violations} />
        ) : null}
        <DefinitionJson
          definition={version.definition}
          label={`Definition of version ${version.versionNo}`}
        />
      </Section>
      <VersionDetails
        version={version}
        names={names}
        changeNote={version.changeNote ?? <span className="text-muted-foreground">None</span>}
      />
    </div>
  );
}
