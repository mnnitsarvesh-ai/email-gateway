'use client';

import { useQuery } from '@tanstack/react-query';
import { useId, useMemo, useState } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { callOperation } from '@/lib/api/call';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import {
  PolicySummaryView,
  summarizeDefinition,
  ViolationList,
  type BuilderCatalog,
  type DirectoryNames,
} from '../builder';
import { ReferenceWarnings } from '../editor/validation-status';
import { detailNumber, POLICY_QUERIES, violationsOf } from '../queries';
import { useBuilderCatalog } from '../use-builder-catalog';
import { useDirectoryOptions } from '../use-directory-options';
import { LifecycleDialog, NextEvaluationNote } from './dialog-shell';

export type PublishResult = SuccessBody<'PolicyManagementController_publish_v1'>;
type Version = SuccessBody<'PolicyManagementController_getVersion_v1'>;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Why a publish failed, in words (the error state below adds code and request id). */
export function publishErrorText(error: ApiError): string | null {
  switch (error.code) {
    case 'policy_conflict':
      return 'The draft changed since it was loaded. Close this dialog, reload the draft and publish again.';
    case 'policy_version_immutable':
      return 'This version is already published.';
    case 'policy_rule_limit_reached': {
      const limit = detailNumber(error, 'limit');
      const requested = detailNumber(error, 'requested');
      return `Activating would exceed the organization’s limit of ${limit ?? '?'} active rules${requested ? ` (${requested} requested)` : ''}. Publish without activating, or disable another policy first.`;
    }
    case 'policy_definition_invalid':
      return 'The server refused the version; fix these problems in a draft first.';
    default:
      return null;
  }
}

/**
 * Publish a draft (design B9): its summary, the server validation re-run, the directory
 * reference check and "Activate now" (default on); `POST …/publish { activate,
 * expectedRowVersion }` with an Idempotency-Key that a retry reuses (`useApiMutation`).
 */
export function PublishDialog({
  open,
  onOpenChange,
  policyId,
  versionNo,
  onPublished,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  policyId: string;
  versionNo: number;
  /** Called when the dialog closes after a successful publish. */
  onPublished?: (result: PublishResult) => void;
}) {
  return (
    <PublishDialogBody
      key={open ? 'open' : 'closed'}
      open={open}
      onOpenChange={onOpenChange}
      policyId={policyId}
      versionNo={versionNo}
      onPublished={onPublished}
    />
  );
}

function PublishDialogBody({
  open,
  onOpenChange,
  policyId,
  versionNo,
  onPublished,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  policyId: string;
  versionNo: number;
  onPublished?: (result: PublishResult) => void;
}) {
  const activateId = useId();
  const [activate, setActivate] = useState(true);
  const [published, setPublished] = useState<PublishResult | null>(null);
  const version = useApiQuery(
    'PolicyManagementController_getVersion_v1',
    { path: { policyId, versionNo } },
    { enabled: open },
  );
  const catalog = useBuilderCatalog();
  const { names } = useDirectoryOptions();
  const publish = useApiMutation('PolicyManagementController_publish_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: null,
  });
  const definition = version.data?.definition;
  const validation = useQuery<SuccessBody<'PolicyToolsController_validate_v1'>, ApiError>({
    queryKey: [
      'PolicyToolsController_validate_v1',
      { purpose: 'publish', policyId, versionNo, sha: version.data?.definitionSha256 },
    ],
    queryFn: ({ signal }) =>
      callOperation(
        'PolicyToolsController_validate_v1',
        { body: { definition: isRecord(definition) ? definition : {} } },
        { signal },
      ),
    enabled: open && isRecord(definition) && version.data?.status === 'draft',
    staleTime: 0,
    gcTime: 0,
    retry: false,
  });

  const close = (next: boolean) => {
    if (next) return;
    if (publish.isPending) return;
    onOpenChange(false);
    if (published) onPublished?.(published);
  };

  const submit = async () => {
    if (!version.data) return;
    const outcome = await publish.submit({
      path: { policyId, versionNo },
      body: { activate, expectedRowVersion: version.data.rowVersion },
    });
    if (outcome.ok) setPublished(outcome.data);
  };

  const invalid = validation.data !== undefined && !validation.data.valid;
  const ready =
    version.data?.status === 'draft' && (validation.isSuccess || validation.isError) && !invalid;

  if (published) {
    const activated = published.policy.activeVersionNo === versionNo;
    return (
      <LifecycleDialog
        open={open}
        onOpenChange={close}
        title={`Version ${versionNo} published`}
        description={
          activated
            ? `Version ${versionNo} is published and active.`
            : `Version ${versionNo} is published; the active version did not change.`
        }
        footer={<Button onClick={() => close(false)}>Done</Button>}
      >
        <NextEvaluationNote generation={activated ? published.generation : null} />
      </LifecycleDialog>
    );
  }

  return (
    <LifecycleDialog
      open={open}
      onOpenChange={close}
      wide
      title={`Publish version ${versionNo}`}
      description="A published version never changes again. The server validates it once more before publishing."
      footer={
        <>
          <Button variant="outline" onClick={() => close(false)} disabled={publish.isPending}>
            Cancel
          </Button>
          {publish.error && publish.error.code !== 'policy_conflict' ? (
            <Button
              variant="outline"
              onClick={() =>
                void publish.retry().then((outcome) => {
                  if (outcome.ok) setPublished(outcome.data);
                })
              }
              disabled={publish.isPending || publish.retryAfterSeconds > 0}
            >
              Retry
            </Button>
          ) : null}
          <Button
            onClick={() => void submit()}
            disabled={!ready || publish.isPending || publish.retryAfterSeconds > 0}
          >
            {publish.isPending ? 'Publishing …' : activate ? 'Publish and activate' : 'Publish'}
          </Button>
        </>
      }
    >
      {version.isLoading || catalog.query.isLoading ? (
        <LoadingState label="Loading the version" rows={3} />
      ) : version.error ? (
        <ErrorState error={version.error} compact />
      ) : version.data ? (
        <PublishChecks
          version={version.data}
          catalog={catalog.catalog}
          names={names}
          validation={validation}
        />
      ) : null}
      <div className="flex items-start gap-3 rounded-md border p-3">
        <Switch
          id={activateId}
          checked={activate}
          onCheckedChange={setActivate}
          aria-describedby={`${activateId}-desc`}
        />
        <div className="grid gap-0.5">
          <Label htmlFor={activateId}>Activate now</Label>
          <p id={`${activateId}-desc`} className="text-xs text-muted-foreground">
            On: this version becomes the policy’s active version (the next evaluation uses it). Off:
            it is published but the active version stays.
          </p>
        </div>
      </div>
      {publish.error ? (
        <div className="grid gap-2">
          {publishErrorText(publish.error) ? (
            <p role="alert" className="text-sm text-destructive">
              {publishErrorText(publish.error)}
            </p>
          ) : null}
          {violationsOf(publish.error).length > 0 ? (
            <ViolationList violations={violationsOf(publish.error)} />
          ) : null}
          <ErrorState error={publish.error} compact />
        </div>
      ) : null}
    </LifecycleDialog>
  );
}

function PublishChecks({
  version,
  catalog,
  names,
  validation,
}: {
  version: Version;
  catalog: BuilderCatalog | null;
  names: DirectoryNames;
  validation: {
    data: SuccessBody<'PolicyToolsController_validate_v1'> | undefined;
    error: ApiError | null;
    isLoading: boolean;
  };
}) {
  const summary = useMemo(
    () => (catalog ? summarizeDefinition(version.definition, catalog, names) : null),
    [catalog, names, version.definition],
  );
  if (version.status !== 'draft') {
    return (
      <p role="alert" className="text-sm text-destructive">
        Version {version.versionNo} is not a draft any more (it is {version.status}).
      </p>
    );
  }
  return (
    <div className="grid min-w-0 gap-3">
      {summary ? (
        <div className="max-h-72 min-w-0 overflow-y-auto rounded-md border p-3">
          <PolicySummaryView summary={summary} compact />
        </div>
      ) : null}
      {validation.isLoading ? (
        <p className="text-sm text-muted-foreground" role="status">
          Validating on the server …
        </p>
      ) : validation.error ? (
        <div className="grid gap-1">
          <p className="text-sm text-muted-foreground">
            The validation could not be re-run; publishing validates again on the server.
          </p>
          <ErrorState error={validation.error} compact />
        </div>
      ) : validation.data ? (
        validation.data.valid ? (
          <div className="grid gap-2">
            <p className="text-sm" role="status">
              The server accepts this version
              {validation.data.ruleCount !== null
                ? ` (${validation.data.ruleCount} ${validation.data.ruleCount === 1 ? 'rule' : 'rules'}${validation.data.hasOverrideRules ? ', with override rules' : ''})`
                : ''}
              .
            </p>
            <ReferenceWarnings warnings={validation.data.referenceViolations} />
          </div>
        ) : (
          <div className="grid gap-2">
            <p className="text-sm text-destructive" role="alert">
              The server does not accept this version; fix the draft before publishing.
            </p>
            <ViolationList violations={validation.data.violations} />
          </div>
        )
      ) : null}
    </div>
  );
}
