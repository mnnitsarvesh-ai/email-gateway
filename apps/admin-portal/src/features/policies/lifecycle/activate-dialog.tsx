'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { diffDefinitions, ViolationList } from '../builder';
import { policyCompareHref } from '../links';
import { detailNumber, POLICY_QUERIES, violationsOf } from '../queries';
import { useBuilderCatalog } from '../use-builder-catalog';
import { useDirectoryOptions } from '../use-directory-options';
import { LifecycleDialog, NextEvaluationNote } from './dialog-shell';

export type ActivateResult = SuccessBody<'PolicyManagementController_activate_v1'>;

/** "Activate vN" (newer than the active version, or none active) or "Roll back to vN" (older). */
export function activationLabel(versionNo: number, activeVersionNo: number | null): string {
  return activeVersionNo !== null && versionNo < activeVersionNo
    ? `Roll back to v${versionNo}`
    : `Activate v${versionNo}`;
}

function activateErrorText(error: ApiError): string | null {
  switch (error.code) {
    case 'policy_conflict':
      return 'The policy changed since this dialog opened. Reload it and confirm again.';
    case 'policy_version_not_published':
      return 'Only a published version can be activated.';
    case 'policy_rule_limit_reached': {
      const limit = detailNumber(error, 'limit');
      const requested = detailNumber(error, 'requested');
      return `Activating would exceed the organization’s limit of ${limit ?? '?'} active rules${requested ? ` (${requested} requested)` : ''}.`;
    }
    case 'policy_definition_invalid':
      return 'The server no longer accepts this version (the DSL moved on, or a referenced department or user is gone).';
    default:
      return null;
  }
}

/**
 * Activate a published version, or roll back to an older one (design B9; ADR-0063 decision 5):
 * the active and target numbers, the diff counts, the next-evaluation note and
 * `POST …/activate { expectedRowVersion: <policy rowVersion> }` with an Idempotency-Key.
 */
export function ActivateDialog({
  open,
  onOpenChange,
  policyId,
  versionNo,
  onActivated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  policyId: string;
  versionNo: number;
  onActivated?: (result: ActivateResult) => void;
}) {
  return (
    <ActivateDialogBody
      key={open ? 'open' : 'closed'}
      open={open}
      onOpenChange={onOpenChange}
      policyId={policyId}
      versionNo={versionNo}
      onActivated={onActivated}
    />
  );
}

function ActivateDialogBody({
  open,
  onOpenChange,
  policyId,
  versionNo,
  onActivated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  policyId: string;
  versionNo: number;
  onActivated?: (result: ActivateResult) => void;
}) {
  const [done, setDone] = useState<ActivateResult | null>(null);
  const policy = useApiQuery(
    'PolicyManagementController_get_v1',
    { path: { policyId } },
    { enabled: open },
  );
  const activeNo = policy.data?.activeVersionNo ?? null;
  const target = useApiQuery(
    'PolicyManagementController_getVersion_v1',
    { path: { policyId, versionNo } },
    { enabled: open },
  );
  const active = useApiQuery(
    'PolicyManagementController_getVersion_v1',
    { path: { policyId, versionNo: activeNo ?? 0 } },
    { enabled: open && activeNo !== null && activeNo !== versionNo },
  );
  const catalog = useBuilderCatalog();
  const { names } = useDirectoryOptions();
  const activation = useApiMutation('PolicyManagementController_activate_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: null,
  });
  const counts = useMemo(() => {
    if (!catalog.catalog || !target.data || !active.data) return null;
    return diffDefinitions(active.data.definition, target.data.definition, catalog.catalog, names)
      .counts;
  }, [catalog.catalog, target.data, active.data, names]);

  const label = activationLabel(versionNo, activeNo);
  const close = (next: boolean) => {
    if (next || activation.isPending) return;
    onOpenChange(false);
    if (done) onActivated?.(done);
  };
  const confirm = async () => {
    if (!policy.data) return;
    const outcome = await activation.submit({
      path: { policyId, versionNo },
      body: { expectedRowVersion: policy.data.rowVersion },
    });
    if (outcome.ok) setDone(outcome.data);
  };

  if (done) {
    return (
      <LifecycleDialog
        open={open}
        onOpenChange={close}
        title={`Version ${versionNo} is active`}
        description={`The policy now evaluates version ${versionNo}${activeNo !== null && activeNo !== versionNo ? ` instead of version ${activeNo}` : ''}.`}
        footer={<Button onClick={() => close(false)}>Done</Button>}
      >
        <NextEvaluationNote generation={done.generation} />
      </LifecycleDialog>
    );
  }

  const conflict = activation.error?.code === 'policy_conflict';
  const loading = policy.isLoading || target.isLoading || (activeNo !== null && active.isLoading);
  return (
    <LifecycleDialog
      open={open}
      onOpenChange={close}
      title={`${label}?`}
      description={
        activeNo !== null && versionNo < activeNo
          ? 'Rolling back re-activates an earlier published version. No version is changed or deleted; the rollback is audited.'
          : 'The published version becomes the policy’s active version.'
      }
      footer={
        <>
          <Button variant="outline" onClick={() => close(false)} disabled={activation.isPending}>
            Cancel
          </Button>
          {conflict ? (
            <Button
              variant="outline"
              onClick={() => {
                activation.reset();
                void policy.refetch();
              }}
            >
              Reload the policy
            </Button>
          ) : activation.error ? (
            <Button
              variant="outline"
              onClick={() =>
                void activation.retry().then((outcome) => {
                  if (outcome.ok) setDone(outcome.data);
                })
              }
              disabled={activation.isPending || activation.retryAfterSeconds > 0}
            >
              Retry
            </Button>
          ) : null}
          <Button
            onClick={() => void confirm()}
            disabled={
              loading ||
              !policy.data ||
              target.data?.status !== 'published' ||
              activeNo === versionNo ||
              activation.isPending ||
              activation.retryAfterSeconds > 0
            }
          >
            {activation.isPending ? 'Working …' : label}
          </Button>
        </>
      }
    >
      {loading ? (
        <LoadingState label="Loading the versions" rows={2} />
      ) : policy.error || target.error ? (
        <ErrorState error={policy.error ?? target.error} compact />
      ) : (
        <div className="grid gap-2 text-sm">
          <p>
            {activeNo === null ? (
              <>The policy has no active version; version {versionNo} becomes active.</>
            ) : activeNo === versionNo ? (
              <>Version {versionNo} is already the active version.</>
            ) : (
              <>
                Active now: <strong>v{activeNo}</strong>. After this: <strong>v{versionNo}</strong>.
              </>
            )}
          </p>
          {counts ? (
            <p>
              {`Changes from v${activeNo ?? '?'} to v${versionNo}: ${counts.added} ${counts.added === 1 ? 'rule' : 'rules'} added, ${counts.removed} removed, ${counts.changed} changed.`}{' '}
              <Link
                href={policyCompareHref(policyId, activeNo, versionNo)}
                className="text-primary underline underline-offset-2"
              >
                Compare the versions
              </Link>
            </p>
          ) : active.error ? (
            <ErrorState error={active.error} compact />
          ) : null}
          {target.data && target.data.status !== 'published' ? (
            <p role="alert" className="text-destructive">
              Only a published version can be activated (this one is {target.data.status}).
            </p>
          ) : null}
          <NextEvaluationNote />
        </div>
      )}
      {activation.error ? (
        <div className="grid gap-2">
          {activateErrorText(activation.error) ? (
            <p role="alert" className="text-sm text-destructive">
              {activateErrorText(activation.error)}
            </p>
          ) : null}
          {violationsOf(activation.error).length > 0 ? (
            <ViolationList violations={violationsOf(activation.error)} />
          ) : null}
          <ErrorState error={activation.error} compact />
        </div>
      ) : null}
    </LifecycleDialog>
  );
}
