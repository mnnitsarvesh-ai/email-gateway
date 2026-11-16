'use client';

import { useRouter } from 'next/navigation';
import { useId, useState } from 'react';
import { toast } from 'sonner';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { ErrorState } from '@/components/states/error-state';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Switch } from '@/components/ui/switch';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation } from '@/lib/api/hooks';
import { LifecycleDialog } from '../lifecycle/dialog-shell';
import { riskProfileVersionHref } from '../links';
import { detailNumber, RISK_QUERIES } from '../queries';

const RISK_NOTE =
  'A risk-profile change applies to the next scan round only; open rounds and stored scores never change.';

function riskErrorText(error: ApiError): string | null {
  switch (error.code) {
    case 'risk_profile_version_conflict':
      return 'The risk profile changed since it was loaded. Reload the page and try again.';
    case 'risk_profile_version_immutable':
      return 'This version is already published.';
    case 'risk_profile_version_not_published':
      return 'Only a published version can be activated.';
    case 'risk_profile_limit_reached':
      return `Your organization reached its limit of ${detailNumber(error, 'limit') ?? '?'} risk-profile versions; delete unused drafts first.`;
    case 'risk_profile_invalid':
      return 'The platform bounds do not accept this version.';
    default:
      return null;
  }
}

function MutationProblem({ error }: { error: ApiError | null }) {
  if (!error) return null;
  const text = riskErrorText(error);
  return (
    <div className="grid gap-1">
      {text ? (
        <p role="alert" className="text-sm text-destructive">
          {text}
        </p>
      ) : null}
      <ErrorState error={error} compact />
    </div>
  );
}

/** `Activate vN` (newer than the active version, or none active) or `Roll back to vN` (older). */
export const riskActivationLabel = (versionNo: number, activeVersionNo: number | null) =>
  activeVersionNo !== null && versionNo < activeVersionNo
    ? `Roll back to v${versionNo}`
    : `Activate v${versionNo}`;

/** New risk-profile draft (design B13): from the active version or from the platform profile. */
export function NewRiskDraftDialog({
  open,
  onOpenChange,
  activeVersionId,
  activeVersionNo,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  activeVersionId: string | null;
  activeVersionNo: number | null;
}) {
  const router = useRouter();
  const ids = { source: useId(), note: useId() };
  const [source, setSource] = useState<'active' | 'platform'>(
    activeVersionId ? 'active' : 'platform',
  );
  const [note, setNote] = useState('');
  const create = useApiMutation('RiskProfilesController_createDraft_v1', {
    invalidates: RISK_QUERIES,
    successMessage: null,
  });
  const submit = async () => {
    const changeNote = note.trim();
    const outcome = await create.submit({
      body: {
        ...(source === 'active' && activeVersionId ? { basedOnVersionId: activeVersionId } : {}),
        ...(changeNote ? { changeNote } : {}),
      },
    });
    if (outcome.ok) {
      toast.success(`Risk-profile draft v${outcome.data.versionNo} created`);
      onOpenChange(false);
      router.push(riskProfileVersionHref(outcome.data.id));
    }
  };
  return (
    <LifecycleDialog
      open={open}
      onOpenChange={(next) => {
        if (!create.isPending) onOpenChange(next);
      }}
      title="New risk-profile draft"
      description="A draft changes nothing until it is published and activated."
      footer={
        <>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={create.isPending}>
            {create.isPending ? 'Creating …' : 'Create draft'}
          </Button>
        </>
      }
    >
      <fieldset className="grid gap-2">
        <legend className="mb-1 text-sm font-medium">Start from</legend>
        <RadioGroup
          value={source}
          onValueChange={(value) => setSource(value === 'active' ? 'active' : 'platform')}
        >
          {activeVersionId ? (
            <div className="flex items-center gap-2">
              <RadioGroupItem id={`${ids.source}-active`} value="active" />
              <Label htmlFor={`${ids.source}-active`} className="font-normal">
                {`The active version (v${activeVersionNo ?? '?'})`}
              </Label>
            </div>
          ) : null}
          <div className="flex items-center gap-2">
            <RadioGroupItem id={`${ids.source}-platform`} value="platform" />
            <Label htmlFor={`${ids.source}-platform`} className="font-normal">
              The platform profile (no overrides)
            </Label>
          </div>
        </RadioGroup>
      </fieldset>
      <div className="grid gap-1">
        <Label htmlFor={ids.note}>Change note</Label>
        <Input
          id={ids.note}
          value={note}
          maxLength={512}
          onChange={(event) => setNote(event.target.value)}
          autoComplete="off"
        />
      </div>
      <MutationProblem error={create.error} />
    </LifecycleDialog>
  );
}

/** Publish a risk-profile draft (activate default on; Idempotency-Key reused on retry). */
export function RiskPublishDialog({
  open,
  onOpenChange,
  versionId,
  versionNo,
  rowVersion,
  onDone,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  versionId: string;
  versionNo: number;
  rowVersion: number;
  onDone?: () => void;
}) {
  const id = useId();
  const [activate, setActivate] = useState(true);
  const publish = useApiMutation('RiskProfilesController_publish_v1', {
    invalidates: RISK_QUERIES,
    successMessage: `Risk profile v${versionNo} published`,
  });
  const finish = (ok: boolean) => {
    if (!ok) return;
    onOpenChange(false);
    onDone?.();
  };
  return (
    <LifecycleDialog
      open={open}
      onOpenChange={(next) => {
        if (!publish.isPending) onOpenChange(next);
      }}
      title={`Publish risk profile v${versionNo}?`}
      description={`A published version never changes again; the server re-validates it against the platform bounds. ${RISK_NOTE}`}
      footer={
        <>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={publish.isPending}
          >
            Cancel
          </Button>
          {publish.error ? (
            <Button
              variant="outline"
              onClick={() => void publish.retry().then((outcome) => finish(outcome.ok))}
              disabled={publish.isPending || publish.retryAfterSeconds > 0}
            >
              Retry
            </Button>
          ) : null}
          <Button
            onClick={() =>
              void publish
                .submit({
                  path: { versionId },
                  body: { activate, expectedRowVersion: rowVersion },
                })
                .then((outcome) => finish(outcome.ok))
            }
            disabled={publish.isPending || publish.retryAfterSeconds > 0}
          >
            {publish.isPending ? 'Publishing …' : activate ? 'Publish and activate' : 'Publish'}
          </Button>
        </>
      }
    >
      <div className="flex items-start gap-3 rounded-md border p-3">
        <Switch id={id} checked={activate} onCheckedChange={setActivate} />
        <div className="grid gap-0.5">
          <Label htmlFor={id}>Activate now</Label>
          <p className="text-xs text-muted-foreground">
            On: the next scan rounds use this version. Off: published, the active version stays.
          </p>
        </div>
      </div>
      <MutationProblem error={publish.error} />
    </LifecycleDialog>
  );
}

/** Activate a published risk-profile version, or roll back to an older one (confirmed). */
export function RiskActivateDialog({
  open,
  onOpenChange,
  versionId,
  versionNo,
  activeVersionNo,
  profileVersion,
  onDone,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  versionId: string;
  versionNo: number;
  activeVersionNo: number | null;
  profileVersion: number;
  onDone?: () => void;
}) {
  const label = riskActivationLabel(versionNo, activeVersionNo);
  const activate = useApiMutation('RiskProfilesController_activate_v1', {
    invalidates: RISK_QUERIES,
    successMessage: `Risk profile v${versionNo} is active`,
  });
  const finish = (ok: boolean) => {
    if (!ok) return;
    onOpenChange(false);
    onDone?.();
  };
  return (
    <LifecycleDialog
      open={open}
      onOpenChange={(next) => {
        if (!activate.isPending) onOpenChange(next);
      }}
      title={`${label}?`}
      description={
        <div className="grid gap-2">
          <p>
            {activeVersionNo === null
              ? `The platform profile applies now; v${versionNo} becomes active.`
              : `Active now: v${activeVersionNo}. After this: v${versionNo}.`}
          </p>
          <p>{RISK_NOTE}</p>
        </div>
      }
      footer={
        <>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={activate.isPending}
          >
            Cancel
          </Button>
          {activate.error ? (
            <Button
              variant="outline"
              onClick={() => void activate.retry().then((outcome) => finish(outcome.ok))}
              disabled={activate.isPending || activate.retryAfterSeconds > 0}
            >
              Retry
            </Button>
          ) : null}
          <Button
            onClick={() =>
              void activate
                .submit({ path: { versionId }, body: { expectedProfileVersion: profileVersion } })
                .then((outcome) => finish(outcome.ok))
            }
            disabled={activate.isPending || activate.retryAfterSeconds > 0}
          >
            {activate.isPending ? 'Working …' : label}
          </Button>
        </>
      }
    >
      <MutationProblem error={activate.error} />
    </LifecycleDialog>
  );
}

/** Back to the platform profile (confirmed; Idempotency-Key reused on retry). */
export function RiskResetDialog({
  open,
  onOpenChange,
  profileVersion,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  profileVersion: number;
}) {
  const reset = useApiMutation('RiskProfilesController_reset_v1', {
    invalidates: RISK_QUERIES,
    successMessage: 'The platform risk profile applies again',
  });
  const finish = (ok: boolean) => {
    if (ok) onOpenChange(false);
  };
  return (
    <LifecycleDialog
      open={open}
      onOpenChange={(next) => {
        if (!reset.isPending) onOpenChange(next);
      }}
      title="Reset to the platform profile?"
      description={`No tenant version is active afterwards; the versions are kept and can be activated again. ${RISK_NOTE}`}
      footer={
        <>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={reset.isPending}>
            Cancel
          </Button>
          {reset.error ? (
            <Button
              variant="outline"
              onClick={() => void reset.retry().then((outcome) => finish(outcome.ok))}
              disabled={reset.isPending || reset.retryAfterSeconds > 0}
            >
              Retry
            </Button>
          ) : null}
          <Button
            variant="destructive"
            onClick={() =>
              void reset
                .submit({ body: { expectedProfileVersion: profileVersion } })
                .then((outcome) => finish(outcome.ok))
            }
            disabled={reset.isPending || reset.retryAfterSeconds > 0}
          >
            {reset.isPending ? 'Working …' : 'Reset to the platform profile'}
          </Button>
        </>
      }
    >
      <MutationProblem error={reset.error} />
    </LifecycleDialog>
  );
}

/** Delete a risk-profile draft (confirmed; `?expectedRowVersion`). */
export function DeleteRiskDraftDialog({
  open,
  onOpenChange,
  versionId,
  versionNo,
  rowVersion,
  onDeleted,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  versionId: string;
  versionNo: number;
  rowVersion: number;
  onDeleted?: () => void;
}) {
  const remove = useApiMutation('RiskProfilesController_deleteDraft_v1', {
    invalidates: RISK_QUERIES,
    successMessage: `Risk-profile draft v${versionNo} deleted`,
  });
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) remove.reset();
        onOpenChange(next);
      }}
      title={`Delete risk-profile draft v${versionNo}?`}
      description="The draft is deleted. Published versions are not affected."
      confirmLabel="Delete draft"
      destructive
      pending={remove.isPending}
      error={<MutationProblem error={remove.error} />}
      onConfirm={async () => {
        const outcome = await remove.submit({
          path: { versionId },
          query: { expectedRowVersion: rowVersion },
        });
        if (outcome.ok) onDeleted?.();
        return outcome.ok;
      }}
    />
  );
}
