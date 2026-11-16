'use client';

import { useId, useState } from 'react';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
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
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation } from '@/lib/api/hooks';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { detailNumber, POLICY_QUERIES } from '../queries';
import { LifecycleDialog } from './dialog-shell';

type Policy = SuccessBody<'PolicyManagementController_get_v1'>;

function conflictText(error: ApiError | null): string | null {
  if (error?.code !== 'policy_conflict') return null;
  const current = detailNumber(error, 'currentRowVersion');
  return `The policy changed since it was loaded${current !== null ? ` (row version ${current})` : ''}. Reload the page and try again.`;
}

/**
 * Enable / disable (design B9): a switch with a confirmation; `POST …/enable|disable
 * { expectedRowVersion }`; enabling is offered only with an active version. Without the
 * permission the status is shown as text by the page.
 */
export function PolicyStatusSwitch({ policy }: { policy: Policy }) {
  const id = useId();
  const canEnable = useCan('PolicyManagementController_enable_v1');
  const canDisable = useCan('PolicyManagementController_disable_v1');
  const [confirming, setConfirming] = useState(false);
  const enable = useApiMutation('PolicyManagementController_enable_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'Policy enabled',
  });
  const disable = useApiMutation('PolicyManagementController_disable_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'Policy disabled',
  });
  if (!canEnable && !canDisable) return null;
  const enabled = policy.status === 'active';
  const hasActive = policy.activeVersionNo !== null;
  const allowed = enabled ? canDisable : canEnable && hasActive;
  const mutation = enabled ? disable : enable;
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Switch
        id={id}
        checked={enabled}
        disabled={!allowed}
        onCheckedChange={() => {
          mutation.reset();
          setConfirming(true);
        }}
        aria-describedby={`${id}-hint`}
      />
      <Label htmlFor={id}>Enabled</Label>
      <span id={`${id}-hint`} className="text-xs text-muted-foreground">
        {hasActive
          ? enabled
            ? 'The active version is evaluated.'
            : 'Not evaluated while disabled.'
          : 'Publish and activate a version first.'}
      </span>
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title={enabled ? 'Disable this policy?' : 'Enable this policy?'}
        description={
          <div className="grid gap-2">
            <p>
              {enabled
                ? `“${policy.name}” stops being evaluated. Its versions stay as they are.`
                : `“${policy.name}” is evaluated again with version ${policy.activeVersionNo ?? '?'}.`}
            </p>
            <p>The change applies to the next evaluation only.</p>
          </div>
        }
        confirmLabel={enabled ? 'Disable' : 'Enable'}
        destructive={enabled}
        pending={mutation.isPending}
        error={
          mutation.error ? (
            <div className="grid gap-1">
              {conflictText(mutation.error) ? (
                <p className="text-sm text-destructive">{conflictText(mutation.error)}</p>
              ) : null}
              <ErrorState error={mutation.error} compact />
            </div>
          ) : null
        }
        onConfirm={async () => {
          const outcome = await mutation.submit({
            path: { policyId: policy.id },
            body: { expectedRowVersion: policy.rowVersion },
          });
          return outcome.ok;
        }}
      />
    </div>
  );
}

const renameSchema = z
  .object({
    name: z.string().trim().min(1, 'Enter a name').max(128, 'At most 128 characters'),
    description: z.string().trim().max(512, 'At most 512 characters'),
  })
  .strict();

export function renameBody(
  policy: Pick<Policy, 'rowVersion'>,
  values: z.output<typeof renameSchema>,
): RequestBody<'PolicyManagementController_update_v1'> {
  return {
    name: values.name,
    description: values.description === '' ? null : values.description,
    expectedRowVersion: policy.rowVersion,
  };
}

/**
 * Rename (design B6): name and description of the policy row, `PATCH /policies/{id}` with the
 * policy `rowVersion`. Direction and priority belong to the version.
 */
export function RenameDialog({
  open,
  onOpenChange,
  policy,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  policy: Policy;
}) {
  const [messages, setMessages] = useState<string[]>([]);
  const form = useZodForm(renameSchema, {
    defaultValues: { name: policy.name, description: policy.description ?? '' },
  });
  const update = useApiMutation('PolicyManagementController_update_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'Policy renamed',
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await update.submit({
      path: { policyId: policy.id },
      body: renameBody(policy, values),
    });
    if (outcome.ok) {
      onOpenChange(false);
      return;
    }
    if (outcome.error.code === 'policy_name_taken') {
      form.setError('name', {
        type: 'server',
        message: 'Another policy of your organization (possibly a deleted one) has this name.',
      });
      return;
    }
    const conflict = conflictText(outcome.error);
    setMessages(conflict ? [conflict] : applyApiErrors(form, outcome.error));
  });
  return (
    <LifecycleDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          form.reset({ name: policy.name, description: policy.description ?? '' });
          setMessages([]);
        }
        onOpenChange(next);
      }}
      title="Rename the policy"
      description="The name and description belong to the policy. Direction and priority belong to its versions: change them in a draft and publish it."
      footer={
        <>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={update.isPending}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="policy-rename-form"
            disabled={update.isPending || update.retryAfterSeconds > 0}
          >
            {update.isPending ? 'Saving …' : 'Save'}
          </Button>
        </>
      }
    >
      <Form {...form}>
        <form
          id="policy-rename-form"
          onSubmit={(event) => void submit(event)}
          className="grid gap-4"
          noValidate
          aria-label="Rename the policy"
        >
          <FormErrorSummary messages={messages} requestId={update.error?.requestId} />
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel required>Name</FormLabel>
                <FormControl>
                  <Input {...field} maxLength={128} autoComplete="off" />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="description"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Description</FormLabel>
                <FormControl>
                  <Textarea {...field} maxLength={512} rows={3} />
                </FormControl>
                <FormDescription>Optional, at most 512 characters.</FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </form>
      </Form>
    </LifecycleDialog>
  );
}

/** Delete (archive) a policy (design B9): typed confirmation of the name; `DELETE ?expectedRowVersion`. */
export function DeletePolicyDialog({
  open,
  onOpenChange,
  policy,
  onDeleted,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  policy: Policy;
  onDeleted: () => void;
}) {
  const remove = useApiMutation('PolicyManagementController_remove_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'Policy deleted',
  });
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) remove.reset();
        onOpenChange(next);
      }}
      title="Delete this policy?"
      description={
        <div className="grid gap-2">
          <p>
            The policy is archived: it disappears from the list
            {policy.status === 'active' ? ', stops being evaluated from the next evaluation' : ''},
            and its name stays reserved. Its versions and audit trail are kept.
          </p>
        </div>
      }
      confirmLabel="Delete policy"
      destructive
      typedConfirmation={policy.name}
      pending={remove.isPending}
      error={
        remove.error ? (
          <div className="grid gap-1">
            {conflictText(remove.error) ? (
              <p className="text-sm text-destructive">{conflictText(remove.error)}</p>
            ) : null}
            <ErrorState error={remove.error} compact />
          </div>
        ) : null
      }
      onConfirm={async () => {
        const outcome = await remove.submit({
          path: { policyId: policy.id },
          query: { expectedRowVersion: policy.rowVersion },
        });
        if (outcome.ok) onDeleted();
        return outcome.ok;
      }}
    />
  );
}

/** Delete a draft version (design B9): confirm; `DELETE …/versions/{n}?expectedRowVersion`. */
export function DeleteDraftDialog({
  open,
  onOpenChange,
  policyId,
  versionNo,
  rowVersion,
  onDeleted,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  policyId: string;
  versionNo: number;
  rowVersion: number;
  onDeleted: () => void;
}) {
  const remove = useApiMutation('PolicyManagementController_deleteDraft_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: `Draft v${versionNo} deleted`,
  });
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) remove.reset();
        onOpenChange(next);
      }}
      title={`Delete draft v${versionNo}?`}
      description="The draft and its unpublished changes are deleted. Published versions are not affected."
      confirmLabel="Delete draft"
      destructive
      pending={remove.isPending}
      error={
        remove.error ? (
          <div className="grid gap-1">
            {remove.error.code === 'policy_version_immutable' ? (
              <p className="text-sm text-destructive">
                This version was published meanwhile; published versions are never deleted.
              </p>
            ) : conflictText(remove.error) ? (
              <p className="text-sm text-destructive">
                The draft changed since it was loaded. Reload the page and try again.
              </p>
            ) : null}
            <ErrorState error={remove.error} compact />
          </div>
        ) : null
      }
      onConfirm={async () => {
        const outcome = await remove.submit({
          path: { policyId, versionNo },
          query: { expectedRowVersion: rowVersion },
        });
        if (outcome.ok) onDeleted();
        return outcome.ok;
      }}
    />
  );
}
