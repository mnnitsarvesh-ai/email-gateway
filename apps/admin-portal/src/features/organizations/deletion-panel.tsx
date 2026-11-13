'use client';

import { useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { type ApiError } from '@/lib/api/errors';
import type { SuccessBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { formatUtc, humanize } from '@/lib/format';
import { ReportSection } from '@/features/reports/report-state';
import { ReasonConfirmDialog } from './reason-confirm-dialog';

type Organization = SuccessBody<'OrganizationsController_get_v1'>;

const INVALIDATES = [
  'OrganizationDeletionController_get_v1',
  'OrganizationsController_get_v1',
  'OrganizationsController_list_v1',
] as const;

/** Explains the two refusals specific to the deletion workflow, then the API error itself. */
export function DeletionError({ error }: { error: ApiError | null }) {
  if (!error) return null;
  const note =
    error.status === 403 && error.code === 'mfa_required'
      ? 'Deletion steps need a session signed in with MFA. Sign out and sign in again with your authenticator code.'
      : error.status === 403
        ? 'Four-eyes rule: the deletion must be confirmed by a different platform user than the one who requested it.'
        : error.status === 409
          ? 'The deletion is not in a state that allows this step (for example the confirmation window has passed).'
          : null;
  return (
    <div className="grid gap-2">
      {note ? (
        <p
          role="note"
          className="rounded-md bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground"
        >
          {note}
        </p>
      ) : null}
      <ErrorState error={error} compact />
    </div>
  );
}

/** Deletion workflow (request → confirm by another platform user → purge; cancel while allowed). */
export function DeletionPanel({ organization }: { organization: Organization }) {
  const state = useApiQuery('OrganizationDeletionController_get_v1', {
    path: { id: organization.id },
  });
  const [dialog, setDialog] = useState<'request' | 'confirm' | 'cancel' | null>(null);
  const request = useApiMutation('OrganizationDeletionController_request_v1', {
    successMessage: 'Deletion requested. Another platform user must confirm it.',
    invalidates: INVALIDATES,
  });
  const confirm = useApiMutation('OrganizationDeletionController_confirm_v1', {
    successMessage: 'Deletion confirmed.',
    invalidates: INVALIDATES,
  });
  const cancel = useApiMutation('OrganizationDeletionController_cancel_v1', {
    successMessage: 'Deletion cancelled; the organization is suspended.',
    invalidates: INVALIDATES,
  });
  const close = () => {
    setDialog(null);
    request.reset();
    confirm.reset();
    cancel.reset();
  };

  if (state.isLoading) return <LoadingState label="Loading the deletion state" rows={4} />;
  if (state.error) return <ErrorState error={state.error} onRetry={() => void state.refetch()} />;
  if (!state.data) return null;
  const d = state.data;
  const rows: [string, string][] = [
    ['State', d.state === 'none' ? 'No deletion requested' : humanize(d.state)],
    ['Requested', d.requestedAt ? formatUtc(d.requestedAt) : 'Not requested'],
    ['Requested by', d.requestedBy ?? 'Nobody'],
    ['Reason', d.reason ?? 'None'],
    [
      'Confirm before',
      d.confirmationDeadline ? formatUtc(d.confirmationDeadline) : 'Not applicable',
    ],
    ['Confirmed', d.confirmedAt ? formatUtc(d.confirmedAt) : 'Not confirmed'],
    ['Confirmed by', d.confirmedBy ?? 'Nobody'],
    ['Data purged after', d.purgeAfter ? formatUtc(d.purgeAfter) : 'Not scheduled'],
  ];
  return (
    <ReportSection
      title="Deletion"
      description="Requesting and confirming need an MFA session; a different platform user must confirm (four-eyes rule)."
    >
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
        {rows.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="break-words">{value}</dd>
          </div>
        ))}
      </dl>
      <div className="flex flex-wrap gap-2">
        {d.state === 'none' ? (
          <Can op="OrganizationDeletionController_request_v1">
            <Button variant="destructive" onClick={() => setDialog('request')}>
              Request deletion
            </Button>
          </Can>
        ) : null}
        {d.state === 'pending_deletion' ? (
          <Can op="OrganizationDeletionController_confirm_v1">
            <Button variant="destructive" onClick={() => setDialog('confirm')}>
              Confirm deletion
            </Button>
          </Can>
        ) : null}
        {d.cancellable ? (
          <Can op="OrganizationDeletionController_cancel_v1">
            <Button variant="outline" onClick={() => setDialog('cancel')}>
              Cancel deletion
            </Button>
          </Can>
        ) : null}
      </div>

      <ReasonConfirmDialog
        open={dialog === 'request'}
        onOpenChange={(open) => (!open ? close() : undefined)}
        title={`Request deletion of ${organization.name}?`}
        description="The organization stops working and is purged after confirmation. A different platform user must confirm within the confirmation window."
        confirmLabel="Request deletion"
        destructive
        minLength={10}
        maxLength={512}
        typedConfirmation={organization.slug}
        onConfirm={async (reason) => {
          const outcome = await request.submit({
            path: { id: organization.id },
            body: { reason, confirmSlug: organization.slug },
          });
          return outcome.ok;
        }}
        error={<DeletionError error={request.error} />}
      />
      <ConfirmDialog
        open={dialog === 'confirm'}
        onOpenChange={(open) => (!open ? close() : undefined)}
        title={`Confirm deletion of ${organization.name}?`}
        description="This cannot be undone after the purge date. You must not be the platform user who requested it."
        confirmLabel="Confirm deletion"
        destructive
        typedConfirmation={organization.slug}
        onConfirm={async () => {
          const outcome = await confirm.submit({
            path: { id: organization.id },
            body: { confirmSlug: organization.slug },
          });
          return outcome.ok;
        }}
        error={<DeletionError error={confirm.error} />}
      />
      <ReasonConfirmDialog
        open={dialog === 'cancel'}
        onOpenChange={(open) => (!open ? close() : undefined)}
        title={`Cancel the deletion of ${organization.name}?`}
        description="The organization returns to the suspended state; reactivate it afterwards if it should work again."
        confirmLabel="Cancel deletion"
        minLength={10}
        maxLength={512}
        onConfirm={async (reason) => {
          const outcome = await cancel.submit({ path: { id: organization.id }, body: { reason } });
          return outcome.ok;
        }}
        error={<DeletionError error={cancel.error} />}
      />
    </ReportSection>
  );
}
