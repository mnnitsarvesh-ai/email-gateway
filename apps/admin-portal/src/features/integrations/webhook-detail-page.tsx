'use client';

import { useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { useId, useState } from 'react';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { CopyableId } from '@/components/domain/copyable-id';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { SecretRevealDialog } from '@/components/secret-reveal-dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { type ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import {
  DetailList,
  FormDialog,
  MutationError,
  QueryView,
  Section,
  isUuid,
} from '@/features/domains/kit';
import { REDACTED_REPLAY_EXPLANATION, WebhookStatusBadge, type Webhook } from './model';
import { DeliveryDetail, WebhookDeliveries } from './webhook-deliveries';
import { WebhookForm, webhookUpdateBody } from './webhook-form';

type TestResult = SuccessBody<'WebhooksController_test_v1'>;

/** POST /webhooks/{id}/rotate-secret: `{ overlapHours? (0–168) }`. */
export const rotateSchema = z
  .object({ overlapHours: z.coerce.number().int().min(0).max(168) })
  .strict();

function versionConflict(error: ApiError | null) {
  if (!error) return null;
  return (
    <div className="grid gap-1">
      <MutationError error={error} />
      {error.code === 'webhook_version_conflict' ? (
        <p className="text-xs text-muted-foreground">
          Someone else changed the webhook; the page shows the current version now. Try again.
        </p>
      ) : null}
      {error.code === 'webhook_not_active' ? (
        <p className="text-xs text-muted-foreground">
          Only active webhooks can be tested. Resume it first.
        </p>
      ) : null}
      {error.code === 'webhooks_not_enabled' ? (
        <p className="text-xs text-muted-foreground">Webhooks are not part of your plan.</p>
      ) : null}
    </div>
  );
}

function filtersSummary(webhook: Webhook): string {
  const f = webhook.filters;
  if (!f) return 'None (every event of the listed types)';
  const parts = [
    f.directions?.length ? `directions ${f.directions.join(', ')}` : null,
    f.domainIds?.length
      ? `${f.domainIds.length} domain${f.domainIds.length === 1 ? '' : 's'}`
      : null,
    f.minSeverity ? `severity ≥ ${f.minSeverity}` : null,
    f.verdicts?.length ? `verdicts ${f.verdicts.join(', ')}` : null,
  ].filter(Boolean);
  return parts.length > 0 ? parts.join(' · ') : 'None';
}

function WebhookContent({ webhook }: { webhook: Webhook }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const overlapId = useId();
  const [editing, setEditing] = useState(false);
  const [statusTarget, setStatusTarget] = useState<'active' | 'paused' | 'disabled' | null>(null);
  const [rotating, setRotating] = useState(false);
  const [overlap, setOverlap] = useState('24');
  const [secret, setSecret] = useState<string | null>(null);
  const [redacted, setRedacted] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [showTest, setShowTest] = useState(false);
  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['WebhooksController_get_v1'] });
  };
  const update = useApiMutation('WebhooksController_update_v1', {
    invalidates: ['WebhooksController_get_v1', 'WebhooksController_list_v1'],
    successMessage: 'Webhook saved.',
  });
  const status = useApiMutation('WebhooksController_update_v1', {
    invalidates: ['WebhooksController_get_v1', 'WebhooksController_list_v1'],
    successMessage: 'Status changed.',
  });
  const rotate = useApiMutation('WebhooksController_rotate_v1', {
    invalidates: ['WebhooksController_get_v1'],
    successMessage: null,
  });
  const test = useApiMutation('WebhooksController_test_v1', {
    invalidates: ['WebhookDeliveriesController_list_v1'],
    successMessage: 'Test event queued.',
  });
  const remove = useApiMutation('WebhooksController_delete_v1', {
    invalidates: ['WebhooksController_list_v1'],
    successMessage: `${webhook.name} deleted.`,
  });
  const deleted = webhook.status === 'deleted';

  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title={webhook.name}
        breadcrumbs={[{ label: 'Integrations', href: '/integrations' }, { label: webhook.name }]}
        description={
          <span className="inline-flex flex-wrap items-center gap-2">
            <WebhookStatusBadge status={webhook.status} />
            {webhook.disabledReason ? <span>{humanize(webhook.disabledReason)}</span> : null}
          </span>
        }
        actions={
          deleted ? null : (
            <>
              <Can op="WebhooksController_update_v1">
                <Button variant="outline" onClick={() => setEditing(true)}>
                  Edit settings
                </Button>
                {webhook.status === 'active' ? (
                  <Button variant="outline" onClick={() => setStatusTarget('paused')}>
                    Pause
                  </Button>
                ) : null}
                {webhook.status === 'paused' ? (
                  <Button variant="outline" onClick={() => setStatusTarget('active')}>
                    Resume
                  </Button>
                ) : null}
                {webhook.status === 'disabled' ? (
                  <Button variant="outline" onClick={() => setStatusTarget('active')}>
                    Re-enable
                  </Button>
                ) : null}
              </Can>
              <Can op="WebhooksController_test_v1">
                <Button
                  variant="outline"
                  disabled={test.isPending || webhook.status !== 'active'}
                  onClick={() =>
                    void test
                      .submit({ path: { webhookId: webhook.id } })
                      .then((o) => o.ok && setTestResult(o.data))
                  }
                >
                  Send test event
                </Button>
              </Can>
              <Can op="WebhooksController_rotate_v1">
                <Button variant="outline" onClick={() => setRotating(true)}>
                  Rotate secret
                </Button>
              </Can>
              <Can op="WebhooksController_delete_v1">
                <Button variant="ghost" onClick={() => setDeleting(true)}>
                  Delete
                </Button>
              </Can>
            </>
          )
        }
      />
      {versionConflict(test.error)}
      {testResult ? (
        <div
          className="flex flex-wrap items-center gap-2 rounded-md border p-3 text-sm"
          role="status"
        >
          <span>A webhook.ping test delivery was queued.</span>
          <Button variant="link" size="sm" onClick={() => setShowTest(true)}>
            View the test delivery
          </Button>
        </div>
      ) : null}
      {webhook.status === 'disabled' && webhook.disabledReason === 'sustained_failure' ? (
        <p
          className="rounded-md bg-tone-danger px-3 py-2 text-sm text-tone-danger-foreground"
          role="alert"
        >
          The gateway disabled this webhook after deliveries kept failing. Fix the receiver,
          re-enable the webhook and replay what was missed.
        </p>
      ) : null}
      <div className="grid min-w-0 gap-6 lg:grid-cols-2 [&>*]:min-w-0">
        <Section title="Settings">
          <DetailList
            items={[
              {
                label: 'Endpoint URL',
                value: (
                  <UntrustedText
                    value={webhook.url}
                    mono
                    copy
                    copyLabel="Copy the endpoint URL"
                    maxLength={200}
                  />
                ),
              },
              { label: 'Description', value: webhook.description ?? 'None' },
              {
                label: 'Event types',
                value: <span className="font-mono text-xs">{webhook.eventTypes.join(', ')}</span>,
              },
              { label: 'Filters', value: filtersSummary(webhook) },
              {
                label: 'Parallel deliveries',
                value: webhook.maxConcurrency ? String(webhook.maxConcurrency) : 'Platform default',
              },
              { label: 'Webhook ID', value: <CopyableId value={webhook.id} label="webhook ID" /> },
              { label: 'Created', value: <DateTime value={webhook.createdAt} mode="absolute" /> },
            ]}
          />
        </Section>
        <Section title="Health and secret">
          <DetailList
            items={[
              { label: 'Last success', value: <DateTime value={webhook.lastSuccessAt} /> },
              { label: 'Last failure', value: <DateTime value={webhook.lastFailureAt} /> },
              { label: 'Failures in a row', value: String(webhook.consecutiveFailures) },
              {
                label: 'Failing since',
                value: <DateTime value={webhook.failingSince} emptyLabel="Not failing" />,
              },
              { label: 'Secret version', value: String(webhook.secretVersion) },
              { label: 'Secret rotated', value: <DateTime value={webhook.secretRotatedAt} /> },
              {
                label: 'Previous secret valid until',
                value: (
                  <DateTime
                    value={webhook.previousSecretExpiresAt}
                    mode="absolute"
                    emptyLabel="No previous secret"
                  />
                ),
              },
            ]}
          />
        </Section>
      </div>
      <Section
        title="Deliveries"
        description="Newest events first. Response snippets are sanitized text from your receiver."
      >
        <WebhookDeliveries webhook={webhook} />
      </Section>

      <FormDialog
        open={editing}
        onOpenChange={(open) => {
          setEditing(open);
          if (!open) update.reset();
        }}
        title="Edit webhook"
        wide
      >
        <WebhookForm
          webhook={webhook}
          submitLabel="Save webhook"
          pending={update.isPending}
          onSubmit={async (values) => {
            const outcome = await update.submit({
              path: { webhookId: webhook.id },
              body: webhookUpdateBody(webhook, values),
            });
            if (outcome.ok) {
              setEditing(false);
              return null;
            }
            if (outcome.error.code === 'webhook_version_conflict') await refresh();
            return outcome.error;
          }}
        />
      </FormDialog>
      <ConfirmDialog
        open={statusTarget !== null}
        onOpenChange={(open) => {
          if (!open) {
            setStatusTarget(null);
            status.reset();
          }
        }}
        title={statusTarget === 'paused' ? `Pause ${webhook.name}?` : `Activate ${webhook.name}?`}
        description={
          statusTarget === 'paused'
            ? 'No new deliveries are created while paused; pending ones wait and resume when you activate the webhook. Events during the pause are not recorded.'
            : 'Pending deliveries become due immediately. Events that occurred while the webhook was not active are not back-filled.'
        }
        confirmLabel={statusTarget === 'paused' ? 'Pause' : 'Activate'}
        error={versionConflict(status.error)}
        onConfirm={async () => {
          if (!statusTarget) return false;
          const outcome = await status.submit({
            path: { webhookId: webhook.id },
            body: { expectedRowVersion: webhook.rowVersion, status: statusTarget },
          });
          if (!outcome.ok && outcome.error.code === 'webhook_version_conflict') await refresh();
          return outcome.ok;
        }}
      />
      <ConfirmDialog
        open={rotating}
        onOpenChange={(open) => {
          setRotating(open);
          if (!open) rotate.reset();
        }}
        title="Rotate the signing secret?"
        confirmLabel="Rotate secret"
        description={
          <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
            <p>
              A new secret is generated and shown once. During the overlap every delivery carries
              two signatures (new secret first), so you can update your receiver at your own pace.
            </p>
            <div className="grid gap-2">
              <Label htmlFor={overlapId}>Overlap in hours (0–168)</Label>
              <Input
                id={overlapId}
                inputMode="numeric"
                className="w-28"
                value={overlap}
                onChange={(e) => setOverlap(e.target.value)}
              />
            </div>
          </div>
        }
        error={versionConflict(rotate.error)}
        onConfirm={async () => {
          const parsed = rotateSchema.safeParse({ overlapHours: overlap });
          if (!parsed.success) return false;
          const outcome = await rotate.submit({
            path: { webhookId: webhook.id },
            body: parsed.data,
          });
          if (outcome.ok) {
            // Secret once (P12): keep it only in the dialog state, drop the mutation's copy.
            if (outcome.data.secret) setSecret(outcome.data.secret);
            else setRedacted(true);
            rotate.reset();
          }
          return outcome.ok;
        }}
      />
      <SecretRevealDialog
        open={secret !== null}
        title="New signing secret"
        description="Deploy it to your receiver. It is shown only now."
        secrets={secret ? [{ label: 'Signing secret', value: secret }] : []}
        onClose={() => setSecret(null)}
      />
      <FormDialog
        open={redacted}
        onOpenChange={setRedacted}
        title="The rotation was already applied"
      >
        <p className="text-sm">{REDACTED_REPLAY_EXPLANATION}</p>
        <Button
          className="justify-self-start"
          onClick={() => {
            setRedacted(false);
            setRotating(true);
          }}
        >
          Rotate again
        </Button>
      </FormDialog>
      <FormDialog open={showTest} onOpenChange={setShowTest} title="Test delivery" wide>
        {testResult ? (
          <DeliveryDetail webhookId={webhook.id} deliveryId={testResult.deliveryId} />
        ) : null}
      </FormDialog>
      <ConfirmDialog
        open={deleting}
        onOpenChange={(open) => {
          setDeleting(open);
          if (!open) remove.reset();
        }}
        title={`Delete ${webhook.name}?`}
        description="Pending deliveries are cancelled and no further events are sent. The delivery history stays visible for its retention period."
        confirmLabel="Delete webhook"
        destructive
        typedConfirmation={webhook.name}
        error={<MutationError error={remove.error} />}
        onConfirm={async () => {
          const outcome = await remove.submit({ path: { webhookId: webhook.id } });
          if (outcome.ok) router.push('/integrations');
          return outcome.ok;
        }}
      />
    </div>
  );
}

/** `/webhooks/[webhookId]` (linked from webhook_disabled alert e-mails); foreign ids are a 404. */
export function WebhookDetailPage({ webhookId }: { webhookId: string }) {
  return (
    <RouteGate gate={['WebhooksController_get_v1']}>
      <WebhookLoader webhookId={webhookId} />
    </RouteGate>
  );
}

function WebhookLoader({ webhookId }: { webhookId: string }) {
  const valid = isUuid(webhookId);
  const webhook = useApiQuery(
    'WebhooksController_get_v1',
    { path: { webhookId } },
    { enabled: valid, retry: false },
  );
  if (!valid) return <NotFoundView />;
  return (
    <QueryView query={webhook} label="webhook">
      {(data) => <WebhookContent webhook={data} />}
    </QueryView>
  );
}
