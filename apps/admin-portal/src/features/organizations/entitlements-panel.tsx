'use client';

import { useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
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
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { PathParams } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import {
  FeaturesTable,
  LimitsTable,
  type FeatureRow,
  type LimitRow,
} from '@/features/billing/entitlements';
import { ReportSection } from '@/features/reports/report-state';
import { limitOverrideSchema } from './schemas';

/** Keys come from the api's own lists; the path enums mirror them. */
type FeatureKey =
  PathParams<'OrganizationConfigurationController_overrideFeature_v1'>['featureKey'];
type LimitKey = PathParams<'OrganizationConfigurationController_overrideLimit_v1'>['limitKey'];

const INVALIDATES = [
  'OrganizationConfigurationController_listFeatures_v1',
  'OrganizationConfigurationController_listLimits_v1',
  'OrganizationsController_getUsage_v1',
] as const;

/** Features and limits with their source; platform users override or reset them. */
export function EntitlementsPanel({ organizationId }: { organizationId: string }) {
  const features = useApiQuery('OrganizationConfigurationController_listFeatures_v1', {
    path: { id: organizationId },
  });
  const limits = useApiQuery('OrganizationConfigurationController_listLimits_v1', {
    path: { id: organizationId },
  });
  const canOverrideFeature = useCan('OrganizationConfigurationController_overrideFeature_v1');
  const canResetFeature = useCan('OrganizationConfigurationController_resetFeature_v1');
  const canOverrideLimit = useCan('OrganizationConfigurationController_overrideLimit_v1');
  const canResetLimit = useCan('OrganizationConfigurationController_resetLimit_v1');
  const [resetFeature, setResetFeature] = useState<FeatureRow | null>(null);
  const [resetLimit, setResetLimit] = useState<LimitRow | null>(null);
  const [editLimit, setEditLimit] = useState<LimitRow | null>(null);

  const toggle = useApiMutation('OrganizationConfigurationController_overrideFeature_v1', {
    successMessage: 'Feature override saved.',
    invalidates: INVALIDATES,
  });
  const resetFeatureMutation = useApiMutation(
    'OrganizationConfigurationController_resetFeature_v1',
    {
      successMessage: 'Feature reset to the plan value.',
      invalidates: INVALIDATES,
    },
  );
  const resetLimitMutation = useApiMutation('OrganizationConfigurationController_resetLimit_v1', {
    successMessage: 'Limit reset to the plan value.',
    invalidates: INVALIDATES,
  });

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <ReportSection title="Features" description="Overrides are kept across plan changes.">
        {toggle.error ? <ErrorState error={toggle.error} compact /> : null}
        {features.isLoading ? (
          <LoadingState label="Loading features" rows={5} />
        ) : features.error ? (
          <ErrorState error={features.error} onRetry={() => void features.refetch()} />
        ) : features.data ? (
          <FeaturesTable
            caption="Features of this organization"
            features={features.data.data}
            actions={
              canOverrideFeature || canResetFeature
                ? (feature) => (
                    <span className="inline-flex flex-wrap justify-end gap-1">
                      {canOverrideFeature ? (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={toggle.isPending}
                          onClick={() =>
                            void toggle.submit({
                              path: { id: organizationId, featureKey: feature.key as FeatureKey },
                              body: { enabled: !feature.enabled },
                            })
                          }
                          aria-label={`${feature.enabled ? 'Disable' : 'Enable'} ${humanize(feature.key)} (override)`}
                        >
                          {feature.enabled ? 'Disable' : 'Enable'}
                        </Button>
                      ) : null}
                      {canResetFeature && feature.source === 'override' ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setResetFeature(feature)}
                          aria-label={`Reset ${humanize(feature.key)} to the plan value`}
                        >
                          Reset
                        </Button>
                      ) : null}
                    </span>
                  )
                : undefined
            }
          />
        ) : null}
      </ReportSection>
      <ReportSection title="Limits">
        {limits.isLoading ? (
          <LoadingState label="Loading limits" rows={5} />
        ) : limits.error ? (
          <ErrorState error={limits.error} onRetry={() => void limits.refetch()} />
        ) : limits.data ? (
          <LimitsTable
            caption="Limits of this organization"
            limits={limits.data.data}
            actions={
              canOverrideLimit || canResetLimit
                ? (limit) => (
                    <span className="inline-flex flex-wrap justify-end gap-1">
                      {canOverrideLimit ? (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setEditLimit(limit)}
                          aria-label={`Override ${humanize(limit.key)}`}
                        >
                          Override
                        </Button>
                      ) : null}
                      {canResetLimit && limit.source === 'override' ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setResetLimit(limit)}
                          aria-label={`Reset ${humanize(limit.key)} to the plan value`}
                        >
                          Reset
                        </Button>
                      ) : null}
                    </span>
                  )
                : undefined
            }
          />
        ) : null}
      </ReportSection>

      <ConfirmDialog
        open={resetFeature !== null}
        onOpenChange={(open) => {
          if (!open) {
            setResetFeature(null);
            resetFeatureMutation.reset();
          }
        }}
        title={`Reset ${resetFeature ? humanize(resetFeature.key) : ''}?`}
        description="The feature goes back to the value of the organization's plan."
        confirmLabel="Reset to plan"
        destructive
        onConfirm={async () => {
          if (!resetFeature) return false;
          const outcome = await resetFeatureMutation.submit({
            path: { id: organizationId, featureKey: resetFeature.key as FeatureKey },
          });
          return outcome.ok;
        }}
        error={
          resetFeatureMutation.error ? (
            <ErrorState error={resetFeatureMutation.error} compact />
          ) : null
        }
      />
      <ConfirmDialog
        open={resetLimit !== null}
        onOpenChange={(open) => {
          if (!open) {
            setResetLimit(null);
            resetLimitMutation.reset();
          }
        }}
        title={`Reset ${resetLimit ? humanize(resetLimit.key) : ''}?`}
        description="The limit goes back to the value of the organization's plan."
        confirmLabel="Reset to plan"
        destructive
        onConfirm={async () => {
          if (!resetLimit) return false;
          const outcome = await resetLimitMutation.submit({
            path: { id: organizationId, limitKey: resetLimit.key as LimitKey },
          });
          return outcome.ok;
        }}
        error={
          resetLimitMutation.error ? <ErrorState error={resetLimitMutation.error} compact /> : null
        }
      />
      {editLimit ? (
        <LimitOverrideDialog
          organizationId={organizationId}
          limit={editLimit}
          onClose={() => setEditLimit(null)}
        />
      ) : null}
    </div>
  );
}

function LimitOverrideDialog({
  organizationId,
  limit,
  onClose,
}: {
  organizationId: string;
  limit: LimitRow;
  onClose: () => void;
}) {
  const [messages, setMessages] = useState<string[]>([]);
  const form = useZodForm(limitOverrideSchema, { defaultValues: { value: limit.value } });
  const mutation = useApiMutation('OrganizationConfigurationController_overrideLimit_v1', {
    successMessage: 'Limit override saved.',
    invalidates: INVALIDATES,
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await mutation.submit({
      path: { id: organizationId, limitKey: limit.key as LimitKey },
      body: { value: values.value },
    });
    if (outcome.ok) onClose();
    else setMessages(applyApiErrors(form, outcome.error));
  });
  return (
    <Dialog open onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Override {humanize(limit.key)}</DialogTitle>
          <DialogDescription>
            The override replaces the plan value ({limit.value}) until it is reset.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={(event) => void submit(event)} className="grid gap-4" noValidate>
            <FormErrorSummary messages={messages} requestId={mutation.error?.requestId} />
            <FormField
              control={form.control}
              name="value"
              render={({ field }) => (
                <FormItem>
                  <FormLabel required>Value</FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min={0}
                      inputMode="numeric"
                      name={field.name}
                      ref={field.ref}
                      onBlur={field.onBlur}
                      value={
                        typeof field.value === 'number' || typeof field.value === 'string'
                          ? String(field.value)
                          : ''
                      }
                      onChange={(event) => field.onChange(event.target.value)}
                    />
                  </FormControl>
                  <FormDescription>A non-negative whole number.</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <DialogFooter>
              <Button variant="outline" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={mutation.isPending || mutation.retryAfterSeconds > 0}>
                {mutation.isPending ? 'Saving …' : 'Save override'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
