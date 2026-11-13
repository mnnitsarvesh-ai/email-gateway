'use client';

import { useState } from 'react';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
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
import { useApiMutation } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { usePermissions } from '@/lib/auth/me';
import { profileBody, profileSchema } from './schemas';

type Organization = SuccessBody<'OrganizationsController_get_v1'>;

/** `PUT /organizations/{id}`: name; plan code only for `platform:organizations` holders. */
export function ProfileForm({
  organization,
  allowPlan,
}: {
  organization: Organization;
  allowPlan: boolean;
}) {
  const permissions = usePermissions();
  const includePlan = allowPlan && permissions.has('platform:organizations');
  const [messages, setMessages] = useState<string[]>([]);
  const form = useZodForm(profileSchema, {
    defaultValues: { name: organization.name, planCode: organization.plan.code },
  });
  const mutation = useApiMutation('OrganizationsController_update_v1', {
    successMessage: 'Organization profile saved.',
    invalidates: ['OrganizationsController_get_v1', 'OrganizationsController_list_v1'],
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await mutation.submit({
      path: { id: organization.id },
      body: profileBody(values, { includePlan, currentPlan: organization.plan.code }),
    });
    if (!outcome.ok) setMessages(applyApiErrors(form, outcome.error));
  });
  const locked = organization.status === 'pending_deletion' || organization.status === 'deleted';
  return (
    <Form {...form}>
      <form
        onSubmit={(event) => void submit(event)}
        className="grid max-w-md gap-4"
        noValidate
        aria-label="Edit organization profile"
      >
        <FormErrorSummary messages={messages} requestId={mutation.error?.requestId} />
        {locked ? (
          <p className="text-sm text-muted-foreground">
            The profile cannot be changed while the organization is pending deletion or deleted.
          </p>
        ) : null}
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel required>Name</FormLabel>
              <FormControl>
                <Input {...field} disabled={locked} autoComplete="organization" />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        {includePlan ? (
          <FormField
            control={form.control}
            name="planCode"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Plan code</FormLabel>
                <FormControl>
                  <Input {...field} disabled={locked} className="font-mono" autoComplete="off" />
                </FormControl>
                <FormDescription>
                  Changing the plan rewrites every plan-sourced limit and feature; overrides are
                  kept.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        ) : null}
        <Button
          type="submit"
          className="justify-self-start"
          disabled={locked || mutation.isPending || mutation.retryAfterSeconds > 0}
        >
          {mutation.isPending ? 'Saving …' : 'Save profile'}
        </Button>
      </form>
    </Form>
  );
}
