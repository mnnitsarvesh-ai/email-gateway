'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { toast } from 'sonner';
import { FormErrorSummary, useZodForm } from '@/components/form';
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
import { Textarea } from '@/components/ui/textarea';
import { overrideFormSchema } from '@/features/shell/tenant-switcher';
import { ApiError } from '@/lib/api/errors';
import type { SuccessBody } from '@/lib/api/types';
import { useStartOverride } from '@/lib/auth/me';

type Organization = SuccessBody<'OrganizationsController_get_v1'>;

/**
 * "Act in this organization" (platform:tenant_override): the audited override of WP2
 * (`useStartOverride` → `POST /bff/session/override`); needs an MFA session.
 */
export function ActInOrganizationDialog({
  open,
  onOpenChange,
  organization,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  organization: Organization;
}) {
  const router = useRouter();
  const startOverride = useStartOverride();
  const [messages, setMessages] = useState<string[]>([]);
  const [requestId, setRequestId] = useState<string | null>(null);
  const form = useZodForm(overrideFormSchema, {
    defaultValues: { organizationId: organization.id, reason: '', durationMinutes: 30 },
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    setRequestId(null);
    try {
      const started = await startOverride({ ...values, organizationId: organization.id });
      toast.success(`Now acting in ${started.organizationName}.`);
      onOpenChange(false);
      router.push('/dashboard');
    } catch (error) {
      if (error instanceof ApiError) {
        setRequestId(error.requestId);
        setMessages(
          error.status === 403 && error.code === 'mfa_required'
            ? [
                'Starting an override needs an MFA session. Sign out and sign in again with your authenticator code.',
              ]
            : error.messages,
        );
      } else {
        setMessages(['The override could not be started.']);
      }
    }
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Act in {organization.name}</DialogTitle>
          <DialogDescription>
            Starts an audited platform override. Every request is recorded with your reason; your
            platform permissions are removed while it is active.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form
            onSubmit={(event) => void submit(event)}
            className="grid gap-4"
            noValidate
            aria-label="Start override"
          >
            <FormErrorSummary messages={messages} requestId={requestId} />
            <FormField
              control={form.control}
              name="reason"
              render={({ field }) => (
                <FormItem>
                  <FormLabel required>Reason</FormLabel>
                  <FormControl>
                    <Textarea {...field} rows={3} maxLength={500} />
                  </FormControl>
                  <FormDescription>10 to 500 characters, e.g. a ticket reference.</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="durationMinutes"
              render={({ field }) => (
                <FormItem>
                  <FormLabel required>Duration (minutes)</FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min={5}
                      max={240}
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
                  <FormDescription>
                    5 minutes up to the platform maximum (PLATFORM_OVERRIDE_MAX_MINUTES).
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>
                {form.formState.isSubmitting ? 'Starting …' : 'Start override'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
