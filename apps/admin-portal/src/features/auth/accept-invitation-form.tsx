'use client';

import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { useState } from 'react';
import { z } from 'zod';
import { DateTime } from '@/components/domain/date-time';
import { FormErrorSummary, PASSWORD_HINT, PasswordInput, useZodForm } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
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
import { callOperation } from '@/lib/api/call';
import { ApiError } from '@/lib/api/errors';
import { newPasswordField } from './password-fields';
import { InvalidLink } from './reset-password-form';
import { useHashToken } from './use-hash-token';

export const acceptInvitationSchema = z
  .object({
    displayName: z.string().trim().min(1, 'Enter your name').max(255),
    password: newPasswordField,
    confirmPassword: z.string(),
  })
  .strict()
  .refine((v) => v.password === v.confirmPassword, {
    path: ['confirmPassword'],
    message: 'The passwords do not match',
  });

export function acceptInvitationBody(
  token: string,
  values: z.output<typeof acceptInvitationSchema>,
) {
  return { token, password: values.password, displayName: values.displayName };
}

/** `/auth/accept-invitation#token=…`: inspect (without consuming), then accept. */
export function AcceptInvitationForm() {
  const token = useHashToken();
  const [done, setDone] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const form = useZodForm(acceptInvitationSchema, {
    defaultValues: { displayName: '', password: '', confirmPassword: '' },
  });
  const tokenValue = token.status === 'present' ? token.token : null;
  const inspect = useQuery({
    queryKey: ['invitation-inspect', tokenValue ? 'present' : 'none'],
    queryFn: () =>
      callOperation('AuthController_inspectInvitation_v1', { body: { token: tokenValue ?? '' } }),
    enabled: Boolean(tokenValue),
    retry: false,
    gcTime: 0,
    staleTime: Infinity,
  });

  if (token.status === 'reading') return <LoadingState label="Reading the invitation" rows={2} />;
  if (token.status === 'missing') return <InvalidLink what="invitation" />;
  if (inspect.isLoading) return <LoadingState label="Checking the invitation" rows={3} />;
  if (inspect.error) {
    if (inspect.error instanceof ApiError && inspect.error.status === 400)
      return <InvalidLink what="invitation" />;
    return <ErrorState error={inspect.error} onRetry={() => void inspect.refetch()} />;
  }
  if (done) {
    return (
      <div className="grid gap-4" role="status">
        <p className="text-sm">
          Your account is ready. Sign in with your email address and the new password.
        </p>
        <Button asChild>
          <Link href="/login">Sign in</Link>
        </Button>
      </div>
    );
  }
  const invitation = inspect.data;
  const submit = form.handleSubmit(async (values) => {
    setErrors([]);
    try {
      await callOperation('AuthController_acceptInvitation_v1', {
        body: acceptInvitationBody(tokenValue ?? '', values),
      });
      setDone(true);
    } catch (error) {
      setErrors(
        error instanceof ApiError ? error.messages : ['The invitation could not be accepted.'],
      );
    }
  });
  return (
    <div className="grid gap-4">
      {invitation ? (
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 rounded-md bg-muted p-3 text-sm">
          <dt className="text-muted-foreground">Organization</dt>
          <dd className="font-medium">{invitation.organizationName}</dd>
          <dt className="text-muted-foreground">Email</dt>
          <dd className="break-all">{invitation.email}</dd>
          <dt className="text-muted-foreground">Expires</dt>
          <dd>
            <DateTime value={invitation.expiresAt} mode="absolute" />
          </dd>
        </dl>
      ) : null}
      <Form {...form}>
        <form onSubmit={(event) => void submit(event)} className="grid gap-4" noValidate>
          <FormErrorSummary messages={errors} />
          <FormField
            control={form.control}
            name="displayName"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Your name</FormLabel>
                <FormControl>
                  <Input autoComplete="name" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="password"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Password</FormLabel>
                <FormControl>
                  <PasswordInput autoComplete="new-password" {...field} />
                </FormControl>
                <FormDescription>{PASSWORD_HINT}</FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="confirmPassword"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Repeat the password</FormLabel>
                <FormControl>
                  <PasswordInput autoComplete="new-password" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <Button type="submit" disabled={form.formState.isSubmitting}>
            {form.formState.isSubmitting ? 'Creating your account …' : 'Accept invitation'}
          </Button>
        </form>
      </Form>
    </div>
  );
}
