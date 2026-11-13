'use client';

import Link from 'next/link';
import { useState } from 'react';
import { z } from 'zod';
import { FormErrorSummary, PASSWORD_HINT, PasswordInput, useZodForm } from '@/components/form';
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
import { callOperation } from '@/lib/api/call';
import { ApiError } from '@/lib/api/errors';
import { newPasswordField } from './password-fields';
import { useCountdown } from './rate-limit';
import { useHashToken } from './use-hash-token';

export const resetPasswordSchema = z
  .object({ newPassword: newPasswordField, confirmPassword: z.string() })
  .strict()
  .refine((v) => v.newPassword === v.confirmPassword, {
    path: ['confirmPassword'],
    message: 'The passwords do not match',
  });

export function InvalidLink({
  what,
  retryHref,
  retryLabel,
}: {
  what: string;
  retryHref?: string;
  retryLabel?: string;
}) {
  return (
    <div className="grid gap-4" role="alert">
      <p className="text-sm">This {what} link is invalid, was already used, or has expired.</p>
      {retryHref ? (
        <Button asChild>
          <Link href={retryHref}>{retryLabel}</Link>
        </Button>
      ) : null}
      <Link href="/login" className="text-center text-sm font-medium text-primary hover:underline">
        Back to sign in
      </Link>
    </div>
  );
}

/** `/auth/reset-password#token=…` (the token is read from the hash and cleared at once). */
export function ResetPasswordForm() {
  const token = useHashToken();
  const [done, setDone] = useState(false);
  const [invalid, setInvalid] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [retryIn, setRetryIn] = useCountdown();
  const form = useZodForm(resetPasswordSchema, {
    defaultValues: { newPassword: '', confirmPassword: '' },
  });

  if (token.status === 'reading') return <LoadingState label="Reading the link" rows={2} />;
  if (token.status === 'missing' || invalid) {
    return (
      <InvalidLink
        what="password reset"
        retryHref="/forgot-password"
        retryLabel="Request a new link"
      />
    );
  }
  if (done) {
    return (
      <div className="grid gap-4" role="status">
        <p className="text-sm">
          Your password was changed and every session was signed out. Sign in with the new password.
        </p>
        <Button asChild>
          <Link href="/login">Sign in</Link>
        </Button>
      </div>
    );
  }

  const submit = form.handleSubmit(async (values) => {
    setErrors([]);
    try {
      await callOperation('AuthController_resetPassword_v1', {
        body: { token: token.token, newPassword: values.newPassword },
      });
      setDone(true);
    } catch (error) {
      if (error instanceof ApiError && error.status === 400 && !Array.isArray(error.apiMessage))
        setInvalid(true);
      else if (error instanceof ApiError && error.status === 429) {
        setRetryIn(error.retryAfterSeconds ?? 60);
        setErrors([`Too many attempts. Try again in ${error.retryAfterSeconds ?? 60} seconds.`]);
      } else if (error instanceof ApiError)
        setErrors(error.messages.map((m) => m.replace(/^newPassword: /, '')));
      else setErrors(['The password could not be changed.']);
    }
  });

  return (
    <Form {...form}>
      <form onSubmit={(event) => void submit(event)} className="grid gap-4" noValidate>
        <FormErrorSummary messages={errors} />
        <FormField
          control={form.control}
          name="newPassword"
          render={({ field }) => (
            <FormItem>
              <FormLabel>New password</FormLabel>
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
              <FormLabel>Repeat the new password</FormLabel>
              <FormControl>
                <PasswordInput autoComplete="new-password" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button type="submit" disabled={form.formState.isSubmitting || retryIn > 0}>
          {form.formState.isSubmitting ? 'Saving …' : 'Set new password'}
        </Button>
      </form>
    </Form>
  );
}
