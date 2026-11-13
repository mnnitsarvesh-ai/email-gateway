'use client';

import { useState } from 'react';
import { z } from 'zod';
import { FormErrorSummary, PASSWORD_HINT, PasswordInput, useZodForm } from '@/components/form';
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
import { useApiMutation } from '@/lib/api/hooks';
import { newPasswordField } from '@/features/auth/password-fields';

export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1, 'Enter your current password').max(1024),
    newPassword: newPasswordField,
    confirmPassword: z.string(),
  })
  .strict()
  .refine((v) => v.newPassword === v.confirmPassword, {
    path: ['confirmPassword'],
    message: 'The passwords do not match',
  })
  .refine((v) => v.newPassword !== v.currentPassword, {
    path: ['newPassword'],
    message: 'Choose a different password',
  });

export function changePasswordBody(values: z.output<typeof changePasswordSchema>) {
  return { currentPassword: values.currentPassword, newPassword: values.newPassword };
}

/** `POST /auth/password/change`; other sessions are signed out by the api. */
export function ChangePasswordForm() {
  const mutation = useApiMutation('AuthController_changePassword_v1', {
    successMessage: 'Password changed. Your other sessions were signed out.',
  });
  const [errors, setErrors] = useState<string[]>([]);
  const form = useZodForm(changePasswordSchema, {
    defaultValues: { currentPassword: '', newPassword: '', confirmPassword: '' },
  });
  const submit = form.handleSubmit(async (values) => {
    setErrors([]);
    const outcome = await mutation.submit({ body: changePasswordBody(values) });
    if (outcome.ok) form.reset();
  });
  const error = mutation.error;
  const messages =
    errors.length > 0
      ? errors
      : error
        ? error.status === 403
          ? ['The current password is not correct.']
          : error.status === 400
            ? error.messages.map((m) => m.replace(/^newPassword: /, ''))
            : error.status === 429
              ? [`Too many attempts. Try again in ${mutation.retryAfterSeconds} s.`]
              : error.messages
        : [];
  return (
    <Form {...form}>
      <form
        onSubmit={(event) => void submit(event)}
        className="grid max-w-md gap-4"
        noValidate
        aria-label="Change password"
      >
        <FormErrorSummary messages={messages} requestId={error?.requestId} />
        <FormField
          control={form.control}
          name="currentPassword"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Current password</FormLabel>
              <FormControl>
                <PasswordInput autoComplete="current-password" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
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
        <Button
          type="submit"
          className="justify-self-start"
          disabled={mutation.isPending || mutation.retryAfterSeconds > 0}
        >
          {mutation.isPending ? 'Changing …' : 'Change password'}
        </Button>
      </form>
    </Form>
  );
}
