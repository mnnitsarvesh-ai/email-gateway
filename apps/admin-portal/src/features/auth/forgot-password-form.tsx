'use client';

import Link from 'next/link';
import { useState } from 'react';
import { z } from 'zod';
import { FormErrorSummary, useZodForm } from '@/components/form';
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
import { useCountdown } from './rate-limit';

export const forgotPasswordSchema = z
  .object({
    email: z
      .string()
      .trim()
      .min(1, 'Enter your email address')
      .max(320)
      .email('Enter a valid email address'),
    organization: z
      .string()
      .trim()
      .regex(/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)?$/, 'Use the organization slug')
      .optional(),
  })
  .strict();

export function forgotPasswordBody(values: z.output<typeof forgotPasswordSchema>) {
  return {
    email: values.email,
    ...(values.organization ? { organization: values.organization } : {}),
  };
}

/** Always the same confirmation: the answer never reveals whether an account exists. */
export function ForgotPasswordForm() {
  const [sent, setSent] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [retryIn, setRetryIn] = useCountdown();
  const form = useZodForm(forgotPasswordSchema, { defaultValues: { email: '', organization: '' } });

  const submit = form.handleSubmit(async (values) => {
    setErrors([]);
    try {
      await callOperation('AuthController_forgotPassword_v1', { body: forgotPasswordBody(values) });
      setSent(true);
    } catch (error) {
      if (error instanceof ApiError && error.status === 429) {
        setRetryIn(error.retryAfterSeconds ?? 60);
        setErrors([`Too many requests. Try again in ${error.retryAfterSeconds ?? 60} seconds.`]);
      } else if (error instanceof ApiError && error.status === 400) {
        setErrors(error.messages);
      } else {
        setSent(true);
      }
    }
  });

  if (sent) {
    return (
      <div className="grid gap-4" role="status">
        <p className="text-sm">
          If an account with a verified email address matches, we have sent a link to reset the
          password. The link is valid for 30 minutes. Check your inbox and spam folder.
        </p>
        <Button asChild variant="outline">
          <Link href="/login">Back to sign in</Link>
        </Button>
      </div>
    );
  }
  return (
    <Form {...form}>
      <form onSubmit={(event) => void submit(event)} className="grid gap-4" noValidate>
        <FormErrorSummary messages={errors} />
        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Email address</FormLabel>
              <FormControl>
                <Input type="email" autoComplete="email" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="organization"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Organization (optional)</FormLabel>
              <FormControl>
                <Input spellCheck={false} {...field} value={field.value ?? ''} />
              </FormControl>
              <FormDescription>
                The organization slug, if your address belongs to several organizations.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button type="submit" disabled={form.formState.isSubmitting || retryIn > 0}>
          {form.formState.isSubmitting
            ? 'Sending …'
            : retryIn > 0
              ? `Try again in ${retryIn} s`
              : 'Send reset link'}
        </Button>
        <Link
          href="/login"
          className="text-center text-sm font-medium text-primary hover:underline"
        >
          Back to sign in
        </Link>
      </form>
    </Form>
  );
}
