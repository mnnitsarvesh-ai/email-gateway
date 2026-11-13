'use client';

import { useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useState } from 'react';
import { z } from 'zod';
import { FormErrorSummary, PasswordInput, useZodForm } from '@/components/form';
import { Button } from '@/components/ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
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
import { ApiError } from '@/lib/api/errors';
import { login } from '@/lib/session/session-client';
import { useCountdown } from './rate-limit';
import { safeNextPath } from './safe-next';

/** Mirrors `POST /auth/login` (strict; `organization` is the optional slug). */
export const loginSchema = z
  .object({
    email: z
      .string()
      .trim()
      .min(1, 'Enter your email address')
      .max(320)
      .email('Enter a valid email address'),
    password: z.string().min(1, 'Enter your password').max(1024),
    organization: z
      .string()
      .trim()
      .max(63)
      .regex(
        /^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)?$/,
        'Use the organization slug (lower-case letters, digits, hyphens)',
      )
      .optional(),
  })
  .strict();

export type LoginValues = z.output<typeof loginSchema>;

/** Request body for the BFF: drops an empty organization (the api rejects an empty slug). */
export function loginBody(values: LoginValues): {
  email: string;
  password: string;
  organization?: string;
} {
  return {
    email: values.email,
    password: values.password,
    ...(values.organization ? { organization: values.organization } : {}),
  };
}

const REASONS: Record<string, string> = {
  expired: 'Your session ended. Sign in again to continue.',
  mfa: 'This action needs a session signed in with MFA. Sign in again with your authenticator code.',
};

export function LoginForm() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const params = useSearchParams();
  const next = safeNextPath(params.get('next'));
  const reason = params.get('reason');
  const [errors, setErrors] = useState<string[]>([]);
  const [requestId, setRequestId] = useState<string | null>(null);
  const [retryIn, setRetryIn] = useCountdown();
  const form = useZodForm(loginSchema, {
    defaultValues: { email: '', password: '', organization: '' },
  });

  const submit = form.handleSubmit(async (values) => {
    setErrors([]);
    setRequestId(null);
    try {
      const result = await login(loginBody(values));
      queryClient.clear();
      if (result.status === 'mfa_required') {
        router.push(`/login/mfa?next=${encodeURIComponent(next)}`);
      } else if (result.mfaEnrollmentRequired) {
        router.replace(`/mfa/enroll?next=${encodeURIComponent(next)}`);
      } else {
        router.replace(next);
      }
    } catch (error) {
      form.setValue('password', '');
      if (error instanceof ApiError) {
        setRequestId(error.requestId);
        if (error.status === 401) setErrors(['The email address or password is incorrect.']);
        else if (error.status === 429) {
          setRetryIn(error.retryAfterSeconds ?? 60);
          setErrors([
            error.retryAfterSeconds
              ? `Too many sign-in attempts. Try again in ${error.retryAfterSeconds} seconds.`
              : 'Too many sign-in attempts from this network. Try again later.',
          ]);
        } else setErrors(error.messages);
      } else {
        setErrors(['Sign-in failed. Try again.']);
      }
    }
  });

  const submitting = form.formState.isSubmitting;
  return (
    <Form {...form}>
      <form onSubmit={(event) => void submit(event)} className="grid gap-4" noValidate>
        {reason && REASONS[reason] ? (
          <p
            role="status"
            className="rounded-md bg-tone-info px-3 py-2 text-sm text-tone-info-foreground"
          >
            {REASONS[reason]}
          </p>
        ) : null}
        <FormErrorSummary messages={errors} requestId={requestId} />
        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Email address</FormLabel>
              <FormControl>
                <Input type="email" autoComplete="username" {...field} />
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
              <div className="flex items-center justify-between">
                <FormLabel>Password</FormLabel>
                <Link
                  href="/forgot-password"
                  className="text-xs font-medium text-primary hover:underline"
                >
                  Forgot password?
                </Link>
              </div>
              <FormControl>
                <PasswordInput autoComplete="current-password" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <Collapsible>
          <CollapsibleTrigger asChild>
            <Button variant="link" className="h-auto px-0 text-xs">
              Sign in to a specific organization
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="pt-2">
            <FormField
              control={form.control}
              name="organization"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Organization (optional)</FormLabel>
                  <FormControl>
                    <Input
                      autoComplete="organization"
                      spellCheck={false}
                      {...field}
                      value={field.value ?? ''}
                    />
                  </FormControl>
                  <FormDescription>
                    Only needed when your email address belongs to several organizations.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          </CollapsibleContent>
        </Collapsible>
        <Button type="submit" disabled={submitting || retryIn > 0}>
          {submitting ? 'Signing in …' : retryIn > 0 ? `Try again in ${retryIn} s` : 'Sign in'}
        </Button>
      </form>
    </Form>
  );
}
