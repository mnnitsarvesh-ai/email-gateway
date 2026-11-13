'use client';

import { useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
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
import { ApiError } from '@/lib/api/errors';
import { verifyMfa } from '@/lib/session/session-client';
import { useCountdown } from './rate-limit';
import { safeNextPath } from './safe-next';

export const totpSchema = z
  .object({
    code: z
      .string()
      .trim()
      .regex(/^\d{6}$/, 'Enter the 6-digit code'),
  })
  .strict();
export const recoverySchema = z
  .object({ recoveryCode: z.string().trim().min(10, 'Enter a recovery code').max(32) })
  .strict();

/** Second sign-in step: TOTP code or a recovery code (`POST /bff/session/mfa`). */
export function MfaForm() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const next = safeNextPath(useSearchParams().get('next'));
  const [mode, setMode] = useState<'code' | 'recovery'>('code');
  const [errors, setErrors] = useState<string[]>([]);
  const [expired, setExpired] = useState(false);
  const [retryIn, setRetryIn] = useCountdown();
  const codeForm = useZodForm(totpSchema, { defaultValues: { code: '' } });
  const recoveryForm = useZodForm(recoverySchema, { defaultValues: { recoveryCode: '' } });

  const handle = async (body: { code: string } | { recoveryCode: string }) => {
    setErrors([]);
    try {
      const result = await verifyMfa(body);
      queryClient.clear();
      if (result.status === 'authenticated' && result.mfaEnrollmentRequired)
        router.replace('/mfa/enroll');
      else router.replace(next);
    } catch (error) {
      codeForm.setValue('code', '');
      if (error instanceof ApiError) {
        if (error.code === 'mfa_challenge_expired') {
          setExpired(true);
          setErrors(['The sign-in challenge expired. Sign in again.']);
        } else if (error.status === 401)
          setErrors(['The code is not valid. Try the current code from your app.']);
        else if (error.status === 429) {
          setRetryIn(error.retryAfterSeconds ?? 60);
          setErrors([`Too many attempts. Try again in ${error.retryAfterSeconds ?? 60} seconds.`]);
        } else setErrors(error.messages);
      } else setErrors(['Verification failed. Try again.']);
    }
  };

  const onCode = codeForm.handleSubmit((values) => handle({ code: values.code }));
  const onRecovery = recoveryForm.handleSubmit((values) =>
    handle({ recoveryCode: values.recoveryCode }),
  );
  const busy = codeForm.formState.isSubmitting || recoveryForm.formState.isSubmitting;

  return (
    <div className="grid gap-4">
      <FormErrorSummary messages={errors} />
      {expired ? (
        <Button asChild>
          <Link href={`/login?next=${encodeURIComponent(next)}`}>Back to sign in</Link>
        </Button>
      ) : mode === 'code' ? (
        <Form {...codeForm}>
          <form onSubmit={(event) => void onCode(event)} className="grid gap-4" noValidate>
            <FormField
              control={codeForm.control}
              name="code"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Authentication code</FormLabel>
                  <FormControl>
                    <Input
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={6}
                      className="font-mono tracking-widest"
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>The 6-digit code from your authenticator app.</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button type="submit" disabled={busy || retryIn > 0}>
              {busy ? 'Verifying …' : retryIn > 0 ? `Try again in ${retryIn} s` : 'Verify'}
            </Button>
          </form>
        </Form>
      ) : (
        <Form {...recoveryForm}>
          <form onSubmit={(event) => void onRecovery(event)} className="grid gap-4" noValidate>
            <FormField
              control={recoveryForm.control}
              name="recoveryCode"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Recovery code</FormLabel>
                  <FormControl>
                    <Input autoComplete="off" spellCheck={false} className="font-mono" {...field} />
                  </FormControl>
                  <FormDescription>Each recovery code works once.</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button type="submit" disabled={busy || retryIn > 0}>
              {busy ? 'Verifying …' : 'Use recovery code'}
            </Button>
          </form>
        </Form>
      )}
      {!expired ? (
        <Button
          variant="link"
          className="h-auto justify-self-start px-0 text-xs"
          onClick={() => setMode((m) => (m === 'code' ? 'recovery' : 'code'))}
        >
          {mode === 'code' ? 'Use a recovery code instead' : 'Use an authentication code instead'}
        </Button>
      ) : null}
    </div>
  );
}
