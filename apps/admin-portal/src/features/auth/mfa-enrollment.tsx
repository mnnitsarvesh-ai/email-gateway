'use client';

import { useQueryClient } from '@tanstack/react-query';
import { DownloadIcon } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { CopyButton } from '@/components/copy-button';
import { FormErrorSummary, useZodForm } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
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
import { Label } from '@/components/ui/label';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation } from '@/lib/api/hooks';
import { ME_QUERY_KEY, SESSION_QUERY_KEY } from '@/lib/auth/me';
import { refreshSession } from '@/lib/session/refresh';
import { QrCode } from './qr-code';

export const enableMfaSchema = z
  .object({
    code: z
      .string()
      .trim()
      .regex(/^\d{6}$/, 'Enter the 6-digit code'),
  })
  .strict();

/** `ABCD EFGH …` for manual entry. */
export function groupSecret(secret: string): string {
  return (
    secret
      .replace(/\s+/g, '')
      .match(/.{1,4}/g)
      ?.join(' ') ?? secret
  );
}

export function recoveryCodesText(codes: readonly string[], account: string): string {
  return [
    'Email Security Gateway recovery codes',
    `Account: ${account}`,
    `Generated: ${new Date().toISOString()}`,
    '',
    'Each code works once. Keep them somewhere safe.',
    '',
    ...codes,
    '',
  ].join('\n');
}

/** Generates the text file in the browser (no server round trip, nothing stored). */
export function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function RecoveryCodes({
  codes,
  account,
  onDone,
  doneLabel = 'Continue',
}: {
  codes: readonly string[];
  account: string;
  onDone: () => void;
  doneLabel?: string;
}) {
  const [stored, setStored] = useState(false);
  const text = recoveryCodesText(codes, account);
  return (
    <div className="grid gap-4">
      <p className="text-sm">
        Save these recovery codes now. Each one signs you in once if you lose your authenticator.
        They are shown only this time.
      </p>
      <ul
        className="grid grid-cols-2 gap-2 rounded-md border bg-muted p-3 font-mono text-sm"
        aria-label="Recovery codes"
      >
        {codes.map((code) => (
          <li key={code} data-secret="">
            {code}
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <CopyButton value={codes.join('\n')} label="Copy recovery codes" size="sm" />
        <Button
          variant="outline"
          size="sm"
          onClick={() => downloadText('email-gateway-recovery-codes.txt', text)}
        >
          <DownloadIcon aria-hidden /> Download as text
        </Button>
      </div>
      <div className="flex items-start gap-2">
        <Checkbox
          id="codes-stored"
          checked={stored}
          onCheckedChange={(v) => setStored(v === true)}
        />
        <Label htmlFor="codes-stored" className="leading-snug font-normal">
          I have stored my recovery codes in a safe place.
        </Label>
      </div>
      <Button onClick={onDone} disabled={!stored}>
        {doneLabel}
      </Button>
    </div>
  );
}

/**
 * TOTP enrollment (design §3.1): setup (secret as grouped text + local QR), enable with a code,
 * recovery codes once, then a forced refresh so the session carries an `otp` token (P3).
 */
export function MfaEnrollment({
  account,
  onComplete,
}: {
  account: string;
  onComplete: () => void;
}) {
  const queryClient = useQueryClient();
  const setup = useApiMutation('MfaController_setup_v1', { successMessage: null });
  const enable = useApiMutation('MfaController_enable_v1', { successMessage: null });
  const [errors, setErrors] = useState<string[]>([]);
  const [finishing, setFinishing] = useState(false);
  const started = useRef(false);
  const form = useZodForm(enableMfaSchema, { defaultValues: { code: '' } });

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void setup.submit({});
  }, [setup]);

  const submit = form.handleSubmit(async (values) => {
    setErrors([]);
    const outcome = await enable.submit({ body: values });
    if (!outcome.ok) {
      setErrors(
        outcome.error.status === 403
          ? ['The code is not valid. Check the time on your device and try the current code.']
          : outcome.error.messages,
      );
    }
  });

  const finish = async () => {
    setFinishing(true);
    try {
      // The refreshed session no longer requires enrollment: write it into the cache at once.
      // Invalidating alone leaves the inactive session query's old `mfaEnrollmentRequired: true`
      // in place until a background refetch, and the shell would redirect back to /mfa/enroll
      // (found by the step 7.1 e2e suite).
      const state = await refreshSession({ force: true });
      queryClient.setQueryData(SESSION_QUERY_KEY, state);
    } catch {
      // A failed refresh surfaces as a session-expired event; the enrollment itself succeeded.
      queryClient.removeQueries({ queryKey: SESSION_QUERY_KEY });
    }
    setup.reset();
    enable.reset();
    await queryClient.refetchQueries({ queryKey: ME_QUERY_KEY, type: 'all' });
    setFinishing(false);
    onComplete();
  };

  if (enable.data) {
    return (
      <RecoveryCodes
        codes={enable.data.recoveryCodes}
        account={account}
        onDone={() => void finish()}
        doneLabel={finishing ? 'Finishing …' : 'Continue'}
      />
    );
  }
  if (setup.isPending || (!setup.data && !setup.error))
    return <LoadingState label="Preparing your authenticator key" rows={4} />;
  if (setup.error) {
    if (setup.error instanceof ApiError && setup.error.status === 409) {
      return (
        <div className="grid gap-3">
          <p className="text-sm">
            Multi-factor authentication is already enabled for your account.
          </p>
          <Button onClick={() => void finish()} disabled={finishing}>
            {finishing ? 'Finishing …' : 'Continue'}
          </Button>
        </div>
      );
    }
    return <ErrorState error={setup.error} onRetry={() => void setup.submit({})} />;
  }
  const secret = setup.data?.secret ?? '';
  return (
    <div className="grid gap-5">
      <ol className="grid gap-4 text-sm">
        <li className="grid gap-2">
          <p>
            <strong>1.</strong> Scan the code with an authenticator app (any RFC 6238 app), or enter
            the key manually.
          </p>
          <div className="flex flex-wrap items-center gap-4">
            <QrCode
              value={setup.data?.otpauthUri ?? ''}
              label="QR code with your authenticator key"
            />
            <div className="grid min-w-0 gap-1">
              <span className="text-xs text-muted-foreground">Key for manual entry</span>
              <span className="flex items-center gap-1">
                <code className="font-mono text-sm break-all" data-secret="">
                  {groupSecret(secret)}
                </code>
                <CopyButton value={secret} label="Copy authenticator key" />
              </span>
              <span className="text-xs text-muted-foreground">
                Time-based, 6 digits, 30 seconds.
              </span>
            </div>
          </div>
        </li>
        <li>
          <p>
            <strong>2.</strong> Enter the 6-digit code the app shows.
          </p>
        </li>
      </ol>
      <Form {...form}>
        <form onSubmit={(event) => void submit(event)} className="grid gap-4" noValidate>
          <FormErrorSummary messages={errors} requestId={enable.error?.requestId} />
          <FormField
            control={form.control}
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
                <FormDescription>Enabling MFA signs out your other sessions.</FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
          <Button type="submit" disabled={enable.isPending || enable.retryAfterSeconds > 0}>
            {enable.isPending ? 'Enabling …' : 'Enable MFA'}
          </Button>
        </form>
      </Form>
    </div>
  );
}
