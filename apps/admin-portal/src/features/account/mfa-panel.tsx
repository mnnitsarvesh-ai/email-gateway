'use client';

import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { z } from 'zod';
import { FormErrorSummary, PasswordInput, useZodForm } from '@/components/form';
import { SecretRevealDialog } from '@/components/secret-reveal-dialog';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { useApiMutation } from '@/lib/api/hooks';
import type { Me } from '@/lib/api/types';
import { ME_QUERY_KEY, useMe } from '@/lib/auth/me';
import { MfaEnrollment, downloadText, recoveryCodesText } from '@/features/auth/mfa-enrollment';

export const disableMfaSchema = z
  .object({
    password: z.string().min(1, 'Enter your password').max(1024),
    code: z
      .string()
      .trim()
      .regex(/^\d{6}$/, 'Enter the 6-digit code'),
  })
  .strict();
export const regenerateSchema = z
  .object({
    code: z
      .string()
      .trim()
      .regex(/^\d{6}$/, 'Enter the 6-digit code'),
  })
  .strict();

function CodeField({ form }: { form: ReturnType<typeof useZodForm<typeof regenerateSchema>> }) {
  return (
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
              className="font-mono"
              {...field}
            />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

/** MFA status with enroll, disable and recovery-code regeneration (Settings → Security). */
export function MfaPanel() {
  const queryClient = useQueryClient();
  const me = useMe();
  const [enrolling, setEnrolling] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  const disable = useApiMutation('MfaController_disable_v1', {
    successMessage: 'MFA disabled.',
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ME_QUERY_KEY }),
  });
  const regenerate = useApiMutation('MfaController_regenerate_v1', { successMessage: null });
  const disableForm = useZodForm(disableMfaSchema, { defaultValues: { password: '', code: '' } });
  const regenerateForm = useZodForm(regenerateSchema, { defaultValues: { code: '' } });

  if (me.isLoading) return <LoadingState rows={2} />;
  if (me.error) return <ErrorState error={me.error} onRetry={() => void me.refetch()} />;
  const data = me.data as Me;

  const onDisable = disableForm.handleSubmit(async (values) => {
    const outcome = await disable.submit({ body: values });
    if (outcome.ok) disableForm.reset();
  });
  const onRegenerate = regenerateForm.handleSubmit(async (values) => {
    await regenerate.submit({ body: values });
    regenerateForm.reset();
  });

  const errorMessages = (error: typeof disable.error) =>
    !error
      ? []
      : error.status === 403
        ? ['The password or code is not correct.']
        : error.status === 409
          ? ['Your organization requires MFA; it cannot be disabled.']
          : error.messages;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Multi-factor authentication
          <Badge variant={data.mfaEnabled ? 'success' : 'neutral'}>
            {data.mfaEnabled ? 'Enabled' : 'Not enabled'}
          </Badge>
        </CardTitle>
        <CardDescription>
          Time-based codes from an authenticator app. Required for platform operators and when your
          organization requires it.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {enrolling ? (
          <MfaEnrollment account={data.user.email} onComplete={() => setEnrolling(false)} />
        ) : data.mfaEnabled ? (
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => setRegenerating(true)}>
              Regenerate recovery codes
            </Button>
            <Button variant="outline" onClick={() => setDisabling(true)}>
              Disable MFA
            </Button>
          </div>
        ) : (
          <Button className="justify-self-start" onClick={() => setEnrolling(true)}>
            Set up MFA
          </Button>
        )}
      </CardContent>

      <Dialog
        open={disabling}
        onOpenChange={(open) => {
          setDisabling(open);
          if (!open) disable.reset();
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Disable MFA</DialogTitle>
            <DialogDescription>Confirm with your password and a current code.</DialogDescription>
          </DialogHeader>
          {disable.isSuccess ? (
            <p role="status" className="text-sm">
              MFA is disabled.
            </p>
          ) : (
            <Form {...disableForm}>
              <form onSubmit={(event) => void onDisable(event)} className="grid gap-4" noValidate>
                <FormErrorSummary
                  messages={errorMessages(disable.error)}
                  requestId={disable.error?.requestId}
                />
                <FormField
                  control={disableForm.control}
                  name="password"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Password</FormLabel>
                      <FormControl>
                        <PasswordInput autoComplete="current-password" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <CodeField form={disableForm as never} />
                <DialogFooter>
                  <Button variant="outline" onClick={() => setDisabling(false)}>
                    Cancel
                  </Button>
                  <Button type="submit" variant="destructive" disabled={disable.isPending}>
                    {disable.isPending ? 'Disabling …' : 'Disable MFA'}
                  </Button>
                </DialogFooter>
              </form>
            </Form>
          )}
        </DialogContent>
      </Dialog>

      <Dialog
        open={regenerating && !regenerate.data}
        onOpenChange={(open) => {
          setRegenerating(open);
          if (!open) regenerate.reset();
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Regenerate recovery codes</DialogTitle>
            <DialogDescription>All existing recovery codes stop working.</DialogDescription>
          </DialogHeader>
          <Form {...regenerateForm}>
            <form onSubmit={(event) => void onRegenerate(event)} className="grid gap-4" noValidate>
              <FormErrorSummary
                messages={errorMessages(regenerate.error)}
                requestId={regenerate.error?.requestId}
              />
              <CodeField form={regenerateForm} />
              <DialogFooter>
                <Button variant="outline" onClick={() => setRegenerating(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={regenerate.isPending}>
                  {regenerate.isPending ? 'Generating …' : 'Regenerate'}
                </Button>
              </DialogFooter>
            </form>
          </Form>
        </DialogContent>
      </Dialog>

      <SecretRevealDialog
        open={Boolean(regenerate.data)}
        title="New recovery codes"
        description="Each code signs you in once. They are shown only this time."
        secrets={(regenerate.data?.recoveryCodes ?? []).map((code, index) => ({
          label: `Recovery code ${index + 1}`,
          value: code,
        }))}
        extra={
          <Button
            variant="outline"
            size="sm"
            className="justify-self-start"
            onClick={() =>
              downloadText(
                'email-gateway-recovery-codes.txt',
                recoveryCodesText(regenerate.data?.recoveryCodes ?? [], data.user.email),
              )
            }
          >
            Download as text
          </Button>
        }
        onClose={() => {
          regenerate.reset();
          setRegenerating(false);
        }}
      />
    </Card>
  );
}
