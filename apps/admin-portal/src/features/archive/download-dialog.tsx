'use client';

import { useQueryClient } from '@tanstack/react-query';
import { DownloadIcon } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';
import { z } from 'zod';
import { FormErrorSummary, PasswordInput, useZodForm } from '@/components/form';
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
import { useApiMutation } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { formatBytes } from '@/lib/format';
import { archiveDownloadHref, explainArchiveError, useArchiveAccess } from './model';

/**
 * Navigation to the BFF download door (`GET /archive/downloads/{token}` streamed by the BFF). The
 * browser saves the bytes (`Content-Disposition: attachment`); the page never reads them. An
 * object so tests can observe the navigation (jsdom cannot navigate).
 */
export const archiveDownloadNavigation = {
  assign(url: string): void {
    window.location.assign(url);
  },
};

export const reauthSchema = z
  .object({
    password: z.string().min(1, 'Enter your password').max(1024),
    totpCode: z
      .string()
      .trim()
      .regex(/^(\d{6})?$/, 'Enter the 6-digit code from your authenticator app')
      .optional(),
  })
  .strict();
export type ReauthValues = z.output<typeof reauthSchema>;

export function reauthBody(
  values: ReauthValues,
): RequestBody<'ArchiveMessagesController_grant_v1'> {
  return { password: values.password, ...(values.totpCode ? { totpCode: values.totpCode } : {}) };
}

type Target =
  | {
      readonly kind: 'message';
      readonly messageId: string;
      /** Step 8.6: a merged copy's id to download its stored content variant instead. */
      readonly variant?: string;
    }
  | { readonly kind: 'export'; readonly caseId: string; readonly exportId: string };

/**
 * Download through a single-use grant (A19, A18): fresh re-authentication with the password (and
 * the TOTP code when MFA is enrolled), then one navigation to the BFF door. The token is used
 * once and never stored: not in state, not in the query or mutation cache, not in the URL bar
 * history of the page (the navigation is a download).
 */
export function GrantDownloadDialog({
  target,
  open,
  onOpenChange,
  title,
  description,
}: {
  target: Target;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
}) {
  const access = useArchiveAccess();
  const queryClient = useQueryClient();
  const messageGrant = useApiMutation('ArchiveMessagesController_grant_v1', {
    successMessage: null,
  });
  const exportGrant = useApiMutation('EdiscoveryExportsController_grant_v1', {
    successMessage: null,
  });
  const grant = target.kind === 'message' ? messageGrant : exportGrant;
  const [messages, setMessages] = useState<string[]>([]);
  const form = useZodForm(reauthSchema, { defaultValues: { password: '', totpCode: '' } });

  const close = (next: boolean) => {
    if (!next) {
      form.reset({ password: '', totpCode: '' });
      setMessages([]);
      messageGrant.reset();
      exportGrant.reset();
    }
    onOpenChange(next);
  };

  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    if (access.mfaEnrolled && !values.totpCode) {
      form.setError('totpCode', { message: 'Enter the 6-digit code from your authenticator app' });
      return;
    }
    const body = reauthBody(values);
    const outcome =
      target.kind === 'message'
        ? await messageGrant.submit({
            path: { messageId: target.messageId },
            body: target.variant ? { ...body, variant: target.variant } : body,
          })
        : await exportGrant.submit({
            path: { caseId: target.caseId, exportId: target.exportId },
            body,
          });
    form.setValue('password', '');
    form.setValue('totpCode', '');
    if (!outcome.ok) {
      setMessages([...explainArchiveError(outcome.error), `Code: ${outcome.error.code}`]);
      return;
    }
    const { token, filename, sizeBytes } = outcome.data;
    // The single-use token must not linger anywhere: drop it from the mutation state and cache.
    messageGrant.reset();
    exportGrant.reset();
    const cache = queryClient.getMutationCache();
    for (const key of [
      'ArchiveMessagesController_grant_v1',
      'EdiscoveryExportsController_grant_v1',
    ]) {
      for (const mutation of cache.findAll({ mutationKey: [key] })) cache.remove(mutation);
    }
    archiveDownloadNavigation.assign(archiveDownloadHref(token));
    toast.success(`Download started: ${filename} (${formatBytes(sizeBytes)})`);
    close(false);
  });

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form
            onSubmit={(event) => void submit(event)}
            className="grid gap-4"
            noValidate
            aria-label="Confirm your identity"
          >
            <FormErrorSummary messages={messages} requestId={grant.error?.requestId} />
            <FormField
              control={form.control}
              name="password"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Your password (required)</FormLabel>
                  <FormControl>
                    <PasswordInput autoComplete="current-password" {...field} />
                  </FormControl>
                  <FormDescription>
                    Failed attempts count toward the sign-in lockout.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            {access.mfaEnrolled ? (
              <FormField
                control={form.control}
                name="totpCode"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Authenticator code (required)</FormLabel>
                    <FormControl>
                      <Input
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        maxLength={6}
                        {...field}
                        value={field.value ?? ''}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            ) : null}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={grant.isPending || grant.retryAfterSeconds > 0}>
                <DownloadIcon aria-hidden />
                {grant.isPending
                  ? 'Checking …'
                  : grant.retryAfterSeconds > 0
                    ? `Try again in ${grant.retryAfterSeconds} s`
                    : 'Download'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
