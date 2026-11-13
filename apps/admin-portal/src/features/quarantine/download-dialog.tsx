'use client';

import { useQueryClient } from '@tanstack/react-query';
import { DownloadIcon } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';
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
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { useApiMutation } from '@/lib/api/hooks';
import { useMe } from '@/lib/auth/me';
import { formatBytes } from '@/lib/format';
import { downloadGrantBody, downloadGrantSchema } from './forms';
import { downloadHref } from './links';
import { explainQuarantineError } from './reason-confirm';
import type { PreviewBody } from './types';

/**
 * Navigation to the BFF download door. The browser fetches the bytes as a download
 * (`Content-Disposition: attachment`); the page never reads them. Exposed as an object so tests
 * can observe the navigation (jsdom cannot navigate).
 */
export const downloadNavigation = {
  assign(url: string): void {
    window.location.assign(url);
  },
};

/**
 * Download through a 5.3 grant (design P12, 17-quarantine Q12): fresh re-authentication with the
 * password (and the TOTP code when MFA is enrolled), then one navigation to the single-use URL.
 * The token is used once and never stored (not in state, not in the query cache).
 */
export function DownloadDialog({
  entryId,
  open,
  onOpenChange,
  attachments,
}: {
  entryId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Attachments from the sanitized preview, when it was loaded (for the part picker). */
  attachments?: PreviewBody['attachments'];
}) {
  const me = useMe();
  const queryClient = useQueryClient();
  const mfa = me.data?.mfaEnabled ?? false;
  const grant = useApiMutation('QuarantineEntriesController_grant_v1', { successMessage: null });
  const [messages, setMessages] = useState<string[]>([]);
  const form = useZodForm(downloadGrantSchema, {
    defaultValues: { object: 'eml', password: '', totpCode: '' },
  });
  const object = form.watch('object');

  const close = (next: boolean) => {
    if (!next) {
      form.reset({ object: 'eml', password: '', totpCode: '' });
      setMessages([]);
      grant.reset();
    }
    onOpenChange(next);
  };

  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    if (mfa && !values.totpCode) {
      form.setError('totpCode', { message: 'Enter the 6-digit code from your authenticator app' });
      return;
    }
    const outcome = await grant.submit({ path: { entryId }, body: downloadGrantBody(values) });
    // Clear the password from the form whatever the result.
    form.setValue('password', '');
    form.setValue('totpCode', '');
    if (!outcome.ok) {
      setMessages([...explainQuarantineError(outcome.error), `Code: ${outcome.error.code}`]);
      return;
    }
    const { token, filename, sizeBytes } = outcome.data;
    // The single-use token must not linger anywhere: drop it from the mutation state and cache.
    grant.reset();
    const cache = queryClient.getMutationCache();
    for (const mutation of cache.findAll({
      mutationKey: ['QuarantineEntriesController_grant_v1'],
    })) {
      cache.remove(mutation);
    }
    downloadNavigation.assign(downloadHref(token));
    toast.success(`Download started: ${filename} (${formatBytes(sizeBytes)})`);
    close(false);
  });

  const downloadable = attachments?.filter((a) => a.downloadable) ?? [];
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Download quarantined content</DialogTitle>
          <DialogDescription>
            Confirm your identity to create a single-use download link valid for a short time. Only
            clean content can be downloaded; the file is saved, never opened in the portal.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form
            onSubmit={(event) => void submit(event)}
            className="grid gap-4"
            noValidate
            aria-label="Download grant"
          >
            <FormErrorSummary messages={messages} requestId={grant.error?.requestId} />
            <FormField
              control={form.control}
              name="object"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>What to download</FormLabel>
                  <FormControl>
                    <RadioGroup
                      value={field.value}
                      onValueChange={(value) => field.onChange(value)}
                      className="grid gap-2"
                    >
                      <div className="flex items-center gap-2">
                        <RadioGroupItem value="eml" id={`${entryId}-eml`} />
                        <Label htmlFor={`${entryId}-eml`}>The whole message (.eml.bin)</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <RadioGroupItem value="attachment" id={`${entryId}-att`} />
                        <Label htmlFor={`${entryId}-att`}>One attachment (.bin)</Label>
                      </div>
                    </RadioGroup>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {object === 'attachment' ? (
              <FormField
                control={form.control}
                name="partIndex"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Attachment part number (required)</FormLabel>
                    <FormControl>
                      <Input
                        type="number"
                        inputMode="numeric"
                        min={0}
                        max={65535}
                        value={field.value ?? ''}
                        onChange={(event) =>
                          field.onChange(
                            event.target.value === '' ? undefined : Number(event.target.value),
                          )
                        }
                        onBlur={field.onBlur}
                        name={field.name}
                        ref={field.ref}
                      />
                    </FormControl>
                    <FormDescription>
                      {downloadable.length > 0
                        ? `Downloadable parts: ${downloadable.map((a) => a.partIndex).join(', ')}.`
                        : 'The part number is listed in the sanitized preview and in the security scan details.'}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            ) : null}
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
            {mfa ? (
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
                {grant.isPending ? 'Checking …' : 'Download'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
