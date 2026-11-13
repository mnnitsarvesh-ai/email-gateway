'use client';

import { Building2Icon, CheckIcon } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';
import { z } from 'zod';
import { FormErrorSummary, useZodForm } from '@/components/form';
import { Button } from '@/components/ui/button';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command';
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
import { Textarea } from '@/components/ui/textarea';
import { useDebouncedValue } from '@/hooks/use-debounced-value';
import { ApiError } from '@/lib/api/errors';
import { useApiQuery } from '@/lib/api/hooks';
import { useStartOverride } from '@/lib/auth/me';
import { cn } from '@/lib/utils';

/** Bounds of `POST /platform/overrides` (OpenAPI: reason 10–500, duration 5–240 minutes). */
export const overrideFormSchema = z
  .object({
    organizationId: z.uuid('Choose an organization'),
    reason: z
      .string()
      .trim()
      .min(10, 'Give a reason of at least 10 characters (a ticket reference)')
      .max(500),
    durationMinutes: z.coerce
      .number()
      .int()
      .min(5, 'At least 5 minutes')
      .max(240, 'At most 240 minutes (the platform may allow less)'),
  })
  .strict();

export type OverrideFormInput = z.input<typeof overrideFormSchema>;

function OrganizationPicker({
  value,
  onChange,
}: {
  value: string;
  onChange: (id: string, name: string) => void;
}) {
  const [search, setSearch] = useState('');
  const q = useDebouncedValue(search.trim(), 300);
  const organizations = useApiQuery('OrganizationsController_list_v1', {
    query: { kind: 'customer', status: 'active', limit: 20, ...(q ? { q } : {}) },
  });
  const rows = organizations.data?.data ?? [];
  return (
    <Command shouldFilter={false} className="rounded-md border border-input">
      <CommandInput
        placeholder="Search organizations by name or slug"
        value={search}
        onValueChange={setSearch}
        aria-label="Search organizations"
      />
      <CommandList>
        {organizations.isLoading ? (
          <p className="p-3 text-sm text-muted-foreground">Loading …</p>
        ) : null}
        {organizations.error ? (
          <p className="p-3 text-sm text-destructive">
            Organizations could not be loaded ({organizations.error.code}).
          </p>
        ) : null}
        <CommandEmpty>No organization matches.</CommandEmpty>
        <CommandGroup>
          {rows.map((org) => (
            <CommandItem key={org.id} value={org.id} onSelect={() => onChange(org.id, org.name)}>
              <Building2Icon aria-hidden />
              <span className="truncate">{org.name}</span>
              <span className="ml-1 font-mono text-xs text-muted-foreground">{org.slug}</span>
              <CheckIcon
                className={cn('ml-auto', value === org.id ? 'opacity-100' : 'opacity-0')}
                aria-hidden
              />
            </CommandItem>
          ))}
        </CommandGroup>
      </CommandList>
    </Command>
  );
}

/**
 * Tenant switcher for holders of `platform:tenant_override` (design P11): pick a customer
 * organization, give a reason and a duration; the BFF starts the audited override. The api
 * requires an MFA session (`403 mfa_required` is explained in the dialog).
 */
export function TenantSwitcher({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const startOverride = useStartOverride();
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [formErrors, setFormErrors] = useState<string[]>([]);
  const [requestId, setRequestId] = useState<string | null>(null);
  const form = useZodForm(overrideFormSchema, {
    defaultValues: { organizationId: '', reason: '', durationMinutes: 30 },
  });

  const submit = form.handleSubmit(async (values) => {
    setFormErrors([]);
    setRequestId(null);
    try {
      const started = await startOverride(values);
      toast.success(`Now acting in ${started.organizationName}.`);
      form.reset();
      setSelectedName(null);
      onOpenChange(false);
    } catch (error) {
      if (error instanceof ApiError) {
        setRequestId(error.requestId);
        if (error.status === 403 && error.code === 'mfa_required') {
          setFormErrors([
            'Starting an override needs an MFA session. Sign out and sign in again with your authenticator code.',
          ]);
        } else if (error.status === 400 && error.code === 'validation_failed') {
          setFormErrors(error.messages);
        } else {
          setFormErrors(error.messages);
        }
      } else {
        setFormErrors(['The override could not be started.']);
      }
    }
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Act in a customer organization</DialogTitle>
          <DialogDescription>
            Starts an audited platform override. Every request is recorded with your reason.
            Platform permissions are removed while it is active.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={(event) => void submit(event)} className="grid gap-4" noValidate>
            <FormErrorSummary messages={formErrors} requestId={requestId} />
            <FormField
              control={form.control}
              name="organizationId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel required>Organization</FormLabel>
                  <FormControl>
                    <div>
                      <OrganizationPicker
                        value={field.value}
                        onChange={(id, name) => {
                          field.onChange(id);
                          setSelectedName(name);
                        }}
                      />
                    </div>
                  </FormControl>
                  {selectedName ? (
                    <FormDescription>Selected: {selectedName}</FormDescription>
                  ) : null}
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="reason"
              render={({ field }) => (
                <FormItem>
                  <FormLabel required>Reason</FormLabel>
                  <FormControl>
                    <Textarea {...field} rows={3} maxLength={500} />
                  </FormControl>
                  <FormDescription>10 to 500 characters, e.g. a ticket reference.</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="durationMinutes"
              render={({ field }) => (
                <FormItem>
                  <FormLabel required>Duration (minutes)</FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min={5}
                      max={240}
                      inputMode="numeric"
                      name={field.name}
                      ref={field.ref}
                      onBlur={field.onBlur}
                      value={
                        typeof field.value === 'number' || typeof field.value === 'string'
                          ? String(field.value)
                          : ''
                      }
                      onChange={(event) => field.onChange(event.target.value)}
                    />
                  </FormControl>
                  <FormDescription>
                    5 minutes up to the platform maximum (PLATFORM_OVERRIDE_MAX_MINUTES, 30 by
                    default).
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>
                {form.formState.isSubmitting ? 'Starting …' : 'Start override'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
