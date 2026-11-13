'use client';

import { MailXIcon, PlusIcon } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { EmptyState } from '@/components/states/empty-state';
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
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useUrlState } from '@/hooks/use-url-state';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation, useCursorList } from '@/lib/api/hooks';
import type { ListItem, QueryParams, RequestBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { FilterSelect, FormDialog, MutationError } from '@/features/domains/kit';

type Suppression = ListItem<'RecipientSuppressionsController_list_v1'>;
const REASONS = ['hard_bounce', 'complaint', 'manual', 'unsubscribe'] as const;

const URL_SHAPE = {
  reason: z.enum(REASONS).optional().catch(undefined),
  address: z.string().max(320).optional().catch(undefined),
  active: z.enum(['true', 'false']).optional().catch(undefined),
  sort: z.enum(['-id']).optional().catch(undefined),
};

const MAX_EXPIRY_DAYS = 3650;

/** POST /recipients/suppressions: address, reason (manual | unsubscribe), optional expiry day. */
export const suppressionCreateSchema = z
  .object({
    address: z
      .string()
      .trim()
      .min(3)
      .max(320)
      .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Enter an email address'),
    reason: z.enum(['manual', 'unsubscribe']),
    expiresOn: z
      .string()
      .regex(/^(\d{4}-\d{2}-\d{2})?$/, 'Enter a date')
      .refine((day) => {
        if (!day) return true;
        const at = Date.parse(`${day}T23:59:59.000Z`);
        return at > Date.now() && at <= Date.now() + MAX_EXPIRY_DAYS * 86_400_000;
      }, `Choose a future date within ${MAX_EXPIRY_DAYS} days`),
  })
  .strict();

export function suppressionCreateBody(
  values: z.output<typeof suppressionCreateSchema>,
): RequestBody<'RecipientSuppressionsController_create_v1'> {
  return {
    address: values.address.toLowerCase(),
    reason: values.reason,
    ...(values.expiresOn ? { expiresAt: `${values.expiresOn}T23:59:59.000Z` } : {}),
  };
}

function CreateSuppression({
  onDone,
  onShowExisting,
}: {
  onDone: () => void;
  onShowExisting: (address: string) => void;
}) {
  const [messages, setMessages] = useState<string[]>([]);
  const [existing, setExisting] = useState<string | null>(null);
  const create = useApiMutation('RecipientSuppressionsController_create_v1', {
    invalidates: ['RecipientSuppressionsController_list_v1'],
    successMessage: 'Address suppressed.',
  });
  const form = useZodForm(suppressionCreateSchema, {
    defaultValues: { address: '', reason: 'manual', expiresOn: '' },
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    setExisting(null);
    const body = suppressionCreateBody(values);
    const outcome = await create.submit({ body });
    if (outcome.ok) return onDone();
    const error = outcome.error;
    if (error instanceof ApiError && error.code === 'suppression_exists') {
      setExisting(body.address);
      setMessages(['This address is already on the suppression list.']);
    } else if (error instanceof ApiError && error.code === 'suppression_limit_reached') {
      setMessages([
        'Your organization has reached its limit of manual suppressions. Remove entries you no longer need, or ask the platform operator to raise the limit.',
      ]);
    } else {
      setMessages(applyApiErrors(form, error));
    }
  });
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label="Suppress an address"
        onSubmit={(e) => void submit(e)}
      >
        <FormErrorSummary messages={messages} requestId={create.error?.requestId} />
        {existing ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="justify-self-start"
            onClick={() => onShowExisting(existing)}
          >
            Show the existing entry
          </Button>
        ) : null}
        <FormField
          control={form.control}
          name="address"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Address (required)</FormLabel>
              <FormControl>
                <Input type="email" autoComplete="off" spellCheck={false} {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="reason"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Reason</FormLabel>
              <Select value={field.value} onValueChange={field.onChange}>
                <FormControl>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="manual">Manual</SelectItem>
                  <SelectItem value="unsubscribe">Unsubscribe</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="expiresOn"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Expires on (optional)</FormLabel>
              <FormControl>
                <Input type="date" {...field} />
              </FormControl>
              <FormDescription>End of that day, UTC. Empty: until removed.</FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button
          type="submit"
          className="justify-self-start"
          disabled={create.isPending || create.retryAfterSeconds > 0}
        >
          {create.isPending ? 'Saving …' : 'Suppress address'}
        </Button>
      </form>
    </Form>
  );
}

function AddressFilter({
  value,
  onChange,
}: {
  value: string | undefined;
  onChange: (v: string | undefined) => void;
}) {
  const [text, setText] = useState(value ?? '');
  useEffect(() => setText(value ?? ''), [value]);
  return (
    <form
      className="flex items-center gap-1"
      role="search"
      aria-label="Filter by address"
      onSubmit={(event) => {
        event.preventDefault();
        onChange(text.trim().toLowerCase() || undefined);
      }}
    >
      <Label htmlFor="suppression-address" className="sr-only">
        Exact address
      </Label>
      <Input
        id="suppression-address"
        type="email"
        className="h-8 w-56"
        placeholder="Exact address"
        value={text}
        onChange={(event) => setText(event.target.value)}
      />
      <Button type="submit" variant="outline" size="sm">
        Find
      </Button>
    </form>
  );
}

/** Recipient suppressions (`/recipients/suppressions`, v1 cursor): outbound mail is not sent to them. */
export function SuppressionsTab() {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const canManage = useCan('RecipientSuppressionsController_delete_v1');
  const [creating, setCreating] = useState(false);
  const [removing, setRemoving] = useState<Suppression | null>(null);
  const remove = useApiMutation('RecipientSuppressionsController_delete_v1', {
    invalidates: ['RecipientSuppressionsController_list_v1'],
    successMessage: 'Suppression removed.',
  });
  const query = {
    ...(filters.reason ? { reason: filters.reason } : {}),
    ...(filters.address ? { address: filters.address } : {}),
    ...(filters.active ? { active: filters.active } : {}),
    ...(filters.sort ? { sort: filters.sort } : {}),
  } as QueryParams<'RecipientSuppressionsController_list_v1'>;
  const list = useCursorList('RecipientSuppressionsController_list_v1', query);

  const columns = useMemo<DataTableColumn<Suppression>[]>(
    () => [
      {
        id: 'address',
        header: 'Address',
        meta: { label: 'Address' },
        cell: ({ row }) => (
          <UntrustedText
            value={row.original.address}
            copy
            copyLabel={`Copy ${row.original.address}`}
          />
        ),
      },
      {
        id: 'reason',
        header: 'Reason',
        meta: { label: 'Reason' },
        cell: ({ row }) => humanize(row.original.reason),
      },
      {
        id: 'active',
        header: 'State',
        meta: { label: 'State' },
        cell: ({ row }) => (
          <ToneBadge tone={row.original.active ? 'warning' : 'neutral'}>
            {row.original.active ? 'Suppressing' : 'Expired'}
          </ToneBadge>
        ),
      },
      {
        id: 'expiresAt',
        header: 'Expires',
        meta: { label: 'Expires' },
        cell: ({ row }) => <DateTime value={row.original.expiresAt} emptyLabel="Never" />,
      },
      {
        id: 'source',
        header: 'Source',
        meta: { label: 'Source' },
        cell: ({ row }) => <UntrustedText value={row.original.source} emptyLabel="Unknown" />,
      },
      {
        id: 'createdAt',
        header: 'Added',
        meta: { label: 'Added' },
        cell: ({ row }) => <DateTime value={row.original.createdAt} />,
      },
    ],
    [],
  );

  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          Outbound mail of your organization is not delivered to these addresses (bounces,
          complaints and manual entries).
        </p>
        <Can op="RecipientSuppressionsController_create_v1">
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon aria-hidden />
            Suppress address
          </Button>
        </Can>
      </div>
      <DataTable
        tableId="recipient-suppressions"
        caption="Recipient suppressions"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.address}
        sort={{
          operationId: 'RecipientSuppressionsController_list_v1',
          columnId: 'createdAt',
          value: filters.sort,
          onChange: (sort) => setFilters({ sort: sort as '-id' | undefined }),
        }}
        filters={
          <>
            <AddressFilter
              value={filters.address}
              onChange={(address) => setFilters({ address })}
            />
            <FilterSelect
              label="Reason"
              value={filters.reason}
              onChange={(reason) =>
                setFilters({ reason: reason as (typeof REASONS)[number] | undefined })
              }
              options={REASONS.map((r) => ({ value: r, label: humanize(r) }))}
            />
            <FilterSelect
              label="State"
              value={filters.active}
              onChange={(active) => setFilters({ active: active as 'true' | 'false' | undefined })}
              options={[
                { value: 'true', label: 'Suppressing' },
                { value: 'false', label: 'Expired' },
              ]}
            />
          </>
        }
        isFiltered={Boolean(filters.reason || filters.address || filters.active)}
        onClearFilters={() =>
          setFilters({ reason: undefined, address: undefined, active: undefined })
        }
        rowActions={
          canManage
            ? (row) => [{ label: 'Remove', destructive: true, onSelect: () => setRemoving(row) }]
            : undefined
        }
        emptyState={
          <EmptyState
            icon={MailXIcon}
            title="No suppressed addresses"
            description="Hard bounces and complaints are added automatically."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <UntrustedText value={row.address} />
            <span className="text-xs text-muted-foreground">
              {humanize(row.reason)} · {row.active ? 'suppressing' : 'expired'}
            </span>
          </div>
        )}
      />
      <FormDialog open={creating} onOpenChange={setCreating} title="Suppress an address">
        <CreateSuppression
          onDone={() => setCreating(false)}
          onShowExisting={(address) => {
            setCreating(false);
            setFilters({ address, reason: undefined, active: undefined });
          }}
        />
      </FormDialog>
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRemoving(null);
            remove.reset();
          }
        }}
        title={`Remove ${removing?.address ?? ''} from the list?`}
        description={
          removing && removing.reason !== 'manual' && removing.reason !== 'unsubscribe'
            ? `This entry came from a ${humanize(removing.reason).toLowerCase()}; outbound mail to the address is delivered again.`
            : 'Outbound mail to the address is delivered again.'
        }
        confirmLabel="Remove"
        destructive
        error={<MutationError error={remove.error} />}
        onConfirm={async () =>
          removing ? (await remove.submit({ path: { suppressionId: removing.id } })).ok : false
        }
      />
    </div>
  );
}
