'use client';

import { PlusIcon, WebhookIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { SecretRevealDialog } from '@/components/secret-reveal-dialog';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useCursorList } from '@/lib/api/hooks';

import { Can } from '@/lib/auth/can';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { FilterSelect, FormDialog, Section } from '@/features/domains/kit';
import {
  REDACTED_REPLAY_EXPLANATION,
  WEBHOOK_STATUSES,
  WebhookStatusBadge,
  type Webhook,
} from './model';
import { WebhookForm, webhookCreateBody } from './webhook-form';

const URL_SHAPE = {
  wstatus: z.enum(['active', 'paused', 'disabled', 'deleted']).optional().catch(undefined),
  wsort: z.enum(['-id']).optional().catch(undefined),
};

type Created = { id: string; name: string; secret: string | null };

function CreateWebhook({ onCreated }: { onCreated: (created: Created) => void }) {
  const create = useApiMutation('WebhooksController_create_v1', {
    invalidates: ['WebhooksController_list_v1'],
    successMessage: null,
  });
  // A lost response (network failure) is retried with the SAME Idempotency-Key: the api then
  // answers with the stored, redacted representation (secret: null) and creates nothing.
  const lost = create.error?.status === 0;
  return (
    <WebhookForm
      submitLabel="Create webhook"
      pending={create.isPending}
      extra={
        lost ? (
          <div className="grid gap-2 rounded-md border border-dashed p-3 text-sm" role="alert">
            <p>
              The response did not arrive. Retry the same request: if the webhook was created,
              nothing is created twice.
            </p>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="justify-self-start"
              onClick={() =>
                void create.retry().then((outcome) => {
                  if (outcome.ok) {
                    onCreated({
                      id: outcome.data.id,
                      name: outcome.data.name,
                      secret: outcome.data.secret ?? null,
                    });
                    create.reset();
                  }
                })
              }
            >
              Retry the same request
            </Button>
          </div>
        ) : undefined
      }
      onSubmit={async (values) => {
        const outcome = await create.submit({ body: webhookCreateBody(values) });
        if (!outcome.ok) return outcome.error;
        // The signing secret is in this response only (P12): hand it to the one-time dialog and
        // drop the mutation's copy.
        onCreated({
          id: outcome.data.id,
          name: outcome.data.name,
          secret: outcome.data.secret ?? null,
        });
        create.reset();
        return null;
      }}
    />
  );
}

/** Webhook subscriptions (`GET /webhooks`, v1 cursor, `status`, `sort=-id`) and creation. */
export function WebhooksSection() {
  const router = useRouter();
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const canCreate = useCan('WebhooksController_create_v1');
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<Created | null>(null);
  const list = useCursorList('WebhooksController_list_v1', {
    ...(filters.wstatus ? { status: filters.wstatus } : {}),
    ...(filters.wsort ? { sort: filters.wsort } : {}),
  });

  const columns = useMemo<DataTableColumn<Webhook>[]>(
    () => [
      {
        id: 'name',
        header: 'Webhook',
        meta: { label: 'Webhook' },
        cell: ({ row }) => (
          <Link
            href={`/webhooks/${row.original.id}`}
            className="font-medium text-primary hover:underline"
          >
            {row.original.name}
          </Link>
        ),
      },
      {
        id: 'url',
        header: 'Endpoint',
        meta: { label: 'Endpoint' },
        cell: ({ row }) => (
          <UntrustedText
            value={row.original.url}
            mono
            copy
            copyLabel={`Copy the URL of ${row.original.name}`}
            maxLength={60}
          />
        ),
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => <WebhookStatusBadge status={row.original.status} />,
      },
      {
        id: 'events',
        header: 'Events',
        meta: { label: 'Events' },
        cell: ({ row }) => <span className="text-xs">{row.original.eventTypes.join(', ')}</span>,
      },
      {
        id: 'health',
        header: 'Health',
        meta: { label: 'Health' },
        cell: ({ row }) =>
          row.original.consecutiveFailures > 0 ? (
            <span className="text-xs">{row.original.consecutiveFailures} failures in a row</span>
          ) : (
            <span className="text-xs text-muted-foreground">
              Last success <DateTime value={row.original.lastSuccessAt} />
            </span>
          ),
      },
      {
        id: 'createdAt',
        header: 'Created',
        meta: { label: 'Created' },
        cell: ({ row }) => <DateTime value={row.original.createdAt} />,
      },
    ],
    [],
  );

  return (
    <Section
      title="Webhooks"
      description="Signed HTTP callbacks for mail, threat, quarantine and domain events. Endpoint URLs are shown as text only."
      actions={
        <Can op="WebhooksController_create_v1">
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon aria-hidden />
            New webhook
          </Button>
        </Can>
      }
    >
      <DataTable
        tableId="webhooks"
        caption="Webhooks"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        sort={{
          operationId: 'WebhooksController_list_v1',
          columnId: 'createdAt',
          value: filters.wsort,
          onChange: (wsort) => setFilters({ wsort: wsort as '-id' | undefined }),
        }}
        filters={
          <FilterSelect
            label="Status"
            allLabel="All but deleted"
            value={filters.wstatus}
            onChange={(wstatus) =>
              setFilters({ wstatus: wstatus as Webhook['status'] | undefined })
            }
            options={WEBHOOK_STATUSES.map((s) => ({ value: s, label: humanize(s) }))}
          />
        }
        isFiltered={Boolean(filters.wstatus)}
        onClearFilters={() => setFilters({ wstatus: undefined })}
        rowActions={(row) => [
          { label: 'Open', onSelect: () => router.push(`/webhooks/${row.id}`) },
        ]}
        emptyState={
          <EmptyState
            icon={WebhookIcon}
            title="No webhooks yet"
            description="Receive signed events for threats, quarantine and domain changes at your own endpoint."
            action={
              canCreate ? (
                <Button size="sm" onClick={() => setCreating(true)}>
                  New webhook
                </Button>
              ) : undefined
            }
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <Link href={`/webhooks/${row.id}`} className="font-medium text-primary hover:underline">
              {row.name}
            </Link>
            <UntrustedText value={row.url} mono maxLength={40} />
            <WebhookStatusBadge status={row.status} />
          </div>
        )}
      />
      <FormDialog open={creating} onOpenChange={setCreating} title="New webhook" wide>
        <CreateWebhook
          onCreated={(result) => {
            setCreating(false);
            setCreated(result);
          }}
        />
      </FormDialog>
      <SecretRevealDialog
        open={created !== null && created.secret !== null}
        title="Webhook signing secret"
        description="Verify the EG-Signature header of every delivery with this secret (HMAC-SHA256). It is shown only now."
        secrets={created?.secret ? [{ label: 'Signing secret', value: created.secret }] : []}
        onClose={() => {
          const id = created?.id;
          setCreated(null);
          if (id) router.push(`/webhooks/${id}`);
        }}
      />
      <FormDialog
        open={created !== null && created.secret === null}
        onOpenChange={(open) => !open && setCreated(null)}
        title="The webhook already existed"
      >
        <p className="text-sm">{REDACTED_REPLAY_EXPLANATION}</p>
        <Button asChild className="justify-self-start">
          <Link href={created ? `/webhooks/${created.id}` : '/integrations'}>
            Open {created?.name ?? 'the webhook'} to rotate the secret
          </Link>
        </Button>
      </FormDialog>
    </Section>
  );
}
