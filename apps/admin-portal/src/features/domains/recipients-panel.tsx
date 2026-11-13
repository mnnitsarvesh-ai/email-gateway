'use client';

import { UsersIcon } from 'lucide-react';
import { useEffect, useId, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { FormErrorSummary } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Textarea } from '@/components/ui/textarea';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem, RequestBody, SuccessBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan } from '@/lib/auth/me';
import { formatNumber } from '@/lib/format';
import { FormDialog, MutationError, Section, splitList } from './kit';

type Validation = SuccessBody<'DomainRecipientsController_get_v1'>;
type Recipient = ListItem<'DomainRecipientsController_list_v1'>;

const MODES = [
  {
    value: 'accept_all',
    label: 'Accept every recipient',
    description: 'Every local part of the domain is accepted at RCPT time.',
  },
  {
    value: 'allow_list',
    label: 'Allow list',
    description: 'Only the local parts in the registry below are known recipients.',
  },
  {
    value: 'smtp_callout',
    label: 'SMTP callout (not implemented)',
    description: 'Not implemented by the gateway; the api refuses it.',
  },
  {
    value: 'ldap',
    label: 'LDAP lookup (not implemented)',
    description: 'Not implemented by the gateway; the api refuses it.',
  },
] as const;

/** PUT /domains/{id}/recipient-validation: `enforcement` only (and always) with `allow_list`. */
export const recipientValidationSchema = z
  .object({
    mode: z.enum(['accept_all', 'allow_list']),
    enforcement: z.enum(['reject', 'monitor']),
  })
  .strict();

export function recipientValidationBody(
  values: z.output<typeof recipientValidationSchema>,
): RequestBody<'DomainRecipientsController_set_v1'> {
  return values.mode === 'allow_list'
    ? { mode: 'allow_list', enforcement: values.enforcement }
    : { mode: 'accept_all' };
}

/** POST /domains/{id}/recipients: 1–1000 local parts (the part before `@`). */
export const addRecipientsSchema = z
  .object({
    localParts: z
      .array(
        z
          .string()
          .min(1)
          .max(64)
          .regex(/^[^@\s]+$/, 'Enter local parts only (before @), without spaces'),
      )
      .min(1, 'Enter at least one local part')
      .max(1000, 'At most 1000 local parts per request'),
  })
  .strict();

function ValidationForm({ domainId, current }: { domainId: string; current: Validation }) {
  const canEdit = useCan('DomainRecipientsController_set_v1');
  const [mode, setMode] = useState<string>(current.mode);
  const [enforcement, setEnforcement] = useState<'reject' | 'monitor'>(current.enforcement);
  const groupId = useId();
  const enforcementId = useId();
  const save = useApiMutation('DomainRecipientsController_set_v1', {
    successMessage: 'Recipient validation saved.',
    invalidates: ['DomainRecipientsController_get_v1'],
  });
  useEffect(() => {
    setMode(current.mode);
    setEnforcement(current.enforcement);
  }, [current.mode, current.enforcement]);

  const parsed = recipientValidationSchema.safeParse({ mode, enforcement });
  const dirty =
    mode !== current.mode || (mode === 'allow_list' && enforcement !== current.enforcement);
  return (
    <form
      className="grid min-w-0 gap-4 [&>*]:min-w-0"
      aria-label="Recipient validation"
      onSubmit={(event) => {
        event.preventDefault();
        if (!parsed.success) return;
        void save.submit({ path: { id: domainId }, body: recipientValidationBody(parsed.data) });
      }}
    >
      {!current.implemented ? (
        <p
          role="alert"
          className="rounded-md bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground"
        >
          The stored mode is not implemented by the gateway: every recipient is accepted until you
          choose another mode.
        </p>
      ) : null}
      <fieldset className="grid gap-2" disabled={!canEdit}>
        <legend className="mb-1 text-sm font-medium" id={groupId}>
          Mode
        </legend>
        <RadioGroup value={mode} onValueChange={setMode} aria-labelledby={groupId}>
          {MODES.map((option) => {
            const id = `${groupId}-${option.value}`;
            const unavailable = option.value === 'smtp_callout' || option.value === 'ldap';
            return (
              <div key={option.value} className="flex items-start gap-2">
                <RadioGroupItem id={id} value={option.value} disabled={unavailable} />
                <Label htmlFor={id} className="grid gap-0.5 font-normal">
                  <span className="font-medium">{option.label}</span>
                  <span className="text-xs text-muted-foreground">{option.description}</span>
                </Label>
              </div>
            );
          })}
        </RadioGroup>
      </fieldset>
      {mode === 'allow_list' ? (
        <fieldset className="grid gap-2" disabled={!canEdit}>
          <legend className="mb-1 text-sm font-medium" id={enforcementId}>
            Enforcement
          </legend>
          <RadioGroup
            value={enforcement}
            onValueChange={(value) => setEnforcement(value as 'reject' | 'monitor')}
            aria-labelledby={enforcementId}
          >
            <div className="flex items-start gap-2">
              <RadioGroupItem id={`${enforcementId}-monitor`} value="monitor" />
              <Label htmlFor={`${enforcementId}-monitor`} className="grid gap-0.5 font-normal">
                <span className="font-medium">Monitor</span>
                <span className="text-xs text-muted-foreground">
                  Accept unknown recipients and only count would-be rejections (onboarding).
                </span>
              </Label>
            </div>
            <div className="flex items-start gap-2">
              <RadioGroupItem id={`${enforcementId}-reject`} value="reject" />
              <Label htmlFor={`${enforcementId}-reject`} className="grid gap-0.5 font-normal">
                <span className="font-medium">Reject</span>
                <span className="text-xs text-muted-foreground">
                  Refuse unknown recipients with 550 5.1.1. Needs at least one registered recipient.
                </span>
              </Label>
            </div>
          </RadioGroup>
        </fieldset>
      ) : null}
      <MutationError error={save.error} />
      {canEdit ? (
        <Button
          type="submit"
          className="justify-self-start"
          disabled={!dirty || !parsed.success || save.isPending}
        >
          {save.isPending ? 'Saving …' : 'Save recipient validation'}
        </Button>
      ) : null}
    </form>
  );
}

/** Recipient validation settings of a domain (`GET/PUT /domains/{id}/recipient-validation`). */
export function RecipientValidationSection({ domainId }: { domainId: string }) {
  const validation = useApiQuery('DomainRecipientsController_get_v1', { path: { id: domainId } });
  return (
    <Section
      title="Recipient validation"
      description="Checks at SMTP RCPT time; changes reach the mail path within about a minute."
    >
      {validation.isLoading ? (
        <LoadingState label="Loading recipient validation" />
      ) : validation.error ? (
        <ErrorState error={validation.error} onRetry={() => void validation.refetch()} />
      ) : validation.data ? (
        <>
          <p className="text-sm text-muted-foreground">
            {formatNumber(validation.data.addressCount)} registered recipient
            {validation.data.addressCount === 1 ? '' : 's'}.
          </p>
          <ValidationForm domainId={domainId} current={validation.data} />
        </>
      ) : null}
    </Section>
  );
}

const REGISTRY_SHAPE = { rq: z.string().max(64).optional().catch(undefined) };

/** The domain's recipient registry (`GET/POST /domains/{id}/recipients`, `…/recipients/remove`). */
export function RecipientRegistrySection({ domainId }: { domainId: string }) {
  const [filters, setFilters] = useUrlState(REGISTRY_SHAPE);
  const list = useCursorList(
    'DomainRecipientsController_list_v1',
    filters.rq ? { q: filters.rq } : {},
    { path: { id: domainId } },
  );
  const canManage = useCan('DomainRecipientsController_add_v1');
  const [adding, setAdding] = useState(false);
  const [text, setText] = useState('');
  const [addErrors, setAddErrors] = useState<string[]>([]);
  const [removing, setRemoving] = useState<string[] | null>(null);
  const textId = useId();
  const add = useApiMutation('DomainRecipientsController_add_v1', {
    invalidates: ['DomainRecipientsController_list_v1', 'DomainRecipientsController_get_v1'],
    onSuccess: (data) => {
      toast.success(`Added ${data.added}; ${data.existing} already registered.`);
    },
  });
  const remove = useApiMutation('DomainRecipientsController_remove_v1', {
    invalidates: ['DomainRecipientsController_list_v1', 'DomainRecipientsController_get_v1'],
    onSuccess: (data) => {
      toast.success(`Removed ${data.removed}.`);
    },
  });

  const columns = useMemo<DataTableColumn<Recipient>[]>(
    () => [
      {
        id: 'localPart',
        header: 'Local part',
        meta: { label: 'Local part' },
        cell: ({ row }) => <UntrustedText value={row.original.localPart} mono />,
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
    <Section
      title="Recipient registry"
      description="Known local parts of the domain (the part before @). Used by the allow-list mode."
      actions={
        <Can op="DomainRecipientsController_add_v1">
          <Button size="sm" onClick={() => setAdding(true)}>
            Add recipients
          </Button>
        </Can>
      }
    >
      <DataTable
        tableId="domain-recipients"
        caption="Registered recipients"
        columns={columns}
        list={list}
        getRowId={(row) => row.localPart}
        getRowLabel={(row) => row.localPart}
        search={{
          value: filters.rq ?? '',
          onChange: (value) => setFilters({ rq: value || undefined }),
          label: 'Search recipients by local-part prefix',
          placeholder: 'Search recipients',
        }}
        isFiltered={Boolean(filters.rq)}
        onClearFilters={() => setFilters({ rq: undefined })}
        rowActions={
          canManage
            ? (row) => [
                {
                  label: 'Remove',
                  destructive: true,
                  onSelect: () => setRemoving([row.localPart]),
                },
              ]
            : undefined
        }
        enableSelection={canManage}
        bulkActions={(rows, clear) => (
          <Button
            variant="destructive"
            size="sm"
            onClick={() => {
              setRemoving(rows.map((row) => row.localPart));
              clear();
            }}
          >
            Remove selected
          </Button>
        )}
        emptyState={
          <EmptyState
            icon={UsersIcon}
            title="No registered recipients"
            description="Add the local parts that should receive mail when the allow list is enforced."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-0.5">
            <UntrustedText value={row.localPart} mono />
            <span className="text-xs text-muted-foreground">
              Added <DateTime value={row.createdAt} />
            </span>
          </div>
        )}
      />
      <FormDialog
        open={adding}
        onOpenChange={(open) => {
          setAdding(open);
          if (!open) {
            setText('');
            setAddErrors([]);
            add.reset();
          }
        }}
        title="Add recipients"
        description="One local part per line (or separated by commas). Existing entries are kept."
      >
        <form
          className="grid min-w-0 gap-4 [&>*]:min-w-0"
          aria-label="Add recipients"
          onSubmit={(event) => {
            event.preventDefault();
            const parsed = addRecipientsSchema.safeParse({ localParts: splitList(text) });
            if (!parsed.success) {
              setAddErrors(parsed.error.issues.map((issue) => issue.message));
              return;
            }
            setAddErrors([]);
            void add.submit({ path: { id: domainId }, body: parsed.data }).then((outcome) => {
              if (outcome.ok) {
                setAdding(false);
                setText('');
              }
            });
          }}
        >
          <FormErrorSummary messages={addErrors} />
          <div className="grid gap-2">
            <Label htmlFor={textId}>Local parts (required)</Label>
            <Textarea
              id={textId}
              value={text}
              onChange={(event) => setText(event.target.value)}
              rows={6}
              placeholder={'sales\nsupport\njane.doe'}
            />
          </div>
          <MutationError error={add.error} />
          <Button type="submit" className="justify-self-start" disabled={add.isPending}>
            {add.isPending ? 'Adding …' : 'Add'}
          </Button>
        </form>
      </FormDialog>
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRemoving(null);
            remove.reset();
          }
        }}
        title={
          removing && removing.length === 1
            ? `Remove ${removing[0]}?`
            : `Remove ${removing?.length ?? 0} recipients?`
        }
        description="With an enforced allow list, mail to removed recipients is refused."
        confirmLabel="Remove"
        destructive
        error={<MutationError error={remove.error} />}
        onConfirm={async () => {
          if (!removing) return false;
          const outcome = await remove.submit({
            path: { id: domainId },
            body: { localParts: removing },
          });
          return outcome.ok;
        }}
      />
    </Section>
  );
}
