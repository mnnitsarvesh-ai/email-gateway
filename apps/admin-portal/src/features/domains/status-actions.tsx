'use client';

import { useRouter } from 'next/navigation';
import { useId, useState } from 'react';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useApiMutation } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { MutationError } from './kit';
import type { DomainDetail } from './model';

/** PATCH /domains/{id}/status: `reason` (1–512) is required to suspend. */
export const domainStatusSchema = z
  .object({
    status: z.enum(['active', 'suspended']),
    reason: z.string().trim().max(512),
  })
  .strict()
  .refine((v) => v.status !== 'suspended' || v.reason.length > 0, {
    path: ['reason'],
    message: 'Enter a reason for suspending the domain',
  });

export function domainStatusBody(
  values: z.output<typeof domainStatusSchema>,
): RequestBody<'DomainsController_changeStatus_v1'> {
  return values.reason
    ? { status: values.status, reason: values.reason }
    : { status: values.status };
}

const INVALIDATES = [
  'DomainsController_get_v1',
  'DomainsController_list_v1',
  'DomainDnsController_status_v1',
] as const;

/** Activate / suspend / reactivate (the transitions `PATCH /domains/{id}/status` accepts). */
export function DomainStatusActions({
  domain,
  onActivated,
}: {
  domain: DomainDetail;
  onActivated?: () => void;
}) {
  const [target, setTarget] = useState<'active' | 'suspended' | null>(null);
  const [reason, setReason] = useState('');
  const [reasonError, setReasonError] = useState<string | null>(null);
  const reasonId = useId();
  const change = useApiMutation('DomainsController_changeStatus_v1', {
    invalidates: INVALIDATES,
    successMessage: null,
  });
  const canActivate = domain.status === 'verified' || domain.status === 'suspended';
  const canSuspend = domain.status === 'active';
  if (!canActivate && !canSuspend) return null;

  return (
    <Can op="DomainsController_changeStatus_v1">
      {canActivate ? (
        <Button onClick={() => setTarget('active')}>
          {domain.status === 'suspended' ? 'Reactivate' : 'Activate domain'}
        </Button>
      ) : null}
      {canSuspend ? (
        <Button variant="outline" onClick={() => setTarget('suspended')}>
          Suspend
        </Button>
      ) : null}
      <ConfirmDialog
        open={target !== null}
        onOpenChange={(open) => {
          if (!open) {
            setTarget(null);
            setReason('');
            setReasonError(null);
            change.reset();
          }
        }}
        title={
          target === 'suspended'
            ? `Suspend ${domain.unicodeName}?`
            : `Activate ${domain.unicodeName}?`
        }
        confirmLabel={target === 'suspended' ? 'Suspend domain' : 'Activate'}
        destructive={target === 'suspended'}
        description={
          target === 'suspended' ? (
            <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
              <p>While suspended, the gateway refuses mail for this domain.</p>
              <div className="grid gap-2">
                <Label htmlFor={reasonId}>Reason (required)</Label>
                <Textarea
                  id={reasonId}
                  value={reason}
                  maxLength={512}
                  onChange={(event) => setReason(event.target.value)}
                  aria-invalid={reasonError ? true : undefined}
                  aria-describedby={reasonError ? `${reasonId}-error` : undefined}
                />
                {reasonError ? (
                  <p id={`${reasonId}-error`} className="text-xs font-medium text-destructive">
                    {reasonError}
                  </p>
                ) : null}
              </div>
            </div>
          ) : (
            <p>
              The gateway starts accepting mail for this domain. Point the MX record to the gateway
              afterwards; mail arriving during DNS propagation is accepted.
            </p>
          )
        }
        error={<MutationError error={change.error} />}
        onConfirm={async () => {
          if (!target) return false;
          const parsed = domainStatusSchema.safeParse({ status: target, reason });
          if (!parsed.success) {
            setReasonError(parsed.error.issues[0]?.message ?? 'Invalid');
            return false;
          }
          setReasonError(null);
          const outcome = await change.submit({
            path: { id: domain.id },
            body: domainStatusBody(parsed.data),
          });
          if (outcome.ok && target === 'active') onActivated?.();
          return outcome.ok;
        }}
      />
    </Can>
  );
}

/** Delete (soft) with typed confirmation; an active domain must be suspended first (409). */
export function DeleteDomainButton({ domain }: { domain: DomainDetail }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const remove = useApiMutation('DomainsController_remove_v1', {
    successMessage: `${domain.unicodeName} deleted.`,
    invalidates: ['DomainsController_list_v1'],
  });
  const blocked = domain.status === 'active';
  return (
    <Can op="DomainsController_remove_v1">
      <Button
        variant="ghost"
        onClick={() => setOpen(true)}
        disabled={blocked}
        title={blocked ? 'Suspend the domain before deleting it' : undefined}
      >
        Delete domain
      </Button>
      {blocked ? (
        <span className="text-xs text-muted-foreground">
          Suspend the domain before deleting it.
        </span>
      ) : null}
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) remove.reset();
        }}
        title={`Delete ${domain.unicodeName}?`}
        description="The domain, its DNS checks and its settings are removed. Mail for it is refused. You can add the name again later as a new domain."
        confirmLabel="Delete domain"
        destructive
        typedConfirmation={domain.name}
        error={<MutationError error={remove.error} />}
        onConfirm={async () => {
          const outcome = await remove.submit({ path: { id: domain.id } });
          if (outcome.ok) router.push('/domains');
          return outcome.ok;
        }}
      />
    </Can>
  );
}
