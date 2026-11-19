'use client';

import { useId, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useApiMutation } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { AtoErrorSummary, AtoReasonDialog } from './components';
import {
  TRUSTED_CONTEXT_KINDS,
  type AtoAccountDetail,
  type AtoTrustedContext,
  type TrustedContextKind,
} from './model';

/**
 * Analyst controls of an account (§5.1 #5, #10–#13; `ato:manage`, users only): protection, the
 * benign/compromised override with its expiry, clearing it, adding and removing trusted contexts.
 * Every control asks for a reason; one Idempotency-Key per intent (reused by "Retry").
 */

const INVALIDATES = [
  'AtoAccountsController_get_v1',
  'AtoAccountsController_list_v1',
  'AtoAccountsController_scoreHistory_v1',
  'AtoOverviewController_overview_v1',
] as const;

export function ProtectControl({ account }: { account: AtoAccountDetail }) {
  const can = useCan('AtoAccountsController_update_v1');
  const [open, setOpen] = useState(false);
  const mutation = useApiMutation('AtoAccountsController_update_v1', {
    invalidates: INVALIDATES,
    successMessage: account.protected
      ? 'Protection removed'
      : 'Account protected from automatic responses',
  });
  if (!can) return null;
  const next = !account.protected;
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        {account.protected ? 'Remove protection' : 'Protect account'}
      </Button>
      <AtoReasonDialog
        open={open}
        onOpenChange={setOpen}
        title={account.protected ? 'Remove protection?' : 'Protect this account?'}
        description={
          next
            ? 'A protected account is never acted on automatically: medium and high-impact responses always need an approval. Detection and incidents continue.'
            : 'Automatic responses may act on this account again when the tenant’s automation conditions hold.'
        }
        confirmLabel={account.protected ? 'Remove protection' : 'Protect'}
        minChars={1}
        maxChars={512}
        pending={mutation.isPending}
        onSubmit={(reason) =>
          mutation.submit({
            path: { accountId: account.id },
            body: {
              protected: next,
              reason: reason ?? null,
              expectedRowVersion: account.rowVersion,
            },
          })
        }
        onRetry={mutation.retry}
      />
    </>
  );
}

const EXPIRY_OPTIONS = [
  { value: 24, label: '1 day' },
  { value: 72, label: '3 days' },
  { value: 168, label: '7 days' },
  { value: 336, label: '14 days' },
  { value: 720, label: '30 days' },
];

export function OverrideControls({ account }: { account: AtoAccountDetail }) {
  const canSet = useCan('AtoAccountsController_setOverride_v1');
  const canClear = useCan('AtoAccountsController_clearOverride_v1');
  const [open, setOpen] = useState<'set' | 'clear' | null>(null);
  const [verdict, setVerdict] = useState<'benign' | 'compromised'>('benign');
  const [hours, setHours] = useState(72);
  const verdictId = useId();
  const hoursId = useId();
  const set = useApiMutation('AtoAccountsController_setOverride_v1', {
    invalidates: INVALIDATES,
    successMessage: 'Override set; the account was rescored',
  });
  const clear = useApiMutation('AtoAccountsController_clearOverride_v1', {
    invalidates: INVALIDATES,
    successMessage: 'Override cleared; the account was rescored',
  });
  return (
    <div className="flex flex-wrap gap-2">
      {canSet ? (
        <Button variant="outline" size="sm" onClick={() => setOpen('set')}>
          {account.override ? 'Change override' : 'Set override'}
        </Button>
      ) : null}
      {canClear && account.override ? (
        <Button variant="outline" size="sm" onClick={() => setOpen('clear')}>
          Clear override
        </Button>
      ) : null}
      <AtoReasonDialog
        open={open === 'set'}
        onOpenChange={(next) => setOpen(next ? 'set' : null)}
        title="Set an analyst override"
        description="Benign caps the score below the medium band until a strong signal contradicts it; compromised raises the score to at least 90. The account is rescored at once."
        confirmLabel="Set override"
        pending={set.isPending}
        extra={
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor={verdictId}>Verdict</Label>
              <Select value={verdict} onValueChange={(v) => setVerdict(v as typeof verdict)}>
                <SelectTrigger id={verdictId}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="benign">Benign (expected activity)</SelectItem>
                  <SelectItem value="compromised">Compromised</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor={hoursId}>Expires after</Label>
              <Select value={String(hours)} onValueChange={(v) => setHours(Number(v))}>
                <SelectTrigger id={hoursId}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {EXPIRY_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={String(o.value)}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        }
        onSubmit={(reason) =>
          set.submit({
            path: { accountId: account.id },
            body: { verdict, reason: reason ?? '', expiresInHours: hours },
          })
        }
        onRetry={set.retry}
      />
      <AtoReasonDialog
        open={open === 'clear'}
        onOpenChange={(next) => setOpen(next ? 'clear' : null)}
        title="Clear the override?"
        description="The score returns to what the stored signals give; the account is rescored at once."
        confirmLabel="Clear override"
        pending={clear.isPending}
        onSubmit={(reason) =>
          clear.submit({ path: { accountId: account.id }, body: { reason: reason ?? '' } })
        }
        onRetry={clear.retry}
      />
    </div>
  );
}

const KIND_TEXT: Record<TrustedContextKind, { label: string; placeholder: string }> = {
  ip_cidr: { label: 'IP network (CIDR)', placeholder: '198.51.100.0/24' },
  asn: { label: 'Autonomous system number', placeholder: '64500' },
  country: { label: 'Country code (ISO 3166-1)', placeholder: 'GB' },
  device: { label: 'Device fingerprint', placeholder: 'device hash from the sign-ins tab' },
};

export function trustedKindLabel(kind: string): string {
  return KIND_TEXT[kind as TrustedContextKind]?.label ?? kind;
}

/** The trusted-context fields shared by the account tab and the false-positive feedback. */
export function TrustedContextFields({
  kind,
  value,
  days,
  onKind,
  onValue,
  onDays,
}: {
  kind: TrustedContextKind;
  value: string;
  days: number;
  onKind: (kind: TrustedContextKind) => void;
  onValue: (value: string) => void;
  onDays: (days: number) => void;
}) {
  const kindId = useId();
  const valueId = useId();
  const daysId = useId();
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <div className="grid gap-1.5">
        <Label htmlFor={kindId}>Kind</Label>
        <Select value={kind} onValueChange={(v) => onKind(v as TrustedContextKind)}>
          <SelectTrigger id={kindId}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TRUSTED_CONTEXT_KINDS.map((k) => (
              <SelectItem key={k} value={k}>
                {KIND_TEXT[k].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor={valueId}>Value</Label>
        <Input
          id={valueId}
          value={value}
          maxLength={64}
          placeholder={KIND_TEXT[kind].placeholder}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => onValue(event.target.value)}
        />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor={daysId}>Expires after (days)</Label>
        <Input
          id={daysId}
          type="number"
          inputMode="numeric"
          min={1}
          max={365}
          value={String(days)}
          onChange={(event) => onDays(Number(event.target.value))}
        />
      </div>
    </div>
  );
}

export function AddTrustedContext({ accountId }: { accountId: string }) {
  const can = useCan('AtoAccountsController_addTrustedContext_v1');
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<TrustedContextKind>('ip_cidr');
  const [value, setValue] = useState('');
  const [days, setDays] = useState(90);
  const mutation = useApiMutation('AtoAccountsController_addTrustedContext_v1', {
    invalidates: INVALIDATES,
    successMessage: 'Trusted context added',
  });
  if (!can) return null;
  const valid = value.trim().length > 0 && Number.isInteger(days) && days >= 1 && days <= 365;
  return (
    <>
      <Button size="sm" onClick={() => setOpen(true)}>
        Add trusted context
      </Button>
      <AtoReasonDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) setValue('');
        }}
        title="Add a trusted context"
        description="Sign-ins from a trusted network, ASN, country or device do not raise access, geography or reputation signals for this account until the context expires."
        confirmLabel="Add"
        minChars={1}
        maxChars={512}
        disabled={!valid}
        pending={mutation.isPending}
        extra={
          <>
            <TrustedContextFields
              kind={kind}
              value={value}
              days={days}
              onKind={setKind}
              onValue={setValue}
              onDays={setDays}
            />
            {!valid ? (
              <p className="text-xs text-muted-foreground">
                Enter a value and an expiry of 1–365 days.
              </p>
            ) : null}
          </>
        }
        onSubmit={(reason) =>
          mutation.submit({
            path: { accountId },
            body: { kind, value: value.trim(), reason: reason ?? '', expiresInDays: days },
          })
        }
        onRetry={mutation.retry}
      />
    </>
  );
}

export function RemoveTrustedContext({
  accountId,
  context,
}: {
  accountId: string;
  context: AtoTrustedContext;
}) {
  const can = useCan('AtoAccountsController_removeTrustedContext_v1');
  const [open, setOpen] = useState(false);
  const mutation = useApiMutation('AtoAccountsController_removeTrustedContext_v1', {
    invalidates: INVALIDATES,
    successMessage: 'Trusted context removed',
  });
  if (!can) return null;
  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        onClick={() => setOpen(true)}
        aria-label={`Remove trusted context ${context.value}`}
      >
        Remove
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) mutation.reset();
        }}
        title="Remove this trusted context?"
        description={`Sign-ins matching ${context.value} are evaluated normally again. The removal is audited.`}
        confirmLabel="Remove"
        destructive
        pending={mutation.isPending}
        onConfirm={async () =>
          (await mutation.submit({ path: { accountId, contextId: context.id } })).ok
        }
        error={mutation.error ? <AtoErrorSummary error={mutation.error} /> : null}
      />
    </>
  );
}
