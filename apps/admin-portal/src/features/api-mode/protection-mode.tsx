'use client';

import { AlertTriangleIcon } from 'lucide-react';
import Link from 'next/link';
import { useId, useState } from 'react';
import { DateTime } from '@/components/domain/date-time';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Textarea } from '@/components/ui/textarea';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan, useMe } from '@/lib/auth/me';
import { formatNumber } from '@/lib/format';
import { cn } from '@/lib/utils';
import { DetailList, Section } from '@/features/domains/kit';
import type { DomainDetail } from '@/features/domains/model';
import {
  MODE_EXPLANATION,
  MODE_LABEL,
  NOT_ENTITLED_REASON,
  PROTECTION_MODES,
  ProtectionModeBadge,
  needsEntitlement,
  protectionModeErrorText,
  type DomainModeChoice,
  type OrganizationProtectionMode,
  type ProtectionMode,
} from './model';

/** Reason of a mode change: 1–500 characters, stored in the audit metadata only (D2). */
export const REASON_MAX = 500;

export function reasonError(reason: string): string | null {
  const trimmed = reason.trim();
  if (trimmed.length === 0) return 'Enter a reason.';
  if (trimmed.length > REASON_MAX) return `Use at most ${REASON_MAX} characters.`;
  return null;
}

const MODE_QUERIES: readonly OperationId[] = [
  'DomainsController_get_v1',
  'DomainsController_list_v1',
  'ProtectionModeController_getOrganization_v1',
  'OrganizationsController_get_v1',
  'ApiModeController_overview_v1',
  'ApiModeController_listConnections_v1',
];

/**
 * The organization's protection-mode block (D2, `GET /organizations/{id}/protection-mode`; the
 * acting organization by default). `data` stays undefined without `organization:read`: the
 * options are then all offered and the api decides on submit (`403 api_mode_not_enabled`).
 */
export function useOrganizationProtectionMode(organizationId?: string): {
  data: OrganizationProtectionMode | undefined;
  isLoading: boolean;
  error: ApiError | null;
} {
  const me = useMe();
  const id = organizationId ?? me.data?.organization.id;
  const canRead = useCan('ProtectionModeController_getOrganization_v1');
  const query = useApiQuery(
    'ProtectionModeController_getOrganization_v1',
    { path: { id: id ?? '' } },
    { enabled: canRead && Boolean(id), retry: false },
  );
  return {
    data: query.data,
    isLoading: me.isLoading || (canRead && Boolean(id) && query.isLoading),
    error: query.error,
  };
}

/**
 * The mode options as explained cards (wizard step, change dialogs). Without the entitlement the
 * API and Hybrid cards are disabled with the reason (D1); `inherit` names the organization mode.
 */
export function ModeOptions({
  value,
  onChange,
  choices = PROTECTION_MODES,
  entitled,
  organizationMode,
  legend,
  compact = false,
}: {
  value: DomainModeChoice;
  onChange: (value: DomainModeChoice) => void;
  choices?: readonly DomainModeChoice[];
  entitled: boolean;
  organizationMode?: ProtectionMode;
  legend: string;
  compact?: boolean;
}) {
  const base = useId();
  const reasonId = `${base}-not-entitled`;
  const anyDisabled = !entitled && choices.some(needsEntitlement);
  return (
    <fieldset className="grid min-w-0 gap-2">
      <legend className="mb-2 text-sm font-semibold">{legend}</legend>
      <RadioGroup
        value={value}
        onValueChange={(next) => onChange(next as DomainModeChoice)}
        className={cn('grid gap-3', compact ? 'grid-cols-1' : 'lg:grid-cols-3')}
        aria-describedby={anyDisabled ? reasonId : undefined}
      >
        {choices.map((choice) => {
          const id = `${base}-${choice}`;
          const disabled = !entitled && needsEntitlement(choice);
          const title =
            choice === 'inherit'
              ? `Inherit from organization${organizationMode ? ` (${MODE_LABEL[organizationMode]})` : ''}`
              : MODE_LABEL[choice];
          const text =
            choice === 'inherit'
              ? 'Follow the organization’s mode; a later change of the organization mode applies to this domain too.'
              : MODE_EXPLANATION[choice];
          return (
            <label
              key={choice}
              htmlFor={id}
              className={cn(
                'flex items-start gap-3 rounded-md border p-3 has-[[data-state=checked]]:border-primary',
                disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer',
              )}
            >
              <RadioGroupItem id={id} value={choice} className="mt-1" disabled={disabled} />
              <span className="grid gap-1">
                <span className="font-medium">{title}</span>
                <span className="text-xs text-muted-foreground">{text}</span>
                {disabled ? (
                  <span className="text-xs font-medium text-muted-foreground">
                    Not available on your plan
                  </span>
                ) : null}
              </span>
            </label>
          );
        })}
      </RadioGroup>
      {anyDisabled ? (
        <p id={reasonId} className="text-xs text-muted-foreground">
          {NOT_ENTITLED_REASON}
        </p>
      ) : null}
    </fieldset>
  );
}

function ModeErrorBlock({ error }: { error: ApiError | null }) {
  if (!error) return null;
  const text = protectionModeErrorText(error);
  return (
    <div className="grid gap-2" role="alert">
      {text ? <p className="text-sm font-medium text-destructive">{text}</p> : null}
      <ErrorState error={error} compact />
    </div>
  );
}

function ReasonField({
  value,
  onChange,
  error,
}: {
  value: string;
  onChange: (value: string) => void;
  error: string | null;
}) {
  const id = useId();
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>
        Reason <span className="text-xs font-normal text-muted-foreground">(required)</span>
      </Label>
      <Textarea
        id={id}
        rows={3}
        value={value}
        maxLength={REASON_MAX}
        onChange={(event) => onChange(event.target.value)}
        aria-invalid={error ? true : undefined}
        aria-describedby={`${id}-hint${error ? ` ${id}-error` : ''}`}
      />
      <p id={`${id}-hint`} className="text-xs text-muted-foreground">
        1 to {REASON_MAX} characters; recorded in the audit log.
      </p>
      {error ? (
        <p id={`${id}-error`} className="text-xs font-medium text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}

/** `PUT /domains/{domainId}/protection-mode` (mode incl. `inherit`, reason; D2). */
export function ChangeDomainModeDialog({
  domain,
  open,
  onOpenChange,
}: {
  domain: Pick<DomainDetail, 'id' | 'unicodeName' | 'protectionMode'>;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const organization = useOrganizationProtectionMode();
  const current: DomainModeChoice = domain.protectionMode.inherited
    ? 'inherit'
    : (domain.protectionMode.configured ?? 'inherit');
  const [mode, setMode] = useState<DomainModeChoice>(current);
  const [reason, setReason] = useState('');
  const [touched, setTouched] = useState(false);
  const change = useApiMutation('ProtectionModeController_putDomain_v1', {
    invalidates: MODE_QUERIES,
    successMessage: null,
  });
  const problem = reasonError(reason);
  const entitled = organization.data?.entitled ?? true;
  const close = (next: boolean) => {
    if (change.isPending) return;
    if (!next) {
      setMode(current);
      setReason('');
      setTouched(false);
      change.reset();
    }
    onOpenChange(next);
  };
  const confirm = async () => {
    setTouched(true);
    if (problem) return;
    const outcome = await change.submit({
      path: { domainId: domain.id },
      body: { mode, reason: reason.trim() },
    });
    if (outcome.ok) close(false);
  };
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Change the protection mode of {domain.unicodeName}</DialogTitle>
          <DialogDescription>
            The mode controls the API side only: inbound and outbound mail flow, destinations and
            connectors are never changed by it. The change is audited.
          </DialogDescription>
        </DialogHeader>
        <ModeOptions
          legend="Protection mode"
          value={mode}
          onChange={setMode}
          choices={['inherit', ...PROTECTION_MODES]}
          entitled={entitled}
          organizationMode={organization.data?.mode}
          compact
        />
        <ReasonField value={reason} onChange={setReason} error={touched ? problem : null} />
        <ModeErrorBlock error={change.error} />
        <DialogFooter>
          <Button variant="outline" onClick={() => close(false)} disabled={change.isPending}>
            Cancel
          </Button>
          <Button onClick={() => void confirm()} disabled={change.isPending}>
            {change.isPending ? 'Saving …' : 'Change mode'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * MX observation of the domain (`GET /domains/{id}/status`): an effective-`api` domain whose MX
 * points to the gateway gets a warning (D2 "Health hint"); nothing changes automatically.
 */
function useMxPointsToGateway(domainId: string, enabled: boolean): boolean {
  const status = useApiQuery(
    'DomainDnsController_status_v1',
    { path: { id: domainId } },
    { enabled },
  );
  return (status.data?.checks.mx.observed ?? []).some((record) => record.pointsToGateway);
}

export function ApiModeMxWarning({ domainName }: { domainName: string }) {
  return (
    <p
      role="status"
      className="flex items-start gap-2 rounded-md bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground"
    >
      <AlertTriangleIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <span>
        {domainName} is in API mode, but its MX record points to the gateway: mail reaches the
        gateway inline while the domain is not protected inline. Change the mode to Hybrid, or move
        the MX record to your provider.
      </span>
    </p>
  );
}

/** "Protection mode" panel of the domain page (D14): effective, set or inherited, change. */
export function DomainProtectionModePanel({ domain }: { domain: DomainDetail }) {
  const [open, setOpen] = useState(false);
  const mode = domain.protectionMode;
  const mxToGateway = useMxPointsToGateway(domain.id, mode.effective === 'api');
  return (
    <Section
      title="Protection mode"
      description="How the gateway protects this domain: inline through the MX record, through the provider's API without an MX change, or both."
      actions={
        <Can op="ProtectionModeController_putDomain_v1">
          <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
            Change mode
          </Button>
        </Can>
      }
    >
      <DetailList
        items={[
          {
            label: 'Effective mode',
            value: <ProtectionModeBadge mode={mode.effective} inherited={mode.inherited} />,
          },
          {
            label: 'Set on',
            value: mode.inherited
              ? 'Inherited from the organization (no mode of its own)'
              : `This domain (${MODE_LABEL[mode.effective]})`,
          },
          { label: 'What it means', value: MODE_EXPLANATION[mode.effective] },
          {
            label: 'Changed',
            value: <DateTime value={mode.changedAt} emptyLabel="Never" />,
          },
        ]}
      />
      {mode.effective === 'api' && mxToGateway ? (
        <ApiModeMxWarning domainName={domain.unicodeName} />
      ) : null}
      {mode.effective !== 'inline' ? (
        <p className="text-sm">
          <Link href="/api-mode" className="text-primary underline underline-offset-2">
            Open mailbox protection
          </Link>{' '}
          for coverage, connections and detections.
        </p>
      ) : null}
      {open ? <ChangeDomainModeDialog domain={domain} open={open} onOpenChange={setOpen} /> : null}
    </Section>
  );
}

/**
 * How many of the organization's domains inherit its mode: counted from the tenant's domain list
 * (first 100 rows) when the viewer acts in that organization; `null` when unknown.
 */
function useInheritingDomains(organizationId: string): { count: number; more: boolean } | null {
  const me = useMe();
  const own = me.data?.organization.id === organizationId;
  const canList = useCan('DomainsController_list_v1');
  const list = useCursorList('DomainsController_list_v1', undefined, {
    limit: 100,
    enabled: own && canList,
  });
  if (!own || !canList || !list.query.data) return null;
  return {
    count: list.rows.filter((row) => row.protectionMode.inherited).length,
    more: list.hasNext,
  };
}

/** `PUT /organizations/{id}/protection-mode` (D2): mode, reason, inheriting domains stated. */
function ChangeOrganizationModeDialog({
  organizationId,
  organizationName,
  current,
  open,
  onOpenChange,
}: {
  organizationId: string;
  organizationName: string;
  current: OrganizationProtectionMode;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [mode, setMode] = useState<ProtectionMode>(current.mode);
  const [reason, setReason] = useState('');
  const [touched, setTouched] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const inheriting = useInheritingDomains(organizationId);
  const change = useApiMutation('ProtectionModeController_putOrganization_v1', {
    invalidates: MODE_QUERIES,
    successMessage: null,
  });
  const problem = reasonError(reason);
  const close = (next: boolean) => {
    if (change.isPending) return;
    if (!next) {
      setMode(current.mode);
      setReason('');
      setTouched(false);
      setResult(null);
      change.reset();
    }
    onOpenChange(next);
  };
  const confirm = async () => {
    setTouched(true);
    if (problem) return;
    const outcome = await change.submit({
      path: { id: organizationId },
      body: { mode, reason: reason.trim() },
    });
    if (outcome.ok) {
      setResult(
        outcome.data.changed
          ? `Organization mode is now ${MODE_LABEL[outcome.data.mode]}; ${formatNumber(outcome.data.inheritingDomains)} domain${outcome.data.inheritingDomains === 1 ? '' : 's'} inherit it.`
          : `The organization mode already was ${MODE_LABEL[outcome.data.mode]}; nothing changed.`,
      );
    }
  };
  const inheritingText = inheriting
    ? `${formatNumber(inheriting.count)}${inheriting.more ? ' or more' : ''} domain${inheriting.count === 1 && !inheriting.more ? '' : 's'} without a mode of their own inherit${inheriting.count === 1 && !inheriting.more ? 's' : ''} the organization mode and change with it.`
    : 'Domains without a mode of their own inherit the organization mode and change with it; the result names how many.';
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Change the organization protection mode</DialogTitle>
          <DialogDescription asChild>
            <div className="grid gap-1">
              <p>
                The default mode of {organizationName}&apos;s domains. Mail flow, destinations and
                connectors are never changed by it. The change is audited.
              </p>
              <p className="font-medium text-foreground">{inheritingText}</p>
            </div>
          </DialogDescription>
        </DialogHeader>
        {result ? (
          <p role="status" className="rounded-md border p-3 text-sm">
            {result}
          </p>
        ) : (
          <>
            <ModeOptions
              legend="Organization mode"
              value={mode}
              onChange={(next) => setMode(next as ProtectionMode)}
              entitled={current.entitled}
              compact
            />
            <ReasonField value={reason} onChange={setReason} error={touched ? problem : null} />
            <ModeErrorBlock error={change.error} />
          </>
        )}
        <DialogFooter>
          {result ? (
            <Button onClick={() => close(false)}>Done</Button>
          ) : (
            <>
              <Button variant="outline" onClick={() => close(false)} disabled={change.isPending}>
                Cancel
              </Button>
              <Button onClick={() => void confirm()} disabled={change.isPending}>
                {change.isPending ? 'Saving …' : 'Change organization mode'}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Organization mode panel (D14): mode, entitlement, domains per effective mode, change. */
export function OrganizationProtectionModePanel({
  organizationId,
  organizationName,
}: {
  organizationId: string;
  organizationName: string;
}) {
  const [open, setOpen] = useState(false);
  const query = useApiQuery('ProtectionModeController_getOrganization_v1', {
    path: { id: organizationId },
  });
  return (
    <Section
      title="Protection mode"
      description="The default mode of the organization's domains; a domain can set its own."
      actions={
        query.data ? (
          <Can op="ProtectionModeController_putOrganization_v1">
            <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
              Change organization mode
            </Button>
          </Can>
        ) : null
      }
    >
      {query.isLoading ? (
        <LoadingState label="Loading the protection mode" rows={3} />
      ) : query.error ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : query.data ? (
        <>
          <DetailList
            items={[
              { label: 'Organization mode', value: <ProtectionModeBadge mode={query.data.mode} /> },
              { label: 'What it means', value: MODE_EXPLANATION[query.data.mode] },
              {
                label: 'API-mode protection',
                value: query.data.entitled
                  ? query.data.active
                    ? 'Included in the plan; active (at least one domain in API or Hybrid mode)'
                    : 'Included in the plan; not active (no domain in API or Hybrid mode)'
                  : 'Not included in the plan (Inline only)',
              },
              {
                label: 'Changed',
                value: <DateTime value={query.data.changedAt} emptyLabel="Never" />,
              },
            ]}
          />
          <ul className="grid gap-2 sm:grid-cols-3" aria-label="Domains per effective mode">
            {PROTECTION_MODES.map((mode) => (
              <li key={mode} className="grid gap-1 rounded-md border p-3">
                <span className="text-xs text-muted-foreground">{MODE_LABEL[mode]}</span>
                <span className="text-xl font-semibold tabular-nums">
                  {formatNumber(query.data.domainsByEffectiveMode[mode])}
                </span>
                <span className="text-xs text-muted-foreground">
                  domain{query.data.domainsByEffectiveMode[mode] === 1 ? '' : 's'}
                </span>
              </li>
            ))}
          </ul>
          {open ? (
            <ChangeOrganizationModeDialog
              organizationId={organizationId}
              organizationName={organizationName}
              current={query.data}
              open={open}
              onOpenChange={setOpen}
            />
          ) : null}
        </>
      ) : null}
    </Section>
  );
}
