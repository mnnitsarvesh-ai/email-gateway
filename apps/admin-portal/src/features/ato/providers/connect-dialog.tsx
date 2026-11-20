'use client';

import { useRouter } from 'next/navigation';
import { useId, useMemo, useState } from 'react';
import { ToneBadge } from '@/components/domain';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { humanize } from '@/lib/format';
import { FormDialog } from '@/features/domains/kit';
import { MfaPrompt, ProfileTable, ProviderErrorSummary, useMfaSession } from './components';
import {
  CONNECTION_PROVIDER_LABELS,
  ELIGIBILITY_TONE,
  PROVIDER_LABELS,
  PROVIDER_QUERIES,
  SETTINGS_BOUNDS,
  STREAM_LABELS,
  codeText,
  defaultBindingSettings,
  providerHref,
  type ProviderCandidate,
  type ProviderRequirement,
  type ProviderStream,
} from './model';

/**
 * "Connect identity provider" (§7, §6 #2–#4): pick an eligible step 8.2 connection, see the
 * required and granted permissions per profile, choose the streams and the backfill days, confirm
 * (an MFA session is needed). The settings sent are the full `ato-idp-binding/1` defaults with the
 * chosen streams and backfill; the api validates them and decides eligibility.
 */
export function ConnectProviderDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <FormDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Connect an identity provider"
      description="Account takeover detection reads sign-ins, risk events, OAuth consents and mailbox changes through a Microsoft 365 or Google Workspace connection of this organization."
      wide
    >
      {open ? <ConnectForm onDone={() => onOpenChange(false)} /> : null}
    </FormDialog>
  );
}

function ConnectForm({ onDone }: { onDone: () => void }) {
  const router = useRouter();
  const mfa = useMfaSession();
  const connections = useApiQuery('AtoProvidersController_connections_v1', undefined, {
    retry: false,
  });
  const requirements = useApiQuery('AtoProvidersController_requirements_v1');
  const [connectionId, setConnectionId] = useState<string>('');
  const [streams, setStreams] = useState<Partial<Record<ProviderStream, boolean>>>({});
  const [backfill, setBackfill] = useState<string>(String(defaultBindingSettings().backfillDays));
  const backfillId = useId();
  const create = useApiMutation('AtoProvidersController_create_v1', {
    invalidates: PROVIDER_QUERIES,
    successMessage: 'Identity provider connected',
  });

  const candidates = connections.data?.data ?? [];
  const selected = candidates.find((c) => c.id === connectionId) ?? null;
  const requirement: ProviderRequirement | null =
    (selected?.kind && requirements.data?.providers.find((p) => p.provider === selected.kind)) ||
    null;
  const offered = useMemo(
    () => (requirement?.streams ?? []).filter((s) => s.role !== 'unsupported'),
    [requirement],
  );
  const enabled = (stream: ProviderStream): boolean => streams[stream] ?? true;
  const backfillDays = Number(backfill);
  const backfillOk =
    backfill.trim() !== '' &&
    Number.isInteger(backfillDays) &&
    backfillDays >= SETTINGS_BOUNDS.backfillDays.min &&
    backfillDays <= SETTINGS_BOUNDS.backfillDays.max;

  if (connections.isLoading || requirements.isLoading) {
    return <LoadingState label="Loading the connections" rows={3} />;
  }
  if (connections.error) {
    return (
      <ErrorState error={connections.error} onRetry={() => void connections.refetch()} compact />
    );
  }
  if (requirements.error) {
    return (
      <ErrorState error={requirements.error} onRetry={() => void requirements.refetch()} compact />
    );
  }
  const limit = connections.data?.limit;
  const atLimit = limit ? limit.used >= limit.max : false;

  const submit = async () => {
    if (!selected || !backfillOk) return;
    const settings = defaultBindingSettings();
    for (const s of offered) settings.streams[s.stream].enabled = enabled(s.stream);
    // A companion follows its primary (D10): it is sent disabled with a disabled primary.
    for (const s of offered) {
      if (s.role === 'companion' && s.primary && !enabled(s.primary)) {
        settings.streams[s.stream].enabled = false;
      }
    }
    settings.backfillDays = backfillDays;
    const outcome = await create.submit({
      body: { connectionId: selected.id, settings },
    });
    if (outcome.ok) {
      onDone();
      router.push(providerHref(outcome.data.id));
    }
  };

  return (
    <div className="grid gap-4">
      {candidates.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          This organization has no Microsoft 365 or Google Workspace connection yet. Create one in
          Integrations first, with the account takeover telemetry permissions.
        </p>
      ) : (
        <fieldset className="grid gap-2">
          <legend className="mb-1 text-sm font-medium">Connection</legend>
          <RadioGroup value={connectionId} onValueChange={setConnectionId} aria-label="Connection">
            {candidates.map((c) => (
              <CandidateRow key={c.id} candidate={c} />
            ))}
          </RadioGroup>
        </fieldset>
      )}
      {limit ? (
        <p className="text-xs text-muted-foreground">
          {limit.used} of {limit.max} identity providers in use.
          {atLimit ? ' Remove one before connecting another.' : ''}
        </p>
      ) : null}
      {selected && requirement ? (
        <>
          <div className="grid gap-2">
            <h3 className="text-sm font-medium">Permissions</h3>
            <ProfileTable
              profiles={selected.profiles}
              caption="Required and granted permissions of the connection"
            />
            <p className="text-xs text-muted-foreground">
              Missing response permissions only make those actions unavailable; telemetry needs its
              profile. Grant permissions in the connection’s Setup tab.
            </p>
          </div>
          <fieldset className="grid gap-2">
            <legend className="mb-1 text-sm font-medium">Streams</legend>
            <ul className="grid gap-2 sm:grid-cols-2">
              {offered.map((s) => {
                const blocked = s.role === 'companion' && s.primary !== null && !enabled(s.primary);
                const id = `stream-${s.stream}`;
                return (
                  <li key={s.stream} className="flex items-start gap-2">
                    <Checkbox
                      id={id}
                      checked={enabled(s.stream) && !blocked}
                      disabled={blocked}
                      onCheckedChange={(checked) =>
                        setStreams((prev) => ({ ...prev, [s.stream]: checked === true }))
                      }
                    />
                    <Label htmlFor={id} className="grid gap-0.5 text-sm font-normal">
                      <span>{STREAM_LABELS[s.stream]}</span>
                      <span className="text-xs text-muted-foreground">
                        {s.role === 'companion' && s.primary
                          ? `Read together with ${STREAM_LABELS[s.primary].toLowerCase()}`
                          : s.licences.length > 0
                            ? `Needs ${s.licences.join(', ')}`
                            : 'Polled'}
                      </span>
                    </Label>
                  </li>
                );
              })}
            </ul>
          </fieldset>
          <div className="grid gap-1.5">
            <Label htmlFor={backfillId}>Backfill days</Label>
            <Input
              id={backfillId}
              type="number"
              inputMode="numeric"
              className="w-32"
              min={SETTINGS_BOUNDS.backfillDays.min}
              max={SETTINGS_BOUNDS.backfillDays.max}
              value={backfill}
              aria-invalid={backfillOk ? undefined : true}
              aria-describedby={`${backfillId}-help`}
              onChange={(e) => setBackfill(e.target.value)}
            />
            <p id={`${backfillId}-help`} className="text-xs text-muted-foreground">
              History read once in historical mode (no alerts, baselines only):{' '}
              {SETTINGS_BOUNDS.backfillDays.min}–{SETTINGS_BOUNDS.backfillDays.max} days, limited by
              the provider’s retention. 0 starts from now.
            </p>
          </div>
        </>
      ) : null}
      {!mfa ? <MfaPrompt action="Connecting an identity provider" /> : null}
      {create.error ? <ProviderErrorSummary error={create.error} /> : null}
      <div className="flex flex-wrap justify-end gap-2">
        <Button type="button" variant="outline" onClick={onDone}>
          Cancel
        </Button>
        <Button
          type="button"
          disabled={
            !mfa ||
            !selected ||
            selected.eligibility !== 'eligible' ||
            !backfillOk ||
            atLimit ||
            create.isPending
          }
          onClick={() => void submit()}
        >
          Connect
        </Button>
      </div>
    </div>
  );
}

function CandidateRow({ candidate: c }: { candidate: ProviderCandidate }) {
  const id = `connection-${c.id}`;
  const disabled = c.eligibility !== 'eligible';
  return (
    <div className="flex items-start gap-2 rounded-md border p-2">
      <RadioGroupItem id={id} value={c.id} disabled={disabled} className="mt-0.5" />
      <Label htmlFor={id} className="grid min-w-0 flex-1 gap-1 text-sm font-normal">
        <span className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{c.displayName}</span>
          <span className="text-xs text-muted-foreground">
            {c.kind
              ? PROVIDER_LABELS[c.kind]
              : (CONNECTION_PROVIDER_LABELS[c.provider] ?? c.provider)}
          </span>
          <ToneBadge tone={ELIGIBILITY_TONE[c.eligibility] ?? 'neutral'}>
            {c.eligibility === 'eligible'
              ? 'Eligible'
              : c.eligibility === 'already_bound'
                ? 'Already connected'
                : humanize(c.eligibility)}
          </ToneBadge>
        </span>
        <span className="text-xs text-muted-foreground">
          Connection {humanize(c.status)} · {c.providerVerifiedDomainCount} verified domain
          {c.providerVerifiedDomainCount === 1 ? '' : 's'}
        </span>
        {c.reasons.length > 0 ? (
          <span className="text-xs text-muted-foreground">
            {c.reasons.map((r) => codeText(r)).join('; ')}
          </span>
        ) : null}
      </Label>
    </div>
  );
}
