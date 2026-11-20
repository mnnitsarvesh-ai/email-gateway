'use client';

import { ShieldAlertIcon } from 'lucide-react';
import { CopyButton } from '@/components/copy-button';
import { ToneBadge } from '@/components/domain';
import { FormErrorSummary } from '@/components/form';
import { Button } from '@/components/ui/button';
import type { ApiError } from '@/lib/api/errors';
import { humanize } from '@/lib/format';
import { emitSessionEvent } from '@/lib/session/events';
import { useMfaSession } from '../components';
import {
  CAPABILITY_VIEW_TONE,
  HEALTH_TONE,
  INTEGRATION_STATUS_TONE,
  capabilityViewText,
  codeText,
  explainProviderError,
  healthText,
  type ProviderProfileView,
} from './model';

/** Health of an integration (label always printed; "stale" when the last probe is old). */
export function HealthBadge({ status, stale = false }: { status: string; stale?: boolean }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <ToneBadge tone={HEALTH_TONE[status] ?? 'neutral'}>{healthText(status)}</ToneBadge>
      {stale ? <ToneBadge tone="warning">Health check out of date</ToneBadge> : null}
    </span>
  );
}

export function IntegrationStatusBadge({ status }: { status: string }) {
  return (
    <ToneBadge tone={INTEGRATION_STATUS_TONE[status] ?? 'neutral'}>
      {status === 'disabled' ? 'Removed' : humanize(status)}
    </ToneBadge>
  );
}

export function CapabilityBadge({ value }: { value: string }) {
  return (
    <ToneBadge tone={CAPABILITY_VIEW_TONE[value] ?? 'neutral'}>
      {capabilityViewText(value)}
    </ToneBadge>
  );
}

/** A provider code as text with the code itself (never colour or text only). */
export function CodeText({ code }: { code: string | null | undefined }) {
  if (!code) return <span className="text-muted-foreground">—</span>;
  return (
    <span>
      {codeText(code)} <span className="font-mono text-xs text-muted-foreground">({code})</span>
    </span>
  );
}

/** The api's coded error explained, with its code and request id. */
export function ProviderErrorSummary({ error }: { error: ApiError }) {
  return (
    <FormErrorSummary
      messages={[...explainProviderError(error), `Code: ${error.code}`]}
      requestId={error.requestId}
    />
  );
}

/**
 * The MFA prompt of the routes that need an MFA session (connect, settings, removal; §6): the
 * control stays disabled and the user can sign in again with MFA. The api decides.
 */
export function MfaPrompt({ action }: { action: string }) {
  return (
    <div
      role="note"
      className="flex items-start gap-2 rounded-md border border-border bg-tone-warning px-3 py-2 text-xs text-tone-warning-foreground"
    >
      <ShieldAlertIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="grid gap-1.5">
        <p>
          {action} needs a session signed in with multi-factor authentication (MFA). Your current
          session was not.
        </p>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="justify-self-start"
          onClick={() => emitSessionEvent({ type: 'mfa-required' })}
        >
          Sign in again with MFA
        </Button>
      </div>
    </div>
  );
}

export { useMfaSession };

/** Permission or scope names with a copy button each (administrators paste them into consent). */
export function PermissionNames({
  names,
  emptyLabel = 'None',
  tone,
}: {
  names: readonly string[];
  emptyLabel?: string;
  tone?: 'danger' | 'success';
}) {
  if (names.length === 0) return <span className="text-muted-foreground">{emptyLabel}</span>;
  return (
    <ul className="grid gap-1">
      {names.map((name) => (
        <li key={name} className="flex min-w-0 items-center gap-1">
          <code
            className={
              tone === 'danger'
                ? 'font-mono text-xs break-all text-destructive'
                : 'font-mono text-xs break-all'
            }
          >
            {name}
          </code>
          <CopyButton value={name} label={`Copy ${name}`} />
        </li>
      ))}
    </ul>
  );
}

/** Required / granted / missing permissions of each profile (D5, D6). */
export function ProfileTable({
  profiles,
  caption,
}: {
  profiles: readonly ProviderProfileView[];
  caption: string;
}) {
  return (
    <div
      role="group"
      aria-label={caption}
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable region
      tabIndex={0}
      className="min-w-0 overflow-x-auto rounded-md border"
    >
      <table className="w-full min-w-[36rem] text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="bg-muted/50 text-xs text-muted-foreground">
          <tr>
            {['Profile', 'Required', 'Grant', 'Missing'].map((h) => (
              <th key={h} scope="col" className="px-2 py-1.5 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {profiles.map((p) => (
            <tr key={p.profile} className="border-t align-top">
              <th scope="row" className="px-2 py-1.5 font-normal">
                <span className="font-medium">{p.title}</span>
                <span className="block text-xs text-muted-foreground">
                  {p.purpose === 'ato_telemetry' ? 'Telemetry (read only)' : 'Response actions'}
                  {p.readOnly ? '' : ' · writes'}
                </span>
              </th>
              <td className="px-2 py-1.5">
                <PermissionNames names={p.required} />
                {p.notObservable.length > 0 ? (
                  <p className="mt-1 text-xs text-muted-foreground">
                    {p.notObservable.join(', ')}: proven by the health check only.
                  </p>
                ) : null}
              </td>
              <td className="px-2 py-1.5">
                {p.grant ? (
                  <span className="grid gap-0.5">
                    <ToneBadge
                      tone={
                        p.grant.status === 'active'
                          ? 'success'
                          : p.grant.status === 'pending'
                            ? 'info'
                            : 'danger'
                      }
                    >
                      {humanize(p.grant.status)}
                    </ToneBadge>
                    {p.grant.observed === null ? (
                      <span className="text-xs text-muted-foreground">Not verified yet</span>
                    ) : null}
                  </span>
                ) : (
                  <span className="text-muted-foreground">Not granted</span>
                )}
              </td>
              <td className="px-2 py-1.5">
                {p.grant ? (
                  <PermissionNames names={p.grant.missing} tone="danger" />
                ) : (
                  <PermissionNames names={p.required} tone="danger" />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
