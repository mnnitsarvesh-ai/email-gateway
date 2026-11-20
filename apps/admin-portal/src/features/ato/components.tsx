'use client';

import { ShieldOffIcon } from 'lucide-react';
import { useId, useState, type ReactNode } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { ToneBadge } from '@/components/domain';
import { FormErrorSummary } from '@/components/form';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import type { ApiError } from '@/lib/api/errors';
import type { PagerState } from '@/features/messages/controls';
import { useMe } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { cn } from '@/lib/utils';
import {
  CAPABILITY_TONE,
  KIND_LABELS,
  LEVEL_TONE,
  capabilityText,
  explainAtoError,
  isRetryable,
  labelOf,
  type AtoCapabilities,
} from './model';

/** A risk level badge (label always printed: colour is never the only cue). */
export function LevelBadge({ level }: { level: string | null | undefined }) {
  if (!level) return <span className="text-muted-foreground">—</span>;
  return <ToneBadge tone={LEVEL_TONE[level] ?? 'neutral'}>{humanize(level)}</ToneBadge>;
}

/** An ATO risk score 0–100 with its level (a meter, the number and the level label). */
export function AtoScore({
  score,
  level,
  className,
}: {
  score: number | null | undefined;
  level?: string | null;
  className?: string;
}) {
  if (score === null || score === undefined) {
    return <span className={cn('text-sm text-muted-foreground', className)}>Not scored</span>;
  }
  const value = Math.max(0, Math.min(100, Math.round(score)));
  const tone = level ? (LEVEL_TONE[level] ?? 'neutral') : 'neutral';
  const bar =
    tone === 'danger'
      ? 'bg-destructive'
      : tone === 'orange'
        ? 'bg-chart-3'
        : tone === 'warning'
          ? 'bg-warning'
          : 'bg-primary';
  return (
    <span className={cn('inline-flex items-center gap-2', className)}>
      <span
        role="meter"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={value}
        aria-label={`Account takeover risk score ${value} of 100${level ? `, ${humanize(level)}` : ''}`}
        className="relative h-1.5 w-16 overflow-hidden rounded-full bg-muted"
      >
        <span
          className={cn('absolute inset-y-0 left-0 rounded-full', bar)}
          style={{ width: `${value}%` }}
        />
      </span>
      <span className="font-mono text-sm tabular-nums">{value}</span>
      {level ? <LevelBadge level={level} /> : null}
    </span>
  );
}

export function KindLabel({ kind }: { kind: string }) {
  return <span className="text-xs text-muted-foreground">{labelOf(KIND_LABELS, kind)}</span>;
}

/** The feature-off state (D17: reads answer empty data while `ato_detection` is off). */
export function FeatureOffNotice({ className }: { className?: string }) {
  return (
    <section
      aria-label="Account takeover detection is off"
      className={cn(
        'flex flex-col gap-1 rounded-lg border border-dashed border-input bg-card p-5',
        className,
      )}
    >
      <div className="flex items-center gap-2">
        <ShieldOffIcon className="size-4 text-muted-foreground" aria-hidden />
        <h2 className="text-sm font-semibold">Account takeover detection is off</h2>
      </div>
      <p className="text-sm text-muted-foreground">
        Detection is off by default for every organization. A platform operator enables it per
        organization (feature <code className="font-mono">ato_detection</code>); until then no
        sign-in, SMTP or outbound activity is analysed and nothing is shown here.
      </p>
    </section>
  );
}

/** Whether the signed-in session is MFA-authenticated (approvals and roll-backs need it). */
export function useMfaSession(): boolean {
  const me = useMe();
  return me.data?.session.mfaAuthenticated === true;
}

/** The MFA-required state of an approval or roll-back control. */
export function MfaRequiredNote({ action }: { action: string }) {
  return (
    <p role="note" className="text-xs text-muted-foreground">
      {action} needs a session signed in with MFA. Sign out and sign in again with your
      authenticator to {action.toLowerCase()}.
    </p>
  );
}

const CAPABILITY_ROWS: ReadonlyArray<{ key: keyof AtoCapabilities; label: string }> = [
  { key: 'geoipCity', label: 'GeoIP City (locations, impossible travel)' },
  { key: 'geoipAsn', label: 'GeoIP ASN (networks)' },
  { key: 'geoipAnonymous', label: 'Anonymous IP (VPN, proxy, Tor)' },
  { key: 'dnsbl', label: 'DNS block lists for IPs' },
  { key: 'breachIntel', label: 'Breach intelligence' },
  { key: 'becObservations', label: 'Outbound BEC observations' },
];

/** Worker capabilities (D17): operator data such as MaxMind databases may be missing. */
export function CapabilityList({ capabilities }: { capabilities: AtoCapabilities }) {
  return (
    <div className="grid gap-2">
      {capabilities.status === 'unknown' ? (
        <p role="note" className="text-xs text-muted-foreground">
          The detection worker has not reported its capabilities in the last 15 minutes; every
          capability is shown as unknown.
        </p>
      ) : null}
      <ul className="grid gap-1.5 text-sm" aria-label="Detection capabilities">
        {CAPABILITY_ROWS.map((row) => {
          const state = String(capabilities[row.key]);
          return (
            <li key={row.key} className="flex flex-wrap items-center justify-between gap-2">
              <span>{row.label}</span>
              <ToneBadge tone={CAPABILITY_TONE[state] ?? 'neutral'}>
                {capabilityText(state)}
              </ToneBadge>
            </li>
          );
        })}
        <li className="flex flex-wrap items-center justify-between gap-2">
          <span>Identity-provider adapters</span>
          <span className="text-xs text-muted-foreground">
            {capabilities.providers.length > 0
              ? capabilities.providers.map(humanize).join(', ')
              : 'None reported by the detection worker (connected identity providers report their own capabilities on the Identity providers page)'}
          </span>
        </li>
      </ul>
    </div>
  );
}

interface Outcome {
  readonly ok: boolean;
  readonly error?: ApiError;
}

/** The api's coded error explained, with its code and request id. */
export function AtoErrorSummary({
  error,
  explain = explainAtoError,
}: {
  error: ApiError;
  /** The texts of a feature's own codes (identity providers); the 8.4 texts by default. */
  explain?: (error: ApiError) => string[];
}) {
  return (
    <FormErrorSummary
      messages={[...explain(error), `Code: ${error.code}`]}
      requestId={error.requestId}
    />
  );
}

/**
 * A confirmation with a reason (every ATO and incident mutation records who and why). Confirm
 * submits a new intent (new Idempotency-Key); "Retry the same request" repeats the failed intent
 * with the same key (P8). `minChars` mirrors the api's bound so a short reason is caught here.
 */
export function AtoReasonDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  destructive = false,
  minChars = 10,
  maxChars = 1000,
  required = true,
  reasonLabel = 'Reason',
  extra,
  onSubmit,
  onRetry,
  pending = false,
  disabled = false,
  explain,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  minChars?: number;
  maxChars?: number;
  required?: boolean;
  reasonLabel?: string;
  extra?: ReactNode;
  onSubmit: (reason: string | undefined) => Promise<Outcome>;
  onRetry?: () => Promise<Outcome>;
  pending?: boolean;
  /** Blocks Confirm (e.g. an incomplete form in `extra`); the reason is still validated. */
  disabled?: boolean;
  /** Error texts of the feature's own codes (see `AtoErrorSummary`). */
  explain?: (error: ApiError) => string[];
}) {
  const id = useId();
  const [reason, setReason] = useState('');
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<ApiError | null>(null);
  const reset = () => {
    setReason('');
    setFieldError(null);
    setApiError(null);
  };
  const handle = (outcome: Outcome) => {
    if (outcome.ok) {
      reset();
      return true;
    }
    setApiError(outcome.error ?? null);
    return false;
  };
  const confirm = async () => {
    const trimmed = reason.trim();
    if (disabled) return false;
    if (required || trimmed) {
      if (trimmed.length < (required ? Math.max(1, minChars) : 1)) {
        setFieldError(
          minChars > 1
            ? `Enter a reason of at least ${minChars} characters (it is recorded with the action)`
            : 'Enter a reason (it is recorded with the action)',
        );
        return false;
      }
      if (trimmed.length > maxChars) {
        setFieldError(`Use at most ${maxChars} characters`);
        return false;
      }
    }
    setFieldError(null);
    setApiError(null);
    return handle(await onSubmit(trimmed || undefined));
  };
  const retry = async () => {
    if (!onRetry) return;
    if (handle(await onRetry())) onOpenChange(false);
  };
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset();
        onOpenChange(next);
      }}
      title={title}
      description={description}
      confirmLabel={confirmLabel}
      destructive={destructive}
      pending={pending}
      onConfirm={confirm}
      error={
        <div className="grid gap-3">
          {extra}
          <div className="grid gap-1.5">
            <Label htmlFor={id}>
              {reasonLabel}
              {required ? ' (required)' : ' (optional)'}
            </Label>
            <Textarea
              id={id}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              maxLength={maxChars}
              rows={3}
              aria-invalid={fieldError ? true : undefined}
              aria-describedby={`${id}-help${fieldError ? ` ${id}-error` : ''}`}
            />
            <p id={`${id}-help`} className="text-xs text-muted-foreground">
              Recorded with the action and in the audit log
              {required && minChars > 1 ? ` (${minChars}–${maxChars} characters)` : ''}.
            </p>
            {fieldError ? (
              <p id={`${id}-error`} className="text-xs font-medium text-destructive">
                {fieldError}
              </p>
            ) : null}
          </div>
          {apiError ? (
            <div className="grid gap-2">
              <AtoErrorSummary error={apiError} explain={explain} />
              {onRetry && isRetryable(apiError) ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="justify-self-start"
                  disabled={pending}
                  onClick={() => void retry()}
                >
                  Retry the same request
                </Button>
              ) : null}
            </div>
          ) : null}
        </div>
      }
    />
  );
}

/** The pager state of a cursor list (`CursorPager` for lists rendered without `DataTable`). */
export function pagerOf(list: {
  page: number;
  hasNext: boolean;
  hasPrevious: boolean;
  isShortPage: boolean;
  next: () => void;
  previous: () => void;
  rows: readonly unknown[];
  query: { isFetching: boolean };
}): PagerState {
  return {
    page: list.page,
    hasNext: list.hasNext,
    hasPrevious: list.hasPrevious,
    isShortPage: list.isShortPage,
    next: list.next,
    previous: list.previous,
    rowCount: list.rows.length,
    isFetching: list.query.isFetching,
  };
}

/**
 * A horizontally scrollable table region (design system "Tables"): focusable so keyboard users
 * can scroll it (axe `scrollable-region-focusable`), labelled for assistive technologies.
 */
export function ScrollRegion({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      role="group"
      aria-label={label}
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable region
      tabIndex={0}
      className="min-w-0 overflow-x-auto rounded-md border"
    >
      {children}
    </div>
  );
}
