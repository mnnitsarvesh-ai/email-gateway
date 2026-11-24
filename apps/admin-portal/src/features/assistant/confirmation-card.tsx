'use client';

import {
  AlertTriangleIcon,
  CheckCircle2Icon,
  ClockIcon,
  ExternalLinkIcon,
  Loader2Icon,
  ShieldAlertIcon,
  XCircleIcon,
} from 'lucide-react';
import Link from 'next/link';
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { PasswordInput } from '@/components/form';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { callOperation } from '@/lib/api/call';
import { ApiError } from '@/lib/api/errors';
import { useMe } from '@/lib/auth/me';
import { cn } from '@/lib/utils';
import { turnErrorText } from './model';
import { safePortalHref } from './portal-routes';
import { ResultCard } from './result-card';
import { cardSchema, parseConfirmationView } from './stream';
import type { ConfirmationAction, ConfirmationPhase } from './turn-state';
import type {
  AssistantCard,
  ConfirmationRisk,
  ConfirmationStatus,
  ConfirmationSummary,
  ConfirmationView,
} from './types';

/**
 * Confirmation card of a write the assistant proposed (step AI-2 D10, ADR-0093 amended). It is
 * rendered from the stored, server-authored summary (`assistant-confirmation/1`), never from the
 * model's text, and is the only place a proposed write can run: Confirm sends exactly
 * `{ token, actionDigest, reauth? }` (`POST /assistant/confirmations/{id}/confirm`). High-risk
 * actions ask for the password (and the authenticator code when MFA is enrolled) unless the
 * session re-authenticated recently; both fields are cleared after every attempt and never
 * stored. Without the single-use token (reload, another tab) the card can only cancel.
 */

const RISK: Record<
  ConfirmationRisk,
  { label: string; variant: 'info' | 'warning' | 'danger'; tone: string }
> = {
  low: { label: 'Low risk', variant: 'info', tone: 'border-border' },
  medium: { label: 'Medium risk', variant: 'warning', tone: 'border-tone-warning-foreground/40' },
  high: { label: 'High risk', variant: 'danger', tone: 'border-destructive/50' },
};

const STATUS_LABEL: Record<ConfirmationStatus, string> = {
  pending: 'Waiting for your confirmation',
  executing: 'Running',
  executed: 'Done',
  failed: 'Failed',
  expired: 'Expired',
  cancelled: 'Cancelled',
};

const REAUTH_REASON: Record<string, string> = {
  password: 'The password is not correct.',
  totp: 'The authenticator code is not correct.',
  totp_required: 'Enter the 6-digit code from your authenticator app.',
  locked: 'Your account is temporarily locked after too many failed attempts. Try again later.',
  inactive: 'Your account is not active.',
};

const NOT_PENDING: Record<string, string> = {
  executing: 'This action is already being applied.',
  executed: 'This action was already confirmed.',
  failed: 'This action was already confirmed and failed.',
  expired: 'This proposal has expired.',
  cancelled: 'This action was cancelled.',
};

const TOTP = /^[0-9]{6}$/;
const PASSWORD_MAX = 1024;
const EXECUTING_POLL_MS = 3000;

/** How the card reacts to a refused confirm or cancel request. */
export interface ConfirmationRefusal {
  readonly code: string;
  readonly message: string;
  /** The token can no longer be used (the confirmation ended or cannot be confirmed here). */
  readonly ends: boolean;
  /** Re-read the confirmation (its status changed on the server). */
  readonly refresh: boolean;
  /** Show the password (and code) fields. */
  readonly reauth?: 'show' | 'totp';
  readonly requestId: string | null;
}

/** Plain-language refusals of `confirm` / `cancel` (contracts §35.1 error codes). */
export function confirmationRefusal(error: unknown): ConfirmationRefusal {
  if (!(error instanceof ApiError)) {
    return {
      code: 'client_error',
      message: 'The request could not be sent. Check your connection and try again.',
      ends: false,
      refresh: false,
      requestId: null,
    };
  }
  const base = { code: error.code, requestId: error.requestId };
  switch (error.code) {
    case 'assistant_reauth_required':
      return {
        ...base,
        message: 'Confirm your identity to run this action.',
        ends: false,
        refresh: false,
        reauth: 'show',
      };
    case 'assistant_reauth_failed': {
      const reason = typeof error.details.reason === 'string' ? error.details.reason : '';
      return {
        ...base,
        message: REAUTH_REASON[reason] ?? 'Your identity could not be confirmed.',
        ends: false,
        refresh: false,
        reauth: reason === 'totp_required' ? 'totp' : 'show',
      };
    }
    case 'assistant_confirmation_expired':
      return {
        ...base,
        message:
          'This proposal expired before it was confirmed. Nothing changed. Ask again to get a new one.',
        ends: true,
        refresh: true,
      };
    case 'assistant_confirmation_state_changed':
      return {
        ...base,
        message: 'The record changed since this was proposed. Ask again to see the current state.',
        ends: true,
        refresh: true,
      };
    case 'assistant_confirmation_not_pending': {
      const status = typeof error.details.status === 'string' ? error.details.status : '';
      return {
        ...base,
        message: `${NOT_PENDING[status] ?? 'This action was already decided.'} It cannot be confirmed or cancelled again.`,
        ends: true,
        refresh: true,
      };
    }
    case 'assistant_confirmation_session_mismatch':
      return {
        ...base,
        message:
          'This action was proposed in another sign-in session. Ask again in this session to confirm it.',
        ends: true,
        refresh: false,
      };
    case 'assistant_confirmation_token_invalid':
      return {
        ...base,
        message: 'The confirmation could not be verified. Ask the assistant again.',
        ends: true,
        refresh: true,
      };
    case 'assistant_confirmation_digest_mismatch':
      return {
        ...base,
        message: 'The action no longer matches what this card shows. Ask the assistant again.',
        ends: true,
        refresh: true,
      };
    case 'assistant_confirmation_tool_changed':
      return {
        ...base,
        message: 'This action is no longer available in chat. Ask again or use the portal page.',
        ends: true,
        refresh: true,
      };
    case 'assistant_action_not_allowed':
      return {
        ...base,
        message: 'This change is not allowed in chat. Nothing changed.',
        ends: true,
        refresh: true,
      };
    case 'assistant_confirmation_not_found':
      return {
        ...base,
        message: 'This proposal no longer exists. Ask the assistant again.',
        ends: true,
        refresh: false,
      };
    case 'assistant_turn_in_progress':
      return {
        ...base,
        message: 'An answer is still running in this conversation. Confirm when it has finished.',
        ends: false,
        refresh: false,
      };
    case 'forbidden':
      return {
        ...base,
        message: 'You no longer have the permission this action needs.',
        ends: true,
        refresh: true,
      };
    case 'rate_limited':
      return {
        ...base,
        message: `Too many requests. Try again in ${error.retryAfterSeconds ?? 30} s.`,
        ends: false,
        refresh: false,
      };
    default:
      return {
        ...base,
        message: turnErrorText(error.code, error.message),
        ends: false,
        refresh: false,
      };
  }
}

/**
 * Whether an executed write is waiting for a second approver: a 202 from an approval-gated route.
 * Some tools answer 202 for queued work instead (a report email goes out asynchronously).
 */
const QUEUED_202_TOOLS: ReadonlySet<string> = new Set(['report_send_email']);
export function awaitsApproval(view: ConfirmationView): boolean {
  return view.result?.httpStatus === 202 && !QUEUED_202_TOOLS.has(view.tool);
}

/** The outcome line of a decided confirmation. */
export function outcomeText(view: ConfirmationView, resultCard: AssistantCard | null): string {
  switch (view.status) {
    case 'executed':
      return awaitsApproval(view)
        ? 'Submitted for approval: another person must approve it before it takes effect.'
        : 'Done: the action was applied.';
    case 'failed': {
      const code = view.result?.error ?? resultCard?.error?.code ?? null;
      if (code === 'assistant_confirmation_outcome_unknown')
        return 'The outcome is unknown: the action was interrupted. Check the current state in the portal before trying again.';
      if (code === 'assistant_confirmation_state_changed')
        return 'Not run: the record changed since this was proposed. Ask again to see the current state.';
      if (code === 'assistant_action_not_allowed')
        return 'Not run: this change is not allowed in chat. Nothing changed.';
      const status = view.result?.httpStatus ?? resultCard?.error?.httpStatus ?? null;
      const detail = [status ? `HTTP ${status}` : null, code].filter(Boolean).join(', ');
      return `The action failed${detail ? ` (${detail})` : ''}.`;
    }
    case 'cancelled':
      return view.result?.error === 'assistant_confirmation_token_locked'
        ? 'Cancelled after too many invalid confirmation attempts. Nothing changed.'
        : 'Cancelled. Nothing changed.';
    case 'expired':
      return 'Expired without confirmation. Nothing changed. Ask again to get a new proposal.';
    case 'executing':
      return 'Applying the action …';
    case 'pending':
    default:
      return STATUS_LABEL.pending;
  }
}

/** `m:ss` until the deadline (never negative). */
export function formatRemaining(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
}

/** The current time, ticking every second while `active`. */
function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [active]);
  return now;
}

function parseCard(value: unknown): AssistantCard | null {
  const parsed = cardSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function ValueText({ value, untrusted }: { value: string; untrusted?: boolean }) {
  if (!untrusted) return <span className="break-words">{value}</span>;
  return (
    <span className="inline-flex max-w-full min-w-0 flex-wrap items-center gap-x-1.5">
      <UntrustedText value={value} maxLength={200} />
      <span className="text-xs text-muted-foreground">(from the message)</span>
    </span>
  );
}

function SummaryBody({ summary }: { summary: ConfirmationSummary }) {
  return (
    <div className="grid gap-3">
      <p>{summary.action}</p>
      {summary.target.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm" aria-label="What it applies to">
            <caption className="pb-1 text-left text-xs font-medium text-muted-foreground">
              Applies to
            </caption>
            <tbody>
              {summary.target.map((target, index) => (
                <tr key={`${target.label}-${index}`} className="border-t first:border-t-0">
                  <th scope="row" className="py-1 pr-3 align-top font-medium whitespace-nowrap">
                    {target.label}
                  </th>
                  <td className="py-1 align-top">
                    <ValueText value={target.value} untrusted={target.untrusted} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {summary.changes.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm" aria-label="Changes">
            <caption className="pb-1 text-left text-xs font-medium text-muted-foreground">
              Changes
            </caption>
            <thead>
              <tr className="text-xs text-muted-foreground">
                <th scope="col" className="py-1 pr-3 font-medium">
                  Field
                </th>
                <th scope="col" className="py-1 pr-3 font-medium">
                  Now
                </th>
                <th scope="col" className="py-1 font-medium">
                  After
                </th>
              </tr>
            </thead>
            <tbody>
              {summary.changes.map((change, index) => (
                <tr key={`${change.label}-${index}`} className="border-t">
                  <th scope="row" className="py-1 pr-3 align-top font-medium">
                    {change.label}
                  </th>
                  <td className="py-1 pr-3 align-top text-muted-foreground">
                    {change.before === undefined || change.before === null ? (
                      '—'
                    ) : (
                      <span className="break-words">{change.before}</span>
                    )}
                  </td>
                  <td className="py-1 align-top">
                    <span className="break-words">{change.after}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {summary.definition ? (
        <div className="grid gap-1">
          <p className="text-xs font-medium text-muted-foreground">
            Policy rules ({summary.definition.direction}, priority {summary.definition.priority})
          </p>
          <ol className="grid gap-1" aria-label="Policy rules">
            {summary.definition.rules.map((rule) => (
              <li key={rule.id} className="rounded-md bg-muted/50 px-2 py-1.5">
                <p className="font-mono text-xs">{rule.id}</p>
                <p>
                  <span className="text-muted-foreground">When </span>
                  <span className="break-words">{rule.when}</span>
                </p>
                <p>
                  <span className="text-muted-foreground">Then </span>
                  <span className="break-words">{rule.actions}</span>
                </p>
              </li>
            ))}
          </ol>
        </div>
      ) : null}
      {summary.impact.length > 0 ? (
        <div className="grid gap-1">
          <p className="text-xs font-medium text-muted-foreground">Impact</p>
          <ul className="list-disc space-y-0.5 pl-5" aria-label="Impact">
            {summary.impact.map((line, index) => (
              <li key={index}>{line}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {summary.warnings.length > 0 ? (
        <ul
          className="grid gap-1 rounded-md border border-destructive/40 bg-tone-danger px-3 py-2 text-tone-danger-foreground"
          aria-label="Warnings"
        >
          {summary.warnings.map((line, index) => (
            <li key={index} className="flex items-start gap-2">
              <AlertTriangleIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
              <span>{line}</span>
            </li>
          ))}
        </ul>
      ) : null}
      <p className="text-xs text-muted-foreground">
        {summary.reversible ? 'This can be undone later.' : 'This cannot be undone.'}
      </p>
    </div>
  );
}

function Outcome({
  view,
  resultCard,
  portalHref,
  onNavigate,
}: {
  view: ConfirmationView;
  resultCard: AssistantCard | null;
  portalHref: string | null;
  onNavigate?: () => void;
}) {
  const ok = view.status === 'executed';
  const failed = view.status === 'failed';
  const Icon = ok
    ? awaitsApproval(view)
      ? ClockIcon
      : CheckCircle2Icon
    : failed
      ? XCircleIcon
      : view.status === 'executing'
        ? Loader2Icon
        : ClockIcon;
  return (
    <div className="grid gap-2">
      <p
        className={cn(
          'flex items-start gap-2 rounded-md px-3 py-2',
          ok && 'bg-tone-success text-tone-success-foreground',
          failed && 'bg-tone-danger text-tone-danger-foreground',
          !ok && !failed && 'bg-muted text-muted-foreground',
        )}
      >
        <Icon
          className={cn('mt-0.5 size-4 shrink-0', view.status === 'executing' && 'animate-spin')}
          aria-hidden
        />
        <span>{outcomeText(view, resultCard)}</span>
      </p>
      {(ok || failed) && portalHref ? (
        <Link
          href={portalHref}
          onClick={onNavigate}
          className="inline-flex items-center gap-1 text-xs text-primary underline underline-offset-2 hover:no-underline"
        >
          <ExternalLinkIcon className="size-3" aria-hidden />
          Open it in the portal
        </Link>
      ) : null}
      {resultCard ? <ResultCard card={resultCard} onNavigate={onNavigate} /> : null}
    </div>
  );
}

export interface ConfirmationCardProps {
  readonly view: ConfirmationView;
  /** The single-use token (memory of this tab only); null after a reload or in another tab. */
  readonly token: string | null;
  readonly phase: ConfirmationPhase;
  readonly resultCard: AssistantCard | null;
  /** A new live proposal: move focus to the card once. */
  readonly focusPending?: boolean;
  /** A turn of this conversation is streaming (confirm would be refused). */
  readonly streaming: boolean;
  readonly dispatch: (action: ConfirmationAction) => void;
  /** After a confirm or cancel reached the api (refresh the stored messages). */
  readonly onChanged?: () => void;
  /** Status changes for the conversation's live region. */
  readonly onAnnounce?: (text: string) => void;
  readonly onNavigate?: () => void;
}

export function ConfirmationCard({
  view,
  token,
  phase,
  resultCard,
  focusPending = false,
  streaming,
  dispatch,
  onChanged,
  onAnnounce,
  onNavigate,
}: ConfirmationCardProps) {
  const me = useMe();
  const titleId = useId();
  const fieldId = useId();
  const regionRef = useRef<HTMLElement>(null);
  const summary = view.summary;
  const title = summary?.title ?? 'Proposed action';
  const risk = RISK[view.risk];

  const pending = view.status === 'pending';
  const now = useNow(pending);
  const remaining = Date.parse(view.expiresAt) - now;
  const expiredHere = pending && remaining <= 0;
  const status: ConfirmationStatus = expiredHere ? 'expired' : view.status;
  const shownView = expiredHere ? { ...view, status } : view;

  const [askReauth, setAskReauth] = useState(view.requiresReauth && !view.reauthFresh);
  const [askTotp, setAskTotp] = useState(false);
  const mfa = (me.data?.mfaEnabled ?? false) || askTotp;
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [fieldErrors, setFieldErrors] = useState<{ password?: string; totpCode?: string }>({});
  const [refusal, setRefusal] = useState<ConfirmationRefusal | null>(null);

  const busy = phase === 'confirming' || phase === 'cancelling';
  const portalHref = summary?.portalRoute ? safePortalHref(summary.portalRoute) : null;

  useEffect(() => {
    if (!focusPending) return;
    regionRef.current?.focus();
    dispatch({ type: 'focused', executionId: view.executionId });
  }, [dispatch, focusPending, view.executionId]);

  // Expiry seen in this tab: the token is useless from now on.
  useEffect(() => {
    if (!expiredHere || !token) return;
    dispatch({ type: 'drop_token', executionId: view.executionId });
    onAnnounce?.(`${title}: the proposal expired. Nothing changed.`);
  }, [dispatch, expiredHere, onAnnounce, title, token, view.executionId]);

  const refresh = useCallback(async () => {
    try {
      const latest = parseConfirmationView(
        await callOperation('AssistantConfirmationsController_get_v1', {
          path: { confirmationId: view.id },
        }),
      );
      if (latest) dispatch({ type: 'settled', view: latest });
    } catch {
      // Best effort: the card keeps the refusal message; the stored messages refresh too.
    }
  }, [dispatch, view.id]);

  // A write being applied (another tab, or a reload while it ran): follow it to its outcome.
  useEffect(() => {
    if (view.status !== 'executing') return;
    const timer = setInterval(() => void refresh(), EXECUTING_POLL_MS);
    return () => clearInterval(timer);
  }, [refresh, view.status]);

  const refused = (error: unknown) => {
    const info = confirmationRefusal(error);
    setRefusal(info);
    if (info.reauth) setAskReauth(true);
    if (info.reauth === 'totp') setAskTotp(true);
    dispatch({ type: 'phase', executionId: view.executionId, phase: 'idle' });
    if (info.ends) dispatch({ type: 'drop_token', executionId: view.executionId });
    onAnnounce?.(`${title}: ${info.message}`);
    if (info.refresh) void refresh();
    if (info.ends) onChanged?.();
  };

  const confirm = async () => {
    if (!token || busy || streaming || !pending || expiredHere) return;
    let reauth: { password: string; totpCode?: string } | undefined;
    if (askReauth) {
      const errors: { password?: string; totpCode?: string } = {};
      if (!password) errors.password = 'Enter your password';
      else if (password.length > PASSWORD_MAX) errors.password = 'The password is too long';
      if (mfa && !TOTP.test(totpCode))
        errors.totpCode = 'Enter the 6-digit code from your authenticator app';
      setFieldErrors(errors);
      if (errors.password || errors.totpCode) return;
      reauth = { password, ...(mfa ? { totpCode } : {}) };
    }
    setRefusal(null);
    dispatch({ type: 'phase', executionId: view.executionId, phase: 'confirming' });
    try {
      const result = await callOperation('AssistantConfirmationsController_confirm_v1', {
        path: { confirmationId: view.id },
        body: { token, actionDigest: view.actionDigest, ...(reauth ? { reauth } : {}) },
      });
      const next = parseConfirmationView(result.confirmation);
      const card = parseCard(result.execution?.card);
      if (!next) {
        dispatch({ type: 'drop_token', executionId: view.executionId });
        dispatch({ type: 'phase', executionId: view.executionId, phase: 'idle' });
        void refresh();
      } else {
        dispatch({ type: 'settled', view: next, resultCard: card });
        onAnnounce?.(`${title}: ${outcomeText(next, card)}`);
      }
      onChanged?.();
    } catch (error) {
      refused(error);
    } finally {
      // Never keep the secrets after an attempt, whatever the result.
      setPassword('');
      setTotpCode('');
    }
  };

  const cancel = async () => {
    if (busy) return;
    setRefusal(null);
    dispatch({ type: 'phase', executionId: view.executionId, phase: 'cancelling' });
    try {
      const result = await callOperation('AssistantConfirmationsController_cancel_v1', {
        path: { confirmationId: view.id },
      });
      const next = parseConfirmationView(result.confirmation);
      if (next) {
        dispatch({ type: 'settled', view: next });
        onAnnounce?.(`${title}: ${outcomeText(next, null)}`);
      } else {
        dispatch({ type: 'drop_token', executionId: view.executionId });
        void refresh();
      }
      onChanged?.();
    } catch (error) {
      refused(error);
    } finally {
      setPassword('');
      setTotpCode('');
    }
  };

  const showForm = pending && !expiredHere;
  return (
    <section
      ref={regionRef}
      tabIndex={-1}
      aria-labelledby={titleId}
      className={cn(
        'grid gap-3 rounded-lg border-2 bg-card p-3 text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring',
        risk.tone,
      )}
    >
      <header className="flex flex-wrap items-start justify-between gap-2">
        <div className="grid min-w-0 gap-0.5">
          <p className="text-xs text-muted-foreground">Action proposed by the assistant</p>
          <h3 id={titleId} className="text-sm font-semibold break-words">
            {title}
          </h3>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge variant={risk.variant}>
            {view.risk === 'high' ? <ShieldAlertIcon aria-hidden /> : null}
            {risk.label}
          </Badge>
          <Badge variant="outline">{STATUS_LABEL[status]}</Badge>
        </div>
      </header>

      {summary ? (
        <SummaryBody summary={summary} />
      ) : (
        <p className="text-muted-foreground">
          The details of this action are no longer available (the conversation content was deleted).
        </p>
      )}

      <details className="text-xs">
        <summary className="cursor-pointer text-muted-foreground">Technical details</summary>
        <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
          {summary ? (
            <>
              <dt className="text-muted-foreground">Request</dt>
              <dd className="font-mono break-all">
                {summary.request.method} {summary.request.path}
              </dd>
            </>
          ) : null}
          <dt className="text-muted-foreground">Tool</dt>
          <dd className="font-mono break-all">{view.tool}</dd>
          <dt className="text-muted-foreground">Confirmation</dt>
          <dd className="font-mono break-all">{view.id}</dd>
        </dl>
      </details>

      {showForm ? (
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <ClockIcon className="size-3.5" aria-hidden />
          <span>
            Expires in <span className="tabular-nums">{formatRemaining(remaining)}</span>
          </span>
        </p>
      ) : null}

      {refusal ? (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-md border border-destructive/40 bg-tone-danger px-3 py-2 text-tone-danger-foreground"
        >
          <AlertTriangleIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          <div className="grid gap-0.5">
            <p>{refusal.message}</p>
            {refusal.requestId ? (
              <p className="text-xs">
                Request ID: <span className="font-mono">{refusal.requestId}</span>
              </p>
            ) : null}
          </div>
        </div>
      ) : null}

      {!showForm ? (
        <Outcome
          view={shownView}
          resultCard={resultCard}
          portalHref={portalHref}
          onNavigate={onNavigate}
        />
      ) : token ? (
        <form
          className="grid gap-3"
          noValidate
          aria-label={`Confirm: ${title}`}
          onSubmit={(event) => {
            event.preventDefault();
            void confirm();
          }}
        >
          {askReauth ? (
            <fieldset className="grid gap-2 rounded-md border p-3">
              <legend className="px-1 text-xs font-medium">Confirm your identity</legend>
              <p className="text-xs text-muted-foreground">
                {mfa
                  ? 'High-risk actions need your password and the code from your authenticator app.'
                  : 'High-risk actions need your password.'}{' '}
                Failed attempts count toward the sign-in lockout.
              </p>
              <div className="grid gap-1">
                <Label htmlFor={`${fieldId}-password`}>Your password (required)</Label>
                <PasswordInput
                  id={`${fieldId}-password`}
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  aria-invalid={fieldErrors.password ? true : undefined}
                  aria-describedby={fieldErrors.password ? `${fieldId}-password-error` : undefined}
                  disabled={busy}
                />
                {fieldErrors.password ? (
                  <p id={`${fieldId}-password-error`} className="text-xs text-destructive">
                    {fieldErrors.password}
                  </p>
                ) : null}
              </div>
              {mfa ? (
                <div className="grid gap-1">
                  <Label htmlFor={`${fieldId}-totp`}>Authenticator code (required)</Label>
                  <Input
                    id={`${fieldId}-totp`}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    value={totpCode}
                    onChange={(event) => setTotpCode(event.target.value.trim())}
                    aria-invalid={fieldErrors.totpCode ? true : undefined}
                    aria-describedby={fieldErrors.totpCode ? `${fieldId}-totp-error` : undefined}
                    disabled={busy}
                    className="max-w-40"
                  />
                  {fieldErrors.totpCode ? (
                    <p id={`${fieldId}-totp-error`} className="text-xs text-destructive">
                      {fieldErrors.totpCode}
                    </p>
                  ) : null}
                </div>
              ) : null}
            </fieldset>
          ) : null}
          {streaming ? (
            <p className="text-xs text-muted-foreground">
              Wait until the assistant has finished answering to confirm.
            </p>
          ) : null}
          <div className="flex flex-wrap justify-end gap-2">
            <Button type="button" variant="outline" onClick={() => void cancel()} disabled={busy}>
              {phase === 'cancelling' ? 'Cancelling …' : 'Cancel'}
            </Button>
            <Button
              type="submit"
              variant={view.risk === 'high' ? 'destructive' : 'default'}
              disabled={busy || streaming}
            >
              {phase === 'confirming' ? 'Confirming …' : 'Confirm'}
            </Button>
          </div>
        </form>
      ) : (
        <div className="grid gap-2">
          <p className="text-muted-foreground">
            Confirm in the tab where it was proposed, or ask again.
          </p>
          <div className="flex justify-end">
            <Button type="button" variant="outline" onClick={() => void cancel()} disabled={busy}>
              {phase === 'cancelling' ? 'Cancelling …' : 'Cancel'}
            </Button>
          </div>
        </div>
      )}
    </section>
  );
}
