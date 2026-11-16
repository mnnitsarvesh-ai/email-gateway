'use client';

import { CircleCheckIcon, InfoIcon, TriangleAlertIcon } from 'lucide-react';
import { useEffect, useId, useRef, useState } from 'react';
import { ErrorState } from '@/components/states/error-state';
import type { ApiError } from '@/lib/api/errors';
import { describePath, useBuilderContext, type Violation } from '../builder';
import { formatSize, isTooLarge, TOO_LARGE_MESSAGE } from '../size';

/**
 * The server's verdict on a document (design B4): from `POST /policies/validate`, from a save
 * refused with `400 policy_definition_invalid`, or the stored version's `validation`. Bound to
 * the canonical JSON it was made for: an edit makes it stale (never mapped onto changed nodes).
 */
export interface ServerCheck {
  readonly key: string;
  readonly valid: boolean;
  readonly violations: readonly Violation[];
  /** Unknown departments/users: allowed in a draft, refused at publish, activation, enable. */
  readonly referenceViolations: readonly Violation[];
  readonly source: 'validate' | 'save' | 'stored';
}

export const EMPTY_VIOLATIONS: readonly Violation[] = Object.freeze([]);

function useSecondsLeft(until: number | null): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (until === null) return undefined;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [until]);
  return until === null ? 0 : Math.max(0, Math.ceil((until - now) / 1000));
}

/** Directory references a publish would refuse (warnings in a draft). */
export function ReferenceWarnings({ warnings }: { warnings: readonly Violation[] }) {
  const headingId = useId();
  if (warnings.length === 0) return null;
  return (
    <section
      aria-labelledby={headingId}
      className="grid gap-1 rounded-md border border-warning/50 bg-tone-warning p-3 text-sm text-tone-warning-foreground"
    >
      <h3 id={headingId} className="flex items-center gap-2 font-semibold">
        <TriangleAlertIcon className="size-4 shrink-0" aria-hidden />
        {warnings.length === 1
          ? 'One directory reference does not exist (yet)'
          : `${warnings.length} directory references do not exist (yet)`}
      </h3>
      <p className="text-xs">
        A draft may reference a department or user created later; publishing, activating and
        enabling refuse unknown references.
      </p>
      <ul className="grid gap-0.5">
        {warnings.map((warning, i) => (
          <li key={`${warning.path}-${i}`} className="min-w-0 break-words">
            <span className="font-medium">{describePath(warning.path)}</span>
            {`: ${warning.message} `}
            <span className="font-mono text-xs">({warning.code})</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

/**
 * A one-line status of the server validation plus the reference warnings. Announces new results
 * through the builder's polite live region (must render inside `BuilderProvider`).
 */
export function ValidationStatus({
  check,
  currentKey,
  pending,
  error,
  pausedUntil,
  auto,
  documentBytes,
}: {
  check: ServerCheck | null;
  currentKey: string;
  pending: boolean;
  error: ApiError | null;
  pausedUntil: number | null;
  auto: boolean;
  documentBytes: number;
}) {
  const { announce } = useBuilderContext();
  const fresh = check !== null && check.key === currentKey;
  const secondsLeft = useSecondsLeft(pausedUntil);
  const announced = useRef<ServerCheck | null>(check);
  useEffect(() => {
    if (!check || check === announced.current || check.source === 'stored') return;
    announced.current = check;
    announce(
      check.valid
        ? check.referenceViolations.length > 0
          ? `The server accepts the document; ${check.referenceViolations.length} directory references need attention before publishing.`
          : 'The server accepts the document.'
        : `The server reported ${check.violations.length} ${check.violations.length === 1 ? 'problem' : 'problems'}.`,
    );
  }, [check, announce]);

  let line: { tone: 'ok' | 'bad' | 'info'; text: string };
  if (pending) line = { tone: 'info', text: 'Validating on the server …' };
  else if (fresh && check.valid) line = { tone: 'ok', text: 'The server accepts this document.' };
  else if (fresh) {
    line = {
      tone: 'bad',
      text: `The server reported ${check.violations.length} ${check.violations.length === 1 ? 'problem' : 'problems'} with this document.`,
    };
  } else if (check) {
    line = {
      tone: 'info',
      text: auto
        ? 'Changed since the last validation; the server checks it again shortly after you stop editing.'
        : 'Changed since the last validation; validate to check it on the server.',
    };
  } else {
    line = {
      tone: 'info',
      text: auto
        ? 'Not validated yet; the server checks the document shortly after you change it.'
        : 'Not validated yet.',
    };
  }
  const Icon =
    line.tone === 'ok' ? CircleCheckIcon : line.tone === 'bad' ? TriangleAlertIcon : InfoIcon;
  return (
    <div className="grid min-w-0 gap-2" data-testid="validation-status">
      <p className="flex min-w-0 items-start gap-2 text-sm">
        <Icon
          className={
            line.tone === 'bad'
              ? 'mt-0.5 size-4 shrink-0 text-destructive'
              : 'mt-0.5 size-4 shrink-0 text-muted-foreground'
          }
          aria-hidden
        />
        <span className="min-w-0">{line.text}</span>
      </p>
      {secondsLeft > 0 ? (
        <p className="text-xs text-muted-foreground">
          {`Automatic validation is paused for ${secondsLeft} s (too many requests).`}
        </p>
      ) : null}
      {error && !pending ? (
        isTooLarge(error) ? (
          <p role="alert" className="text-sm text-destructive">
            {`${TOO_LARGE_MESSAGE} Document size: ${formatSize(documentBytes)}.`}
          </p>
        ) : error.status === 429 ? null : (
          <ErrorState error={error} compact />
        )
      ) : null}
      {fresh ? <ReferenceWarnings warnings={check.referenceViolations} /> : null}
    </div>
  );
}
