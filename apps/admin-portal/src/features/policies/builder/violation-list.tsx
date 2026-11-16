'use client';

import { CircleAlertIcon } from 'lucide-react';
import { useId } from 'react';
import { useOptionalBuilderContext, type Violation } from './context';
import { describePath, keyForPath } from './paths';

/**
 * The error summary of server violations (design B4, B14): every item names the location and
 * the server's message and code; selecting it moves the focus to the node (through the path
 * index of the surrounding `BuilderProvider`) and calls `onSelect(path)` (e.g. to set
 * `highlightPath`). Not a live region: validation results are announced by the page.
 */
export function ViolationList({
  violations,
  onSelect,
}: {
  violations: Violation[];
  onSelect?: (path: string) => void;
}) {
  const builder = useOptionalBuilderContext();
  const headingId = useId();
  if (violations.length === 0) return null;
  const select = (path: string) => {
    onSelect?.(path);
    if (!builder) return;
    const key = keyForPath(builder.paths, path);
    if (key !== null && !builder.focus.focusNow(key)) builder.focus.request(key);
  };
  return (
    <section
      aria-labelledby={headingId}
      className="grid gap-2 rounded-md border border-destructive/40 bg-tone-danger p-3 text-sm text-tone-danger-foreground"
    >
      <h2 id={headingId} className="flex items-center gap-2 text-sm font-semibold">
        <CircleAlertIcon className="size-4 shrink-0" aria-hidden />
        {violations.length === 1
          ? 'The server reported 1 problem'
          : `The server reported ${violations.length} problems`}
      </h2>
      <ul className="grid gap-1">
        {violations.map((violation, i) => (
          <li key={`${violation.path}-${violation.code}-${i}`} className="min-w-0">
            <button
              type="button"
              onClick={() => select(violation.path)}
              className="rounded-sm text-left underline underline-offset-2 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            >
              <span className="font-medium">{describePath(violation.path)}</span>
              {`: ${violation.message}`}
            </button>{' '}
            <span className="font-mono text-xs break-all">
              ({violation.code}
              {violation.path ? `, ${violation.path}` : ''})
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
