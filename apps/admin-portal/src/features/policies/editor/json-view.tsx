'use client';

import type { ParseResult } from '../builder';

type Refusal = Extract<ParseResult, { ok: false }>;

/** Why the builder shows a definition as JSON only (design B3: legacy rows, unknown keys). */
export function refusalText(refusal: Refusal): string {
  switch (refusal.reason) {
    case 'unsupported_version':
      return 'This version is not a policy-dsl/1 document (a retired legacy version); it is shown as stored.';
    case 'unknown_key':
      return `This definition has a key the builder does not know (${refusal.path}); it is shown as stored and cannot be edited here.`;
    case 'malformed':
      return `This definition is malformed at ${refusal.path || 'the top level'}; it is shown as stored.`;
    default:
      return 'This definition is not a JSON object; it is shown as stored.';
  }
}

/** A stored definition as text (never rendered as HTML). */
export function DefinitionJson({ definition, label }: { definition: unknown; label: string }) {
  return (
    <pre
      className="max-h-[32rem] overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap"
      aria-label={label}
      data-testid="policy-definition"
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable region
      tabIndex={0}
    >
      {JSON.stringify(definition, null, 2)}
    </pre>
  );
}
