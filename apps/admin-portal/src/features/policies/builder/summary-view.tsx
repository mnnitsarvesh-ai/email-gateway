'use client';

import { useId, useMemo } from 'react';
import { CopyButton } from '@/components/copy-button';
import { cn } from '@/lib/utils';
import {
  summaryToText,
  type PolicySummaryDoc,
  type RuleSummary,
  type SummaryLine,
  type SummaryToken,
} from './summary';

/**
 * The readable summary (design B5): structured lines with emphasized keywords, rule by rule in
 * evaluation order, the policy-wide exceptions and the catalogue's floor statement, with "Copy
 * summary" (the text grammar of `summaryToText`). Presentation only: it never states an outcome.
 */

const DEPTH_CLASS = ['pl-0', 'pl-4', 'pl-8', 'pl-12', 'pl-16', 'pl-20', 'pl-24', 'pl-28', 'pl-32'];

const depthClass = (depth: number): string =>
  DEPTH_CLASS[Math.min(Math.max(depth - 1, 0), DEPTH_CLASS.length - 1)]!;

function Token({ token }: { token: SummaryToken }) {
  switch (token.kind) {
    case 'keyword':
      return <span className="font-semibold">{token.text}</span>;
    case 'field':
      return <span className="font-medium">{token.text}</span>;
    case 'value':
      return <span className="font-medium break-words">{token.text}</span>;
    default:
      return <>{token.text}</>;
  }
}

function Lines({ lines, label }: { lines: readonly SummaryLine[]; label: string }) {
  return (
    <ul className="grid gap-0.5" aria-label={label}>
      {lines.map((line, i) => (
        <li
          key={`${line.path ?? ''}-${i}`}
          className={cn('min-w-0 break-words', depthClass(line.depth))}
        >
          {line.tokens.map((token, j) => (
            <Token key={j} token={token} />
          ))}
        </li>
      ))}
    </ul>
  );
}

function Block({
  keyword,
  lines,
  label,
}: {
  keyword: string;
  lines: readonly SummaryLine[];
  label: string;
}) {
  if (lines.length === 0) return null;
  return (
    <div className="grid gap-0.5">
      <p className="font-semibold">{keyword}</p>
      <div className="pl-4">
        <Lines lines={lines} label={label} />
      </div>
    </div>
  );
}

function RuleBlock({ rule, compact }: { rule: RuleSummary; compact: boolean }) {
  const headingId = useId();
  return (
    <article
      aria-labelledby={headingId}
      className={cn(
        'grid min-w-0 gap-1',
        !rule.enabled && 'text-muted-foreground',
        !compact && 'rounded-md border p-3',
      )}
    >
      <h3
        id={headingId}
        className={cn('font-semibold break-words', compact ? 'text-xs' : 'text-sm')}
      >
        {rule.title}
      </h3>
      <Block keyword="IF:" lines={rule.when} label={`Conditions of rule ${rule.ruleId}`} />
      <Block keyword="UNLESS:" lines={rule.unless} label={`Exceptions of rule ${rule.ruleId}`} />
      <Block keyword="THEN:" lines={rule.then} label={`Actions of rule ${rule.ruleId}`} />
      {rule.notes.length > 0 ? (
        <ul
          className="grid gap-0.5 pl-4 text-muted-foreground italic"
          aria-label={`Notes of rule ${rule.ruleId}`}
        >
          {rule.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      ) : null}
    </article>
  );
}

export function PolicySummaryView({
  summary,
  compact = false,
}: {
  summary: PolicySummaryDoc;
  compact?: boolean;
}) {
  const headingId = useId();
  const text = useMemo(() => summaryToText(summary), [summary]);
  return (
    <section
      aria-labelledby={headingId}
      className={cn('grid min-w-0 gap-3', compact ? 'text-xs' : 'text-sm')}
      data-compact={compact || undefined}
    >
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <h2 id={headingId} className={cn('font-semibold', compact ? 'text-sm' : 'text-base')}>
          Readable summary
        </h2>
        <CopyButton value={text} label="Copy summary" size="sm" />
      </div>
      {summary.header.length > 0 ? <Lines lines={summary.header} label="Policy" /> : null}
      {summary.rules.map((rule, i) => (
        <RuleBlock key={`${rule.ruleId}-${i}`} rule={rule} compact={compact} />
      ))}
      {summary.exceptions.length > 0 ? (
        <div className={cn('grid gap-1', !compact && 'rounded-md border p-3')}>
          <p className="font-semibold">Policy-wide exceptions</p>
          <div className="pl-4">
            <Lines lines={summary.exceptions} label="Policy-wide exceptions" />
          </div>
        </div>
      ) : null}
      {summary.floorNote ? (
        <p className="text-xs text-muted-foreground">{summary.floorNote}</p>
      ) : null}
    </section>
  );
}
