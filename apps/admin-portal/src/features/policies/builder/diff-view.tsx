'use client';

import { useId, useState } from 'react';
import { ToneBadge } from '@/components/domain/tone-badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import type { Tone } from '@/lib/design/tokens';
import { cn } from '@/lib/utils';
import type { DefinitionDiff, LineDiff } from './diff';

/**
 * A version diff (design B10): a summary tab (counts, policy changes, one card per rule with
 * property changes and `+`/`−` line diffs of IF, UNLESS and THEN) and a "Raw JSON" tab (the
 * canonical pretty JSON line diff with folded unchanged runs). Changes carry a marker and a text
 * label; colour is never the only cue.
 */

export type DiffViewMode = 'summary' | 'json';

const CHANGE_TONE: Readonly<Record<string, Tone>> = {
  added: 'success',
  removed: 'danger',
  changed: 'warning',
  unchanged: 'neutral',
};
const CHANGE_LABEL: Readonly<Record<string, string>> = {
  added: 'Added',
  removed: 'Removed',
  changed: 'Changed',
  unchanged: 'Unchanged',
};
const CONTEXT = 3;

function DiffLine({ line }: { line: LineDiff[number] }) {
  const marker = line.op === 'insert' ? '+' : line.op === 'delete' ? '−' : ' ';
  const label = line.op === 'insert' ? 'Added: ' : line.op === 'delete' ? 'Removed: ' : '';
  return (
    <li
      data-op={line.op}
      className={cn(
        'grid grid-cols-[1.25rem_1fr] px-1 font-mono text-xs whitespace-pre-wrap',
        line.op === 'insert' && 'bg-tone-success text-tone-success-foreground',
        line.op === 'delete' && 'bg-tone-danger text-tone-danger-foreground',
      )}
    >
      <span aria-hidden className="select-none">
        {marker}
      </span>
      <span className="min-w-0 break-all">
        {label ? <span className="sr-only">{label}</span> : null}
        {line.text}
      </span>
    </li>
  );
}

type Chunk = { kind: 'lines'; lines: LineDiff } | { kind: 'fold'; lines: LineDiff };

/** Unchanged runs longer than 2 × CONTEXT + 1 are folded (expandable). */
function chunksOf(diff: LineDiff, fold: boolean): Chunk[] {
  if (!fold) return [{ kind: 'lines', lines: diff }];
  const chunks: Chunk[] = [];
  let i = 0;
  while (i < diff.length) {
    if (diff[i]!.op !== 'equal') {
      let j = i;
      while (j < diff.length && diff[j]!.op !== 'equal') j += 1;
      chunks.push({ kind: 'lines', lines: diff.slice(i, j) });
      i = j;
      continue;
    }
    let j = i;
    while (j < diff.length && diff[j]!.op === 'equal') j += 1;
    const run = diff.slice(i, j);
    const head = i === 0 ? 0 : CONTEXT;
    const tail = j === diff.length ? 0 : CONTEXT;
    if (run.length > head + tail + 1) {
      if (head > 0) chunks.push({ kind: 'lines', lines: run.slice(0, head) });
      chunks.push({ kind: 'fold', lines: run.slice(head, run.length - tail) });
      if (tail > 0) chunks.push({ kind: 'lines', lines: run.slice(run.length - tail) });
    } else {
      chunks.push({ kind: 'lines', lines: run });
    }
    i = j;
  }
  return chunks;
}

function Fold({ lines }: { lines: LineDiff }) {
  const [open, setOpen] = useState(false);
  if (open) {
    return (
      <>
        {lines.map((line, i) => (
          <DiffLine key={i} line={line} />
        ))}
      </>
    );
  }
  return (
    <li className="px-1 py-0.5">
      <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={() => setOpen(true)}>
        {`Show ${lines.length} unchanged lines`}
      </Button>
    </li>
  );
}

export function LineDiffList({
  diff,
  label,
  fold = false,
}: {
  diff: LineDiff;
  label: string;
  fold?: boolean;
}) {
  if (diff.length === 0)
    return <p className="text-xs text-muted-foreground">Nothing here in either version.</p>;
  return (
    <ol aria-label={label} className="grid min-w-0 overflow-hidden rounded-md border">
      {chunksOf(diff, fold).map((chunk, i) =>
        chunk.kind === 'fold' ? (
          <Fold key={i} lines={chunk.lines} />
        ) : (
          chunk.lines.map((line, j) => <DiffLine key={`${i}-${j}`} line={line} />)
        ),
      )}
    </ol>
  );
}

function RuleDiffCard({
  rule,
  fromLabel,
  toLabel,
}: {
  rule: DefinitionDiff['rules'][number];
  fromLabel: string;
  toLabel: string;
}) {
  const headingId = useId();
  const sections: Array<[string, LineDiff]> = [
    ['IF', rule.when],
    ['UNLESS', rule.unless],
    ['THEN', rule.then],
  ];
  return (
    <article aria-labelledby={headingId} className="grid min-w-0 gap-2 rounded-md border p-3">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <h3 id={headingId} className="text-sm font-semibold break-all">
          {`Rule ${rule.ruleId}`}
        </h3>
        <ToneBadge tone={CHANGE_TONE[rule.change] ?? 'neutral'}>
          {CHANGE_LABEL[rule.change] ?? rule.change}
        </ToneBadge>
      </div>
      {rule.change === 'unchanged' ? (
        <p className="text-xs text-muted-foreground">No changes.</p>
      ) : (
        <>
          {rule.properties.length > 0 ? (
            <ul
              className="grid gap-0.5 text-xs"
              aria-label={`Changed settings of rule ${rule.ruleId}`}
            >
              {rule.properties.map((p) => (
                <li key={p.property}>
                  <span className="font-medium">{p.property}</span>
                  {`: ${p.before} (${fromLabel}) → ${p.after} (${toLabel})`}
                </li>
              ))}
            </ul>
          ) : null}
          {sections
            .filter(([, diff]) => diff.length > 0)
            .map(([keyword, diff]) => (
              <div key={keyword} className="grid gap-1">
                <p className="text-xs font-semibold">{`${keyword}:`}</p>
                <LineDiffList diff={diff} label={`${keyword} lines of rule ${rule.ruleId}`} />
              </div>
            ))}
        </>
      )}
    </article>
  );
}

export function DefinitionDiffView({
  diff,
  fromLabel,
  toLabel,
  view,
  onViewChange,
}: {
  diff: DefinitionDiff;
  fromLabel: string;
  toLabel: string;
  /** Controlled tab (e.g. `?view=` of the compare page); uncontrolled when omitted. */
  view?: DiffViewMode;
  onViewChange?: (view: DiffViewMode) => void;
}) {
  const [local, setLocal] = useState<DiffViewMode>('summary');
  const current = view ?? local;
  const policyId = useId();
  const { added, removed, changed } = diff.counts;
  const noRuleView = diff.rules.length === 0 && diff.policy.length === 0;
  return (
    <Tabs
      value={current}
      onValueChange={(next) => {
        const mode: DiffViewMode = next === 'json' ? 'json' : 'summary';
        setLocal(mode);
        onViewChange?.(mode);
      }}
      className="min-w-0"
    >
      <TabsList aria-label={`Changes from ${fromLabel} to ${toLabel}`}>
        <TabsTrigger value="summary">Summary</TabsTrigger>
        <TabsTrigger value="json">Raw JSON</TabsTrigger>
      </TabsList>
      <TabsContent value="summary" className="grid min-w-0 gap-3">
        <p className="text-sm">
          {`From ${fromLabel} to ${toLabel}: ${added} ${added === 1 ? 'rule' : 'rules'} added, ${removed} removed, ${changed} changed.`}
        </p>
        {noRuleView && diff.json.some((l) => l.op !== 'equal') ? (
          <p className="text-sm text-muted-foreground">
            At least one version cannot be shown as rules; see the raw JSON.
          </p>
        ) : null}
        {diff.policy.length > 0 ? (
          <section aria-labelledby={policyId} className="grid gap-1 rounded-md border p-3">
            <h3 id={policyId} className="text-sm font-semibold">
              Policy settings
            </h3>
            <ul className="grid gap-1 text-sm">
              {diff.policy.map((change) => (
                <li key={change.property} className="grid gap-0.5">
                  <span className="font-medium">
                    {change.property === 'direction'
                      ? 'Direction'
                      : change.property === 'priority'
                        ? 'Priority'
                        : 'Policy-wide exceptions'}
                  </span>
                  <span className="text-xs whitespace-pre-wrap">{`${fromLabel}: ${change.before}`}</span>
                  <span className="text-xs whitespace-pre-wrap">{`${toLabel}: ${change.after}`}</span>
                </li>
              ))}
            </ul>
          </section>
        ) : null}
        {diff.rules.map((rule) => (
          <RuleDiffCard
            key={`${rule.ruleId}-${rule.change}`}
            rule={rule}
            fromLabel={fromLabel}
            toLabel={toLabel}
          />
        ))}
      </TabsContent>
      <TabsContent value="json" className="min-w-0">
        <LineDiffList
          diff={diff.json}
          label={`Canonical JSON from ${fromLabel} to ${toLabel}`}
          fold
        />
      </TabsContent>
    </Tabs>
  );
}
