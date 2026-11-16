'use client';

import { ChevronDownIcon, ChevronUpIcon } from 'lucide-react';
import { useId, useState, type ReactNode } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Button } from '@/components/ui/button';
import { UNSAVED_CHANGES_MESSAGE, type UnsavedChangesGuard } from '@/hooks/use-unsaved-changes';
import { cn } from '@/lib/utils';
import { PolicySummaryView, type PolicySummaryDoc } from '../builder';

/**
 * The builder page layout (design B14): at ≥ 1280 px the editor and the readable summary side by
 * side (summary sticky); below, the summary is a collapsible section above the editor. Pure CSS
 * breakpoints (no layout flash, nothing measured in JavaScript); `min-w-0` everywhere so long
 * values wrap instead of scrolling the page sideways.
 */
export function EditorLayout({ summary, children }: { summary: ReactNode; children: ReactNode }) {
  return (
    <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(18rem,26rem)] xl:items-start">
      <div className="min-w-0 xl:sticky xl:top-4 xl:col-start-2 xl:row-start-1">{summary}</div>
      <div className="min-w-0 xl:col-start-1 xl:row-start-1">{children}</div>
    </div>
  );
}

/** The live summary: always shown at ≥ 1280 px, a toggle above the editor below that. */
export function SummaryAside({
  summary,
  defaultOpen = false,
}: {
  summary: PolicySummaryDoc;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const contentId = useId();
  return (
    <aside
      aria-label="Readable summary of the policy"
      className="grid min-w-0 gap-2 rounded-lg border bg-card p-3 sm:p-4 xl:max-h-[calc(100dvh-2rem)] xl:overflow-y-auto"
    >
      <Button
        variant="ghost"
        size="sm"
        className="w-fit xl:hidden"
        aria-expanded={open}
        aria-controls={contentId}
        onClick={() => setOpen((value) => !value)}
      >
        {open ? <ChevronUpIcon aria-hidden /> : <ChevronDownIcon aria-hidden />}
        {open ? 'Hide the readable summary' : 'Show the readable summary'}
      </Button>
      <div id={contentId} className={cn('min-w-0', open ? 'block' : 'hidden', 'xl:block')}>
        <PolicySummaryView summary={summary} compact />
      </div>
    </aside>
  );
}

/** The confirmation of `useUnsavedChanges` for the page's own navigation controls. */
export function UnsavedChangesDialog({ guard }: { guard: UnsavedChangesGuard }) {
  return (
    <ConfirmDialog
      open={guard.pending}
      onOpenChange={(open) => {
        if (!open) guard.cancel();
      }}
      title="Discard unsaved changes?"
      description={UNSAVED_CHANGES_MESSAGE}
      confirmLabel="Discard and leave"
      cancelLabel="Stay on this page"
      destructive
      onConfirm={() => guard.confirm()}
    />
  );
}

/**
 * A wrapping group of actions (buttons never force a horizontal scroll at 390 px). A named
 * `group`, not `toolbar`: every control stays in the Tab order (no arrow-key roving).
 */
export function Toolbar({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div role="group" aria-label={label} className="flex min-w-0 flex-wrap items-center gap-2">
      {children}
    </div>
  );
}

/** Saves a JSON document as a local file (only on explicit request; design §7). */
export function downloadJson(fileName: string, json: string): void {
  const url = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
