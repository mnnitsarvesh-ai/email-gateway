'use client';

import {
  AlertTriangleIcon,
  ArrowDownIcon,
  ArrowUpIcon,
  CircleAlertIcon,
  Trash2Icon,
} from 'lucide-react';
import { useCallback, useEffect, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { useBuilderContext, type Violation } from './context';

/** Server violations of one node, shown inline (the node's controls reference the list id). */
export function ViolationMessages({
  id,
  violations,
}: {
  id: string;
  violations: readonly Violation[];
}) {
  if (violations.length === 0) return null;
  return (
    <ul id={id} className="grid gap-0.5" aria-label="Problems reported by the server">
      {violations.map((v, i) => (
        <li
          key={`${v.path}-${v.code}-${i}`}
          className="flex gap-1.5 text-xs font-medium text-destructive"
        >
          <CircleAlertIcon className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span>
            {v.message} <span className="font-mono font-normal">({v.code})</span>
          </span>
        </li>
      ))}
    </ul>
  );
}

/** Catalogue-derived warnings (not errors): the server decides. */
export function WarningMessages({ id, warnings }: { id: string; warnings: readonly string[] }) {
  if (warnings.length === 0) return null;
  return (
    <ul id={id} className="grid gap-0.5" aria-label="Warnings">
      {warnings.map((warning) => (
        <li
          key={warning}
          className="flex gap-1.5 rounded-sm bg-tone-warning px-2 py-1 text-xs text-tone-warning-foreground"
        >
          <AlertTriangleIcon className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span>
            <span className="font-semibold">Warning:</span> {warning}
          </span>
        </li>
      ))}
    </ul>
  );
}

/**
 * Violations, highlight state and the scroll-into-view of the highlighted node; `keys` are the
 * node's own key plus keys rendered through it (a NOT shown as a toggle on its child).
 */
export function useNodeStatus(keys: ReadonlyArray<string | null | undefined>) {
  const { violationsByKey, highlightKey } = useBuilderContext();
  const own = keys.filter((k): k is string => typeof k === 'string');
  const violations = own.flatMap((k) => violationsByKey.get(k) ?? []);
  const highlighted = highlightKey !== null && own.includes(highlightKey);
  const element = useRef<HTMLElement | null>(null);
  const ref = useCallback((node: HTMLElement | null) => {
    element.current = node;
  }, []);
  useEffect(() => {
    if (!highlighted) return;
    const reduced =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches === true;
    element.current?.scrollIntoView?.({ block: 'center', behavior: reduced ? 'auto' : 'smooth' });
  }, [highlighted]);
  return { violations, highlighted, ref };
}

export const HIGHLIGHT_CLASS = 'ring-2 ring-primary ring-offset-2 ring-offset-background';

export function MoveButtons({
  name,
  onUp,
  onDown,
  canUp,
  canDown,
  upRef,
  downRef,
}: {
  /** What moves, e.g. "condition 2". */
  name: string;
  onUp: () => void;
  onDown: () => void;
  canUp: boolean;
  canDown: boolean;
  upRef?: (element: HTMLElement | null) => void;
  downRef?: (element: HTMLElement | null) => void;
}) {
  return (
    <>
      <Button
        ref={upRef}
        variant="ghost"
        size="icon"
        className="size-7"
        aria-label={`Move ${name} up`}
        title="Move up"
        disabled={!canUp}
        onClick={onUp}
      >
        <ArrowUpIcon aria-hidden />
      </Button>
      <Button
        ref={downRef}
        variant="ghost"
        size="icon"
        className="size-7"
        aria-label={`Move ${name} down`}
        title="Move down"
        disabled={!canDown}
        onClick={onDown}
      >
        <ArrowDownIcon aria-hidden />
      </Button>
    </>
  );
}

export function RemoveButton({
  name,
  onClick,
  className,
}: {
  name: string;
  onClick: () => void;
  className?: string;
}) {
  return (
    <Button
      variant="ghost"
      size="icon"
      className={cn('size-7 text-destructive hover:text-destructive', className)}
      aria-label={`Remove ${name}`}
      title="Remove"
      onClick={onClick}
    >
      <Trash2Icon aria-hidden />
    </Button>
  );
}

/** Indentation of nested groups: a 2 px left rule (plus padding from 640 px). */
export const LEVEL_CLASS = 'border-l-2 border-border pl-2 sm:pl-4';

/** Visible "Level n" marker of nested groups below 640 px (the group's name says it too). */
export function LevelLabel({ level }: { level: number }) {
  return (
    <span className="text-xs font-medium text-muted-foreground sm:hidden" aria-hidden>
      {`Level ${level}`}
    </span>
  );
}
