'use client';

import { useId, useState } from 'react';
import { z } from 'zod';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useUrlState } from '@/hooks/use-url-state';
import {
  ADMIN_MAX_DAYS,
  ADMIN_RANGE_PRESETS,
  customRange,
  presetRange,
  type AdminRange,
  type AdminRangePreset,
} from './model';

const day = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .optional()
  .catch(undefined);

export const ADMIN_RANGE_URL_SHAPE = {
  days: z.enum(ADMIN_RANGE_PRESETS).default('30').catch('30'),
  from: day,
  to: day,
};

/** The page's window (`?days=7|30|90` or `?from=YYYY-MM-DD&to=YYYY-MM-DD`, ≤ 92 days, UTC). */
export function useAdminRange(): [
  AdminRange,
  (next: { preset: AdminRangePreset } | { from: string; to: string }) => void,
] {
  const [state, setState] = useUrlState(ADMIN_RANGE_URL_SHAPE);
  let range = presetRange(state.days);
  if (state.from && state.to) {
    const custom = customRange(state.from, state.to);
    if (custom.ok) range = custom.range;
  }
  const set = (next: { preset: AdminRangePreset } | { from: string; to: string }) => {
    if ('preset' in next) setState({ days: next.preset, from: undefined, to: undefined });
    else setState({ days: undefined, from: next.from, to: next.to });
  };
  return [range, set];
}

const CUSTOM = 'custom';

/** Range selector of the administration page: 7, 30 or 90 days, or a custom UTC-day window. */
export function AdminRangeControl({ className }: { className?: string }) {
  const [range, setRange] = useAdminRange();
  const [state] = useUrlState(ADMIN_RANGE_URL_SHAPE);
  const isCustom = Boolean(state.from && state.to);
  const [editing, setEditing] = useState(false);
  const [from, setFrom] = useState(range.fromDay);
  const [to, setTo] = useState(range.toDay);
  const [error, setError] = useState<string | null>(null);
  const fromId = useId();
  const toId = useId();
  const errorId = useId();
  const showCustom = editing || isCustom;

  const apply = () => {
    const result = customRange(from, to);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setError(null);
    setEditing(false);
    setRange({ from, to });
  };

  return (
    <div className={className}>
      <div className="flex flex-wrap items-end gap-2">
        <Select
          value={showCustom ? CUSTOM : state.days}
          onValueChange={(value) => {
            if (value === CUSTOM) {
              setFrom(range.fromDay);
              setTo(range.toDay);
              setEditing(true);
            } else {
              setEditing(false);
              setError(null);
              setRange({ preset: value as AdminRangePreset });
            }
          }}
        >
          <SelectTrigger aria-label="Time range" size="sm" className="min-w-40">
            <SelectValue>{showCustom ? 'Custom range' : range.label}</SelectValue>
          </SelectTrigger>
          <SelectContent>
            {ADMIN_RANGE_PRESETS.map((preset) => (
              <SelectItem key={preset} value={preset}>
                Last {preset} days
              </SelectItem>
            ))}
            <SelectItem value={CUSTOM}>Custom range …</SelectItem>
          </SelectContent>
        </Select>
        {showCustom ? (
          <>
            <div className="grid gap-1">
              <Label htmlFor={fromId} className="text-xs">
                From (UTC)
              </Label>
              <Input
                id={fromId}
                type="date"
                value={from}
                onChange={(event) => setFrom(event.target.value)}
                className="h-8 w-40"
                aria-describedby={error ? errorId : undefined}
              />
            </div>
            <div className="grid gap-1">
              <Label htmlFor={toId} className="text-xs">
                To (inclusive)
              </Label>
              <Input
                id={toId}
                type="date"
                value={to}
                onChange={(event) => setTo(event.target.value)}
                className="h-8 w-40"
                aria-describedby={error ? errorId : undefined}
              />
            </div>
            <Button size="sm" variant="outline" onClick={apply}>
              Apply
            </Button>
          </>
        ) : null}
      </div>
      {error ? (
        <p id={errorId} role="alert" className="mt-1 text-xs font-medium text-destructive">
          {error}
        </p>
      ) : (
        <p className="mt-1 text-xs text-muted-foreground">
          {range.fromDay} to {range.toDay} (UTC), at most {ADMIN_MAX_DAYS} days.
        </p>
      )}
    </div>
  );
}
