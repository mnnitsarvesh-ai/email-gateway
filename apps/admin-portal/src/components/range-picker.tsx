'use client';

import { CalendarIcon } from 'lucide-react';
import { useId, useState } from 'react';
import { z } from 'zod';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useUrlState } from '@/hooks/use-url-state';
import {
  RANGE_PRESETS,
  resolvePreset,
  validateCustomRange,
  type RangePreset,
  type ResolvedRange,
} from '@/lib/range';

const day = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .optional()
  .catch(undefined);
export const RANGE_URL_SHAPE = {
  range: z.enum(RANGE_PRESETS).default('7d').catch('7d'),
  from: day,
  to: day,
};

/** The report range from the URL (`?range=7d` or `?from=YYYY-MM-DD&to=YYYY-MM-DD`). */
export function useRangeState(): [
  ResolvedRange,
  (next: { preset: RangePreset } | { from: string; to: string }) => void,
] {
  const [state, setState] = useUrlState(RANGE_URL_SHAPE);
  let range = resolvePreset(state.range);
  if (state.from && state.to) {
    const custom = validateCustomRange(state.from, state.to);
    if (custom.ok) range = custom.range;
  }
  const set = (next: { preset: RangePreset } | { from: string; to: string }) => {
    if ('preset' in next) setState({ range: next.preset, from: undefined, to: undefined });
    else setState({ range: undefined, from: next.from, to: next.to });
  };
  return [range, set];
}

const LABELS: Record<RangePreset, string> = {
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
};

/** Range selector: three presets and a custom UTC-day range (≤ 31 days). */
export function RangePicker({ className }: { className?: string }) {
  const [range, setRange] = useRangeState();
  const [open, setOpen] = useState(false);
  const [from, setFrom] = useState(range.preset === 'custom' ? range.from.slice(0, 10) : '');
  const [to, setTo] = useState(
    range.preset === 'custom'
      ? new Date(Date.parse(range.to) - 86_400_000).toISOString().slice(0, 10)
      : '',
  );
  const [error, setError] = useState<string | null>(null);
  const fromId = useId();
  const toId = useId();
  const errorId = useId();

  const apply = () => {
    const result = validateCustomRange(from, to);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setError(null);
    setRange({ from, to });
    setOpen(false);
  };

  return (
    <div className={className}>
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={range.preset === 'custom' ? 'custom' : range.preset}
          onValueChange={(value) => {
            if (value === 'custom') setOpen(true);
            else setRange({ preset: value as RangePreset });
          }}
        >
          <SelectTrigger aria-label="Report range" size="sm" className="min-w-40">
            <SelectValue>{range.label}</SelectValue>
          </SelectTrigger>
          <SelectContent>
            {RANGE_PRESETS.map((preset) => (
              <SelectItem key={preset} value={preset}>
                {LABELS[preset]}
              </SelectItem>
            ))}
            <SelectItem value="custom">Custom range …</SelectItem>
          </SelectContent>
        </Select>
        <Popover open={open} onOpenChange={setOpen}>
          <PopoverTrigger asChild>
            <Button variant="outline" size="sm" aria-label="Choose a custom range">
              <CalendarIcon aria-hidden />
              <span className="hidden sm:inline">Custom</span>
            </Button>
          </PopoverTrigger>
          <PopoverContent align="end" className="grid gap-3">
            <p className="text-sm font-medium">Custom range (UTC days)</p>
            <div className="grid gap-1.5">
              <Label htmlFor={fromId}>From</Label>
              <Input
                id={fromId}
                type="date"
                value={from}
                onChange={(e) => setFrom(e.target.value)}
                aria-describedby={error ? errorId : undefined}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor={toId}>To (inclusive)</Label>
              <Input
                id={toId}
                type="date"
                value={to}
                onChange={(e) => setTo(e.target.value)}
                aria-describedby={error ? errorId : undefined}
              />
            </div>
            {error ? (
              <p id={errorId} role="alert" className="text-xs font-medium text-destructive">
                {error}
              </p>
            ) : (
              <p className="text-xs text-muted-foreground">At most 31 days.</p>
            )}
            <Button size="sm" onClick={apply}>
              Apply
            </Button>
          </PopoverContent>
        </Popover>
      </div>
    </div>
  );
}
