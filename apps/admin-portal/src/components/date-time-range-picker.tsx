'use client';

import { CalendarClockIcon } from 'lucide-react';
import { useId, useState } from 'react';
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
import {
  DATE_TIME_PRESETS,
  DATE_TIME_PRESET_LABEL,
  MESSAGES_MAX_RANGE_DAYS,
  browserTimeZone,
  formatLocalRange,
  toLocalInput,
  validateCustomDateTimeRange,
  type DateTimePreset,
  type DateTimeRangeError,
  type DateTimeRangeValue,
} from '@/lib/date-time-range';
import { cn } from '@/lib/utils';

/**
 * Minute-precision range picker (step 7.2 §2 E10): presets 1 h, 24 h, 7 d, 30 d and a custom
 * from/to entered in the browser's time zone (native `datetime-local` inputs) and emitted as UTC
 * ISO 8601; at most `maxDays` days, validated inline before anything is applied. Controlled: the
 * caller keeps the value (usually in the URL).
 */
export function DateTimeRangePicker({
  value,
  onChange,
  maxDays = MESSAGES_MAX_RANGE_DAYS,
  label = 'Time range',
  now = () => Date.now(),
  className,
}: {
  value: DateTimeRangeValue;
  onChange: (value: DateTimeRangeValue) => void;
  maxDays?: number;
  label?: string;
  /** Clock (tests). */
  now?: () => number;
  className?: string;
}) {
  const labelId = useId();
  const fromId = useId();
  const toId = useId();
  const hintId = useId();
  const [open, setOpen] = useState(false);
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [errors, setErrors] = useState<readonly DateTimeRangeError[]>([]);
  const timeZone = browserTimeZone();

  const openCustom = () => {
    if (value.kind === 'custom') {
      setFrom(toLocalInput(value.from));
      setTo(toLocalInput(value.to));
    } else {
      const end = now();
      setFrom(toLocalInput(new Date(end - 24 * 3_600_000).toISOString()));
      setTo(toLocalInput(new Date(end).toISOString()));
    }
    setErrors([]);
    setOpen(true);
  };

  const apply = () => {
    const result = validateCustomDateTimeRange(from, to, now(), maxDays);
    if (!result.ok) {
      setErrors(result.errors);
      return;
    }
    setErrors([]);
    setOpen(false);
    onChange({ kind: 'custom', from: result.from, to: result.to });
  };

  const errorOf = (field: DateTimeRangeError['field']) =>
    errors.find((error) => error.field === field)?.message;
  const fromError = errorOf('from');
  const toError = errorOf('to');
  const rangeError = errorOf('range');
  const summary =
    value.kind === 'custom'
      ? `Custom: ${formatLocalRange(value.from, value.to)}`
      : DATE_TIME_PRESET_LABEL[value.kind];

  return (
    <div className={cn('grid gap-1', className)}>
      <span id={labelId} className="text-xs font-medium text-muted-foreground">
        {label}
      </span>
      <div className="flex flex-wrap items-center gap-1">
        <Select
          value={value.kind}
          onValueChange={(next) => {
            if (next === 'custom') openCustom();
            else onChange({ kind: next as DateTimePreset });
          }}
        >
          <SelectTrigger
            size="sm"
            aria-labelledby={`${labelId} ${labelId}-value`}
            className="max-w-full min-w-40"
          >
            <SelectValue>
              <span id={`${labelId}-value`} className="truncate">
                {summary}
              </span>
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            {DATE_TIME_PRESETS.map((preset) => (
              <SelectItem key={preset} value={preset}>
                {DATE_TIME_PRESET_LABEL[preset]}
              </SelectItem>
            ))}
            <SelectItem value="custom">Custom range …</SelectItem>
          </SelectContent>
        </Select>
        <Popover
          open={open}
          onOpenChange={(next) => {
            if (next) openCustom();
            else setOpen(false);
          }}
        >
          <PopoverTrigger asChild>
            <Button variant="outline" size="sm" aria-label="Choose a custom time range">
              <CalendarClockIcon aria-hidden />
              <span className="hidden sm:inline">Custom</span>
            </Button>
          </PopoverTrigger>
          <PopoverContent
            align="start"
            className="grid w-80 max-w-[calc(100vw-2rem)] gap-3"
            aria-labelledby={`${labelId}-title`}
          >
            <div className="grid gap-0.5">
              <p id={`${labelId}-title`} className="text-sm font-medium">
                Custom time range
              </p>
              <p id={hintId} className="text-xs text-muted-foreground">
                Times in your time zone ({timeZone}), sent as UTC. At most {maxDays} days.
              </p>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor={fromId}>From</Label>
              <Input
                id={fromId}
                type="datetime-local"
                step={60}
                value={from}
                onChange={(event) => setFrom(event.target.value)}
                aria-invalid={fromError || rangeError ? true : undefined}
                aria-describedby={ids(hintId, fromError ? `${fromId}-error` : null)}
              />
              {fromError ? (
                <p id={`${fromId}-error`} className="text-xs font-medium text-destructive">
                  {fromError}
                </p>
              ) : null}
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor={toId}>To</Label>
              <Input
                id={toId}
                type="datetime-local"
                step={60}
                value={to}
                onChange={(event) => setTo(event.target.value)}
                aria-invalid={toError || rangeError ? true : undefined}
                aria-describedby={ids(hintId, toError ? `${toId}-error` : null)}
              />
              {toError ? (
                <p id={`${toId}-error`} className="text-xs font-medium text-destructive">
                  {toError}
                </p>
              ) : null}
            </div>
            {errors.length > 0 ? (
              <p role="alert" className="text-xs font-medium text-destructive">
                {rangeError ?? 'Correct the highlighted fields.'}
              </p>
            ) : null}
            <div className="flex justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button size="sm" onClick={apply}>
                Apply
              </Button>
            </div>
          </PopoverContent>
        </Popover>
      </div>
    </div>
  );
}

/** Space-separated element ids (aria-describedby). */
function ids(...values: (string | null)[]): string {
  return values.filter(Boolean).join(' ');
}
