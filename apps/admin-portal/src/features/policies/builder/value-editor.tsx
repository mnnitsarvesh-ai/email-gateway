'use client';

import { CheckIcon, PencilIcon, PlusIcon, UsersIcon, XIcon } from 'lucide-react';
import { useId, useState } from 'react';
import { Combobox } from '@/components/combobox';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { cn } from '@/lib/utils';
import type { BuilderCatalog, CatalogField, CatalogOperator } from './catalog';
import { useBuilderContext, type DirectoryOption } from './context';
import {
  CheckboxList,
  ChipsInput,
  ChoiceSelect,
  FieldMessage,
  parseInteger,
  ToggleList,
  useDraft,
  type SelectOption,
} from './inputs';
import { isPlainObject } from './model';
import { humanizeValue, timeKindOf } from './summary';

/**
 * The value input of a condition, chosen by the operator's value shape × the field's type and
 * vocabulary (design §4.7, B1): every choice comes from the catalogue; a shape the builder has
 * no widget for is shown read-only (and kept unchanged).
 */

export interface ValueEditorProps {
  readonly field: CatalogField;
  readonly operator: CatalogOperator;
  readonly value: unknown;
  readonly onChange: (value: unknown) => void;
  /** Id of the visible "Value" label. */
  readonly labelledBy: string;
  readonly describedBy?: string;
  readonly invalid?: boolean;
}

const optionsOf = (values: readonly string[]): SelectOption[] =>
  values.map((value) => ({ value, label: humanizeValue(value) }));

const asList = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

// ---------------------------------------------------------------------------------------------
// Numbers (bytes with B/KiB/MiB/GiB, counts, scores; integers only)
// ---------------------------------------------------------------------------------------------

const BYTE_UNITS: ReadonlyArray<readonly [string, number]> = [
  ['B', 1],
  ['KiB', 1024],
  ['MiB', 1024 ** 2],
  ['GiB', 1024 ** 3],
];

/** The largest unit that divides the value exactly (inputs are whole numbers of the unit). */
export function unitFor(value: unknown, unit: string | null): number {
  if (unit !== 'bytes' || typeof value !== 'number' || value === 0) return 1;
  for (const [, factor] of [...BYTE_UNITS].reverse()) {
    if (value % factor === 0) return factor;
  }
  return 1;
}

const SAFE = Number.MAX_SAFE_INTEGER;

/** A whole-number text input (the caller owns the text). */
function WholeNumberInput({
  text,
  onText,
  factor,
  labelledBy,
  ariaLabel,
  describedBy,
  min,
  max,
  invalid,
}: {
  text: string;
  onText: (text: string) => void;
  factor: number;
  labelledBy?: string;
  ariaLabel?: string;
  describedBy?: string;
  min: number | null;
  max: number | null;
  invalid?: boolean;
}) {
  const messageId = useId();
  const bad = text.trim() !== '' && parseInteger(text) === null;
  return (
    <div className="grid min-w-0 gap-1">
      <Input
        type="number"
        inputMode="numeric"
        step={1}
        min={min !== null ? Math.ceil(min / factor) : undefined}
        max={max !== null && max < SAFE ? Math.floor(max / factor) : undefined}
        value={text}
        aria-labelledby={labelledBy}
        aria-label={ariaLabel}
        aria-invalid={bad || invalid || undefined}
        aria-describedby={
          [describedBy, bad ? messageId : null].filter(Boolean).join(' ') || undefined
        }
        onChange={(event) => onText(event.target.value)}
        className="h-8 min-w-0"
      />
      {bad ? <FieldMessage id={messageId}>Enter a whole number.</FieldMessage> : null}
    </div>
  );
}

function UnitSelect({
  factor,
  onChange,
  label,
}: {
  factor: number;
  onChange: (factor: number) => void;
  label: string;
}) {
  return (
    <ChoiceSelect
      ariaLabel={label}
      value={String(factor)}
      options={BYTE_UNITS.map(([name, f]) => ({ value: String(f), label: name }))}
      onChange={(next) => onChange(Number(next ?? 1))}
      className="w-24 shrink-0"
    />
  );
}

const textOf = (value: unknown, factor: number): string =>
  typeof value === 'number' ? String(value / factor) : '';

/** An integer value; byte fields get a unit (B/KiB/MiB/GiB) and are stored as integer bytes. */
export function NumberWithUnit({
  field,
  value,
  onChange,
  labelledBy,
  describedBy,
  invalid,
}: Pick<
  ValueEditorProps,
  'field' | 'value' | 'onChange' | 'labelledBy' | 'describedBy' | 'invalid'
>) {
  const [factor, setFactor] = useState(() => unitFor(value, field.unit));
  const [text, setText] = useDraft(textOf(value, factor), (draft) => {
    const n = parseInteger(draft);
    return n === null ? value === undefined : n * factor === value;
  });
  const emit = (draft: string, f: number) => {
    const n = parseInteger(draft);
    onChange(n === null ? undefined : n * f);
  };
  const unitLabel = field.unit && field.unit !== 'bytes' ? field.unit : null;
  return (
    <div className="flex min-w-0 items-start gap-2">
      <div className="min-w-0 flex-1">
        <WholeNumberInput
          text={text}
          onText={(next) => {
            setText(next);
            emit(next, factor);
          }}
          factor={factor}
          labelledBy={labelledBy}
          describedBy={describedBy}
          min={field.min}
          max={field.max}
          invalid={invalid}
        />
      </div>
      {field.unit === 'bytes' ? (
        <UnitSelect
          label="Unit"
          factor={factor}
          onChange={(next) => {
            setFactor(next);
            emit(text, next);
          }}
        />
      ) : unitLabel ? (
        <span className="pt-2 text-xs text-muted-foreground">{unitLabel}</span>
      ) : null}
    </div>
  );
}

/** `[low, high]` integers (one unit for both); written only when both are whole numbers. */
function RangeInput({
  field,
  value,
  onChange,
  labelledBy,
  describedBy,
  invalid,
}: Pick<
  ValueEditorProps,
  'field' | 'value' | 'onChange' | 'labelledBy' | 'describedBy' | 'invalid'
>) {
  const pair = Array.isArray(value) ? value : [];
  const [factor, setFactor] = useState(() =>
    Math.min(unitFor(pair[0], field.unit), unitFor(pair[1], field.unit)),
  );
  const [low, setLow] = useState(() => textOf(pair[0], factor));
  const [high, setHigh] = useState(() => textOf(pair[1], factor));
  const [seen, setSeen] = useState(value);
  if (value !== seen) {
    // Another complete pair arrived from outside (a replaced model): show it.
    setSeen(value);
    const lo = parseInteger(low);
    const hi = parseInteger(high);
    if (
      Array.isArray(value) &&
      value.length === 2 &&
      !(lo !== null && hi !== null && lo * factor === value[0] && hi * factor === value[1])
    ) {
      setLow(textOf(value[0], factor));
      setHigh(textOf(value[1], factor));
    }
  }
  const emit = (lowText: string, highText: string, f: number) => {
    const lo = parseInteger(lowText);
    const hi = parseInteger(highText);
    onChange(lo !== null && hi !== null ? [lo * f, hi * f] : undefined);
  };
  return (
    <div
      role="group"
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      className="flex min-w-0 flex-wrap items-start gap-2"
    >
      <div className="min-w-24 flex-1">
        <WholeNumberInput
          ariaLabel="From"
          text={low}
          onText={(next) => {
            setLow(next);
            emit(next, high, factor);
          }}
          factor={factor}
          min={field.min}
          max={field.max}
          invalid={invalid}
        />
      </div>
      <span className="pt-2 text-xs text-muted-foreground">and</span>
      <div className="min-w-24 flex-1">
        <WholeNumberInput
          ariaLabel="To"
          text={high}
          onText={(next) => {
            setHigh(next);
            emit(low, next, factor);
          }}
          factor={factor}
          min={field.min}
          max={field.max}
          invalid={invalid}
        />
      </div>
      {field.unit === 'bytes' ? (
        <UnitSelect
          label="Unit"
          factor={factor}
          onChange={(next) => {
            setFactor(next);
            emit(low, high, next);
          }}
        />
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Regular expressions (never compiled in the browser; the server checks them with RE2)
// ---------------------------------------------------------------------------------------------

const regexParts = (item: unknown): { pattern: string; insensitive: boolean } | null => {
  if (typeof item === 'string') return { pattern: item, insensitive: false };
  if (isPlainObject(item) && typeof item.pattern === 'string') {
    return { pattern: item.pattern, insensitive: item.flags === 'i' };
  }
  return null;
};

/** A pattern string, or `{ pattern, flags: 'i' }` when case-insensitive. */
export const regexItem = (pattern: string, insensitive: boolean): unknown =>
  insensitive ? { pattern, flags: 'i' } : pattern;

function RegexList({
  operator,
  value,
  onChange,
  labelledBy,
  describedBy,
}: Pick<ValueEditorProps, 'operator' | 'value' | 'onChange' | 'labelledBy' | 'describedBy'>) {
  const items = asList(value);
  const [pattern, setPattern] = useState('');
  const [insensitive, setInsensitive] = useState(false);
  const checkboxId = useId();
  const atMax = operator.maxItems !== null && items.length >= operator.maxItems;
  const add = () => {
    if (pattern === '' || atMax) return;
    onChange([...items, regexItem(pattern, insensitive)]);
    setPattern('');
    setInsensitive(false);
  };
  return (
    <div
      role="group"
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      className="grid min-w-0 gap-2"
    >
      {items.length > 0 ? (
        <ul className="grid gap-1.5" aria-label="Patterns">
          {items.map((item, i) => {
            const parts = regexParts(item);
            const shown = parts
              ? `/${parts.pattern}/${parts.insensitive ? 'i' : ''}`
              : JSON.stringify(item);
            return (
              <li
                key={`${shown}-${i}`}
                className="flex min-w-0 flex-wrap items-center gap-1 rounded-md border bg-muted px-2 py-1 text-xs"
              >
                <span className="min-w-0 flex-1 font-mono break-all">{shown}</span>
                {parts ? (
                  <>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 px-1.5"
                      aria-pressed={parts.insensitive}
                      aria-label={`Case-insensitive: ${shown}`}
                      onClick={() =>
                        onChange(
                          items.map((it, j) =>
                            j === i ? regexItem(parts.pattern, !parts.insensitive) : it,
                          ),
                        )
                      }
                    >
                      {parts.insensitive ? <CheckIcon aria-hidden /> : null}
                      Aa
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-6"
                      aria-label={`Edit ${shown}`}
                      onClick={() => {
                        setPattern(parts.pattern);
                        setInsensitive(parts.insensitive);
                        onChange(items.filter((_, j) => j !== i));
                      }}
                    >
                      <PencilIcon className="size-3.5" aria-hidden />
                    </Button>
                  </>
                ) : null}
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-6"
                  aria-label={`Remove ${shown}`}
                  onClick={() => onChange(items.filter((_, j) => j !== i))}
                >
                  <XIcon className="size-3.5" aria-hidden />
                </Button>
              </li>
            );
          })}
        </ul>
      ) : null}
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <Input
          value={pattern}
          maxLength={operator.maxItemLength ?? undefined}
          placeholder="Pattern, e.g. ^invoice-[0-9]+\.pdf$"
          aria-label="Add pattern"
          autoComplete="off"
          spellCheck={false}
          disabled={atMax}
          onChange={(event) => setPattern(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              add();
            }
          }}
          className="h-8 min-w-40 flex-1 font-mono"
        />
        <div className="flex items-center gap-1.5">
          <Checkbox
            id={checkboxId}
            checked={insensitive}
            disabled={atMax}
            onCheckedChange={(next) => setInsensitive(next === true)}
          />
          <Label htmlFor={checkboxId} className="text-xs font-normal">
            Case-insensitive
          </Label>
        </div>
        <Button variant="outline" size="sm" onClick={add} disabled={atMax || pattern === ''}>
          <PlusIcon aria-hidden />
          Add
        </Button>
      </div>
      {atMax ? (
        <p className="text-xs text-muted-foreground">{`At most ${String(operator.maxItems)} patterns.`}</p>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Directory ids (departments and users)
// ---------------------------------------------------------------------------------------------

/**
 * Which directory an `id` field references. The catalogue does not say; the last segment of the
 * field name does (`department` / `user`); any other `id` field offers both lists.
 */
export function directoryKindOf(field: Pick<CatalogField, 'name'>): 'departments' | 'users' | null {
  const last = field.name.slice(field.name.lastIndexOf('.') + 1);
  return last === 'department' ? 'departments' : last === 'user' ? 'users' : null;
}

function DirectoryPicker({
  field,
  operator,
  value,
  onChange,
  labelledBy,
  describedBy,
}: Pick<
  ValueEditorProps,
  'field' | 'operator' | 'value' | 'onChange' | 'labelledBy' | 'describedBy'
>) {
  const { directory } = useBuilderContext();
  const [open, setOpen] = useState(false);
  const kind = directoryKindOf(field);
  const groups: Array<{ heading: string; options: DirectoryOption[] }> = [];
  if (kind !== 'users' && directory?.departments?.length) {
    groups.push({ heading: 'Departments', options: directory.departments });
  }
  if (kind !== 'departments' && directory?.users?.length) {
    groups.push({ heading: 'Users', options: directory.users });
  }
  const items = asList(value);
  const labelOf = new Map(groups.flatMap((g) => g.options.map((o) => [o.id, o.label] as const)));
  const noun =
    kind === 'departments' ? 'department' : kind === 'users' ? 'user' : 'directory entry';
  const shown = (item: unknown) =>
    typeof item === 'string' ? (labelOf.get(item) ?? `${item.slice(0, 8)}…`) : JSON.stringify(item);
  if (groups.length === 0) {
    // No directory options (none loaded or none exist): plain UUID entry.
    return (
      <div className="grid min-w-0 gap-1">
        <ChipsInput
          labelledBy={labelledBy}
          describedBy={describedBy}
          items={items}
          onChange={onChange}
          noun={`${noun} id`}
          maxItems={operator.maxItems}
          placeholder="Public id (UUID)"
          split
        />
        <p className="text-xs text-muted-foreground">
          {directory?.loading
            ? 'Loading the directory …'
            : `Enter the ${noun} public id; names are not available here.`}
        </p>
      </div>
    );
  }
  const atMax = operator.maxItems !== null && items.length >= operator.maxItems;
  return (
    <div
      role="group"
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      className="grid min-w-0 gap-2"
    >
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button variant="outline" size="sm" className="w-fit" disabled={atMax}>
            <UsersIcon aria-hidden />
            {`Add ${noun}`}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-72 p-0" align="start">
          <Command>
            <CommandInput placeholder={`Search ${noun}s …`} aria-label={`Search ${noun}s`} />
            <CommandList>
              <CommandEmpty>No match.</CommandEmpty>
              {groups.map((group) => (
                <CommandGroup key={group.heading} heading={group.heading}>
                  {group.options.map((option) => {
                    const selected = items.includes(option.id);
                    return (
                      <CommandItem
                        key={option.id}
                        value={`${option.label} ${option.id}`}
                        onSelect={() => {
                          onChange(
                            selected ? items.filter((i) => i !== option.id) : [...items, option.id],
                          );
                          setOpen(false);
                        }}
                      >
                        <CheckIcon
                          className={cn(selected ? 'opacity-100' : 'opacity-0')}
                          aria-hidden
                        />
                        <span className="truncate">{option.label}</span>
                      </CommandItem>
                    );
                  })}
                </CommandGroup>
              ))}
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
      {items.length > 0 ? (
        <ul className="flex min-w-0 flex-wrap gap-1.5" aria-label={`Selected ${noun}s`}>
          {items.map((item, i) => (
            <li
              key={`${String(item)}-${i}`}
              className="inline-flex max-w-full items-center gap-0.5 rounded-md border bg-muted py-0.5 pr-0.5 pl-2 text-xs"
            >
              <span className="min-w-0 break-all">{shown(item)}</span>
              <Button
                variant="ghost"
                size="icon"
                className="size-6"
                aria-label={`Remove ${shown(item)}`}
                onClick={() => onChange(items.filter((_, j) => j !== i))}
              >
                <XIcon className="size-3.5" aria-hidden />
              </Button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-muted-foreground">{`No ${noun} chosen.`}</p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Time windows and date ranges (time zones and weekdays from the catalogue)
// ---------------------------------------------------------------------------------------------

type TimeKind = 'window' | 'date_range';

function setKey(
  value: Record<string, unknown>,
  key: string,
  next: unknown,
  order: readonly string[],
) {
  const merged: Record<string, unknown> = { ...value };
  if (next === undefined || next === '') delete merged[key];
  else merged[key] = next;
  // Keys in the DSL's order, then anything else as it was.
  const out: Record<string, unknown> = {};
  for (const k of order) if (merged[k] !== undefined) out[k] = merged[k];
  for (const [k, v] of Object.entries(merged)) if (!order.includes(k)) out[k] = v;
  return Object.keys(out).length > 0 ? out : undefined;
}

function TimeValueInput({
  catalog,
  field,
  value,
  onChange,
  labelledBy,
  describedBy,
}: Pick<ValueEditorProps, 'field' | 'value' | 'onChange' | 'labelledBy' | 'describedBy'> & {
  catalog: BuilderCatalog;
}) {
  const object = isPlainObject(value) ? value : {};
  const fixed = timeKindOf(field);
  const [chosen, setChosen] = useState<TimeKind>(() =>
    'days' in object ? 'window' : 'from' in object ? 'date_range' : 'window',
  );
  const kind: TimeKind = fixed ?? chosen;
  const order = kind === 'window' ? ['timeZone', 'days', 'from', 'to'] : ['timeZone', 'from', 'to'];
  const update = (key: string, next: unknown) => onChange(setKey(object, key, next, order));
  const fromId = useId();
  const toId = useId();
  const str = (key: string): string => {
    const v = object[key];
    return typeof v === 'string' ? v : '';
  };
  return (
    <div
      role="group"
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      className="grid min-w-0 gap-2"
    >
      {fixed === null ? (
        <ChoiceSelect
          ariaLabel="Kind of time value"
          value={chosen}
          options={[
            { value: 'window', label: 'Weekly window' },
            { value: 'date_range', label: 'Date range' },
          ]}
          onChange={(next) => setChosen(next === 'date_range' ? 'date_range' : 'window')}
          className="w-48"
        />
      ) : null}
      <Combobox
        label="Time zone"
        value={str('timeZone') || null}
        onChange={(zone) => update('timeZone', zone ?? undefined)}
        options={catalog.timeZones.map((zone) => ({ value: zone, label: zone }))}
        placeholder="Choose a time zone"
        searchPlaceholder="Search time zones …"
        className="h-8 sm:max-w-72"
      />
      {kind === 'window' ? (
        <ToggleList
          label="Days"
          options={catalog.weekdays.map((day) => ({
            value: day,
            label: day.charAt(0).toUpperCase() + day.slice(1),
          }))}
          values={
            Array.isArray(object.days)
              ? object.days.filter((d): d is string => typeof d === 'string')
              : []
          }
          onChange={(days) => update('days', days.length > 0 ? days : undefined)}
        />
      ) : null}
      <div className="flex min-w-0 flex-wrap items-end gap-2">
        <div className="grid gap-1">
          <Label htmlFor={fromId} className="text-xs text-muted-foreground">
            {kind === 'window' ? 'From (HH:MM)' : 'From date'}
          </Label>
          <Input
            id={fromId}
            type={kind === 'window' ? 'text' : 'date'}
            inputMode={kind === 'window' ? 'numeric' : undefined}
            placeholder={kind === 'window' ? '09:00' : undefined}
            maxLength={kind === 'window' ? 5 : undefined}
            value={str('from')}
            onChange={(event) => update('from', event.target.value.trim() || undefined)}
            className="h-8 w-36"
          />
        </div>
        <div className="grid gap-1">
          <Label htmlFor={toId} className="text-xs text-muted-foreground">
            {kind === 'window' ? 'To (HH:MM, 24:00 = midnight)' : 'To date'}
          </Label>
          <Input
            id={toId}
            type={kind === 'window' ? 'text' : 'date'}
            inputMode={kind === 'window' ? 'numeric' : undefined}
            placeholder={kind === 'window' ? '18:00' : undefined}
            maxLength={kind === 'window' ? 5 : undefined}
            value={str('to')}
            onChange={(event) => update('to', event.target.value.trim() || undefined)}
            className="h-8 w-36"
          />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// The dispatcher
// ---------------------------------------------------------------------------------------------

export function ValueEditor(props: ValueEditorProps) {
  const { catalog } = useBuilderContext();
  const { field, operator, value, onChange, labelledBy, describedBy, invalid } = props;
  switch (operator.valueShape) {
    case 'none':
      return <p className="pt-2 text-xs text-muted-foreground">No value needed.</p>;
    case 'boolean':
      return (
        <ChoiceSelect
          labelledBy={labelledBy}
          describedBy={describedBy}
          invalid={invalid}
          placeholder="Choose yes or no"
          value={value === true ? 'yes' : value === false ? 'no' : undefined}
          options={[
            { value: 'yes', label: 'Yes' },
            { value: 'no', label: 'No' },
          ]}
          onChange={(next) => onChange(next === 'yes' ? true : next === 'no' ? false : undefined)}
        />
      );
    case 'scalar':
      if (field.values) {
        return (
          <ChoiceSelect
            labelledBy={labelledBy}
            describedBy={describedBy}
            invalid={invalid}
            placeholder="Choose a value"
            value={typeof value === 'string' ? value : undefined}
            options={optionsOf(field.values)}
            onChange={onChange}
          />
        );
      }
      if (field.type === 'int') return <NumberWithUnit {...props} />;
      if (field.type === 'id') {
        return (
          <DirectoryPicker
            {...props}
            value={typeof value === 'string' ? [value] : []}
            onChange={(next) => onChange(Array.isArray(next) ? next[next.length - 1] : undefined)}
          />
        );
      }
      return <ScalarText {...props} maxLength={catalog.limits.stringValue ?? null} />;
    case 'range':
      return <RangeInput {...props} />;
    case 'time':
      return <TimeValueInput {...props} catalog={catalog} />;
    case 'list':
      return <ListValue {...props} />;
    default:
      return (
        <p className="pt-2 text-xs text-muted-foreground">
          This operator&apos;s value cannot be edited here; it is kept as{' '}
          <span className="font-mono">{JSON.stringify(value) ?? 'not set'}</span>.
        </p>
      );
  }
}

function ScalarText({
  value,
  onChange,
  labelledBy,
  describedBy,
  invalid,
  maxLength,
}: Pick<ValueEditorProps, 'value' | 'onChange' | 'labelledBy' | 'describedBy' | 'invalid'> & {
  maxLength: number | null;
}) {
  const external = typeof value === 'string' ? value : '';
  const [text, setText] = useDraft(external, (draft) => draft.trim() === external);
  return (
    <Input
      value={text}
      maxLength={maxLength ?? undefined}
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      aria-invalid={invalid || undefined}
      autoComplete="off"
      spellCheck={false}
      onChange={(event) => {
        setText(event.target.value);
        const trimmed = event.target.value.trim();
        onChange(trimmed === '' ? undefined : trimmed);
      }}
      className="h-8 min-w-0"
    />
  );
}

const SPLIT_KINDS = ['domain', 'cidr', 'code'];
const SPLIT_TYPES = ['address', 'domain', 'ip', 'id'];

function ListValue(props: ValueEditorProps) {
  const { field, operator, value, onChange, labelledBy, describedBy } = props;
  const items = asList(value);
  const kind = operator.itemKind;
  if (kind === 'regex') return <RegexList {...props} />;
  if (kind === 'field' && field.type === 'id') return <DirectoryPicker {...props} />;
  if ((kind === 'field' || kind === 'code') && field.values) {
    return (
      <CheckboxList
        labelledBy={labelledBy}
        describedBy={describedBy}
        values={items}
        options={optionsOf(field.values)}
        maxItems={operator.maxItems}
        onChange={onChange}
      />
    );
  }
  const noun =
    kind === 'domain'
      ? 'domain'
      : kind === 'glob'
        ? 'pattern'
        : kind === 'cidr'
          ? 'network'
          : kind === 'code'
            ? 'code'
            : 'value';
  return (
    <ChipsInput
      labelledBy={labelledBy}
      describedBy={describedBy}
      items={items}
      onChange={onChange}
      noun={noun}
      maxItems={operator.maxItems}
      maxItemLength={operator.maxItemLength}
      suggestions={kind === 'code' ? field.suggestions : null}
      split={SPLIT_KINDS.includes(kind ?? '') || SPLIT_TYPES.includes(field.type)}
    />
  );
}
