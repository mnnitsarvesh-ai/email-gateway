'use client';

import { CheckIcon, ChevronsUpDownIcon } from 'lucide-react';
import { useId, useState } from 'react';
import { Button } from '@/components/ui/button';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { cn } from '@/lib/utils';
import { fieldOf, groupFields, type BuilderCatalog, type CatalogField } from './catalog';

/**
 * The searchable field picker of a condition: the fields the catalogue allows at this place,
 * grouped and ordered by `fieldGroups`, labelled by `label` (the DSL name is shown too). The
 * trigger's name is "<label> <current field>" (label in name, WCAG 2.5.3).
 */
export function FieldPicker({
  catalog,
  fields,
  value,
  onChange,
  labelId,
  describedBy,
  invalid,
  registerRef,
}: {
  catalog: BuilderCatalog;
  fields: readonly CatalogField[];
  value: string | undefined;
  onChange: (field: string) => void;
  labelId: string;
  describedBy?: string;
  invalid?: boolean;
  registerRef?: (element: HTMLElement | null) => void;
}) {
  const [open, setOpen] = useState(false);
  const valueId = useId();
  const current = fieldOf(catalog, value);
  const offered = value === undefined || fields.some((f) => f.name === value);
  const shown =
    value === undefined
      ? 'Choose a field'
      : `${current?.label ?? value}${offered ? '' : ' (not available here)'}`;
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          ref={registerRef}
          variant="outline"
          role="combobox"
          aria-expanded={open}
          aria-labelledby={`${labelId} ${valueId}`}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          className={cn(
            'h-8 w-full min-w-0 justify-between px-2 font-normal',
            value === undefined && 'text-muted-foreground',
          )}
        >
          <span id={valueId} className="truncate">
            {shown}
          </span>
          <ChevronsUpDownIcon className="opacity-60" aria-hidden />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-(--radix-popover-trigger-width) min-w-72 p-0" align="start">
        <Command>
          <CommandInput placeholder="Search fields …" aria-label="Search fields" />
          <CommandList>
            <CommandEmpty>No field matches.</CommandEmpty>
            {groupFields(catalog, fields).map((group) => (
              <CommandGroup key={group.id} heading={group.label}>
                {group.fields.map((field) => (
                  <CommandItem
                    key={field.name}
                    value={`${field.label} ${field.name}`}
                    onSelect={() => {
                      if (field.name !== value) onChange(field.name);
                      setOpen(false);
                    }}
                  >
                    <CheckIcon
                      className={cn(field.name === value ? 'opacity-100' : 'opacity-0')}
                      aria-hidden
                    />
                    <span className="truncate">{field.label}</span>
                    <span className="ml-auto truncate font-mono text-xs text-muted-foreground">
                      {field.name}
                    </span>
                  </CommandItem>
                ))}
              </CommandGroup>
            ))}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
