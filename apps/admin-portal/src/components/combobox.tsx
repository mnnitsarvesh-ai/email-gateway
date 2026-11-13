'use client';

import { CheckIcon, ChevronsUpDownIcon } from 'lucide-react';
import { useState } from 'react';
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

export interface ComboboxOption {
  readonly value: string;
  readonly label: string;
  readonly description?: string;
}

/**
 * Pick one value from a long or searchable list. With `onSearch` the filtering is server-side
 * (the caller fetches options for the query); otherwise options are filtered locally.
 */
export function Combobox({
  options,
  value,
  onChange,
  label,
  placeholder = 'Select …',
  searchPlaceholder = 'Search …',
  emptyText = 'No match.',
  onSearch,
  loading = false,
  disabled = false,
  className,
  id,
}: {
  options: readonly ComboboxOption[];
  value: string | null;
  onChange: (value: string | null) => void;
  /** Accessible name of the trigger. */
  label: string;
  placeholder?: string;
  searchPlaceholder?: string;
  emptyText?: string;
  onSearch?: (query: string) => void;
  loading?: boolean;
  disabled?: boolean;
  className?: string;
  id?: string;
}) {
  const [open, setOpen] = useState(false);
  const selected = options.find((option) => option.value === value) ?? null;
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          id={id}
          variant="outline"
          role="combobox"
          aria-expanded={open}
          aria-label={label}
          disabled={disabled}
          className={cn(
            'w-full justify-between font-normal',
            !selected && 'text-muted-foreground',
            className,
          )}
        >
          <span className="truncate">{selected ? selected.label : placeholder}</span>
          <ChevronsUpDownIcon className="opacity-60" aria-hidden />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-(--radix-popover-trigger-width) min-w-64 p-0" align="start">
        <Command shouldFilter={!onSearch}>
          <CommandInput
            placeholder={searchPlaceholder}
            onValueChange={onSearch}
            aria-label={searchPlaceholder}
          />
          <CommandList>
            {loading ? <p className="p-3 text-sm text-muted-foreground">Loading …</p> : null}
            <CommandEmpty>{emptyText}</CommandEmpty>
            <CommandGroup>
              {options.map((option) => (
                <CommandItem
                  key={option.value}
                  value={onSearch ? option.value : `${option.label} ${option.value}`}
                  onSelect={() => {
                    onChange(option.value === value ? null : option.value);
                    setOpen(false);
                  }}
                >
                  <CheckIcon
                    className={cn(option.value === value ? 'opacity-100' : 'opacity-0')}
                    aria-hidden
                  />
                  <span className="truncate">{option.label}</span>
                  {option.description ? (
                    <span className="ml-auto truncate text-xs text-muted-foreground">
                      {option.description}
                    </span>
                  ) : null}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
