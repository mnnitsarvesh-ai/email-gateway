'use client';

import type { Control, FieldPath, FieldValues } from 'react-hook-form';
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { humanize } from '@/lib/format';

/** Small react-hook-form field helpers shared by the WP3 dialogs (text, textarea, select). */
export function TextField<T extends FieldValues>({
  control,
  name,
  label,
  required,
  hint,
  type = 'text',
  mono,
  multiline,
}: {
  control: Control<T>;
  name: FieldPath<T>;
  label: string;
  required?: boolean;
  hint?: string;
  type?: string;
  mono?: boolean;
  multiline?: boolean;
}) {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel required={required}>{label}</FormLabel>
          <FormControl>
            {multiline ? (
              <Textarea {...field} value={String(field.value ?? '')} rows={3} />
            ) : (
              <Input
                {...field}
                value={String(field.value ?? '')}
                type={type}
                autoComplete="off"
                spellCheck={false}
                className={mono ? 'font-mono text-xs' : undefined}
              />
            )}
          </FormControl>
          {hint ? <FormDescription>{hint}</FormDescription> : null}
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

export function SelectField<T extends FieldValues>({
  control,
  name,
  label,
  options,
  required,
  labels,
}: {
  control: Control<T>;
  name: FieldPath<T>;
  label: string;
  options: readonly string[];
  required?: boolean;
  labels?: Record<string, string>;
}) {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel required={required}>{label}</FormLabel>
          <Select value={String(field.value ?? '')} onValueChange={field.onChange}>
            <FormControl>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Choose …" />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              {options.map((option) => (
                <SelectItem key={option} value={option}>
                  {labels?.[option] ?? humanize(option)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}
