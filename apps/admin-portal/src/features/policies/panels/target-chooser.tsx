'use client';

import { useId } from 'react';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import type { TargetId, TargetOption } from './targets';

/** The target of a test or dry-run (a radio group; one option is shown as text). */
export function TargetChooser({
  targets,
  value,
  onChange,
  legend = 'Evaluate against',
}: {
  targets: readonly TargetOption[];
  value: TargetId;
  onChange: (id: TargetId) => void;
  legend?: string;
}) {
  const id = useId();
  const current = targets.find((t) => t.id === value) ?? targets[0];
  if (!current) return null;
  if (targets.length === 1) {
    return (
      <div className="grid gap-0.5 text-sm">
        <p className="text-xs font-medium text-muted-foreground">{legend}</p>
        <p className="font-medium">{current.label}</p>
        <p className="text-xs text-muted-foreground">{current.description}</p>
      </div>
    );
  }
  return (
    <fieldset className="grid min-w-0 gap-2">
      <legend className="mb-1 text-xs font-medium text-muted-foreground">{legend}</legend>
      <RadioGroup
        value={current.id}
        onValueChange={(next) => onChange(next as TargetId)}
        className="grid gap-2 sm:grid-cols-2"
      >
        {targets.map((target) => (
          <div key={target.id} className="flex min-w-0 items-start gap-2 rounded-md border p-2">
            <RadioGroupItem
              id={`${id}-${target.id}`}
              value={target.id}
              aria-describedby={`${id}-${target.id}-desc`}
              className="mt-0.5"
            />
            <div className="grid min-w-0 gap-0.5">
              <Label htmlFor={`${id}-${target.id}`} className="font-medium">
                {target.label}
              </Label>
              <span id={`${id}-${target.id}-desc`} className="text-xs text-muted-foreground">
                {target.description}
              </span>
            </div>
          </div>
        ))}
      </RadioGroup>
    </fieldset>
  );
}
