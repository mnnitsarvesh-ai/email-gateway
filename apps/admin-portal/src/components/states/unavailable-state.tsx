import { CalendarClockIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { PLAN_STEPS } from '@/lib/navigation';
import { cn } from '@/lib/utils';

/**
 * A feature that has no API yet ("Arrives in step N" with the plan reference), or that the
 * platform does not offer at all (`step={null}` with the reason). Never a fake screen.
 */
export function UnavailableState({
  step,
  title,
  description,
  className,
}: {
  step: string | null;
  title: string;
  description: ReactNode;
  className?: string;
}) {
  const reference = step
    ? (PLAN_STEPS[step] ?? `Step ${step} (docs/plan/execution-plan.md)`)
    : null;
  return (
    <section
      aria-label={title}
      className={cn(
        'flex flex-col gap-2 rounded-lg border border-dashed border-input bg-card p-5',
        className,
      )}
    >
      <div className="flex items-center gap-2">
        <CalendarClockIcon className="size-4 text-muted-foreground" aria-hidden />
        <h3 className="text-sm font-semibold">{title}</h3>
        {step ? (
          <span className="rounded-sm bg-tone-info px-1.5 py-0.5 text-xs font-medium text-tone-info-foreground">
            Arrives in step {step}
          </span>
        ) : (
          <span className="rounded-sm bg-tone-neutral px-1.5 py-0.5 text-xs font-medium text-tone-neutral-foreground">
            Not offered
          </span>
        )}
      </div>
      <p className="text-sm text-muted-foreground">{description}</p>
      {reference ? <p className="text-xs text-muted-foreground">Plan: {reference}</p> : null}
    </section>
  );
}
