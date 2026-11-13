import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';

/** Skeleton placeholder shaped like content; announces "Loading …" to assistive technology. */
export function LoadingState({
  label = 'Loading',
  rows = 3,
  variant = 'block',
  className,
}: {
  label?: string;
  rows?: number;
  variant?: 'block' | 'table' | 'tile';
  className?: string;
}) {
  return (
    <div role="status" aria-busy="true" aria-live="polite" className={cn('grid gap-2', className)}>
      <span className="sr-only">{label} …</span>
      {variant === 'tile' ? (
        <>
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-8 w-32" />
        </>
      ) : (
        Array.from({ length: rows }, (_, i) => (
          <Skeleton
            key={i}
            className={cn(
              variant === 'table' ? 'h-9 w-full' : 'h-5',
              i === rows - 1 && variant === 'block' && 'w-2/3',
            )}
          />
        ))
      )}
    </div>
  );
}
