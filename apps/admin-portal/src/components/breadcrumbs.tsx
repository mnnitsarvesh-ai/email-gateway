import { ChevronRightIcon } from 'lucide-react';
import Link from 'next/link';
import { cn } from '@/lib/utils';

export interface Crumb {
  readonly label: string;
  readonly href?: string;
}

export function Breadcrumbs({ items, className }: { items: readonly Crumb[]; className?: string }) {
  if (items.length === 0) return null;
  return (
    <nav aria-label="Breadcrumb" className={cn('min-w-0', className)}>
      <ol className="flex min-w-0 items-center gap-1 text-xs text-muted-foreground">
        {items.map((item, index) => {
          const last = index === items.length - 1;
          return (
            <li key={`${item.label}-${index}`} className="flex min-w-0 items-center gap-1">
              {item.href && !last ? (
                <Link href={item.href} className="truncate hover:text-foreground hover:underline">
                  {item.label}
                </Link>
              ) : (
                <span className="truncate" aria-current={last ? 'page' : undefined}>
                  {item.label}
                </span>
              )}
              {!last ? <ChevronRightIcon className="size-3 shrink-0" aria-hidden /> : null}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
