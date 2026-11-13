import { CopyButton } from '@/components/copy-button';
import { cn } from '@/lib/utils';

/** Middle-truncates long ids for display; the full value stays in `title` and the copy button. */
export function middleTruncate(value: string, max = 18): string {
  if (value.length <= max) return value;
  const keep = Math.max(4, Math.floor((max - 1) / 2));
  return `${value.slice(0, keep)}…${value.slice(-keep)}`;
}

export function CopyableId({
  value,
  label = 'ID',
  max = 18,
  className,
}: {
  value: string;
  /** What the value is, for the copy button's name ("Copy message ID"). */
  label?: string;
  max?: number;
  className?: string;
}) {
  return (
    <span className={cn('inline-flex min-w-0 items-center gap-1', className)}>
      <span className="truncate font-mono text-xs" title={value}>
        {middleTruncate(value, max)}
      </span>
      <CopyButton value={value} label={`Copy ${label}`} />
    </span>
  );
}
