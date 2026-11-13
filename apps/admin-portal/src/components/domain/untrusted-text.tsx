import { CopyButton } from '@/components/copy-button';
import { cn } from '@/lib/utils';

/**
 * Attacker-controlled text (subjects, senders, filenames, URLs, webhook response snippets, audit
 * metadata; design P12): rendered as text only, truncated with the full value in `title`, never
 * a link. Control characters are replaced so they cannot spoof layout (bidi overrides).
 */
function isUnsafeCodePoint(code: number): boolean {
  return (
    code <= 0x08 ||
    (code >= 0x0b && code <= 0x1f) ||
    code === 0x7f ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069)
  );
}

export function sanitizeDisplay(value: string): string {
  let out = '';
  for (const char of value) out += isUnsafeCodePoint(char.codePointAt(0) ?? 0) ? '�' : char;
  return out;
}

export function UntrustedText({
  value,
  maxLength = 120,
  copy = false,
  copyLabel = 'Copy value',
  mono = false,
  className,
  emptyLabel = '(empty)',
}: {
  value: string | null | undefined;
  maxLength?: number;
  /** Adds a copy button (URLs, addresses) instead of making the value clickable. */
  copy?: boolean;
  copyLabel?: string;
  mono?: boolean;
  className?: string;
  emptyLabel?: string;
}) {
  if (value === null || value === undefined || value === '') {
    return <span className={cn('text-muted-foreground', className)}>{emptyLabel}</span>;
  }
  const safe = sanitizeDisplay(value);
  const shown = safe.length > maxLength ? `${safe.slice(0, maxLength - 1)}…` : safe;
  return (
    <span className={cn('inline-flex max-w-full min-w-0 items-center gap-1', className)}>
      <span
        className={cn('truncate break-all', mono && 'font-mono text-xs')}
        title={safe}
        data-untrusted=""
      >
        {shown}
      </span>
      {copy ? <CopyButton value={value} label={copyLabel} /> : null}
    </span>
  );
}
