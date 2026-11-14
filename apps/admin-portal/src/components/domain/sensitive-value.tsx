'use client';

import { LockIcon } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { UntrustedText, sanitizeDisplay } from './untrusted-text';

/** The default tooltip of a masked value (ADR-0062: masked for everyone, revealed per action). */
export const MASKED_VALUE_EXPLANATION =
  'Withheld by the gateway for every user. Users with the message:reveal permission can reveal it; every reveal is recorded in the audit log.';

/**
 * A sensitive message value (step 7.2 §2 E5, E11; ADR-0062): subjects, recipient addresses and
 * To/Cc/Subject header values are masked by the api on every read and reach the portal in clear
 * only through an audited reveal.
 *
 * - **masked** (`masked`): a lock icon, the text "Hidden" (text values such as a subject, whose
 *   api value is `null`) or the api's masked form (`kind="address"`: `f***@example.com`), a
 *   visually hidden "masked" and a tooltip explaining reveal and audit. Never colour alone: the
 *   icon and the words carry the state.
 * - **revealed** (`revealed`): the clear value through `UntrustedText` plus a "Revealed" badge.
 * - otherwise the value is in clear from the api (e.g. a quarantine decider's recipient):
 *   `UntrustedText` alone.
 *
 * Values are attacker-controlled text: rendered as text only, never as markup or links.
 */
export function SensitiveValue({
  value,
  masked,
  revealed = false,
  kind = 'text',
  maxLength = 120,
  emptyLabel = '(empty)',
  explanation = MASKED_VALUE_EXPLANATION,
  mono = false,
  copy = false,
  copyLabel,
  className,
}: {
  /** The api value: `null` when withheld, the masked form for an address, or the clear value. */
  value: string | null | undefined;
  /** The api withheld or masked the value (`subjectMasked`, `addressMasked`, `recipientMasked`). */
  masked: boolean;
  /** The clear value came from an audited reveal (wins over `masked`). */
  revealed?: boolean;
  /** `address`: the masked form is shown; `text`: "Hidden". */
  kind?: 'text' | 'address';
  maxLength?: number;
  /** Shown when the clear (or revealed) value is empty or null. */
  emptyLabel?: string;
  /** Tooltip of the masked state. */
  explanation?: string;
  mono?: boolean;
  /** Copy button for clear and revealed values (never for masked ones). */
  copy?: boolean;
  copyLabel?: string;
  className?: string;
}) {
  if (revealed) {
    return (
      <span
        className={cn('inline-flex max-w-full min-w-0 items-center gap-1.5', className)}
        data-sensitive="revealed"
      >
        <UntrustedText
          value={value}
          maxLength={maxLength}
          emptyLabel={emptyLabel}
          mono={mono}
          copy={copy}
          copyLabel={copyLabel}
        />
        <Badge variant="info" className="shrink-0">
          Revealed
        </Badge>
      </span>
    );
  }
  if (!masked) {
    return (
      <UntrustedText
        value={value}
        maxLength={maxLength}
        emptyLabel={emptyLabel}
        mono={mono}
        copy={copy}
        copyLabel={copyLabel}
        className={className}
      />
    );
  }
  const shown =
    kind === 'address' && value
      ? truncate(sanitizeDisplay(value), maxLength)
      : kind === 'address'
        ? 'Hidden address'
        : 'Hidden';
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={cn(
            'inline-flex w-fit max-w-full min-w-0 items-center gap-1 rounded-sm border border-dashed border-input px-1.5 py-0.5 text-xs text-muted-foreground',
            className,
          )}
          data-sensitive="masked"
        >
          <LockIcon className="size-3 shrink-0" aria-hidden />
          <span className={cn('truncate', kind === 'address' && 'font-mono')}>{shown}</span>
          <span className="sr-only">(masked)</span>
        </span>
      </TooltipTrigger>
      <TooltipContent>{explanation}</TooltipContent>
    </Tooltip>
  );
}

function truncate(value: string, maxLength: number): string {
  const chars = Array.from(value);
  return chars.length > maxLength ? `${chars.slice(0, maxLength - 1).join('')}…` : value;
}
