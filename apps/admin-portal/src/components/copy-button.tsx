'use client';

import { CheckIcon, CopyIcon } from 'lucide-react';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

/** Copies a value to the clipboard; announces the result to screen readers. */
export function CopyButton({
  value,
  label,
  className,
  size = 'icon',
}: {
  value: string;
  /** Accessible name, e.g. "Copy request ID". */
  label: string;
  className?: string;
  size?: 'icon' | 'sm';
}) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState('copied');
    } catch {
      setState('failed');
    }
    setTimeout(() => setState('idle'), 2000);
  };
  return (
    <>
      <Button
        variant="ghost"
        size={size}
        className={cn(size === 'icon' && 'size-7', className)}
        onClick={() => void copy()}
        aria-label={label}
        title={label}
      >
        {state === 'copied' ? <CheckIcon aria-hidden /> : <CopyIcon aria-hidden />}
        {size === 'sm' ? <span>{state === 'copied' ? 'Copied' : 'Copy'}</span> : null}
      </Button>
      <span className="sr-only" role="status" aria-live="polite">
        {state === 'copied' ? 'Copied to clipboard' : state === 'failed' ? 'Copy failed' : ''}
      </span>
    </>
  );
}
