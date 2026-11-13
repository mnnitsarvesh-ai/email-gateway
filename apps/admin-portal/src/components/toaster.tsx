'use client';

import { useTheme } from 'next-themes';
import { Toaster as Sonner } from 'sonner';

/** sonner toasts themed from tokens; announced through sonner's live region. */
export function Toaster() {
  const { resolvedTheme } = useTheme();
  return (
    <Sonner
      theme={resolvedTheme === 'dark' ? 'dark' : 'light'}
      position="top-right"
      closeButton
      richColors={false}
      toastOptions={{
        classNames: {
          toast: 'bg-popover text-popover-foreground border border-border shadow-sm',
          description: 'text-muted-foreground',
        },
      }}
    />
  );
}
