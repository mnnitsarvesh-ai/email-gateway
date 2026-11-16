'use client';

import type { ReactNode } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { cn } from '@/lib/utils';

/** Below 640 px a dialog takes the whole screen (design B14). */
export const FULL_SCREEN_BELOW_SM =
  'max-sm:top-0 max-sm:left-0 max-sm:h-dvh max-sm:max-h-dvh max-sm:w-full max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-none';

/** A lifecycle dialog (publish, activate, rename, …): title, description, body, footer. */
export function LifecycleDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  wide = false,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  children?: ReactNode;
  footer: ReactNode;
  wide?: boolean;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={cn(wide && 'sm:max-w-2xl', FULL_SCREEN_BELOW_SM)}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription asChild>
            <div>{description}</div>
          </DialogDescription>
        </DialogHeader>
        {children ? <div className="grid min-w-0 gap-3">{children}</div> : null}
        <DialogFooter>{footer}</DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** The note every activation-changing success shows (P12: next evaluation only). */
export function NextEvaluationNote({ generation }: { generation?: string | null }) {
  return (
    <p className="text-sm text-muted-foreground">
      {generation ? (
        <>
          The organization’s policy generation is now{' '}
          <span className="font-mono text-foreground">{generation}</span>.{' '}
        </>
      ) : null}
      The change applies to the next evaluation only; messages already evaluated keep their
      decision.
    </p>
  );
}
