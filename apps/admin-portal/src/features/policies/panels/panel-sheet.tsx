'use client';

import type { ReactNode } from 'react';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';

/**
 * The container of the test and dry-run panels (design B14): a side panel from the right on
 * tablets and desktops, a full-screen sheet below 640 px. Content scrolls inside the panel.
 */
export function PanelSheet({
  open,
  onOpenChange,
  title,
  description,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full max-w-none gap-0 overflow-y-auto p-0 sm:w-[min(46rem,92vw)] sm:max-w-none"
      >
        <SheetHeader className="border-b pr-12">
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription>{description}</SheetDescription>
        </SheetHeader>
        <div className="grid min-w-0 gap-4 p-4">{children}</div>
      </SheetContent>
    </Sheet>
  );
}
