'use client';

import { useId, useState, type ReactNode } from 'react';
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

/**
 * Confirmation for destructive or state-changing actions. `typedConfirmation` (e.g. the domain
 * name) is required for irreversible actions: confirm stays disabled until the text matches.
 * `onConfirm` may be async; the dialog stays open while it runs and closes on success.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  destructive = false,
  typedConfirmation,
  onConfirm,
  pending = false,
  error,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
  typedConfirmation?: string;
  onConfirm: () => unknown;
  pending?: boolean;
  /** An error to show inside the dialog (e.g. the mutation's ErrorState). */
  error?: ReactNode;
}) {
  const [typed, setTyped] = useState('');
  const [running, setRunning] = useState(false);
  const inputId = useId();
  const matches = !typedConfirmation || typed === typedConfirmation;
  const busy = pending || running;

  const handleOpenChange = (next: boolean) => {
    if (busy) return;
    if (!next) setTyped('');
    onOpenChange(next);
  };

  const confirm = async () => {
    if (!matches || busy) return;
    setRunning(true);
    try {
      const result = await onConfirm();
      if (result !== false) {
        setTyped('');
        onOpenChange(false);
      }
    } finally {
      setRunning(false);
    }
  };

  return (
    <AlertDialog open={open} onOpenChange={handleOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div>{description}</div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {typedConfirmation ? (
          <div className="grid gap-2">
            <Label htmlFor={inputId}>
              Type <span className="font-mono font-semibold">{typedConfirmation}</span> to confirm
            </Label>
            <Input
              id={inputId}
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
        ) : null}
        {error}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>{cancelLabel}</AlertDialogCancel>
          <Button
            variant={destructive ? 'destructive' : 'default'}
            disabled={!matches || busy}
            onClick={() => void confirm()}
          >
            {busy ? 'Working …' : confirmLabel}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
