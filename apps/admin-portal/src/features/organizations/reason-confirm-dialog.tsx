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
import { Textarea } from '@/components/ui/textarea';

/**
 * A confirmation that also asks for an audited reason (and optionally a typed confirmation).
 * Same AlertDialog primitives as `ConfirmDialog`, which has no field slot. `onConfirm` returns
 * `false` to keep the dialog open (the caller shows the API error in `error`).
 */
export function ReasonConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  destructive = false,
  reasonLabel = 'Reason',
  reasonHint,
  minLength = 1,
  maxLength = 512,
  reasonRequired = true,
  typedConfirmation,
  onConfirm,
  error,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  reasonLabel?: string;
  reasonHint?: string;
  minLength?: number;
  maxLength?: number;
  reasonRequired?: boolean;
  typedConfirmation?: string;
  onConfirm: (reason: string) => Promise<boolean | void> | boolean | void;
  error?: ReactNode;
}) {
  const [reason, setReason] = useState('');
  const [typed, setTyped] = useState('');
  const [touched, setTouched] = useState(false);
  const [running, setRunning] = useState(false);
  const reasonId = useId();
  const hintId = useId();
  const errorId = useId();
  const typedId = useId();
  const trimmed = reason.trim();
  const reasonError =
    trimmed.length === 0
      ? reasonRequired
        ? 'Enter a reason.'
        : null
      : trimmed.length < minLength
        ? `Use at least ${minLength} characters.`
        : trimmed.length > maxLength
          ? `Use at most ${maxLength} characters.`
          : null;
  const typedOk = !typedConfirmation || typed === typedConfirmation;

  const close = (next: boolean) => {
    if (running) return;
    if (!next) {
      setReason('');
      setTyped('');
      setTouched(false);
    }
    onOpenChange(next);
  };

  const confirm = async () => {
    setTouched(true);
    if (reasonError || !typedOk || running) return;
    setRunning(true);
    try {
      const result = await onConfirm(trimmed);
      if (result !== false) close(false);
    } finally {
      setRunning(false);
    }
  };

  return (
    <AlertDialog open={open} onOpenChange={close}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div>{description}</div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="grid gap-1.5">
          <Label htmlFor={reasonId}>
            {reasonLabel}
            {reasonRequired ? (
              <span className="text-xs font-normal text-muted-foreground">(required)</span>
            ) : null}
          </Label>
          <Textarea
            id={reasonId}
            value={reason}
            rows={3}
            maxLength={maxLength}
            onChange={(event) => setReason(event.target.value)}
            onBlur={() => setTouched(true)}
            aria-invalid={touched && reasonError ? true : undefined}
            aria-describedby={`${hintId}${touched && reasonError ? ` ${errorId}` : ''}`}
          />
          <p id={hintId} className="text-xs text-muted-foreground">
            {reasonHint ?? `${minLength} to ${maxLength} characters; recorded in the audit log.`}
          </p>
          {touched && reasonError ? (
            <p id={errorId} className="text-xs font-medium text-destructive">
              {reasonError}
            </p>
          ) : null}
        </div>
        {typedConfirmation ? (
          <div className="grid gap-1.5">
            <Label htmlFor={typedId}>
              Type <span className="font-mono font-semibold">{typedConfirmation}</span> to confirm
            </Label>
            <Input
              id={typedId}
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
        ) : null}
        {error}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={running}>Cancel</AlertDialogCancel>
          <Button
            variant={destructive ? 'destructive' : 'default'}
            disabled={running || !typedOk}
            onClick={() => void confirm()}
          >
            {running ? 'Working …' : confirmLabel}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
