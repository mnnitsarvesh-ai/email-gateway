'use client';

import { useId, useState, type ReactNode } from 'react';
import { CopyButton } from '@/components/copy-button';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';

export interface RevealedSecret {
  readonly label: string;
  readonly value: string;
}

/**
 * One-time display of secrets (API keys, SMTP passwords, webhook secrets, TOTP secrets, recovery
 * codes; design P12). Copy buttons; the dialog closes only after the user confirms they stored
 * the values; `onClose` must drop the values (call the mutation's `reset()`; its gcTime is 0).
 * Nothing is logged or persisted. Escape and outside clicks do not dismiss it.
 */
export function SecretRevealDialog({
  open,
  title,
  description,
  secrets,
  onClose,
  extra,
  acknowledgement = 'I have stored this secret in a safe place. It will not be shown again.',
}: {
  open: boolean;
  title: string;
  description: ReactNode;
  secrets: readonly RevealedSecret[];
  onClose: () => void;
  extra?: ReactNode;
  acknowledgement?: string;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const ackId = useId();
  const close = () => {
    setAcknowledged(false);
    onClose();
  };
  return (
    <Dialog open={open} onOpenChange={(next) => (!next && acknowledged ? close() : undefined)}>
      <DialogContent
        showCloseButton={false}
        onEscapeKeyDown={(event) => event.preventDefault()}
        onPointerDownOutside={(event) => event.preventDefault()}
        onInteractOutside={(event) => event.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription asChild>
            <div>{description}</div>
          </DialogDescription>
        </DialogHeader>
        <ul className="grid gap-3">
          {secrets.map((secret) => (
            <li key={secret.label} className="grid gap-1">
              <span className="text-xs font-medium text-muted-foreground">{secret.label}</span>
              <span className="flex items-center gap-2 rounded-md border border-input bg-muted px-3 py-2">
                <code className="min-w-0 flex-1 font-mono text-sm break-all" data-secret="">
                  {secret.value}
                </code>
                <CopyButton value={secret.value} label={`Copy ${secret.label}`} />
              </span>
            </li>
          ))}
        </ul>
        {extra}
        <div className="flex items-start gap-2">
          <Checkbox
            id={ackId}
            checked={acknowledged}
            onCheckedChange={(value) => setAcknowledged(value === true)}
          />
          <Label htmlFor={ackId} className="leading-snug font-normal">
            {acknowledgement}
          </Label>
        </div>
        <DialogFooter>
          <Button onClick={close} disabled={!acknowledged}>
            Done
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
