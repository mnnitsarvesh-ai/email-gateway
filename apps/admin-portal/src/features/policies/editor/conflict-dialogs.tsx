'use client';

import { DownloadIcon } from 'lucide-react';
import { ErrorState } from '@/components/states/error-state';
import { Button } from '@/components/ui/button';
import type { ApiError } from '@/lib/api/errors';
import { LifecycleDialog } from '../lifecycle/dialog-shell';

/**
 * `409 policy_conflict` on a draft save (design B6): someone saved the draft since it was loaded.
 * The user chooses explicitly: reload their version (discarding the local edits), overwrite it
 * with the local edits at the current row version, or download the local definition first.
 */
export function ConflictDialog({
  open,
  onOpenChange,
  currentRowVersion,
  pending,
  error,
  onReload,
  onOverwrite,
  onDownload,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  currentRowVersion: number | null;
  pending: boolean;
  error: ApiError | null;
  onReload: () => void;
  onOverwrite: () => void;
  onDownload: () => void;
}) {
  return (
    <LifecycleDialog
      open={open}
      onOpenChange={(next) => {
        if (!pending) onOpenChange(next);
      }}
      title="The draft changed while you were editing"
      description={
        <div className="grid gap-2">
          <p>
            Someone saved this draft after you opened it
            {currentRowVersion !== null ? ` (it is now at row version ${currentRowVersion})` : ''}.
            Your changes were not saved.
          </p>
          <p>
            Reload their version to discard your changes, or overwrite their version with yours. You
            can download your definition first to keep a copy.
          </p>
        </div>
      }
      footer={
        <>
          <Button variant="outline" onClick={onDownload} disabled={pending}>
            <DownloadIcon aria-hidden />
            Download my definition
          </Button>
          <Button variant="outline" onClick={onReload} disabled={pending}>
            Reload theirs
          </Button>
          <Button variant="destructive" onClick={onOverwrite} disabled={pending}>
            {pending ? 'Saving …' : 'Overwrite with mine'}
          </Button>
        </>
      }
    >
      {error && error.code !== 'policy_conflict' ? <ErrorState error={error} compact /> : null}
    </LifecycleDialog>
  );
}

/**
 * `409 policy_version_immutable` on a draft save (design B6): the draft was published meanwhile.
 * The local edits can be saved as a new draft (`POST …/versions` with the definition).
 */
export function ImmutableDialog({
  open,
  onOpenChange,
  versionNo,
  pending,
  error,
  onSaveAsNew,
  onDownload,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  versionNo: number;
  pending: boolean;
  error: ApiError | null;
  onSaveAsNew: () => void;
  onDownload: () => void;
}) {
  return (
    <LifecycleDialog
      open={open}
      onOpenChange={(next) => {
        if (!pending) onOpenChange(next);
      }}
      title={`Version ${versionNo} was published meanwhile`}
      description="A published version never changes. Save your changes as a new draft of this policy instead."
      footer={
        <>
          <Button variant="outline" onClick={onDownload} disabled={pending}>
            <DownloadIcon aria-hidden />
            Download my definition
          </Button>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
            Cancel
          </Button>
          <Button onClick={onSaveAsNew} disabled={pending}>
            {pending ? 'Saving …' : 'Save as a new draft'}
          </Button>
        </>
      }
    >
      {error ? <ErrorState error={error} compact /> : null}
    </LifecycleDialog>
  );
}
