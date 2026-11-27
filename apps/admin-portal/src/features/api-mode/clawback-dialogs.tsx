'use client';

import { useRouter } from 'next/navigation';
import { useId, useState, type ReactNode } from 'react';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useApiMutation } from '@/lib/api/hooks';
import { FormDialog, MutationError } from '@/features/domains/kit';
import {
  CLAWBACK_QUERIES,
  REASON_MAX_CHARS,
  clawbackErrorText,
  clawbackHref,
} from './clawback-model';

export interface ExpandDraft {
  attachments: boolean;
  urls: boolean;
  senderSubject: boolean;
  /** 1–168 (C14 #1 `expand.senderSubjectHours`). */
  hours: string;
  reason: string;
}

export interface ExpandBody {
  expand?: { attachments?: boolean; urls?: boolean; senderSubjectHours?: number };
  reason: string;
}

/** Hints before the POST (the api validates the expansion against the seed's keys). */
export function validateExpand(draft: ExpandDraft): string[] {
  const issues: string[] = [];
  if (draft.senderSubject) {
    const hours = Number(draft.hours);
    if (!/^\d{1,3}$/.test(draft.hours.trim()) || hours < 1 || hours > 168)
      issues.push('The sender and subject window is 1 to 168 hours.');
  }
  if (!draft.reason.trim()) issues.push('Enter a reason.');
  return issues;
}

/** The `expand` and `reason` of a seed clawback (detection or report). */
export function expandBodyOf(draft: ExpandDraft): ExpandBody {
  const expand = {
    ...(draft.attachments ? { attachments: true } : {}),
    ...(draft.urls ? { urls: true } : {}),
    ...(draft.senderSubject ? { senderSubjectHours: Number(draft.hours) } : {}),
  };
  return {
    ...(Object.keys(expand).length > 0 ? { expand } : {}),
    reason: draft.reason.trim(),
  };
}

const EMPTY: ExpandDraft = {
  attachments: false,
  urls: false,
  senderSubject: false,
  hours: '72',
  reason: '',
};

function ExpandForm({
  label,
  intro,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  label: string;
  intro: ReactNode;
  pending: boolean;
  error: Parameters<typeof clawbackErrorText>[0];
  onSubmit: (body: ExpandBody) => void;
  onCancel: () => void;
}) {
  const base = useId();
  const [draft, setDraft] = useState<ExpandDraft>(EMPTY);
  const [hints, setHints] = useState<string[]>([]);
  const set = (patch: Partial<ExpandDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const errorText = clawbackErrorText(error);
  return (
    <form
      className="grid gap-4"
      aria-label={label}
      onSubmit={(event) => {
        event.preventDefault();
        const problems = validateExpand(draft);
        setHints(problems);
        if (problems.length === 0) onSubmit(expandBodyOf(draft));
      }}
    >
      <div className="text-sm">{intro}</div>
      <fieldset className="grid gap-2">
        <legend className="text-sm font-medium">Also find similar messages</legend>
        <div className="flex items-center gap-2">
          <Checkbox
            id={`${base}-att`}
            checked={draft.attachments}
            onCheckedChange={(checked) => set({ attachments: checked === true })}
          />
          <Label htmlFor={`${base}-att`} className="font-normal">
            With the same attachments (SHA-256)
          </Label>
        </div>
        <div className="flex items-center gap-2">
          <Checkbox
            id={`${base}-urls`}
            checked={draft.urls}
            onCheckedChange={(checked) => set({ urls: checked === true })}
          />
          <Label htmlFor={`${base}-urls`} className="font-normal">
            With the same URLs
          </Label>
        </div>
        <div className="flex items-center gap-2">
          <Checkbox
            id={`${base}-ss`}
            checked={draft.senderSubject}
            onCheckedChange={(checked) => set({ senderSubject: checked === true })}
          />
          <Label htmlFor={`${base}-ss`} className="font-normal">
            From the same sender with the same subject
          </Label>
        </div>
        {draft.senderSubject ? (
          <div className="grid max-w-xs gap-1 pl-6">
            <Label htmlFor={`${base}-hours`}>Hours before and after (1–168)</Label>
            <Input
              id={`${base}-hours`}
              inputMode="numeric"
              value={draft.hours}
              onChange={(event) => set({ hours: event.target.value })}
            />
          </div>
        ) : null}
        <p className="text-xs text-muted-foreground">
          Without an option, the search finds the copies of this message (same Message-ID).
        </p>
      </fieldset>
      <div className="grid gap-2">
        <Label htmlFor={`${base}-reason`}>Reason (required)</Label>
        <Textarea
          id={`${base}-reason`}
          rows={2}
          maxLength={REASON_MAX_CHARS}
          value={draft.reason}
          onChange={(event) => set({ reason: event.target.value })}
        />
      </div>
      {hints.length > 0 ? (
        <ul role="alert" className="grid gap-1 text-sm font-medium text-destructive">
          {hints.map((hint) => (
            <li key={hint}>{hint}</li>
          ))}
        </ul>
      ) : null}
      {error ? (
        <div role="alert" className="grid gap-1">
          {errorText ? <p className="text-sm font-medium text-destructive">{errorText}</p> : null}
          <MutationError error={error} />
        </div>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" size="sm" disabled={pending}>
          {pending ? 'Searching …' : 'Search'}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

/** Detections "Claw back similar…" (C2.4, C14 #1): a search seeded from the detection. */
export function ClawBackSimilarDialog({
  detection,
  onOpenChange,
}: {
  detection: { id: string; mailboxAddress: string } | null;
  onOpenChange: (open: boolean) => void;
}) {
  const router = useRouter();
  const create = useApiMutation('ApiModeClawbackController_create_v1', {
    invalidates: CLAWBACK_QUERIES,
    successMessage: 'Search started: review the hit list before anything changes.',
    onSuccess: (data) => router.push(clawbackHref(data.id)),
  });
  const close = (open: boolean) => {
    if (!open) create.reset();
    onOpenChange(open);
  };
  return (
    <FormDialog
      open={detection !== null}
      onOpenChange={close}
      title="Claw back similar messages"
      description="Searches every mailbox for copies of this message, and optionally similar ones. Nothing changes until you review the hit list and submit a purge."
    >
      {detection ? (
        <ExpandForm
          key={detection.id}
          label="Claw back similar messages"
          intro={
            <p>
              Seed: the copy in <UntrustedText value={detection.mailboxAddress} mono />.
            </p>
          }
          pending={create.isPending}
          error={create.error}
          onCancel={() => close(false)}
          onSubmit={(body) =>
            void create
              .submit({ body: { seedDetectionId: detection.id, ...body } })
              .then((outcome) => outcome.ok && close(false))
          }
        />
      ) : null}
    </FormDialog>
  );
}

/** Reports "Claw back this message…" (C11.5, C14 #14): a search from the report's original. */
export function ReportClawbackDialog({
  reportId,
  onOpenChange,
}: {
  reportId: string | null;
  onOpenChange: (open: boolean) => void;
}) {
  const router = useRouter();
  const create = useApiMutation('ApiModeReportsController_clawback_v1', {
    invalidates: [
      ...CLAWBACK_QUERIES,
      'ApiModeReportsController_list_v1',
      'ApiModeReportsController_detail_v1',
    ],
    successMessage: 'Search started from the report: review the hit list and submit a purge.',
    onSuccess: (data) => router.push(clawbackHref(data.clawbackId)),
  });
  const close = (open: boolean) => {
    if (!open) create.reset();
    onOpenChange(open);
  };
  return (
    <FormDialog
      open={reportId !== null}
      onOpenChange={close}
      title="Claw back the reported message"
      description="Searches every mailbox for copies of the reported message, and optionally similar ones. Nothing changes until you review the hit list and submit a purge (approval rules apply)."
    >
      {reportId ? (
        <ExpandForm
          key={reportId}
          label="Claw back the reported message"
          intro={<p>The search uses the keys identified in the report (never its content).</p>}
          pending={create.isPending}
          error={create.error}
          onCancel={() => close(false)}
          onSubmit={(body) =>
            void create
              .submit({ path: { reportId }, body })
              .then((outcome) => outcome.ok && close(false))
          }
        />
      ) : null}
    </FormDialog>
  );
}
