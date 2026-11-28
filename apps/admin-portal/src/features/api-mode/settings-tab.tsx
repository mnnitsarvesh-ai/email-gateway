'use client';

import { useQueryClient } from '@tanstack/react-query';
import { PlusIcon } from 'lucide-react';
import { useId, useState } from 'react';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Switch } from '@/components/ui/switch';
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber } from '@/lib/format';
import { PROVIDER_LABEL } from '@/features/integrations/providers/model';
import {
  DetailList,
  FormDialog,
  LabelledSelect,
  MutationError,
  Section,
} from '@/features/domains/kit';
import { ReasonConfirm } from '@/features/quarantine/reason-confirm';
import {
  REASON_MAX_CHARS,
  clawbackErrorText,
  explainClawbackError,
  type AutoClawback,
  type OrgSettings,
  type OrgSettingsView,
  type ReportMailbox,
} from './clawback-model';
import { CoverageBadge } from './model';

export const SETTINGS_QUERIES: readonly OperationId[] = [
  'ApiModeSettingsController_get_v1',
  'ApiModeController_overview_v1',
];
const MAILBOX_QUERIES: readonly OperationId[] = [
  'ApiModeReportsController_listMailboxes_v1',
  'ApiModeController_listMailboxes_v1',
  'ApiModeController_overview_v1',
];

export const AUTO_CLAWBACK_TEXT: Record<AutoClawback, string> = {
  enforce: 'Enforce: clawbacks of late verdicts and threat intelligence run automatically',
  review: 'Review: every automatic clawback waits for an administrator',
  off: 'Off: no automatic clawback (searches and reports still work)',
};

type NumberKey =
  'autoMaxMailboxes' | 'purgeApprovalMailboxes' | 'clawbackLookbackDays' | 'tiMinConfidence';
type BoolKey =
  | 'internalMailEnabled'
  | 'reportAckEnabled'
  | 'reportFeedbackEnabled'
  | 'policyEvaluationEnabled'
  | 'outboundDetectionEnabled';

const NUMBER_FIELDS: ReadonlyArray<{ key: NumberKey; label: string; help: string }> = [
  {
    key: 'purgeApprovalMailboxes',
    label: 'Purge approval threshold (mailboxes)',
    help: 'A purge across more distinct mailboxes needs a second approver.',
  },
  {
    key: 'autoMaxMailboxes',
    label: 'Automatic clawback cap (mailboxes)',
    help: 'Automatic clawbacks above this many mailboxes wait for review and approval.',
  },
  {
    key: 'clawbackLookbackDays',
    label: 'Automatic search lookback (days)',
    help: 'How far back an automatic clawback searches before its signal.',
  },
  {
    key: 'tiMinConfidence',
    label: 'Threat-intelligence minimum confidence',
    help: 'Indicators below this confidence never start a clawback.',
  },
];

const BOOL_FIELDS: ReadonlyArray<{ key: BoolKey; label: string; help: string }> = [
  {
    key: 'internalMailEnabled',
    label: 'Protect internal mail',
    help: 'Record and remediate internal (east-west) copies seen in the journal.',
  },
  {
    key: 'reportAckEnabled',
    label: 'Acknowledge reports',
    help: 'Thank reporters by e-mail when their report is received.',
  },
  {
    key: 'reportFeedbackEnabled',
    label: 'Send the triage result',
    help: 'Default of "Notify the reporter" when a report is resolved.',
  },
  // Step API-4 A12 (API4-1, API4-5).
  {
    key: 'policyEvaluationEnabled',
    label: 'Evaluate tenant policies on copies',
    help: 'Your policies (custom rules, allow and block lists, DLP, BEC) are evaluated on every API-mode copy in detect mode; their dispositions drive mailbox actions through the remediation policy mapping. Nothing is delivered, held or bounced.',
  },
  {
    key: 'outboundDetectionEnabled',
    label: 'Detect outbound mail (DLP)',
    help: 'Outbound journal copies are evaluated too; a detection is recorded on the sender’s mailbox and alerted, never remediated (the message has already been sent).',
  },
];

type Draft = Record<NumberKey, string> & Record<BoolKey, boolean> & { autoClawback: AutoClawback };

function draftOf(s: OrgSettings): Draft {
  return {
    internalMailEnabled: s.internalMailEnabled,
    autoClawback: s.autoClawback,
    autoMaxMailboxes: String(s.autoMaxMailboxes),
    purgeApprovalMailboxes: String(s.purgeApprovalMailboxes),
    clawbackLookbackDays: String(s.clawbackLookbackDays),
    tiMinConfidence: String(s.tiMinConfidence),
    reportAckEnabled: s.reportAckEnabled,
    reportFeedbackEnabled: s.reportFeedbackEnabled,
    policyEvaluationEnabled: s.policyEvaluationEnabled,
    outboundDetectionEnabled: s.outboundDetectionEnabled,
  };
}

/** Hints before the PUT (the api applies the same bounds and stays authoritative). */
export function validateSettings(draft: Draft, bounds: OrgSettingsView['bounds']): string[] {
  const issues: string[] = [];
  for (const field of NUMBER_FIELDS) {
    const raw = draft[field.key].trim();
    const { min, max } = bounds[field.key];
    if (!/^\d{1,5}$/.test(raw) || Number(raw) < min || Number(raw) > max)
      issues.push(`${field.label}: a whole number from ${min} to ${max}.`);
  }
  return issues;
}

function OrgSettingsForm({ view }: { view: OrgSettingsView }) {
  const base = useId();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<Draft>(() => draftOf(view.settings));
  const [reason, setReason] = useState('');
  const [hints, setHints] = useState<string[]>([]);
  const save = useApiMutation('ApiModeSettingsController_put_v1', {
    invalidates: SETTINGS_QUERIES,
    successMessage: 'Mailbox protection settings saved.',
    onSuccess: () => setReason(''),
  });
  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }));
  const errorText = clawbackErrorText(save.error);
  return (
    <form
      className="grid gap-4"
      aria-label="Organization settings"
      onSubmit={(event) => {
        event.preventDefault();
        const problems = validateSettings(draft, view.bounds);
        if (!reason.trim()) problems.push('Enter a reason.');
        setHints(problems);
        if (problems.length > 0) return;
        void save
          .submit({
            body: {
              internalMailEnabled: draft.internalMailEnabled,
              autoClawback: draft.autoClawback,
              autoMaxMailboxes: Number(draft.autoMaxMailboxes),
              purgeApprovalMailboxes: Number(draft.purgeApprovalMailboxes),
              clawbackLookbackDays: Number(draft.clawbackLookbackDays),
              tiMinConfidence: Number(draft.tiMinConfidence),
              reportAckEnabled: draft.reportAckEnabled,
              reportFeedbackEnabled: draft.reportFeedbackEnabled,
              policyEvaluationEnabled: draft.policyEvaluationEnabled,
              outboundDetectionEnabled: draft.outboundDetectionEnabled,
              reason: reason.trim(),
              expectedRowVersion: view.rowVersion,
            },
          })
          .then(async (outcome) => {
            if (!outcome.ok && outcome.error.code === 'api_mode_settings_conflict')
              await queryClient.invalidateQueries({
                queryKey: ['ApiModeSettingsController_get_v1'],
              });
          });
      }}
    >
      <fieldset className="grid gap-2">
        <legend className="text-sm font-medium">Automatic clawback</legend>
        <RadioGroup
          value={draft.autoClawback}
          onValueChange={(value) => set({ autoClawback: value as AutoClawback })}
          className="grid gap-2"
        >
          {(['enforce', 'review', 'off'] as const).map((value) => (
            <div key={value} className="flex items-center gap-2">
              <RadioGroupItem id={`${base}-${value}`} value={value} />
              <Label htmlFor={`${base}-${value}`} className="font-normal">
                {AUTO_CLAWBACK_TEXT[value]}
              </Label>
            </div>
          ))}
        </RadioGroup>
      </fieldset>
      <div className="grid gap-3 sm:grid-cols-2">
        {NUMBER_FIELDS.map((field) => (
          <div key={field.key} className="grid gap-1">
            <Label htmlFor={`${base}-${field.key}`}>{field.label}</Label>
            <Input
              id={`${base}-${field.key}`}
              inputMode="numeric"
              value={draft[field.key]}
              onChange={(event) => set({ [field.key]: event.target.value })}
            />
            <p className="text-xs text-muted-foreground">
              {field.help} ({view.bounds[field.key].min}–{view.bounds[field.key].max}, default{' '}
              {view.defaults[field.key]})
            </p>
          </div>
        ))}
      </div>
      <div className="grid gap-3">
        {BOOL_FIELDS.map((field) => (
          <div key={field.key} className="grid gap-0.5">
            <div className="flex items-center gap-2">
              <Switch
                id={`${base}-${field.key}`}
                checked={draft[field.key]}
                onCheckedChange={(checked) => set({ [field.key]: checked })}
              />
              <Label htmlFor={`${base}-${field.key}`} className="font-normal">
                {field.label}
              </Label>
            </div>
            <p className="pl-11 text-xs text-muted-foreground">{field.help}</p>
          </div>
        ))}
      </div>
      <div className="grid gap-2">
        <Label htmlFor={`${base}-reason`}>Reason (required)</Label>
        <Textarea
          id={`${base}-reason`}
          rows={2}
          maxLength={REASON_MAX_CHARS}
          value={reason}
          onChange={(event) => setReason(event.target.value)}
        />
        <p className="text-xs text-muted-foreground">
          Stored in the audit log with the old and new values.
        </p>
      </div>
      {hints.length > 0 ? (
        <ul role="alert" className="grid gap-1 text-sm font-medium text-destructive">
          {hints.map((hint) => (
            <li key={hint}>{hint}</li>
          ))}
        </ul>
      ) : null}
      {save.error ? (
        <div role="alert" className="grid gap-1">
          {errorText ? <p className="text-sm font-medium text-destructive">{errorText}</p> : null}
          <MutationError error={save.error} />
        </div>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" size="sm" disabled={save.isPending}>
          {save.isPending ? 'Saving …' : 'Save settings'}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          onClick={() => {
            save.reset();
            setHints([]);
            setDraft(draftOf(view.settings));
          }}
        >
          Discard changes
        </Button>
      </div>
    </form>
  );
}

function SettingsReadOnly({ view }: { view: OrgSettingsView }) {
  const s = view.settings;
  const onOff = (value: boolean) => (value ? 'On' : 'Off');
  return (
    <DetailList
      items={[
        { label: 'Automatic clawback', value: AUTO_CLAWBACK_TEXT[s.autoClawback] },
        ...NUMBER_FIELDS.map((f) => ({ label: f.label, value: formatNumber(s[f.key]) })),
        ...BOOL_FIELDS.map((f) => ({ label: f.label, value: onOff(s[f.key]) })),
      ]}
    />
  );
}

function OrganizationSettings({ view }: { view: OrgSettingsView }) {
  const canWrite = useCan('ApiModeSettingsController_put_v1');
  const p = view.platform;
  return (
    <Section
      title="Organization settings"
      description="Internal mail, automatic clawback, the purge approval threshold and reporter feedback for every API-mode mailbox of the organization."
    >
      <p className="text-sm">
        {view.source === 'row' ? (
          <>
            Saved settings · updated <DateTime value={view.updatedAt} />
          </>
        ) : (
          'No settings of your own yet: the defaults apply.'
        )}
      </p>
      {canWrite ? <OrgSettingsForm view={view} /> : <SettingsReadOnly view={view} />}
      <p className="text-xs text-muted-foreground">
        Platform: hard delete in purges {p.hardDeleteAvailable ? 'available' : 'turned off'} ·
        searches span at most {p.clawbackMaxWindowDays} days · approvals expire after{' '}
        {p.purgeApprovalTtlHours} hours · up to {p.reportMailboxesMax} report mailboxes.
      </p>
    </Section>
  );
}

function AddByAddressDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const base = useId();
  const [address, setAddress] = useState('');
  const [reason, setReason] = useState('');
  const [hint, setHint] = useState<string | null>(null);
  const add = useApiMutation('ApiModeReportsController_addMailbox_v1', {
    invalidates: MAILBOX_QUERIES,
    successMessage: 'Report mailbox added.',
  });
  const close = (next: boolean) => {
    if (!next) {
      setAddress('');
      setReason('');
      setHint(null);
      add.reset();
    }
    onOpenChange(next);
  };
  const errorText = clawbackErrorText(add.error);
  return (
    <FormDialog
      open={open}
      onOpenChange={close}
      title="Add a report mailbox"
      description="A shared or group-backed mailbox of a domain in API or Hybrid mode, inside the journal scope. Users forward suspicious messages to it; its copies are never remediated."
    >
      <form
        className="grid gap-4"
        aria-label="Add a report mailbox"
        onSubmit={(event) => {
          event.preventDefault();
          if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(address.trim()))
            return setHint('Enter the mailbox address.');
          if (!reason.trim()) return setHint('Enter a reason.');
          setHint(null);
          void add
            .submit({ body: { address: address.trim(), reason: reason.trim() } })
            .then((outcome) => outcome.ok && close(false));
        }}
      >
        <div className="grid gap-2">
          <Label htmlFor={`${base}-address`}>Mailbox address</Label>
          <Input
            id={`${base}-address`}
            value={address}
            maxLength={320}
            placeholder="report-phishing@example.com"
            onChange={(event) => setAddress(event.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${base}-reason`}>Reason (required)</Label>
          <Textarea
            id={`${base}-reason`}
            rows={2}
            maxLength={REASON_MAX_CHARS}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </div>
        {hint ? (
          <p role="alert" className="text-sm font-medium text-destructive">
            {hint}
          </p>
        ) : null}
        {add.error ? (
          <div role="alert" className="grid gap-1">
            {errorText ? <p className="text-sm font-medium text-destructive">{errorText}</p> : null}
            <MutationError error={add.error} />
          </div>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Button type="submit" size="sm" disabled={add.isPending}>
            Add report mailbox
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={() => close(false)}>
            Cancel
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

function DesignateDialog({
  open,
  taken,
  onOpenChange,
}: {
  open: boolean;
  taken: ReadonlySet<string>;
  onOpenChange: (open: boolean) => void;
}) {
  const selectId = useId();
  const [mailboxId, setMailboxId] = useState('');
  const mailboxes = useApiQuery(
    'ApiModeController_listMailboxes_v1',
    { query: { limit: '100' } },
    { enabled: open },
  );
  const set = useApiMutation('ApiModeReportsController_setMailbox_v1', {
    invalidates: MAILBOX_QUERIES,
    successMessage: 'Report mailbox designated.',
  });
  const options = (mailboxes.data?.data ?? [])
    .filter((m) => !taken.has(m.id) && m.status !== 'deleted')
    .map((m) => ({ value: m.id, label: m.address }));
  return (
    <ReasonConfirm
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          setMailboxId('');
          set.reset();
        }
        onOpenChange(next);
      }}
      title="Designate a report mailbox"
      description={
        <p>
          Copies in a report mailbox become reports for triage and are never remediated; they stay
          in coverage.
        </p>
      }
      confirmLabel="Designate"
      maxChars={REASON_MAX_CHARS}
      reasonHelp="Stored in the audit log"
      explainError={explainClawbackError}
      pending={set.isPending}
      extra={
        mailboxes.isLoading ? (
          <LoadingState label="Loading mailboxes" rows={1} />
        ) : options.length === 0 ? (
          <p className="text-sm text-muted-foreground">No mailbox left to designate.</p>
        ) : (
          <LabelledSelect
            id={selectId}
            label="Mailbox"
            value={mailboxId || (options[0]?.value ?? '')}
            onChange={setMailboxId}
            options={options}
          />
        )
      }
      onSubmit={async (reason) => {
        const chosen = mailboxId || options[0]?.value;
        if (!chosen) return { ok: false };
        return set.submit({ path: { mailboxId: chosen }, body: { enabled: true, reason } });
      }}
      onRetry={() => set.retry()}
    />
  );
}

function ReportMailboxes() {
  const canWrite = useCan('ApiModeReportsController_setMailbox_v1');
  const canAdd = useCan('ApiModeReportsController_addMailbox_v1');
  const list = useApiQuery('ApiModeReportsController_listMailboxes_v1');
  const [adding, setAdding] = useState(false);
  const [designating, setDesignating] = useState(false);
  const [removing, setRemoving] = useState<ReportMailbox | null>(null);
  const unset = useApiMutation('ApiModeReportsController_setMailbox_v1', {
    invalidates: MAILBOX_QUERIES,
    successMessage: 'The mailbox is no longer a report mailbox.',
  });
  const rows = (list.data?.data ?? []).filter((m) => m.reportMailbox);
  const max = list.data?.max ?? 5;
  const full = rows.length >= max;
  return (
    <Section
      title="Report mailboxes"
      description={`Users forward suspicious messages to a report mailbox (no add-in needed). ${formatNumber(rows.length)} of ${formatNumber(max)} used.`}
      actions={
        canWrite || canAdd ? (
          <>
            {canAdd ? (
              <Button size="sm" variant="outline" disabled={full} onClick={() => setAdding(true)}>
                <PlusIcon aria-hidden />
                Add by address
              </Button>
            ) : null}
            {canWrite ? (
              <Button
                size="sm"
                variant="outline"
                disabled={full}
                onClick={() => setDesignating(true)}
              >
                Designate a mailbox
              </Button>
            ) : null}
          </>
        ) : null
      }
    >
      {full && (canWrite || canAdd) ? (
        <p role="note" className="text-sm text-muted-foreground">
          The limit of {formatNumber(max)} report mailboxes is reached; remove one to add another.
        </p>
      ) : null}
      {list.isLoading ? (
        <LoadingState label="Loading report mailboxes" rows={2} />
      ) : list.error ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} compact />
      ) : rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">No report mailbox yet.</p>
      ) : (
        <div className="relative overflow-x-auto">
          <Table>
            <TableCaption className="sr-only">Report mailboxes</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead>Mailbox</TableHead>
                <TableHead>Provider</TableHead>
                <TableHead>Coverage</TableHead>
                <TableHead>Designated</TableHead>
                <TableHead>Last report</TableHead>
                {canWrite ? <TableHead>Actions</TableHead> : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((m) => (
                <TableRow key={m.id}>
                  <TableCell>
                    <span className="grid gap-0.5">
                      <UntrustedText value={m.address} mono maxLength={80} />
                      <span className="text-xs text-muted-foreground">{m.status}</span>
                    </span>
                  </TableCell>
                  <TableCell className="text-sm">{PROVIDER_LABEL[m.provider]}</TableCell>
                  <TableCell>
                    <CoverageBadge coverage={m.coverage} />
                  </TableCell>
                  <TableCell>
                    <DateTime value={m.reportMailboxAt} emptyLabel="—" />
                  </TableCell>
                  <TableCell>
                    <DateTime value={m.lastReportAt} emptyLabel="None yet" />
                  </TableCell>
                  {canWrite ? (
                    <TableCell>
                      <Button size="sm" variant="ghost" onClick={() => setRemoving(m)}>
                        Remove <span className="sr-only">report mailbox {m.address}</span>
                      </Button>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <AddByAddressDialog open={adding} onOpenChange={setAdding} />
      <DesignateDialog
        open={designating}
        taken={new Set(rows.map((m) => m.id))}
        onOpenChange={setDesignating}
      />
      <ReasonConfirm
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRemoving(null);
            unset.reset();
          }
        }}
        title="Stop using this report mailbox?"
        description={
          <p>
            New messages in <UntrustedText value={removing?.address ?? ''} mono /> are treated as
            ordinary mail again. Existing reports stay.
          </p>
        }
        confirmLabel="Remove"
        destructive
        maxChars={REASON_MAX_CHARS}
        reasonHelp="Stored in the audit log"
        explainError={explainClawbackError}
        pending={unset.isPending}
        onSubmit={(reason) =>
          unset.submit({
            path: { mailboxId: removing?.id ?? '' },
            body: { enabled: false, reason },
          })
        }
        onRetry={() => unset.retry()}
      />
    </Section>
  );
}

/** Tab "Settings" (C14 #15–#19): organization settings with CAS and the report mailboxes. */
export function SettingsTab() {
  const settings = useApiQuery('ApiModeSettingsController_get_v1');
  const canMailboxes = useCan('ApiModeReportsController_listMailboxes_v1');
  if (settings.isLoading) return <LoadingState label="Loading the settings" rows={6} />;
  if (settings.error)
    return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  if (!settings.data) return null;
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <OrganizationSettings view={settings.data} />
      {canMailboxes ? <ReportMailboxes /> : null}
    </div>
  );
}
