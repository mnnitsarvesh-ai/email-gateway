'use client';

import { KeyRoundIcon, LockIcon, RotateCwIcon, SaveIcon } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useId, useMemo, useState, type ReactNode } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DateTime } from '@/components/domain';
import { FormErrorSummary } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { DetailList, EnumBadge, Section } from '@/features/messages/controls';
import { useDirectoryOptions } from '@/features/policies/use-directory-options';
import { splitList } from '@/features/domains/kit';
import { ArchiveErrorSummary, ConflictDialog, Notice, ReasonDialog } from './components';
import {
  ARCHIVE_DIRECTIONS,
  IMMUTABILITY_MODES,
  KEY_STATUS_TONE,
  LOCK_TONE,
  conflictVersion,
  explainArchiveError,
  retentionHref,
  useArchiveAccess,
  type ArchiveSettings,
  type ImmutabilityMode,
} from './model';

/** The editable part of the archive settings (A22, `archive-settings/1`). */
export interface SettingsDraft {
  enabled: boolean;
  immutability: ImmutabilityMode;
  defaultRetentionPolicyId: string | null;
  directions: { inbound: boolean; outbound: boolean; internal: boolean };
  include: { rejected: boolean; quarantined: boolean; failed: boolean };
  scopeMode: 'all' | 'include' | 'exclude';
  domainIds: string[];
  departmentIds: string[];
  userIds: string[];
  addresses: string[];
  policyArchive: boolean;
  previewEnabled: boolean;
  downloadEnabled: boolean;
}

export function draftOf(settings: ArchiveSettings): SettingsDraft {
  const s = settings.settings;
  return {
    enabled: settings.enabled,
    immutability: settings.immutability,
    defaultRetentionPolicyId: settings.defaultRetentionPolicyId,
    directions: { ...s.directions },
    include: { ...s.include },
    scopeMode: s.scope.mode,
    domainIds: [...s.scope.domainIds],
    departmentIds: [...s.scope.departmentIds],
    userIds: [...s.scope.userIds],
    addresses: [...s.scope.addresses],
    policyArchive: s.policyArchive.enabled,
    previewEnabled: s.access.previewEnabled,
    downloadEnabled: s.access.downloadEnabled,
  };
}

/** The `PUT /archive/settings` body (full document, CAS on `expectedRowVersion`). */
export function settingsBody(
  draft: SettingsDraft,
  expectedRowVersion: number,
): RequestBody<'ArchiveAdminController_update_v1'> {
  return {
    expectedRowVersion,
    enabled: draft.enabled,
    immutability: draft.immutability,
    defaultRetentionPolicyId: draft.defaultRetentionPolicyId,
    settings: {
      directions: { ...draft.directions },
      include: { ...draft.include },
      scope: {
        mode: draft.scopeMode,
        domainIds: draft.scopeMode === 'all' ? [] : [...draft.domainIds],
        departmentIds: draft.scopeMode === 'all' ? [] : [...draft.departmentIds],
        userIds: draft.scopeMode === 'all' ? [] : [...draft.userIds],
        addresses: draft.scopeMode === 'all' ? [] : [...draft.addresses],
      },
      policyArchive: { enabled: draft.policyArchive },
      access: { previewEnabled: draft.previewEnabled, downloadEnabled: draft.downloadEnabled },
    },
  };
}

const EMAIL = /^[^\s@<>()",;]+@[^\s@<>()",;]+\.[^\s@<>()",;]+$/;

/** Client-side checks before the PUT (`field → message`). */
export function draftErrors(draft: SettingsDraft): Record<string, string> {
  const errors: Record<string, string> = {};
  if (draft.enabled && !draft.defaultRetentionPolicyId) {
    errors.defaultRetentionPolicyId =
      'Choose a default retention policy before enabling archiving.';
  }
  if (
    draft.enabled &&
    !draft.directions.inbound &&
    !draft.directions.outbound &&
    !draft.directions.internal
  ) {
    errors.directions = 'Choose at least one direction, or turn archiving off.';
  }
  const bad = draft.addresses.filter((a) => !EMAIL.test(a));
  if (bad.length > 0) errors.addresses = `Not an email address: ${bad.slice(0, 3).join(', ')}`;
  if (draft.addresses.length > 1000) errors.addresses = 'At most 1 000 addresses.';
  if (draft.domainIds.length > 100) errors.domainIds = 'At most 100 domains.';
  if (draft.departmentIds.length > 50) errors.departmentIds = 'At most 50 departments.';
  if (draft.userIds.length > 1000) errors.userIds = 'At most 1 000 users.';
  if (
    draft.scopeMode !== 'all' &&
    draft.domainIds.length +
      draft.departmentIds.length +
      draft.userIds.length +
      draft.addresses.length ===
      0
  ) {
    errors.scope = 'Choose at least one domain, department, user or address for this scope.';
  }
  return errors;
}

/** Field of an api refusal (422 scope reference, 422 default retention, 403 entitlement). */
export function fieldOfError(error: ApiError): string | null {
  switch (error.code) {
    case 'archive_default_retention_required':
      return 'defaultRetentionPolicyId';
    case 'archiving_not_enabled':
      return 'enabled';
    case 'archive_immutability_downgrade_forbidden':
    case 'archive_object_lock_unavailable':
      return 'immutability';
    case 'archive_scope_reference_invalid': {
      const path = typeof error.details.path === 'string' ? error.details.path : '';
      if (path.includes('domainIds')) return 'domainIds';
      if (path.includes('departmentIds')) return 'departmentIds';
      if (path.includes('userIds')) return 'userIds';
      return 'scope';
    }
    default:
      return null;
  }
}

/** Settings → Archive and retention (A22, A28): replaces the 7.1 "arrives in 8.1" state. */
export function ArchiveSettingsPanel() {
  const settings = useApiQuery('ArchiveAdminController_get_v1');
  const access = useArchiveAccess();
  if (settings.isLoading) return <LoadingState label="Loading the archive settings" rows={8} />;
  if (settings.error || !settings.data) {
    return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  }
  return (
    <div className="grid gap-4">
      <AvailabilityBanner settings={settings.data} />
      <ArchiveStatusCard />
      {access.manage ? (
        <SettingsForm settings={settings.data} onReload={() => void settings.refetch()} />
      ) : (
        <SettingsView settings={settings.data} />
      )}
      <KeysSection />
    </div>
  );
}

function AvailabilityBanner({ settings }: { settings: ArchiveSettings }) {
  return (
    <div className="grid gap-2">
      {!settings.entitled ? (
        <Notice tone="warning">
          <span>
            Archiving is not part of your organization’s plan (feature “archiving”). Settings can be
            prepared, but archiving cannot be enabled until your platform operator enables it.
          </span>
        </Notice>
      ) : null}
      <Notice tone={settings.objectLockAvailable ? 'info' : 'warning'} icon={LockIcon}>
        <span>
          {settings.objectLockAvailable
            ? 'Immutable storage (S3 Object Lock) is available: governance or compliance immutability can be enforced for new captures.'
            : 'Immutable storage (S3 Object Lock) is not available on this deployment: only “none” can be chosen. The platform never stores unlocked copies for a tenant that requires a lock.'}
        </span>
      </Notice>
    </div>
  );
}

function ArchiveStatusCard() {
  const status = useApiQuery('ArchiveAdminController_status_v1', undefined, {
    refetchOnWindowFocus: false,
  });
  if (status.isLoading) return <LoadingState label="Loading the archive status" rows={2} />;
  if (status.error || !status.data) {
    return <ErrorState error={status.error} onRetry={() => void status.refetch()} compact />;
  }
  const s = status.data;
  return (
    <Section
      title="Status"
      description={
        <>
          As of <DateTime value={s.generatedAt} />.
        </>
      }
    >
      <DetailList
        items={[
          {
            label: 'Archiving',
            value: `${s.settings.enabled ? 'Enabled' : 'Disabled'} · immutability ${humanize(s.settings.immutability)} · generation ${s.settings.generation}`,
          },
          {
            label: 'Records',
            value: `${formatNumber(s.records.active)} active · ${formatNumber(s.records.expiryReview)} in review · ${formatNumber(s.records.disposing)} being disposed`,
          },
          {
            label: 'Capture',
            value: `${formatNumber(s.capture.pending)} pending · ${formatNumber(s.capture.failed)} failed · ${formatNumber(s.capture.lost)} lost`,
          },
          {
            label: 'Search index',
            value: `${s.search.available ? 'Available' : s.search.configured ? 'Unavailable' : 'Not configured'} · ${formatNumber(s.index.queued)} queued · lag ${formatNumber(s.index.lagSeconds)} s`,
          },
          {
            label: 'Encryption key',
            value:
              s.keys.activeVersion === null
                ? 'No key yet (created at the first capture)'
                : `Version ${s.keys.activeVersion} active · ${s.keys.versions} version(s)`,
          },
        ]}
      />
    </Section>
  );
}

function SettingsView({ settings }: { settings: ArchiveSettings }) {
  const d = draftOf(settings);
  return (
    <Section
      title="Archive and journaling"
      description="Read only: changing these settings needs the archive:manage permission."
    >
      <DetailList
        items={[
          { label: 'Archiving', value: d.enabled ? 'Enabled' : 'Disabled' },
          {
            label: 'Journaled since',
            value: (
              <DateTime value={settings.journalEnabledAt} mode="absolute" emptyLabel="Never" />
            ),
          },
          {
            label: 'Directions',
            value:
              ARCHIVE_DIRECTIONS.filter((k) => d.directions[k])
                .map(humanize)
                .join(', ') || 'None',
          },
          {
            label: 'Also archived',
            value:
              (['rejected', 'quarantined', 'failed'] as const)
                .filter((k) => d.include[k])
                .map(humanize)
                .join(', ') || 'Delivered mail only',
          },
          { label: 'Scope', value: humanize(d.scopeMode) },
          { label: 'Immutability', value: <EnumBadge value={d.immutability} tones={LOCK_TONE} /> },
          { label: 'Policy ARCHIVE action', value: d.policyArchive ? 'Honoured' : 'Ignored' },
          { label: 'Sanitized preview', value: d.previewEnabled ? 'Allowed' : 'Off' },
          { label: 'Original download', value: d.downloadEnabled ? 'Allowed' : 'Off' },
        ]}
      />
    </Section>
  );
}

function SettingsForm({ settings, onReload }: { settings: ArchiveSettings; onReload: () => void }) {
  const [draft, setDraft] = useState<SettingsDraft>(() => draftOf(settings));
  const [base, setBase] = useState(settings);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [confirmCompliance, setConfirmCompliance] = useState(false);
  const [conflict, setConflict] = useState<number | null>(null);
  const update = useApiMutation('ArchiveAdminController_update_v1', {
    successMessage: 'Archive settings saved',
    invalidates: ['ArchiveAdminController_get_v1', 'ArchiveAdminController_status_v1'],
  });
  const policies = useCursorList(
    'ArchiveRetentionController_list_v1',
    { sort: 'priority' },
    { limit: 100 },
  );
  // A new version from the server (after save or reload) replaces the draft.
  useEffect(() => {
    if (settings.rowVersion !== base.rowVersion) {
      setBase(settings);
      setDraft(draftOf(settings));
      setErrors({});
    }
  }, [settings, base.rowVersion]);
  const set = (patch: Partial<SettingsDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const dirty = JSON.stringify(draft) !== JSON.stringify(draftOf(base));
  const lockedCompliance = base.immutability === 'compliance';

  const save = async (rowVersion: number) => {
    const outcome = await update.submit({ body: settingsBody(draft, rowVersion) });
    if (outcome.ok) {
      setErrors({});
      return true;
    }
    const version = conflictVersion(outcome.error);
    if (outcome.error.code === 'archive_settings_conflict' && version !== null) {
      setConflict(version);
      return false;
    }
    const field = fieldOfError(outcome.error);
    if (field) setErrors({ [field]: explainArchiveError(outcome.error).join(' ') });
    return false;
  };
  const submit = async () => {
    const found = draftErrors(draft);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    if (draft.immutability === 'compliance' && base.immutability !== 'compliance') {
      setConfirmCompliance(true);
      return;
    }
    await save(base.rowVersion);
  };
  const formErrors =
    update.error && !fieldOfError(update.error) && update.error.code !== 'archive_settings_conflict'
      ? update.error
      : null;

  return (
    <Section
      title="Archive and journaling"
      description={
        <>
          Version {base.rowVersion} · generation {base.generation} · journaled since{' '}
          <DateTime value={base.journalEnabledAt} mode="absolute" emptyLabel="never" />. Saving
          needs a session signed in with MFA and is recorded in the audit log.
        </>
      }
    >
      <form
        className="grid gap-5"
        aria-label="Archive settings"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <ArchiveErrorSummary error={formErrors} />
        {Object.keys(errors).length > 0 ? (
          <FormErrorSummary messages={Object.values(errors)} />
        ) : null}
        <ToggleRow
          id="archive-enabled"
          label="Archive mail of this organization"
          description={
            base.entitled
              ? 'When on, mail is journaled from the moment you save (earlier mail is not captured).'
              : 'Not available: the plan of your organization does not include archiving.'
          }
          checked={draft.enabled}
          disabled={!base.entitled && !draft.enabled}
          onChange={(enabled) => set({ enabled })}
          error={errors.enabled}
        />
        <Fieldset legend="Directions" error={errors.directions}>
          {ARCHIVE_DIRECTIONS.map((direction) => (
            <CheckRow
              key={direction}
              id={`archive-dir-${direction}`}
              label={humanize(direction)}
              checked={draft.directions[direction]}
              onChange={(checked) =>
                set({ directions: { ...draft.directions, [direction]: checked } })
              }
            />
          ))}
        </Fieldset>
        <Fieldset
          legend="Also archive (besides delivered mail)"
          description="Rejected, quarantined (kept until released or rejected) and failed deliveries."
        >
          {(['rejected', 'quarantined', 'failed'] as const).map((category) => (
            <CheckRow
              key={category}
              id={`archive-include-${category}`}
              label={humanize(category)}
              checked={draft.include[category]}
              onChange={(checked) => set({ include: { ...draft.include, [category]: checked } })}
            />
          ))}
        </Fieldset>
        <ScopeFields draft={draft} set={set} errors={errors} />
        <ImmutabilityField
          value={draft.immutability}
          current={base.immutability}
          available={base.objectLockAvailable}
          locked={lockedCompliance}
          onChange={(immutability) => set({ immutability })}
          error={errors.immutability}
        />
        <DefaultPolicyField
          value={draft.defaultRetentionPolicyId}
          options={policies.rows.map((p) => ({ id: p.id, name: p.name, days: p.retentionDays }))}
          loading={policies.query.isLoading}
          onChange={(defaultRetentionPolicyId) => set({ defaultRetentionPolicyId })}
          error={errors.defaultRetentionPolicyId}
        />
        <Fieldset legend="Policy archiving and access">
          <ToggleRow
            id="archive-policy-action"
            label="Honour the ARCHIVE action of email policies"
            description="Policies can archive a message even when journaling would not (any category)."
            checked={draft.policyArchive}
            onChange={(policyArchive) => set({ policyArchive })}
          />
          <ToggleRow
            id="archive-preview"
            label="Allow the sanitized preview of archived messages"
            description="Text only, audited, for users with archive:retrieve."
            checked={draft.previewEnabled}
            onChange={(previewEnabled) => set({ previewEnabled })}
          />
          <ToggleRow
            id="archive-download"
            label="Allow downloading archived originals"
            description="Single-use links after re-authentication; malicious messages are never downloadable interactively."
            checked={draft.downloadEnabled}
            onChange={(downloadEnabled) => set({ downloadEnabled })}
          />
        </Fieldset>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="submit"
            disabled={!dirty || update.isPending || update.retryAfterSeconds > 0}
          >
            <SaveIcon aria-hidden />
            {update.isPending ? 'Saving …' : 'Save archive settings'}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!dirty || update.isPending}
            onClick={() => {
              setDraft(draftOf(base));
              setErrors({});
            }}
          >
            Discard changes
          </Button>
        </div>
      </form>
      <ConfirmDialog
        open={confirmCompliance}
        onOpenChange={setConfirmCompliance}
        title="Switch to compliance immutability?"
        description={
          <div className="grid gap-2">
            <p>
              <strong>This cannot be undone.</strong> With compliance immutability every archived
              object is locked until its retention date; nobody — no administrator, no platform
              operator — can delete or shorten it before then, and the organization can never switch
              back to governance or none.
            </p>
            <p>
              Existing records are locked by a background pass; new captures are locked at once.
            </p>
          </div>
        }
        typedConfirmation="compliance"
        confirmLabel="Switch to compliance"
        destructive
        onConfirm={() => save(base.rowVersion)}
      />
      <ConflictDialog
        open={conflict !== null}
        onOpenChange={(open) => {
          if (!open) setConflict(null);
        }}
        what="archive settings"
        onReload={() => {
          setConflict(null);
          update.reset();
          onReload();
          setBase({ ...base, rowVersion: -1 });
        }}
        onOverwrite={async () => {
          if (conflict === null) return;
          const version = conflict;
          setConflict(null);
          await save(version);
        }}
      />
    </Section>
  );
}

function Fieldset({
  legend,
  description,
  error,
  children,
}: {
  legend: string;
  description?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <fieldset className="grid gap-2" aria-invalid={error ? true : undefined}>
      <legend className="text-sm font-semibold">{legend}</legend>
      {description ? <p className="text-xs text-muted-foreground">{description}</p> : null}
      <div className="flex flex-wrap gap-x-6 gap-y-2">{children}</div>
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </fieldset>
  );
}

function CheckRow({
  id,
  label,
  checked,
  onChange,
  disabled,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  // At least 28 px per row: stacked checkboxes keep the 24 px target spacing (WCAG 2.5.8).
  return (
    <div className="flex min-h-7 items-center gap-2">
      <Checkbox
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={(next) => onChange(next === true)}
      />
      <Label htmlFor={id} className="font-normal">
        {label}
      </Label>
    </div>
  );
}

function ToggleRow({
  id,
  label,
  description,
  checked,
  onChange,
  disabled,
  error,
}: {
  id: string;
  label: string;
  description?: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  error?: string;
}) {
  return (
    <div className="grid gap-1">
      <div className="flex items-center gap-3">
        <Switch
          id={id}
          checked={checked}
          disabled={disabled}
          onCheckedChange={onChange}
          aria-describedby={description ? `${id}-desc` : undefined}
        />
        <Label htmlFor={id}>{label}</Label>
      </div>
      {description ? (
        <p id={`${id}-desc`} className="text-xs text-muted-foreground">
          {description}
        </p>
      ) : null}
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </div>
  );
}

function ScopeFields({
  draft,
  set,
  errors,
}: {
  draft: SettingsDraft;
  set: (patch: Partial<SettingsDraft>) => void;
  errors: Record<string, string>;
}) {
  const canDomains = useCan('DomainsController_list_v1');
  const domains = useCursorList('DomainsController_list_v1', undefined, {
    limit: 100,
    enabled: canDomains && draft.scopeMode !== 'all',
  });
  const directory = useDirectoryOptions();
  const [addresses, setAddresses] = useState(draft.addresses.join('\n'));
  useEffect(() => setAddresses(draft.addresses.join('\n')), [draft.addresses]);
  return (
    <fieldset className="grid gap-3">
      <legend className="text-sm font-semibold">Journal scope</legend>
      <RadioGroup
        value={draft.scopeMode}
        onValueChange={(value) => set({ scopeMode: value as SettingsDraft['scopeMode'] })}
        className="flex flex-wrap gap-x-6 gap-y-2"
        aria-label="Journal scope"
      >
        {(
          [
            ['all', 'All mail of the organization'],
            ['include', 'Only the chosen parties'],
            ['exclude', 'All mail except the chosen parties'],
          ] as const
        ).map(([value, label]) => (
          <div key={value} className="flex items-center gap-2">
            <RadioGroupItem value={value} id={`archive-scope-${value}`} />
            <Label htmlFor={`archive-scope-${value}`} className="font-normal">
              {label}
            </Label>
          </div>
        ))}
      </RadioGroup>
      {errors.scope ? <p className="text-xs font-medium text-destructive">{errors.scope}</p> : null}
      {draft.scopeMode !== 'all' ? (
        <div className="grid gap-3 lg:grid-cols-2">
          <IdChecklist
            label="Domains"
            options={domains.rows.map((d) => ({ id: d.id, label: d.name }))}
            selected={draft.domainIds}
            onChange={(domainIds) => set({ domainIds })}
            error={errors.domainIds}
            unavailable={!canDomains ? 'Listing domains needs domain:read.' : undefined}
          />
          <IdChecklist
            label="Departments"
            options={directory.directory.departments ?? []}
            selected={draft.departmentIds}
            onChange={(departmentIds) => set({ departmentIds })}
            error={errors.departmentIds}
            unavailable={
              !directory.directory.departments ? 'Listing departments needs user:read.' : undefined
            }
          />
          <IdChecklist
            label="Users"
            options={directory.directory.users ?? []}
            selected={draft.userIds}
            onChange={(userIds) => set({ userIds })}
            error={errors.userIds}
            unavailable={!directory.directory.users ? 'Listing users needs user:read.' : undefined}
          />
          <div className="grid gap-1">
            <Label htmlFor="archive-scope-addresses">Addresses (one per line)</Label>
            <Textarea
              id="archive-scope-addresses"
              rows={4}
              value={addresses}
              onChange={(e) => setAddresses(e.target.value)}
              onBlur={() => set({ addresses: splitList(addresses).map((a) => a.toLowerCase()) })}
              aria-invalid={errors.addresses ? true : undefined}
              aria-describedby="archive-scope-addresses-help"
            />
            <p id="archive-scope-addresses-help" className="text-xs text-muted-foreground">
              Mailboxes of your organization (sender or recipient side), at most 1 000.
            </p>
            {errors.addresses ? (
              <p className="text-xs font-medium text-destructive">{errors.addresses}</p>
            ) : null}
          </div>
        </div>
      ) : null}
    </fieldset>
  );
}

/** A searchable checklist of directory ids (unknown selected ids stay listed by id). */
function IdChecklist({
  label,
  options,
  selected,
  onChange,
  error,
  unavailable,
}: {
  label: string;
  options: readonly { id: string; label: string }[];
  selected: readonly string[];
  onChange: (ids: string[]) => void;
  error?: string;
  unavailable?: string;
}) {
  const id = useId();
  const [filter, setFilter] = useState('');
  const known = new Set(options.map((o) => o.id));
  const unknown = selected.filter((s) => !known.has(s));
  const shown = useMemo(
    () =>
      options
        .filter((o) => !filter || o.label.toLowerCase().includes(filter.toLowerCase()))
        .slice(0, 50),
    [options, filter],
  );
  const toggle = (value: string, on: boolean) =>
    onChange(on ? [...selected, value] : selected.filter((s) => s !== value));
  return (
    <fieldset className="grid gap-1 rounded-md border p-3" aria-invalid={error ? true : undefined}>
      <legend className="px-1 text-sm font-medium">
        {label} ({selected.length} chosen)
      </legend>
      {unavailable ? <p className="text-xs text-muted-foreground">{unavailable}</p> : null}
      {options.length > 8 ? (
        <Input
          aria-label={`Filter ${label.toLowerCase()}`}
          placeholder="Filter …"
          className="h-8"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      ) : null}
      <div className="grid max-h-48 overflow-y-auto">
        {shown.map((option) => (
          <CheckRow
            key={option.id}
            id={`${id}-${option.id}`}
            label={option.label}
            checked={selected.includes(option.id)}
            onChange={(on) => toggle(option.id, on)}
          />
        ))}
        {unknown.map((value) => (
          <CheckRow
            key={value}
            id={`${id}-${value}`}
            label={`${value} (not listed)`}
            checked
            onChange={(on) => toggle(value, on)}
          />
        ))}
        {shown.length === 0 && unknown.length === 0 && !unavailable ? (
          <p className="text-xs text-muted-foreground">None available.</p>
        ) : null}
      </div>
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </fieldset>
  );
}

const IMMUTABILITY_TEXT: Record<ImmutabilityMode, string> = {
  none: 'Objects are write-once and encrypted, but not locked by the storage.',
  governance:
    'Objects are locked until their retention date; only a privileged storage operator could bypass the lock.',
  compliance:
    'Objects are locked until their retention date for everyone. Irreversible: can never be weakened.',
};

function ImmutabilityField({
  value,
  current,
  available,
  locked,
  onChange,
  error,
}: {
  value: ImmutabilityMode;
  current: ImmutabilityMode;
  available: boolean;
  locked: boolean;
  onChange: (value: ImmutabilityMode) => void;
  error?: string;
}) {
  return (
    <fieldset className="grid gap-2" aria-invalid={error ? true : undefined}>
      <legend className="text-sm font-semibold">Immutability (S3 Object Lock)</legend>
      <RadioGroup
        value={value}
        onValueChange={(next) => onChange(next as ImmutabilityMode)}
        className="grid gap-2"
        aria-label="Immutability"
      >
        {IMMUTABILITY_MODES.map((mode) => {
          const disabled =
            (locked && mode !== 'compliance') ||
            (!available && mode !== 'none' && mode !== current);
          return (
            <div key={mode} className="flex items-start gap-2">
              <RadioGroupItem
                value={mode}
                id={`archive-lock-${mode}`}
                disabled={disabled}
                aria-describedby={`archive-lock-${mode}-desc`}
                className="mt-0.5"
              />
              <div className="grid gap-0.5">
                <Label htmlFor={`archive-lock-${mode}`}>{humanize(mode)}</Label>
                <p id={`archive-lock-${mode}-desc`} className="text-xs text-muted-foreground">
                  {IMMUTABILITY_TEXT[mode]}
                </p>
              </div>
            </div>
          );
        })}
      </RadioGroup>
      {locked ? (
        <p className="text-xs text-muted-foreground">
          Compliance immutability is set and can no longer be changed.
        </p>
      ) : null}
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </fieldset>
  );
}

const NO_POLICY = '__none';

function DefaultPolicyField({
  value,
  options,
  loading,
  onChange,
  error,
}: {
  value: string | null;
  options: readonly { id: string; name: string; days: number }[];
  loading: boolean;
  onChange: (value: string | null) => void;
  error?: string;
}) {
  return (
    <div className="grid gap-1">
      <Label htmlFor="archive-default-policy">Default retention policy</Label>
      <Select
        value={value ?? NO_POLICY}
        onValueChange={(next) => onChange(next === NO_POLICY ? null : next)}
      >
        <SelectTrigger
          id="archive-default-policy"
          className="max-w-md"
          aria-invalid={error ? true : undefined}
          aria-describedby="archive-default-policy-help"
        >
          <SelectValue placeholder={loading ? 'Loading …' : 'Choose a policy'} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={NO_POLICY}>None</SelectItem>
          {options.map((option) => (
            <SelectItem key={option.id} value={option.id}>
              {option.name} ({option.days} days)
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p id="archive-default-policy-help" className="text-xs text-muted-foreground">
        Applies to every record no other policy matches; required while archiving is enabled.{' '}
        <Link
          href={retentionHref('policies')}
          className="text-primary underline underline-offset-2"
        >
          Create or edit retention policies
        </Link>
      </p>
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </div>
  );
}

function KeysSection() {
  const access = useArchiveAccess();
  const keys = useCursorList(
    'ArchiveAdminController_listKeys_v1',
    { sort: '-version' },
    { limit: 25 },
  );
  const [rotateOpen, setRotateOpen] = useState(false);
  const rotate = useApiMutation('ArchiveAdminController_rotate_v1', {
    successMessage: 'A new key version is active',
    invalidates: ['ArchiveAdminController_listKeys_v1', 'ArchiveAdminController_status_v1'],
  });
  return (
    <Section
      title="Encryption key versions"
      description="Each record is encrypted with its own data key wrapped under your organization’s key. Key material is never shown."
      actions={
        access.manage ? (
          <Button variant="outline" size="sm" onClick={() => setRotateOpen(true)}>
            <RotateCwIcon aria-hidden />
            Rotate key
          </Button>
        ) : null
      }
    >
      {keys.query.isLoading ? (
        <LoadingState label="Loading key versions" rows={2} />
      ) : keys.query.error ? (
        <ErrorState error={keys.query.error} onRetry={() => void keys.query.refetch()} compact />
      ) : keys.rows.length === 0 ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <KeyRoundIcon className="size-4" aria-hidden />
          No key version yet: version 1 is created with the first capture.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-sm">
            <caption className="sr-only">Encryption key versions</caption>
            <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
              <tr>
                <th scope="col" className="px-3 py-2">
                  Version
                </th>
                <th scope="col" className="px-3 py-2">
                  Status
                </th>
                <th scope="col" className="px-3 py-2">
                  Algorithm
                </th>
                <th scope="col" className="px-3 py-2">
                  Root key
                </th>
                <th scope="col" className="px-3 py-2">
                  Created
                </th>
                <th scope="col" className="px-3 py-2">
                  Retired
                </th>
                <th scope="col" className="px-3 py-2">
                  Reason
                </th>
              </tr>
            </thead>
            <tbody>
              {keys.rows.map((key) => (
                <tr key={key.id} className="border-t">
                  <td className="px-3 py-2 font-mono">{key.version}</td>
                  <td className="px-3 py-2">
                    <EnumBadge value={key.status} tones={KEY_STATUS_TONE} />
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{key.algorithm}</td>
                  <td className="px-3 py-2 font-mono text-xs">{key.rootKeyId}</td>
                  <td className="px-3 py-2">
                    <DateTime value={key.createdAt} />
                  </td>
                  <td className="px-3 py-2">
                    <DateTime value={key.retiredAt} emptyLabel="—" />
                  </td>
                  <td className="px-3 py-2 text-xs">{key.rotationReason ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ReasonDialog
        open={rotateOpen}
        onOpenChange={setRotateOpen}
        title="Rotate the archive encryption key?"
        description={
          <p>
            A new key version becomes active for new captures; the current version is retired and
            keeps decrypting existing records. Rotation needs a session signed in with MFA and is
            recorded in the audit log.
          </p>
        }
        confirmLabel="Rotate key"
        pending={rotate.isPending}
        onSubmit={(reason) => rotate.submit({ body: { reason } })}
        onRetry={() => rotate.retry()}
      />
    </Section>
  );
}
