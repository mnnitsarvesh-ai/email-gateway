'use client';

import { KeyRoundIcon, LockIcon, RotateCwIcon, SaveIcon } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState, type ReactNode } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DateTime } from '@/components/domain';
import { FormErrorSummary } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { formatNumber, humanize } from '@/lib/format';
import { JOURNALING_SETTINGS_HREF } from '@/lib/navigation';
import { DetailList, EnumBadge, Section } from '@/features/messages/controls';
import { ArchiveErrorSummary, ConflictDialog, Notice, ReasonDialog } from './components';
import {
  KEY_STATUS_TONE,
  LOCK_TONE,
  conflictVersion,
  explainArchiveError,
  useArchiveAccess,
  type ArchiveSettings,
  type ImmutabilityMode,
} from './model';
import {
  DefaultPolicyField,
  Fieldset,
  ImmutabilityField,
  ToggleRow,
  type ScopeDraft,
} from './settings-fields';

/**
 * The whole archive settings document (A22, `archive-settings/1`). Since step 8.6 two areas
 * edit it: Settings → Journaling (`enabled`, directions, categories, scope, policy archiving,
 * intake scanning; `PUT /journaling/settings`) and Archive → Retention and lock (immutability,
 * default retention, access; `PUT /archive/settings`). The archive tabs send the full document
 * with the journaling paths unchanged, so the api's per-path check needs `archive:manage` only.
 */
export interface SettingsDraft extends ScopeDraft {
  enabled: boolean;
  immutability: ImmutabilityMode;
  defaultRetentionPolicyId: string | null;
  directions: { inbound: boolean; outbound: boolean; internal: boolean };
  include: { rejected: boolean; quarantined: boolean; failed: boolean };
  policyArchive: boolean;
  intakeScan: boolean;
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
    intakeScan: s.intake.scanEnabled,
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
      scope: scopeBody(draft),
      policyArchive: { enabled: draft.policyArchive },
      access: { previewEnabled: draft.previewEnabled, downloadEnabled: draft.downloadEnabled },
      intake: { scanEnabled: draft.intakeScan },
    },
  };
}

/** The `scope` section of a draft (lists cleared for mode `all`). */
export function scopeBody(draft: ScopeDraft) {
  const all = draft.scopeMode === 'all';
  return {
    mode: draft.scopeMode,
    domainIds: all ? [] : [...draft.domainIds],
    departmentIds: all ? [] : [...draft.departmentIds],
    userIds: all ? [] : [...draft.userIds],
    addresses: all ? [] : [...draft.addresses],
  };
}

const EMAIL = /^[^\s@<>()",;]+@[^\s@<>()",;]+\.[^\s@<>()",;]+$/;

/** Client-side checks of the journal scope (`field → message`). */
export function scopeErrors(draft: ScopeDraft): Record<string, string> {
  const errors: Record<string, string> = {};
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

/** Client-side checks before the PUT (`field → message`). */
export function draftErrors(draft: SettingsDraft): Record<string, string> {
  const errors: Record<string, string> = {};
  if (draft.enabled && !draft.defaultRetentionPolicyId) {
    errors.defaultRetentionPolicyId =
      'Journaling is enabled: a default retention policy is required.';
  }
  if (
    draft.enabled &&
    !draft.directions.inbound &&
    !draft.directions.outbound &&
    !draft.directions.internal
  ) {
    errors.directions = 'Choose at least one direction, or turn journaling off.';
  }
  return { ...errors, ...scopeErrors(draft) };
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

/** The paths of a `403 archive_settings_forbidden_path` refusal (step 8.6, WP5). */
export function forbiddenPaths(error: ApiError | null): string[] {
  if (error?.code !== 'archive_settings_forbidden_path') return [];
  const paths = error.details.paths;
  return Array.isArray(paths)
    ? paths
        .map((p) => {
          const entry = p as { path?: unknown; permission?: unknown } | null;
          if (!entry || typeof entry.path !== 'string') return null;
          const permission = typeof entry.permission === 'string' ? entry.permission : '';
          return `${entry.path} (${permission})`;
        })
        .filter((p): p is string => p !== null)
    : [];
}

/**
 * Archive → Retention and lock → "Immutability and keys" (step 8.6 D14; moved from the 8.1
 * Settings → Archive tab): availability, status, immutability, default retention, key versions.
 */
export function ArchiveImmutabilityPanel() {
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
        <SettingsForm
          kind="immutability"
          settings={settings.data}
          onReload={() => void settings.refetch()}
        />
      ) : (
        <SettingsView kind="immutability" settings={settings.data} />
      )}
      <KeysSection />
    </div>
  );
}

/**
 * Archive → Retention and lock → "Access settings" (step 8.6 D14): whether users with
 * `archive:retrieve` may open the sanitized preview and download archived originals.
 */
export function ArchiveAccessPanel() {
  const settings = useApiQuery('ArchiveAdminController_get_v1');
  const access = useArchiveAccess();
  if (settings.isLoading) return <LoadingState label="Loading the archive settings" rows={4} />;
  if (settings.error || !settings.data) {
    return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  }
  return access.manage ? (
    <SettingsForm kind="access" settings={settings.data} onReload={() => void settings.refetch()} />
  ) : (
    <SettingsView kind="access" settings={settings.data} />
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
      <Notice>
        <span>
          What is journaled (directions, categories, scope, journal intake) is set in{' '}
          <Link href={JOURNALING_SETTINGS_HREF} className="underline underline-offset-2">
            Settings → Journaling
          </Link>
          . Journaling is {settings.enabled ? 'on' : 'off'}.
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
            label: 'Journaling',
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

type PanelKind = 'immutability' | 'access';

const PANEL_TITLE: Record<PanelKind, string> = {
  immutability: 'Immutability and default retention',
  access: 'Access to archived content',
};

function SettingsView({ kind, settings }: { kind: PanelKind; settings: ArchiveSettings }) {
  const d = draftOf(settings);
  const items =
    kind === 'immutability'
      ? [
          { label: 'Immutability', value: <EnumBadge value={d.immutability} tones={LOCK_TONE} /> },
          {
            label: 'Default retention policy',
            value: d.defaultRetentionPolicyId ? <code>{d.defaultRetentionPolicyId}</code> : 'None',
          },
        ]
      : [
          { label: 'Sanitized preview', value: d.previewEnabled ? 'Allowed' : 'Off' },
          { label: 'Original download', value: d.downloadEnabled ? 'Allowed' : 'Off' },
        ];
  return (
    <Section
      title={PANEL_TITLE[kind]}
      description="Read only: changing these settings needs the archive:manage permission."
    >
      <DetailList items={items} />
    </Section>
  );
}

function SettingsForm({
  kind,
  settings,
  onReload,
}: {
  kind: PanelKind;
  settings: ArchiveSettings;
  onReload: () => void;
}) {
  const [draft, setDraft] = useState<SettingsDraft>(() => draftOf(settings));
  const [base, setBase] = useState(settings);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [confirmCompliance, setConfirmCompliance] = useState(false);
  const [conflict, setConflict] = useState<number | null>(null);
  const update = useApiMutation('ArchiveAdminController_update_v1', {
    successMessage: 'Archive settings saved',
    invalidates: [
      'ArchiveAdminController_get_v1',
      'ArchiveAdminController_status_v1',
      'JournalingController_get_v1',
    ],
  });
  const policies = useCursorList(
    'ArchiveRetentionController_list_v1',
    { sort: 'priority' },
    { limit: 100, enabled: kind === 'immutability' },
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
    // Journaling paths always go back as the server holds them (per-path authorization).
    const current = draftOf(base);
    const body =
      kind === 'immutability'
        ? {
            ...current,
            immutability: draft.immutability,
            defaultRetentionPolicyId: draft.defaultRetentionPolicyId,
          }
        : {
            ...current,
            previewEnabled: draft.previewEnabled,
            downloadEnabled: draft.downloadEnabled,
          };
    const outcome = await update.submit({ body: settingsBody(body, rowVersion) });
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
    const found = kind === 'immutability' ? draftErrors(draft) : {};
    delete found.directions;
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
  const pathErrors = forbiddenPaths(update.error);

  let fields: ReactNode;
  if (kind === 'immutability') {
    fields = (
      <>
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
      </>
    );
  } else {
    fields = (
      <Fieldset legend="Access to archived content">
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
    );
  }

  return (
    <Section
      title={PANEL_TITLE[kind]}
      description={
        <>
          Version {base.rowVersion} · generation {base.generation}. Saving needs a session signed in
          with MFA and is recorded in the audit log.
        </>
      }
    >
      <form
        className="grid gap-5"
        aria-label={kind === 'immutability' ? 'Immutability settings' : 'Access settings'}
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <ArchiveErrorSummary error={pathErrors.length > 0 ? null : formErrors} />
        {pathErrors.length > 0 ? (
          <FormErrorSummary
            messages={[`You may not change: ${pathErrors.join(', ')}.`]}
            requestId={update.error?.requestId}
          />
        ) : null}
        {Object.keys(errors).length > 0 ? (
          <FormErrorSummary messages={Object.values(errors)} />
        ) : null}
        {fields}
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
