'use client';

import { ArchiveIcon, ArrowRightIcon, CableIcon, PlusIcon, SaveIcon } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime, UntrustedText } from '@/components/domain';
import { FormErrorSummary } from '@/components/form';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { formatBytes, formatNumber, humanize } from '@/lib/format';
import { DetailList, Section } from '@/features/messages/controls';
import { ArchiveErrorSummary, ConflictDialog, Notice } from '@/features/archive/components';
import { ARCHIVE_DIRECTIONS, conflictVersion, retentionHref } from '@/features/archive/model';
import {
  CheckRow,
  Fieldset,
  ScopeFields,
  ToggleRow,
  type ScopeDraft,
} from '@/features/archive/settings-fields';
import { fieldOfError, scopeBody, scopeErrors } from '@/features/archive/settings-panel';
import {
  INTAKE_KIND_LABEL,
  IntakeHealthBadge,
  IntakeStatusBadge,
  explainJournalingError,
  intakeSourceHref,
  newIntakeSourceHref,
  type IntakeSourceRow,
  type JournalingBody,
  type JournalingSettings,
} from './model';

/** The editable journaling part of the settings row (D11 `PUT /journaling/settings`). */
export interface JournalingDraft extends ScopeDraft {
  enabled: boolean;
  directions: { inbound: boolean; outbound: boolean; internal: boolean };
  include: { rejected: boolean; quarantined: boolean; failed: boolean };
  policyArchive: boolean;
  intakeScan: boolean;
}

export function journalingDraftOf(settings: JournalingSettings): JournalingDraft {
  const s = settings.settings;
  return {
    enabled: settings.enabled,
    directions: { ...s.directions },
    include: { ...s.include },
    scopeMode: s.scope.mode,
    domainIds: [...s.scope.domainIds],
    departmentIds: [...s.scope.departmentIds],
    userIds: [...s.scope.userIds],
    addresses: [...s.scope.addresses],
    policyArchive: s.policyArchive.enabled,
    intakeScan: s.intake.scanEnabled,
  };
}

/** The `PUT /journaling/settings` body: every journaling section, CAS on the shared row. */
export function journalingBody(draft: JournalingDraft, expectedRowVersion: number): JournalingBody {
  return {
    expectedRowVersion,
    enabled: draft.enabled,
    settings: {
      directions: { ...draft.directions },
      include: { ...draft.include },
      scope: scopeBody(draft),
      policyArchive: { enabled: draft.policyArchive },
      intake: { scanEnabled: draft.intakeScan },
    },
  };
}

export function journalingDraftErrors(draft: JournalingDraft): Record<string, string> {
  const errors: Record<string, string> = {};
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

/**
 * Settings → Journaling (step 8.6 D14): what is captured into the archive, from the gateway
 * and from journal intake sources. Storage and use (retention, lock, keys, access, search,
 * holds, eDiscovery) are the Archive menu.
 */
export function JournalingPanel() {
  const settings = useApiQuery('JournalingController_get_v1');
  const canManage = useCan('JournalingController_update_v1');
  const canStatus = useCan('JournalingController_status_v1');
  const canSources = useCan('IntakeSourcesController_list_v1');
  if (settings.isLoading) return <LoadingState label="Loading the journaling settings" rows={8} />;
  if (settings.error || !settings.data) {
    return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  }
  return (
    <div className="grid gap-4">
      <LayersExplainer />
      {!settings.data.entitled ? (
        <Notice tone="warning">
          <span>
            Archiving is not part of your organization’s plan (feature “archiving”). Journaling can
            be prepared but not enabled until your platform operator enables it.
          </span>
        </Notice>
      ) : null}
      {canStatus ? <JournalingStatusCard /> : null}
      {canManage ? (
        <JournalingForm settings={settings.data} onReload={() => void settings.refetch()} />
      ) : (
        <JournalingView settings={settings.data} />
      )}
      {canSources ? <IntakeSourcesSection settings={settings.data} /> : null}
    </div>
  );
}

/** The two-layer explainer: Journaling captures, the Archive keeps (D14). */
function LayersExplainer() {
  const canArchive = useCan('ArchiveRetentionController_list_v1');
  return (
    <section
      aria-labelledby="journaling-layers-title"
      className="grid gap-3 rounded-lg border bg-card p-4"
    >
      <h2 id="journaling-layers-title" className="text-base font-semibold">
        Journaling and the archive
      </h2>
      <ol className="grid gap-3 md:grid-cols-[1fr_auto_1fr] md:items-stretch">
        <li className="grid content-start gap-1 rounded-md border p-3">
          <span className="flex items-center gap-2 font-medium">
            <CableIcon className="size-4" aria-hidden />
            1. Journaling (this page)
          </span>
          <span className="text-sm text-muted-foreground">
            Decides what is captured: mail that flows through the gateway, and copies your own mail
            system sends to a journal intake address (Microsoft 365 journaling, Google Workspace,
            on-premises Exchange or any SMTP server). Managed by IT and mail administrators.
          </span>
        </li>
        <li aria-hidden className="hidden items-center justify-center md:flex">
          <ArrowRightIcon className="size-5 text-muted-foreground" />
        </li>
        <li className="grid content-start gap-1 rounded-md border p-3">
          <span className="flex items-center gap-2 font-medium">
            <ArchiveIcon className="size-4" aria-hidden />
            2. Archive
          </span>
          <span className="text-sm text-muted-foreground">
            Keeps what was captured, encrypted and locked: retention, immutability, keys, access,
            search, legal holds and eDiscovery. Used by compliance officers; reading archived mail
            needs an explicitly assigned archive role.
          </span>
          {canArchive ? (
            <Link
              href={retentionHref('immutability')}
              className="text-sm text-primary underline underline-offset-2"
            >
              Archive → Retention and lock
            </Link>
          ) : null}
        </li>
      </ol>
    </section>
  );
}

function JournalingStatusCard() {
  const status = useApiQuery('JournalingController_status_v1', undefined, {
    refetchOnWindowFocus: false,
  });
  if (status.isLoading) return <LoadingState label="Loading the journaling status" rows={2} />;
  if (status.error || !status.data) {
    return <ErrorState error={status.error} onRetry={() => void status.refetch()} compact />;
  }
  const s = status.data;
  const health = Object.entries(s.sources.byHealth)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `${formatNumber(n)} ${humanize(k).toLowerCase()}`)
    .join(' · ');
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
          { label: 'Journaling', value: s.settings.enabled ? 'Enabled' : 'Disabled' },
          {
            label: 'Capture',
            value: `${formatNumber(s.capture.pending)} pending · ${formatNumber(s.capture.failed)} failed · ${formatNumber(s.capture.lost)} lost`,
          },
          {
            label: 'Intake sources',
            value: `${formatNumber(s.sources.total)}${health ? ` (${health})` : ''}`,
          },
          {
            label: 'Intake today',
            value: `${formatNumber(s.intakeToday.accepted)} accepted · ${formatNumber(s.intakeToday.refused)} refused · ${formatNumber(s.intakeToday.droppedProof)} dropped · ${formatBytes(s.intakeToday.bytes)}`,
          },
        ]}
      />
    </Section>
  );
}

function directionsText(d: JournalingDraft): string {
  return (
    ARCHIVE_DIRECTIONS.filter((k) => d.directions[k])
      .map(humanize)
      .join(', ') || 'None'
  );
}

function JournalingView({ settings }: { settings: JournalingSettings }) {
  const d = journalingDraftOf(settings);
  return (
    <Section
      title="What is journaled"
      description="Read only: changing journaling needs the journal:manage permission."
    >
      <DetailList
        items={[
          { label: 'Journaling', value: d.enabled ? 'Enabled' : 'Disabled' },
          {
            label: 'Journaled since',
            value: (
              <DateTime value={settings.journalEnabledAt} mode="absolute" emptyLabel="Never" />
            ),
          },
          { label: 'Directions', value: directionsText(d) },
          {
            label: 'Also journaled',
            value:
              (['rejected', 'quarantined', 'failed'] as const)
                .filter((k) => d.include[k])
                .map(humanize)
                .join(', ') || 'Delivered mail only',
          },
          { label: 'Scope', value: humanize(d.scopeMode) },
          { label: 'Policy ARCHIVE action', value: d.policyArchive ? 'Honoured' : 'Ignored' },
          { label: 'Scan journal intake copies', value: d.intakeScan ? 'On' : 'Off' },
        ]}
      />
    </Section>
  );
}

function JournalingForm({
  settings,
  onReload,
}: {
  settings: JournalingSettings;
  onReload: () => void;
}) {
  const [draft, setDraft] = useState<JournalingDraft>(() => journalingDraftOf(settings));
  const [base, setBase] = useState(settings);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [conflict, setConflict] = useState<number | null>(null);
  const update = useApiMutation('JournalingController_update_v1', {
    successMessage: 'Journaling settings saved',
    invalidates: [
      'JournalingController_get_v1',
      'JournalingController_status_v1',
      'ArchiveAdminController_get_v1',
    ],
  });
  useEffect(() => {
    if (settings.rowVersion !== base.rowVersion) {
      setBase(settings);
      setDraft(journalingDraftOf(settings));
      setErrors({});
    }
  }, [settings, base.rowVersion]);
  const set = (patch: Partial<JournalingDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const dirty = JSON.stringify(draft) !== JSON.stringify(journalingDraftOf(base));

  const save = async (rowVersion: number) => {
    const outcome = await update.submit({ body: journalingBody(draft, rowVersion) });
    if (outcome.ok) {
      setErrors({});
      return;
    }
    const version = conflictVersion(outcome.error);
    if (outcome.error.code === 'archive_settings_conflict' && version !== null) {
      setConflict(version);
      return;
    }
    const field = fieldOfError(outcome.error);
    if (field) {
      setErrors({
        [field === 'defaultRetentionPolicyId' ? 'enabled' : field]: explainJournalingError(
          outcome.error,
        ),
      });
    }
  };
  const submit = async () => {
    const found = journalingDraftErrors(draft);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    await save(base.rowVersion);
  };
  const formError =
    update.error && !fieldOfError(update.error) && update.error.code !== 'archive_settings_conflict'
      ? update.error
      : null;

  return (
    <Section
      title="What is journaled"
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
        aria-label="Journaling settings"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <ArchiveErrorSummary error={formError} />
        {Object.keys(errors).length > 0 ? (
          <FormErrorSummary messages={Object.values(errors)} />
        ) : null}
        <ToggleRow
          id="journal-enabled"
          label="Journal mail of this organization"
          description={
            base.entitled
              ? 'When on, mail is captured into the archive from the moment you save (earlier mail is not captured). Needs a default retention policy, chosen by a compliance officer under Archive → Retention and lock.'
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
              id={`journal-dir-${direction}`}
              label={humanize(direction)}
              checked={draft.directions[direction]}
              onChange={(checked) =>
                set({ directions: { ...draft.directions, [direction]: checked } })
              }
            />
          ))}
        </Fieldset>
        <Fieldset
          legend="Also journal (besides delivered mail)"
          description="Gateway mail only: rejected, quarantined (kept until released or rejected) and failed deliveries. Journal intake copies are always captured."
        >
          {(['rejected', 'quarantined', 'failed'] as const).map((category) => (
            <CheckRow
              key={category}
              id={`journal-include-${category}`}
              label={humanize(category)}
              checked={draft.include[category]}
              onChange={(checked) => set({ include: { ...draft.include, [category]: checked } })}
            />
          ))}
        </Fieldset>
        <ScopeFields draft={draft} set={set} errors={errors} />
        <Fieldset legend="Policy archiving and intake scanning">
          <ToggleRow
            id="journal-policy-action"
            label="Honour the ARCHIVE action of email policies"
            description="Policies can archive a gateway message even when journaling would not (any category)."
            checked={draft.policyArchive}
            onChange={(policyArchive) => set({ policyArchive })}
          />
          <ToggleRow
            id="journal-intake-scan"
            label="Scan journal intake copies"
            description={
              base.intakeEntitled
                ? 'Runs the security engines on copies received through journal intake and links the results to the archived record. Never quarantines, rejects or delivers them. Applies to copies received after you save.'
                : 'Journal intake is not part of your organization’s plan (feature “journal_intake”).'
            }
            checked={draft.intakeScan}
            disabled={!base.intakeEntitled && !draft.intakeScan}
            onChange={(intakeScan) => set({ intakeScan })}
          />
        </Fieldset>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="submit"
            disabled={!dirty || update.isPending || update.retryAfterSeconds > 0}
          >
            <SaveIcon aria-hidden />
            {update.isPending ? 'Saving …' : 'Save journaling settings'}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!dirty || update.isPending}
            onClick={() => {
              setDraft(journalingDraftOf(base));
              setErrors({});
            }}
          >
            Discard changes
          </Button>
        </div>
      </form>
      <ConflictDialog
        open={conflict !== null}
        onOpenChange={(open) => {
          if (!open) setConflict(null);
        }}
        what="journaling settings"
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

function IntakeSourcesSection({ settings }: { settings: JournalingSettings }) {
  const list = useCursorList('IntakeSourcesController_list_v1', { sort: '-id' }, { limit: 25 });
  const canCreate = useCan('IntakeSourcesController_create_v1');
  const columns: DataTableColumn<IntakeSourceRow>[] = [
    {
      id: 'displayName',
      header: 'Source',
      meta: { label: 'Source', hideable: false },
      cell: ({ row }) => (
        <Link
          href={intakeSourceHref(row.original.id)}
          className="font-medium text-primary underline-offset-4 hover:underline"
        >
          <UntrustedText value={row.original.displayName} maxLength={80} />
        </Link>
      ),
    },
    {
      id: 'kind',
      header: 'Kind',
      meta: { label: 'Kind' },
      cell: ({ row }) => INTAKE_KIND_LABEL[row.original.kind],
    },
    {
      id: 'status',
      header: 'Status',
      meta: { label: 'Status' },
      cell: ({ row }) => <IntakeStatusBadge status={row.original.status} />,
    },
    {
      id: 'health',
      header: 'Health',
      meta: { label: 'Health' },
      cell: ({ row }) => <IntakeHealthBadge health={row.original.health.status} />,
    },
    {
      id: 'lastAcceptedAt',
      header: 'Last accepted',
      meta: { label: 'Last accepted' },
      cell: ({ row }) => <DateTime value={row.original.lastAcceptedAt} emptyLabel="Never" />,
    },
  ];
  const unavailable = !settings.intakeAvailable;
  const notEntitled = !settings.intakeEntitled;
  return (
    <Section
      title="Journal intake sources"
      description="Mail systems that send copies of every message to a journal intake address of the gateway, without routing mail through it. Each source has its own secret address; the gateway accepts copies only from that source’s Microsoft 365 or Google tenant, or from the networks you register."
    >
      {unavailable ? (
        <Notice tone="warning">
          <span>
            Journal intake is not configured on this platform (no intake domain). Ask your platform
            operator.
          </span>
        </Notice>
      ) : notEntitled ? (
        <Notice tone="warning">
          <span>
            Journal intake is not part of your organization’s plan (feature “journal_intake”).
          </span>
        </Notice>
      ) : null}
      <DataTable
        tableId="journal-intake-sources"
        caption="Intake source list"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.displayName}
        filters={
          canCreate && !unavailable && !notEntitled ? (
            <Button asChild size="sm">
              <Link href={newIntakeSourceHref()}>
                <PlusIcon aria-hidden />
                Add source
              </Link>
            </Button>
          ) : null
        }
        emptyState={
          <EmptyState
            title="No journal intake sources"
            description="Add a source to archive mail of Microsoft 365, Google Workspace, an on-premises Exchange server or any SMTP server without routing it through the gateway."
          />
        }
      />
    </Section>
  );
}
