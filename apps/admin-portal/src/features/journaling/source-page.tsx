'use client';

import { DownloadIcon, EyeIcon, PauseIcon, PlayIcon, RotateCwIcon, TrashIcon } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useId, useState } from 'react';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { CopyButton } from '@/components/copy-button';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { FormErrorSummary } from '@/components/form';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { SecretRevealDialog } from '@/components/secret-reveal-dialog';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import { useUrlState } from '@/hooks/use-url-state';
import { api, unwrap } from '@/lib/api/client';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatBytes, formatNumber } from '@/lib/format';
import {
  DetailList,
  MutationError,
  QueryView,
  Section,
  isUuid,
  splitList,
} from '@/features/domains/kit';
import {
  INTAKE_KIND_LABEL,
  IntakeHealthBadge,
  IntakeStatusBadge,
  WIZARD_STEP_LABEL,
  WizardStepBadge,
  explainJournalingError,
  journalingHref,
  providerOfKind,
  refusalText,
  type IntakeCounters,
  type IntakeGuide,
  type IntakeSource,
} from './model';

export const SOURCE_TABS = ['setup', 'guide', 'address', 'health', 'settings'] as const;
type Tab = (typeof SOURCE_TABS)[number];

const TAB_LABEL: Record<Tab, string> = {
  setup: 'Setup',
  guide: 'Setup guide',
  address: 'Intake address',
  health: 'Health',
  settings: 'Settings',
};

const URL_SHAPE = { tab: z.enum(SOURCE_TABS).optional().catch(undefined) };

/** Queries refreshed after any change of a source. */
export const SOURCE_QUERIES = [
  'IntakeSourcesController_get_v1',
  'IntakeSourcesController_list_v1',
  'IntakeSourcesController_wizard_v1',
  'IntakeSourcesController_guide_v1',
  'JournalingController_status_v1',
] as const;

/** `/settings/journaling/intake/[sourceId]` (`?tab=setup|guide|address|health|settings`, D14). */
export function IntakeSourcePage({ sourceId }: { sourceId: string }) {
  return (
    <RouteGate gate={['IntakeSourcesController_get_v1']}>
      <SourceLoader sourceId={sourceId} />
    </RouteGate>
  );
}

function SourceLoader({ sourceId }: { sourceId: string }) {
  const valid = isUuid(sourceId);
  const source = useApiQuery(
    'IntakeSourcesController_get_v1',
    { path: { sourceId } },
    {
      enabled: valid,
      retry: false,
      // Waiting for the first message: poll so the activation shows up without a reload.
      refetchInterval: (query) =>
        query.state.data?.status === 'pending_verification' ? 15_000 : false,
    },
  );
  if (!valid) return <NotFoundView />;
  return (
    <QueryView query={source} label="intake source">
      {(data) => <SourceContent source={data} />}
    </QueryView>
  );
}

function SourceContent({ source }: { source: IntakeSource }) {
  const [state, setState] = useUrlState(URL_SHAPE);
  const tab = state.tab ?? (source.status === 'active' ? 'health' : 'setup');
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title={source.displayName}
        breadcrumbs={[
          { label: 'Settings', href: '/settings' },
          { label: 'Journaling', href: journalingHref },
          { label: source.displayName },
        ]}
        description={
          <span className="inline-flex flex-wrap items-center gap-2">
            <span>{INTAKE_KIND_LABEL[source.kind]}</span>
            <IntakeStatusBadge status={source.status} />
            <IntakeHealthBadge health={source.health.status} />
            <span className="text-muted-foreground">
              Last copy accepted <DateTime value={source.lastAcceptedAt} emptyLabel="never" />
            </span>
          </span>
        }
      />
      {source.status === 'disabled' ? (
        <p role="status" className="rounded-md border p-3 text-sm">
          This source is disabled: its address refuses every copy. Its history stays visible; add a
          new source to start again.
        </p>
      ) : null}
      <Tabs value={tab} onValueChange={(value) => setState({ tab: value as Tab }, { push: true })}>
        <div className="overflow-x-auto">
          <TabsList aria-label="Intake source sections">
            {SOURCE_TABS.map((value) => (
              <TabsTrigger key={value} value={value}>
                {TAB_LABEL[value]}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <TabsContent value="setup" className="min-w-0">
          {tab === 'setup' ? <SetupTab source={source} /> : null}
        </TabsContent>
        <TabsContent value="guide" className="min-w-0">
          {tab === 'guide' ? <GuideTab source={source} /> : null}
        </TabsContent>
        <TabsContent value="address" className="min-w-0">
          {tab === 'address' ? <AddressTab source={source} /> : null}
        </TabsContent>
        <TabsContent value="health" className="min-w-0">
          {tab === 'health' ? <HealthTab source={source} /> : null}
        </TabsContent>
        <TabsContent value="settings" className="min-w-0">
          {tab === 'settings' ? <SettingsTab source={source} /> : null}
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ---- setup -----------------------------------------------------------------------------------

function SetupTab({ source }: { source: IntakeSource }) {
  const wizard = useApiQuery('IntakeSourcesController_wizard_v1', {
    path: { sourceId: source.id },
  });
  const guide = useApiQuery('IntakeSourcesController_guide_v1', {
    path: { sourceId: source.id },
    query: { format: 'json' },
  });
  return (
    <div className="grid gap-4">
      <QueryView query={wizard} label="setup steps" notFound="inline">
        {(data) => (
          <Section
            title="Setup steps"
            description={
              data.nextAction ? (
                <span>
                  Next: {WIZARD_STEP_LABEL[data.nextAction.step]} — {data.nextAction.action}
                </span>
              ) : (
                'Every step is done.'
              )
            }
          >
            <ol className="grid gap-2">
              {data.steps.map((step) => (
                <li
                  key={step.step}
                  className="grid gap-1 rounded-md border p-3 text-sm sm:grid-cols-[minmax(12rem,auto)_auto_1fr] sm:items-start sm:gap-3"
                >
                  <span className="font-medium">{WIZARD_STEP_LABEL[step.step]}</span>
                  <WizardStepBadge status={step.status} />
                  <span className="text-muted-foreground">
                    {step.blockers.length > 0 ? step.blockers.join(' · ') : null}
                  </span>
                </li>
              ))}
            </ol>
            {data.steps.some((s) => s.step === 'connection' && s.status !== 'skipped') &&
            source.providerConnectionId ? (
              <Link
                href={`/integrations/providers/${source.providerConnectionId}`}
                className="text-sm text-primary underline underline-offset-2"
              >
                Open the provider connection
              </Link>
            ) : null}
          </Section>
        )}
      </QueryView>
      <QueryView query={guide} label="statements" notFound="inline">
        {(data) => <Attestations source={source} guide={data} />}
      </QueryView>
    </div>
  );
}

function Attestations({ source, guide }: { source: IntakeSource; guide: IntakeGuide }) {
  const canRecord = useCan('IntakeSourcesController_attest_v1');
  const record = useApiMutation('IntakeSourcesController_attest_v1', {
    invalidates: SOURCE_QUERIES,
    successMessage: 'Statement recorded.',
  });
  if (guide.attestations.length === 0) return null;
  const disabled = !canRecord || record.isPending || source.status === 'disabled';
  return (
    <Section
      title="Your statements"
      description="Customer-side steps the gateway cannot check (it never changes your mail system). Recording one is audited."
    >
      <fieldset className="grid gap-2">
        <legend className="sr-only">Statements about your mail system</legend>
        {guide.attestations.map((a) => {
          const id = `intake-attest-${a.code}`;
          return (
            <div key={a.code} className="flex items-start gap-2 text-sm">
              <Checkbox
                id={id}
                checked={a.attested}
                disabled={disabled}
                onCheckedChange={(checked) =>
                  void record.submit({
                    path: { sourceId: source.id },
                    body: { code: a.code, attested: checked === true },
                  })
                }
              />
              <label htmlFor={id} className="grid gap-0.5 leading-snug">
                <span>{a.statement}</span>
                <span className="text-xs text-muted-foreground">
                  {a.attested ? (
                    <>
                      Stated <DateTime value={a.attestedAt} /> (your statement, not a gateway check)
                    </>
                  ) : (
                    'Not stated yet'
                  )}
                </span>
              </label>
            </div>
          );
        })}
      </fieldset>
      <MutationError error={record.error} />
    </Section>
  );
}

// ---- guide -----------------------------------------------------------------------------------

/** `journal-intake-<kind>-<slug>.md`, used when the api names no file. */
export function intakeGuideFileName(source: Pick<IntakeSource, 'kind' | 'displayName'>): string {
  const slug =
    source.displayName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'source';
  return `journal-intake-${source.kind.replace(/_/g, '-')}-${slug}.md`;
}

/** GET …/setup-guide?format=markdown through the BFF, saved as a file (never stored). */
export async function downloadIntakeGuide(source: IntakeSource): Promise<void> {
  let disposition: string | null = null;
  const text = await unwrap(
    api
      .GET('/api/v1/journaling/intake-sources/{sourceId}/setup-guide', {
        params: { path: { sourceId: source.id }, query: { format: 'markdown' } },
        parseAs: 'text',
      })
      .then((result) => {
        disposition = result.response.headers.get('content-disposition');
        return result;
      }),
    'IntakeSourcesController_guide_v1',
  );
  const match = (disposition as string | null)?.match(/filename="?([A-Za-z0-9._-]+)"?/);
  const blob = new Blob([String(text)], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = match?.[1] ?? intakeGuideFileName(source);
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

type GuideStep = IntakeGuide['sections'][number]['steps'][number];

function GuideStepView({ step }: { step: GuideStep }) {
  return (
    <li id={step.id} className="grid scroll-mt-20 gap-2 rounded-md border p-3">
      <h4 className="font-medium">{step.title}</h4>
      {step.paragraphs.map((p) => (
        <p key={p} className="text-sm">
          {p}
        </p>
      ))}
      {step.values?.length ? (
        <dl className="grid gap-1 text-sm sm:grid-cols-[minmax(8rem,auto)_1fr]">
          {step.values.map((v) => (
            <div key={`${v.label}:${v.value}`} className="contents">
              <dt className="text-xs font-medium text-muted-foreground sm:pt-1">{v.label}</dt>
              <dd className="inline-flex min-w-0 items-center gap-1 font-mono text-xs break-all">
                {v.value}
                <CopyButton value={v.value} label={`Copy ${v.label}`} />
              </dd>
            </div>
          ))}
        </dl>
      ) : null}
      {step.commands?.map((c) => (
        <div key={c.code} className="relative min-w-0">
          <pre
            // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- scrollable region
            tabIndex={0}
            className="overflow-x-auto rounded-md bg-muted p-3 pr-10 font-mono text-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            aria-label={`${c.language} commands`}
          >
            <code>{c.code}</code>
          </pre>
          <CopyButton
            value={c.code}
            label={`Copy the ${c.language === 'powershell' ? 'PowerShell' : c.language} commands of “${step.title}”`}
            className="absolute top-1 right-1"
          />
        </div>
      ))}
      {step.warning ? (
        <p className="rounded-md bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground">
          {step.warning}
        </p>
      ) : null}
      {step.attestation ? (
        <p className="flex flex-wrap items-center gap-2 text-xs">
          <ToneBadge tone={step.attestation.attested ? 'success' : 'neutral'}>
            {step.attestation.attested ? 'Stated' : 'Not stated yet'}
          </ToneBadge>
          <span>{step.attestation.statement}</span>
        </p>
      ) : null}
    </li>
  );
}

function GuideTab({ source }: { source: IntakeSource }) {
  const guide = useApiQuery('IntakeSourcesController_guide_v1', {
    path: { sourceId: source.id },
    query: { format: 'json' },
  });
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  return (
    <QueryView query={guide} label="setup guide" notFound="inline">
      {(data) => (
        <Section
          title={`Setup guide: ${INTAKE_KIND_LABEL[data.kind]}`}
          description={
            <span>
              Written for this source; generated <DateTime value={data.generatedAt} />. The gateway
              never applies these changes: you make them in your own mail system.
            </span>
          }
          actions={
            <Button
              variant="outline"
              size="sm"
              disabled={downloading}
              onClick={() => {
                setDownloading(true);
                setError(null);
                downloadIntakeGuide(source)
                  .catch((e: unknown) => setError(e as ApiError))
                  .finally(() => setDownloading(false));
              }}
            >
              <DownloadIcon aria-hidden />
              Download Markdown
            </Button>
          }
        >
          <MutationError error={error} />
          <p className="text-sm">{data.notice}</p>
          {!data.revealed ? (
            <p className="text-sm text-muted-foreground">
              The intake address is masked in this guide: users with journal:manage see it in full
              (audited).
            </p>
          ) : null}
          <nav aria-label="Guide sections">
            <ol className="grid list-decimal gap-1 pl-5 text-sm">
              {data.sections.map((s) => (
                <li key={s.id}>
                  <a href={`#${s.id}`} className="underline-offset-4 hover:underline">
                    {s.title}
                  </a>
                </li>
              ))}
            </ol>
          </nav>
          {data.sections.map((section) => (
            <section
              key={section.id}
              id={section.id}
              aria-labelledby={`${section.id}-title`}
              className="grid scroll-mt-20 gap-3"
            >
              <h3 id={`${section.id}-title`} className="text-base font-semibold">
                {section.number}. {section.title}
              </h3>
              {section.paragraphs.map((p) => (
                <p key={p} className="text-sm">
                  {p}
                </p>
              ))}
              {section.steps.length > 0 ? (
                <ol className="grid gap-3">
                  {section.steps.map((step) => (
                    <GuideStepView key={step.id} step={step} />
                  ))}
                </ol>
              ) : null}
            </section>
          ))}
        </Section>
      )}
    </QueryView>
  );
}

// ---- address ---------------------------------------------------------------------------------

function AddressTab({ source }: { source: IntakeSource }) {
  const canManage = useCan('IntakeSourcesController_rotate_v1');
  const [reveal, setReveal] = useState(false);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const revealed = useApiQuery(
    'IntakeSourcesController_get_v1',
    { path: { sourceId: source.id }, query: { reveal: 'true' } },
    { enabled: reveal, staleTime: 0, gcTime: 0, retry: false },
  );
  const rotate = useApiMutation('IntakeSourcesController_rotate_v1', {
    invalidates: SOURCE_QUERIES,
    successMessage: null,
  });
  const google = source.kind === 'google_workspace_copy';
  const shown = reveal && revealed.data ? revealed.data : source;
  const rotated = rotate.data;
  return (
    <Section
      title="Intake address"
      description="The secret address your mail system sends copies to. Treat it like a password: anyone who knows it and sends from your tenant or networks can add copies to your archive."
      actions={
        canManage && source.status !== 'disabled' ? (
          <div className="flex flex-wrap gap-2">
            {!reveal ? (
              <Button variant="outline" size="sm" onClick={() => setReveal(true)}>
                <EyeIcon aria-hidden />
                Reveal
              </Button>
            ) : null}
            <Button variant="outline" size="sm" onClick={() => setConfirmRotate(true)}>
              <RotateCwIcon aria-hidden />
              Rotate address
            </Button>
          </div>
        ) : null
      }
    >
      <DetailList
        items={[
          {
            label: 'Address',
            value: shown.address ? (
              <span className="inline-flex min-w-0 items-center gap-1 font-mono text-xs break-all">
                {shown.address}
                {shown.revealed ? (
                  <CopyButton value={shown.address} label="Copy the address" />
                ) : null}
              </span>
            ) : (
              '—'
            ),
          },
          ...(google
            ? [
                {
                  label: 'X-EG-Journal-Token',
                  value: shown.headerToken ? (
                    <span className="inline-flex min-w-0 items-center gap-1 font-mono text-xs break-all">
                      {shown.headerToken}
                      {shown.revealed ? (
                        <CopyButton value={shown.headerToken} label="Copy the header token" />
                      ) : null}
                    </span>
                  ) : (
                    '—'
                  ),
                },
              ]
            : []),
          { label: 'Address version', value: String(source.addressVersion) },
          {
            label: 'Previous address accepted until',
            value: (
              <DateTime
                value={source.previousAddressValidUntil}
                mode="absolute"
                emptyLabel="No previous address"
              />
            ),
          },
        ]}
      />
      {reveal && revealed.error ? <MutationError error={revealed.error} /> : null}
      {reveal && shown.revealed ? (
        <p className="text-xs text-muted-foreground">Revealed (recorded in the audit log).</p>
      ) : null}
      {!canManage ? (
        <p className="text-sm text-muted-foreground">
          The address is masked: revealing or rotating it needs the journal:manage permission.
        </p>
      ) : null}
      <ConfirmDialog
        open={confirmRotate}
        onOpenChange={setConfirmRotate}
        title="Rotate the intake address?"
        description={
          <p>
            A new address{google ? ' and header token' : ''} replaces the current one. The current
            address keeps working for the overlap period (7 days by default) so you can update your
            mail system. Rotation needs a session signed in with MFA and is audited.
          </p>
        }
        confirmLabel="Rotate address"
        pending={rotate.isPending}
        error={rotate.error ? explainJournalingError(rotate.error) : undefined}
        onConfirm={async () => {
          const outcome = await rotate.submit({ path: { sourceId: source.id } });
          if (outcome.ok) setConfirmRotate(false);
        }}
      />
      <SecretRevealDialog
        open={Boolean(rotated)}
        title="New intake address"
        description="Update your mail system with the new address. It is shown in full only now; the previous one stops working when the overlap period ends."
        secrets={[
          ...(rotated?.address ? [{ label: 'Intake address', value: rotated.address }] : []),
          ...(rotated?.headerToken
            ? [{ label: 'X-EG-Journal-Token header value', value: rotated.headerToken }]
            : []),
        ]}
        acknowledgement="I have updated my mail system or stored the new address in a safe place."
        onClose={() => rotate.reset()}
      />
    </Section>
  );
}

// ---- health ----------------------------------------------------------------------------------

const COUNTER_COLUMNS: readonly { key: keyof IntakeCounters; label: string }[] = [
  { key: 'accepted', label: 'Accepted' },
  { key: 'duplicates', label: 'Duplicates' },
  { key: 'droppedProof', label: 'Dropped (proof)' },
  { key: 'refusedAddress', label: 'Refused: address' },
  { key: 'refusedNetwork', label: 'Refused: sender' },
  { key: 'refusedTls', label: 'Refused: TLS' },
  { key: 'refusedSize', label: 'Refused: size' },
  { key: 'refusedRate', label: 'Refused: rate' },
  { key: 'refusedUnavailable', label: 'Refused: paused' },
  { key: 'unwrapFailed', label: 'Unrecognized reports' },
];

function HealthTab({ source }: { source: IntakeSource }) {
  return (
    <div className="grid gap-4">
      <Section title="Health">
        <DetailList
          items={[
            { label: 'Health', value: <IntakeHealthBadge health={source.health.status} /> },
            {
              label: 'Health changed',
              value: <DateTime value={source.health.changedAt} emptyLabel="—" />,
            },
            {
              label: 'Verified (first accepted copy)',
              value: <DateTime value={source.verifiedAt} emptyLabel="Not yet" />,
            },
            {
              label: 'Last accepted',
              value: <DateTime value={source.lastAcceptedAt} emptyLabel="Never" />,
            },
            {
              label: 'Last refused or dropped',
              value: source.lastRefusedAt ? (
                <span>
                  <DateTime value={source.lastRefusedAt} />: {refusalText(source.lastRefusalCode)}
                </span>
              ) : (
                'Never'
              ),
            },
            {
              label: 'Silence alert',
              value:
                source.silenceAlertMinutes === null
                  ? 'Off'
                  : `After ${source.silenceAlertMinutes} minutes without a copy`,
            },
          ]}
        />
      </Section>
      <Section
        title="Last 7 days"
        description="Counted by the gateway per day (UTC). Refusals are answered to your mail system in the SMTP session; copies failing the tenant or token proof are accepted and dropped, never bounced."
      >
        {source.counters.length === 0 ? (
          <p className="text-sm text-muted-foreground">No copies in the last 7 days.</p>
        ) : (
          <div
            className="overflow-x-auto rounded-md border"
            // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- scrollable region
            tabIndex={0}
            role="region"
            aria-label="Daily counters"
          >
            <table className="w-full text-sm">
              <caption className="sr-only">Daily intake counters</caption>
              <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
                <tr>
                  <th scope="col" className="px-3 py-2">
                    Day
                  </th>
                  {COUNTER_COLUMNS.map((c) => (
                    <th key={c.key} scope="col" className="px-3 py-2 text-right">
                      {c.label}
                    </th>
                  ))}
                  <th scope="col" className="px-3 py-2 text-right">
                    Size
                  </th>
                </tr>
              </thead>
              <tbody>
                {source.counters.map((day) => (
                  <tr key={day.day} className="border-t">
                    <th scope="row" className="px-3 py-2 text-left font-mono text-xs font-normal">
                      {day.day}
                    </th>
                    {COUNTER_COLUMNS.map((c) => (
                      <td key={c.key} className="px-3 py-2 text-right tabular-nums">
                        {formatNumber(day[c.key] as number)}
                      </td>
                    ))}
                    <td className="px-3 py-2 text-right tabular-nums">{formatBytes(day.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}

// ---- settings --------------------------------------------------------------------------------

function SettingsTab({ source }: { source: IntakeSource }) {
  const canManage = useCan('IntakeSourcesController_update_v1');
  const id = useId();
  const network = providerOfKind(source.kind) === null;
  const [name, setName] = useState(source.displayName);
  const [networks, setNetworks] = useState((source.networks ?? []).join('\n'));
  const [requireTls, setRequireTls] = useState(source.requireTls);
  const [silence, setSilence] = useState(source.silenceAlertMinutes !== null);
  const [minutes, setMinutes] = useState(String(source.silenceAlertMinutes ?? 240));
  const [confirm, setConfirm] = useState<'pause' | 'resume' | 'disable' | null>(null);
  useEffect(() => {
    setName(source.displayName);
    setNetworks((source.networks ?? []).join('\n'));
    setRequireTls(source.requireTls);
    setSilence(source.silenceAlertMinutes !== null);
    setMinutes(String(source.silenceAlertMinutes ?? 240));
  }, [source]);
  const update = useApiMutation('IntakeSourcesController_update_v1', {
    invalidates: SOURCE_QUERIES,
    successMessage: 'Intake source saved.',
  });
  const disable = useApiMutation('IntakeSourcesController_disable_v1', {
    invalidates: SOURCE_QUERIES,
    successMessage: 'Intake source disabled.',
  });
  const disabled = source.status === 'disabled';
  const silenceMinutes = Number(minutes);
  const silenceInvalid =
    silence && (!Number.isInteger(silenceMinutes) || silenceMinutes < 5 || silenceMinutes > 10_080);

  if (!canManage) {
    return (
      <Section
        title="Settings"
        description="Changing a source needs the journal:manage permission."
      >
        <DetailList
          items={[
            { label: 'Name', value: source.displayName },
            ...(network
              ? [
                  { label: 'Networks', value: (source.networks ?? []).join(', ') || '—' },
                  { label: 'TLS', value: source.requireTls ? 'Required' : 'Optional' },
                ]
              : []),
          ]}
        />
      </Section>
    );
  }
  return (
    <div className="grid gap-4">
      <Section
        title="Settings"
        description="Saving needs a session signed in with MFA and is recorded in the audit log."
      >
        <form
          className="grid max-w-2xl gap-4"
          aria-label="Intake source settings"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            if (silenceInvalid) return;
            void update.submit({
              path: { sourceId: source.id },
              body: {
                expectedRowVersion: source.rowVersion,
                displayName: name.trim(),
                ...(network ? { networks: splitList(networks), requireTls } : {}),
                silenceAlertMinutes: silence ? silenceMinutes : null,
              },
            });
          }}
        >
          {update.error ? (
            <FormErrorSummary
              messages={[explainJournalingError(update.error), `Code: ${update.error.code}`]}
              requestId={update.error.requestId}
            />
          ) : null}
          <div className="grid gap-1">
            <Label htmlFor={`${id}-name`}>Name</Label>
            <Input
              id={`${id}-name`}
              value={name}
              disabled={disabled}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          {network ? (
            <>
              <div className="grid gap-1">
                <Label htmlFor={`${id}-networks`}>Sending networks (one CIDR per line)</Label>
                <Textarea
                  id={`${id}-networks`}
                  rows={4}
                  value={networks}
                  disabled={disabled}
                  onChange={(e) => setNetworks(e.target.value)}
                />
              </div>
              <div className="flex items-center gap-3">
                <Switch
                  id={`${id}-tls`}
                  checked={requireTls}
                  disabled={disabled}
                  onCheckedChange={setRequireTls}
                />
                <Label htmlFor={`${id}-tls`}>Require TLS</Label>
              </div>
            </>
          ) : null}
          <div className="grid gap-1">
            <div className="flex items-center gap-3">
              <Switch
                id={`${id}-silence`}
                checked={silence}
                disabled={disabled}
                onCheckedChange={setSilence}
              />
              <Label htmlFor={`${id}-silence`}>Alert when the source goes silent</Label>
            </div>
            {silence ? (
              <div className="grid max-w-xs gap-1">
                <Label htmlFor={`${id}-minutes`}>Silent after (minutes, 5–10 080)</Label>
                <Input
                  id={`${id}-minutes`}
                  inputMode="numeric"
                  value={minutes}
                  disabled={disabled}
                  aria-invalid={silenceInvalid ? true : undefined}
                  onChange={(e) => setMinutes(e.target.value)}
                />
              </div>
            ) : null}
          </div>
          <div>
            <Button type="submit" disabled={disabled || update.isPending || silenceInvalid}>
              {update.isPending ? 'Saving …' : 'Save'}
            </Button>
          </div>
        </form>
      </Section>
      {!disabled ? (
        <Section
          title="Pause or disable"
          description="Pausing makes your mail system retry later (Microsoft 365 and Exchange retry for up to two days); disabling refuses every copy and cannot be undone."
        >
          <div className="flex flex-wrap gap-2">
            {source.status === 'paused' ? (
              <Button variant="outline" onClick={() => setConfirm('resume')}>
                <PlayIcon aria-hidden />
                Resume intake
              </Button>
            ) : (
              <Button variant="outline" onClick={() => setConfirm('pause')}>
                <PauseIcon aria-hidden />
                Pause intake
              </Button>
            )}
            <Button variant="destructive" onClick={() => setConfirm('disable')}>
              <TrashIcon aria-hidden />
              Disable source
            </Button>
          </div>
          <MutationError error={disable.error} />
        </Section>
      ) : null}
      <ConfirmDialog
        open={confirm === 'pause' || confirm === 'resume'}
        onOpenChange={(open) => (!open ? setConfirm(null) : undefined)}
        title={confirm === 'resume' ? 'Resume journal intake?' : 'Pause journal intake?'}
        description={
          confirm === 'resume' ? (
            <p>
              Copies are accepted again (the source waits for its first copy if it was never
              verified).
            </p>
          ) : (
            <p>
              Copies are refused with a temporary error (450) so your mail system keeps them and
              retries. Copies that are not retried in time are lost to the archive; the silence
              alert does not fire while paused.
            </p>
          )
        }
        confirmLabel={confirm === 'resume' ? 'Resume' : 'Pause'}
        pending={update.isPending}
        error={update.error ? explainJournalingError(update.error) : undefined}
        onConfirm={async () => {
          const outcome = await update.submit({
            path: { sourceId: source.id },
            body: {
              expectedRowVersion: source.rowVersion,
              status: confirm === 'resume' ? 'active' : 'paused',
            },
          });
          if (outcome.ok) setConfirm(null);
        }}
      />
      <ConfirmDialog
        open={confirm === 'disable'}
        onOpenChange={(open) => (!open ? setConfirm(null) : undefined)}
        title="Disable this intake source?"
        description={
          <p>
            <strong>This cannot be undone.</strong> The address refuses every copy permanently
            (550), so your mail system reports them to its alternate journaling mailbox. Copies
            already archived stay archived.
          </p>
        }
        typedConfirmation="disable"
        confirmLabel="Disable source"
        destructive
        pending={disable.isPending}
        onConfirm={async () => {
          const outcome = await disable.submit({ path: { sourceId: source.id } });
          if (outcome.ok) setConfirm(null);
        }}
      />
    </div>
  );
}
