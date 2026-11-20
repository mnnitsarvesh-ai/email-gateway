'use client';

import { ArrowLeftIcon, ArrowRightIcon, ExternalLinkIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useId, useState } from 'react';
import { z } from 'zod';
import { FormErrorSummary } from '@/components/form';
import { PageHeader } from '@/components/page-header';
import { SecretRevealDialog } from '@/components/secret-reveal-dialog';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useCursorList } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { DetailList, Section } from '@/features/messages/controls';
import { splitList } from '@/features/domains/kit';
import {
  INTAKE_KINDS,
  INTAKE_KIND_DESCRIPTION,
  INTAKE_KIND_LABEL,
  explainJournalingError,
  intakeSourceHref,
  journalingHref,
  providerOfKind,
  type IntakeCreateBody,
  type IntakeKind,
} from './model';

const URL_SHAPE = {
  kind: z
    .enum(INTAKE_KINDS as [IntakeKind, ...IntakeKind[]])
    .optional()
    .catch(undefined),
};

export const WIZARD_STEPS = ['kind', 'sender', 'details', 'review'] as const;
type WizardStep = (typeof WIZARD_STEPS)[number];

const STEP_LABEL: Record<WizardStep, string> = {
  kind: 'Source kind',
  sender: 'Sender',
  details: 'Name and alerts',
  review: 'Review',
};

/** The wizard's draft (D14 intake create). */
export interface IntakeDraft {
  kind: IntakeKind;
  providerConnectionId: string;
  networks: string;
  requireTls: boolean;
  fingerprints: string;
  displayName: string;
  silenceAlert: boolean;
  silenceAlertMinutes: string;
  maxMessageMiB: string;
}

export const EMPTY_DRAFT: IntakeDraft = {
  kind: 'microsoft_365_journal',
  providerConnectionId: '',
  networks: '',
  requireTls: true,
  fingerprints: '',
  displayName: '',
  silenceAlert: true,
  silenceAlertMinutes: '240',
  maxMessageMiB: '',
};

const CIDR4 = /^(\d{1,3})(\.\d{1,3}){3}\/(\d{1,2})$/;
const CIDR6 = /^[0-9a-f:]+\/(\d{1,3})$/i;
const FINGERPRINT = /^([0-9a-f]{2}:?){31}[0-9a-f]{2}$/i;

/** Client-side checks of one wizard step (`field → message`); the api re-validates everything. */
export function intakeStepErrors(step: WizardStep, draft: IntakeDraft): Record<string, string> {
  const errors: Record<string, string> = {};
  const provider = providerOfKind(draft.kind);
  if (step === 'sender' || step === 'review') {
    if (provider && !draft.providerConnectionId) {
      errors.providerConnectionId = 'Choose the connection of your tenant.';
    }
    if (!provider) {
      const cidrs = splitList(draft.networks);
      if (cidrs.length === 0) errors.networks = 'Enter at least one network (CIDR).';
      else if (cidrs.length > 32) errors.networks = 'At most 32 networks.';
      else {
        const bad = cidrs.filter((c) => !CIDR4.test(c) && !CIDR6.test(c));
        if (bad.length > 0) errors.networks = `Not a CIDR range: ${bad.slice(0, 3).join(', ')}`;
      }
      const prints = splitList(draft.fingerprints);
      if (prints.length > 4) errors.fingerprints = 'At most 4 certificate fingerprints.';
      else if (prints.some((p) => !FINGERPRINT.test(p))) {
        errors.fingerprints = 'Each fingerprint is a SHA-256 in hex (64 digits, colons allowed).';
      }
    }
  }
  if (step === 'details' || step === 'review') {
    const name = draft.displayName.trim();
    if (!name) errors.displayName = 'Enter a name';
    else if (name.length > 128) errors.displayName = 'At most 128 characters';
    if (draft.silenceAlert) {
      const minutes = Number(draft.silenceAlertMinutes);
      if (!Number.isInteger(minutes) || minutes < 5 || minutes > 10_080) {
        errors.silenceAlertMinutes = 'Enter whole minutes between 5 and 10 080 (7 days).';
      }
    }
    if (draft.maxMessageMiB.trim()) {
      const mib = Number(draft.maxMessageMiB);
      if (!Number.isInteger(mib) || mib < 1 || mib > 150) {
        errors.maxMessageMiB = 'Enter whole MiB between 1 and 150, or leave empty.';
      }
    }
  }
  return errors;
}

/** The `POST /journaling/intake-sources` body of a draft. */
export function intakeCreateBody(draft: IntakeDraft): IntakeCreateBody {
  const provider = providerOfKind(draft.kind);
  const prints = splitList(draft.fingerprints);
  return {
    kind: draft.kind,
    displayName: draft.displayName.trim(),
    ...(provider
      ? { providerConnectionId: draft.providerConnectionId }
      : {
          networks: splitList(draft.networks),
          requireTls: draft.requireTls,
          ...(prints.length > 0 ? { clientCertFingerprints: prints } : {}),
        }),
    silenceAlertMinutes: draft.silenceAlert ? Number(draft.silenceAlertMinutes) : null,
    ...(draft.maxMessageMiB.trim()
      ? { maxMessageBytes: Number(draft.maxMessageMiB) * 1_048_576 }
      : {}),
  };
}

/** `/settings/journaling/intake/new`: kind → sender → name → review → created (D14). */
export function NewIntakeSourcePage() {
  return (
    <RouteGate gate={['IntakeSourcesController_create_v1']}>
      <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
        <PageHeader
          title="Add a journal intake source"
          breadcrumbs={[
            { label: 'Settings', href: '/settings' },
            { label: 'Journaling', href: journalingHref },
            { label: 'New intake source' },
          ]}
          description="Your mail system sends a copy of every message to a secret intake address of the gateway; the gateway archives it and never delivers, bounces or forwards it. Nothing changes in your mail flow or MX records."
        />
        <IntakeWizard />
      </div>
    </RouteGate>
  );
}

function IntakeWizard() {
  const router = useRouter();
  const [{ kind: preset }] = useUrlState(URL_SHAPE);
  const [draft, setDraft] = useState<IntakeDraft>({
    ...EMPTY_DRAFT,
    kind: preset ?? 'microsoft_365_journal',
  });
  const [step, setStep] = useState<WizardStep>(preset ? 'sender' : 'kind');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const create = useApiMutation('IntakeSourcesController_create_v1', {
    invalidates: ['IntakeSourcesController_list_v1', 'JournalingController_status_v1'],
    successMessage: 'Intake source created.',
  });
  const set = (patch: Partial<IntakeDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const index = WIZARD_STEPS.indexOf(step);
  const next = () => {
    const found = intakeStepErrors(step, draft);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    setStep(WIZARD_STEPS[index + 1] ?? step);
  };
  const back = () => {
    setErrors({});
    setStep(WIZARD_STEPS[index - 1] ?? step);
  };
  const submit = async () => {
    const found = intakeStepErrors('review', draft);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    await create.submit({ body: intakeCreateBody(draft) });
  };
  const created = create.data;
  const secrets = created
    ? [
        ...(created.address ? [{ label: 'Intake address', value: created.address }] : []),
        ...(created.headerToken
          ? [{ label: 'X-EG-Journal-Token header value', value: created.headerToken }]
          : []),
      ]
    : [];

  return (
    <Section title={`Step ${index + 1} of ${WIZARD_STEPS.length}: ${STEP_LABEL[step]}`}>
      <ol className="flex flex-wrap gap-2 text-xs" aria-label="Wizard steps">
        {WIZARD_STEPS.map((s, i) => (
          <li
            key={s}
            aria-current={s === step ? 'step' : undefined}
            className={
              s === step
                ? 'rounded-full bg-primary px-2 py-0.5 text-primary-foreground'
                : 'rounded-full bg-muted px-2 py-0.5 text-muted-foreground'
            }
          >
            {i + 1}. {STEP_LABEL[s]}
          </li>
        ))}
      </ol>
      <form
        className="grid max-w-3xl min-w-0 gap-5"
        aria-label="New intake source"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          if (step === 'review') void submit();
          else next();
        }}
      >
        {Object.keys(errors).length > 0 ? (
          <FormErrorSummary messages={Object.values(errors)} />
        ) : null}
        {create.error ? (
          <FormErrorSummary
            messages={[explainJournalingError(create.error), `Code: ${create.error.code}`]}
            requestId={create.error.requestId}
          />
        ) : null}
        {step === 'kind' ? <KindStep draft={draft} set={set} /> : null}
        {step === 'sender' ? <SenderStep draft={draft} set={set} errors={errors} /> : null}
        {step === 'details' ? <DetailsStep draft={draft} set={set} errors={errors} /> : null}
        {step === 'review' ? <ReviewStep draft={draft} /> : null}
        <div className="flex flex-wrap gap-2">
          {index > 0 ? (
            <Button type="button" variant="outline" onClick={back} disabled={create.isPending}>
              <ArrowLeftIcon aria-hidden />
              Back
            </Button>
          ) : null}
          {step === 'review' ? (
            <Button type="submit" disabled={create.isPending || create.retryAfterSeconds > 0}>
              {create.isPending ? 'Creating …' : 'Create intake source'}
            </Button>
          ) : (
            <Button type="submit">
              Next
              <ArrowRightIcon aria-hidden />
            </Button>
          )}
          <Button type="button" variant="ghost" onClick={() => router.push(journalingHref)}>
            Cancel
          </Button>
        </div>
      </form>
      <SecretRevealDialog
        open={Boolean(created)}
        title="Intake source created"
        description={
          <div className="grid gap-2">
            <p>
              This is the address your mail system sends journal copies to
              {created?.headerToken ? ', and the header value of the Gmail routing rule' : ''}. It
              is shown in full only now; users with journal:manage can reveal it again (audited) or
              rotate it.
            </p>
            <p>
              Next: follow the setup guide of the source, written for your values, then send a test
              message. The source becomes active with the first accepted copy.
            </p>
          </div>
        }
        secrets={secrets}
        acknowledgement="I have copied the intake address into my mail system’s configuration or a safe place."
        onClose={() => {
          const id = created?.source.id;
          create.reset();
          if (id) router.push(intakeSourceHref(id, 'guide'));
        }}
      />
    </Section>
  );
}

function KindStep({ draft, set }: { draft: IntakeDraft; set: (p: Partial<IntakeDraft>) => void }) {
  return (
    <fieldset className="grid gap-2">
      <legend className="text-sm font-semibold">Which mail system sends the copies?</legend>
      <RadioGroup
        value={draft.kind}
        onValueChange={(value) => set({ kind: value as IntakeKind, providerConnectionId: '' })}
        className="grid gap-3 sm:grid-cols-2"
      >
        {INTAKE_KINDS.map((kind) => {
          const id = `intake-kind-${kind}`;
          return (
            <label
              key={kind}
              htmlFor={id}
              className="flex cursor-pointer items-start gap-3 rounded-md border p-3 has-[[data-state=checked]]:border-primary"
            >
              <RadioGroupItem id={id} value={kind} className="mt-1" />
              <span className="grid gap-1">
                <span className="font-medium">{INTAKE_KIND_LABEL[kind]}</span>
                <span className="text-xs text-muted-foreground">
                  {INTAKE_KIND_DESCRIPTION[kind]}
                </span>
              </span>
            </label>
          );
        })}
      </RadioGroup>
    </fieldset>
  );
}

function SenderStep({
  draft,
  set,
  errors,
}: {
  draft: IntakeDraft;
  set: (p: Partial<IntakeDraft>) => void;
  errors: Record<string, string>;
}) {
  const provider = providerOfKind(draft.kind);
  return provider ? (
    <ConnectionPicker draft={draft} set={set} error={errors.providerConnectionId} />
  ) : (
    <NetworkFields draft={draft} set={set} errors={errors} />
  );
}

function ConnectionPicker({
  draft,
  set,
  error,
}: {
  draft: IntakeDraft;
  set: (p: Partial<IntakeDraft>) => void;
  error?: string;
}) {
  const provider = providerOfKind(draft.kind)!;
  const canList = useCan('ProviderConnectionsController_list_v1');
  const canCreate = useCan('ProviderConnectionsController_create_v1');
  const list = useCursorList(
    'ProviderConnectionsController_list_v1',
    { provider, sort: '-id' },
    { limit: 100, enabled: canList },
  );
  const rows = list.rows.filter((c) => c.status !== 'disabled');
  const label = provider === 'microsoft_365' ? 'Microsoft 365' : 'Google Workspace';
  return (
    <fieldset className="grid gap-3" aria-invalid={error ? true : undefined}>
      <legend className="text-sm font-semibold">{label} connection</legend>
      <p className="text-sm text-muted-foreground">
        The gateway accepts copies only from {label}’s mail servers and only for your own tenant,
        proven by the connection (domain verification and read-only consent). An archive-only
        organization needs only the “Connect” and “Domains” steps of the connection; no mail-flow
        change is needed.
      </p>
      {!canList ? (
        <p className="text-sm">Listing connections needs the integration:read permission.</p>
      ) : list.query.isLoading ? (
        <LoadingState label="Loading connections" rows={2} />
      ) : rows.length === 0 ? (
        <p className="text-sm">No {label} connection yet.</p>
      ) : (
        <RadioGroup
          value={draft.providerConnectionId}
          onValueChange={(providerConnectionId) => set({ providerConnectionId })}
          className="grid gap-2"
          aria-label={`${label} connection`}
        >
          {rows.map((c) => {
            const id = `intake-connection-${c.id}`;
            return (
              <label
                key={c.id}
                htmlFor={id}
                className="flex cursor-pointer items-start gap-3 rounded-md border p-3 has-[[data-state=checked]]:border-primary"
              >
                <RadioGroupItem id={id} value={c.id} className="mt-1" />
                <span className="grid gap-0.5 text-sm">
                  <span className="font-medium">{c.displayName}</span>
                  <span className="text-xs text-muted-foreground">
                    {c.tenantName ? `Tenant ${c.tenantName}` : 'Tenant not bound yet'} · status{' '}
                    {c.status} · {c.domainCount} linked domain(s)
                  </span>
                </span>
              </label>
            );
          })}
        </RadioGroup>
      )}
      {canCreate ? (
        <Button asChild variant="outline" className="justify-self-start">
          <Link href={`/integrations/providers/new?provider=${provider}`} target="_blank">
            <ExternalLinkIcon aria-hidden />
            Connect {label} (opens the connection wizard)
          </Link>
        </Button>
      ) : null}
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </fieldset>
  );
}

function NetworkFields({
  draft,
  set,
  errors,
}: {
  draft: IntakeDraft;
  set: (p: Partial<IntakeDraft>) => void;
  errors: Record<string, string>;
}) {
  const id = useId();
  return (
    <div className="grid gap-4">
      <div className="grid gap-1">
        <Label htmlFor={`${id}-networks`}>Sending networks (one CIDR per line, required)</Label>
        <Textarea
          id={`${id}-networks`}
          rows={4}
          value={draft.networks}
          onChange={(e) => set({ networks: e.target.value })}
          aria-invalid={errors.networks ? true : undefined}
          aria-describedby={`${id}-networks-help`}
          placeholder={'203.0.113.10/32\n2001:db8:10::/48'}
        />
        <p id={`${id}-networks-help`} className="text-xs text-muted-foreground">
          The public addresses your server sends from, at most 32, each at least /16 (IPv4) or /32
          (IPv6). Ranges shared with Microsoft 365 or Google are refused: shared infrastructure is
          never a credential.
        </p>
        {errors.networks ? (
          <p className="text-xs font-medium text-destructive">{errors.networks}</p>
        ) : null}
      </div>
      <div className="grid gap-1">
        <div className="flex items-center gap-3">
          <Switch
            id={`${id}-tls`}
            checked={draft.requireTls}
            onCheckedChange={(requireTls) => set({ requireTls })}
            aria-describedby={`${id}-tls-help`}
          />
          <Label htmlFor={`${id}-tls`}>Require TLS</Label>
        </div>
        <p id={`${id}-tls-help`} className="text-xs text-muted-foreground">
          Recommended: copies sent without STARTTLS are refused in the SMTP session.
        </p>
      </div>
      <div className="grid gap-1">
        <Label htmlFor={`${id}-prints`}>Client certificate fingerprints (optional)</Label>
        <Textarea
          id={`${id}-prints`}
          rows={2}
          value={draft.fingerprints}
          onChange={(e) => set({ fingerprints: e.target.value })}
          aria-invalid={errors.fingerprints ? true : undefined}
          aria-describedby={`${id}-prints-help`}
        />
        <p id={`${id}-prints-help`} className="text-xs text-muted-foreground">
          SHA-256 fingerprints of the TLS client certificate of your server, one per line, at most
          4. When set, the certificate must match.
        </p>
        {errors.fingerprints ? (
          <p className="text-xs font-medium text-destructive">{errors.fingerprints}</p>
        ) : null}
      </div>
    </div>
  );
}

function DetailsStep({
  draft,
  set,
  errors,
}: {
  draft: IntakeDraft;
  set: (p: Partial<IntakeDraft>) => void;
  errors: Record<string, string>;
}) {
  const id = useId();
  return (
    <div className="grid gap-4">
      <div className="grid gap-1">
        <Label htmlFor={`${id}-name`}>Name (required)</Label>
        <Input
          id={`${id}-name`}
          autoComplete="off"
          value={draft.displayName}
          onChange={(e) => set({ displayName: e.target.value })}
          aria-invalid={errors.displayName ? true : undefined}
          aria-describedby={`${id}-name-help`}
        />
        <p id={`${id}-name-help`} className="text-xs text-muted-foreground">
          For example “Contoso Microsoft 365” or “Head office Exchange”. Unique in your
          organization.
        </p>
        {errors.displayName ? (
          <p className="text-xs font-medium text-destructive">{errors.displayName}</p>
        ) : null}
      </div>
      <div className="grid gap-1">
        <div className="flex items-center gap-3">
          <Switch
            id={`${id}-silence`}
            checked={draft.silenceAlert}
            onCheckedChange={(silenceAlert) => set({ silenceAlert })}
          />
          <Label htmlFor={`${id}-silence`}>Alert when the source goes silent</Label>
        </div>
        {draft.silenceAlert ? (
          <div className="grid max-w-xs gap-1">
            <Label htmlFor={`${id}-minutes`}>Silent after (minutes)</Label>
            <Input
              id={`${id}-minutes`}
              inputMode="numeric"
              value={draft.silenceAlertMinutes}
              onChange={(e) => set({ silenceAlertMinutes: e.target.value })}
              aria-invalid={errors.silenceAlertMinutes ? true : undefined}
            />
          </div>
        ) : null}
        <p className="text-xs text-muted-foreground">
          Users with journal:manage and the organization contact are alerted when no copy arrived
          for this long (default 240 minutes; at most once a day per source).
        </p>
        {errors.silenceAlertMinutes ? (
          <p className="text-xs font-medium text-destructive">{errors.silenceAlertMinutes}</p>
        ) : null}
      </div>
      <div className="grid max-w-xs gap-1">
        <Label htmlFor={`${id}-size`}>Largest copy accepted (MiB, optional)</Label>
        <Input
          id={`${id}-size`}
          inputMode="numeric"
          value={draft.maxMessageMiB}
          onChange={(e) => set({ maxMessageMiB: e.target.value })}
          aria-invalid={errors.maxMessageMiB ? true : undefined}
          aria-describedby={`${id}-size-help`}
        />
        <p id={`${id}-size-help`} className="text-xs text-muted-foreground">
          Empty: the plan limit applies.
        </p>
        {errors.maxMessageMiB ? (
          <p className="text-xs font-medium text-destructive">{errors.maxMessageMiB}</p>
        ) : null}
      </div>
    </div>
  );
}

function ReviewStep({ draft }: { draft: IntakeDraft }) {
  const body = intakeCreateBody(draft);
  const provider = providerOfKind(draft.kind);
  return (
    <DetailList
      items={[
        { label: 'Kind', value: INTAKE_KIND_LABEL[draft.kind] },
        { label: 'Name', value: body.displayName },
        provider
          ? { label: 'Connection', value: <code>{body.providerConnectionId}</code> }
          : { label: 'Networks', value: (body.networks ?? []).join(', ') },
        ...(provider
          ? []
          : [
              { label: 'TLS', value: body.requireTls ? 'Required' : 'Optional' },
              {
                label: 'Client certificates',
                value: body.clientCertFingerprints?.length
                  ? `${body.clientCertFingerprints.length} fingerprint(s)`
                  : 'Not required',
              },
            ]),
        {
          label: 'Silence alert',
          value:
            body.silenceAlertMinutes === null
              ? 'Off'
              : `After ${body.silenceAlertMinutes} minutes without a copy`,
        },
        {
          label: 'Largest copy',
          value: body.maxMessageBytes ? `${draft.maxMessageMiB} MiB` : 'Plan limit',
        },
      ]}
    />
  );
}
