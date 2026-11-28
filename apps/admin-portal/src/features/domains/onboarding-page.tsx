'use client';

import { CheckCircle2Icon, CircleDotIcon, CircleIcon, MinusCircleIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { z } from 'zod';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { cn } from '@/lib/utils';
import {
  MODE_EXPLANATION,
  MODE_LABEL,
  PROTECTION_MODES,
  protectionModeErrorText,
  type ProtectionMode,
} from '@/features/api-mode/model';
import {
  DomainProtectionModePanel,
  ModeOptions,
  useOrganizationProtectionMode,
} from '@/features/api-mode/protection-mode';
import type { DomainOnboarding } from '@/features/api-mode/parity-model';
import { useCan } from '@/lib/auth/me';
import {
  API_STEP_LABEL,
  ActionStep,
  ApiConnectStep,
  FirstCopyCheck,
  IntakeStep,
  MailboxesStep,
  OwnershipStep,
  ProviderOwnershipCard,
  ReviewSummary,
  StepFacts,
} from './api-onboarding-steps';
import { DestinationsEditor } from './destinations-editor';
import { DnsRecordsPanel } from './dns-records';
import { Section, isUuid } from './kit';
import { DomainStatusBadge, isOwned, normalizeDomainName, type DomainDetail } from './model';
import { RecipientValidationSection } from './recipients-panel';
import { DomainStatusActions } from './status-actions';
import { VerificationPanel } from './verification-panel';

/** Every step key of the wizard (the URL `step` accepts any of them). */
export const ONBOARDING_STEPS = [
  'mode',
  'add',
  'dns',
  'verify',
  'ownership',
  'destinations',
  'recipients',
  'mailbox',
  'connect',
  'intake',
  'mailboxes',
  'action',
  'review',
  'activate',
  'done',
] as const;
export type OnboardingStep = (typeof ONBOARDING_STEPS)[number];

/** The API-side steps whose state the api computes (B8). */
export const API_STEPS = [
  'ownership',
  'connect',
  'intake',
  'mailboxes',
  'action',
  'review',
] as const;
type ApiStep = (typeof API_STEPS)[number];
const isApiStep = (step: OnboardingStep): step is ApiStep =>
  (API_STEPS as readonly string[]).includes(step);

/**
 * The steps each mode shows, in order (step API-4 B1). Inline is exactly the step API-1 list
 * (its informational mailbox step stays listed as skipped); API lists only what applies (no
 * DNS records other than ownership, no destinations or recipients); Hybrid is inline plus the
 * API steps.
 */
export const STEPS_BY_MODE: Record<ProtectionMode, readonly OnboardingStep[]> = {
  inline: [
    'mode',
    'add',
    'dns',
    'verify',
    'destinations',
    'recipients',
    'mailbox',
    'activate',
    'done',
  ],
  api: ['mode', 'add', 'ownership', 'connect', 'intake', 'mailboxes', 'action', 'review', 'done'],
  hybrid: [
    'mode',
    'add',
    'dns',
    'verify',
    'destinations',
    'recipients',
    'connect',
    'intake',
    'mailboxes',
    'action',
    'review',
    'done',
  ],
};

const STEP_LABEL: Record<OnboardingStep, string> = {
  mode: 'Protection mode',
  add: 'Add domain',
  dns: 'Publish DNS records',
  verify: 'Verify ownership',
  ownership: 'Verify ownership',
  destinations: 'Destination mail server',
  recipients: 'Recipient validation (optional)',
  mailbox: 'Mailbox protection',
  connect: API_STEP_LABEL.connect,
  intake: API_STEP_LABEL.intake,
  mailboxes: API_STEP_LABEL.mailboxes,
  action: API_STEP_LABEL.action,
  review: API_STEP_LABEL.review,
  activate: 'Activate',
  done: 'Done',
};

const URL_SHAPE = {
  domainId: z.string().optional().catch(undefined),
  step: z.enum(ONBOARDING_STEPS).optional().catch(undefined),
  /** The mode chosen in the first step of a new domain (step API-1 D3). */
  mode: z
    .enum(PROTECTION_MODES as [ProtectionMode, ...ProtectionMode[]])
    .optional()
    .catch(undefined),
};

/** POST /domains: the request schema with the name rules mirrored from the api. */
export const domainCreateSchema = z
  .object({
    name: z
      .string()
      .max(253)
      .transform((value, ctx) => {
        const result = normalizeDomainName(value);
        if (!result.ok) {
          ctx.addIssue({ code: 'custom', message: result.message });
          return z.NEVER;
        }
        return result.name;
      }),
    inboundEnabled: z.boolean(),
    dkim: z.object({ ed25519: z.boolean() }).strict(),
  })
  .strict();

/**
 * The create body with the chosen protection mode (D2, D3): an `api` domain is created with
 * inbound mail through the gateway off (`422 protection_mode_inbound_conflict` otherwise).
 */
export function domainCreateBody(
  values: z.output<typeof domainCreateSchema>,
  mode?: ProtectionMode,
): RequestBody<'DomainsController_create_v1'> {
  return {
    name: values.name,
    inboundEnabled: mode === 'api' ? false : values.inboundEnabled,
    dkim: { ed25519: values.dkim.ed25519 },
    ...(mode ? { protectionMode: mode } : {}),
  };
}

export interface ServerProgress {
  readonly domain: DomainDetail | null;
  readonly hasDestinations: boolean;
  readonly recipientMode: string | null;
  /**
   * The api's onboarding state of an API or Hybrid domain (`GET /api-mode/domains/{id}/
   * onboarding`, B8); absent for inline domains (never requested on the inline path, B9).
   */
  readonly onboarding?: DomainOnboarding | null;
}

/**
 * Steps a mode lists but that do not apply (shown as skipped): only the informational mailbox
 * step of the inline list (unchanged since step API-1). API and Hybrid never list a step that
 * does not apply (B1).
 */
export function skippedSteps(mode: ProtectionMode): ReadonlySet<OnboardingStep> {
  if (mode === 'inline') return new Set<OnboardingStep>(['mailbox']);
  return new Set<OnboardingStep>();
}

/** Completion of each step, from the server state only (never inferred from clicks). */
export function stepCompletion(progress: ServerProgress): Record<OnboardingStep, boolean> {
  const { domain, onboarding } = progress;
  const owned = domain ? isOwned(domain.status) : false;
  const api = (key: ApiStep) => onboarding?.steps.find((s) => s.key === key)?.status === 'done';
  return {
    mode: domain !== null,
    add: domain !== null,
    dns: owned,
    verify: owned,
    ownership: owned,
    destinations: progress.hasDestinations,
    recipients: progress.recipientMode !== null && progress.recipientMode !== 'accept_all',
    mailbox: false,
    connect: api('connect'),
    intake: api('intake'),
    mailboxes: api('mailboxes'),
    action: api('action'),
    review: api('review'),
    activate: domain?.status === 'active',
    done:
      domain?.status === 'active' &&
      (domain.protectionMode.effective === 'inline' || api('review')),
  };
}

/**
 * The step a resumed wizard opens at: the first step of the mode's list the server says is not
 * done. Skipped steps, recipients (optional) and inline's informational mailbox step never hold
 * the wizard.
 */
export function resumeStep(progress: ServerProgress): OnboardingStep {
  const { domain } = progress;
  if (!domain) return 'mode';
  const mode = domain.protectionMode.effective;
  const owned = isOwned(domain.status);
  if (mode === 'api') {
    if (!owned) return 'ownership';
    const steps = progress.onboarding?.steps ?? [];
    const open = API_STEPS.find(
      (key) => key !== 'ownership' && steps.find((s) => s.key === key)?.status !== 'done',
    );
    return open ?? 'done';
  }
  if (!owned) return domain.lastCheckedAt ? 'verify' : 'dns';
  if (!progress.hasDestinations) return 'destinations';
  if (mode === 'hybrid') {
    const steps = progress.onboarding?.steps ?? [];
    const open = API_STEPS.find(
      (key) => key !== 'ownership' && steps.find((s) => s.key === key)?.status !== 'done',
    );
    return open ?? 'done';
  }
  if (domain.status !== 'active') return 'activate';
  return 'done';
}

/** The step after `step` in a mode's list (skipped steps are passed over). */
export function nextStep(step: OnboardingStep, mode: ProtectionMode): OnboardingStep {
  const list = STEPS_BY_MODE[mode];
  const skipped = skippedSteps(mode);
  const index = list.indexOf(step);
  return list.slice(index + 1).find((candidate) => !skipped.has(candidate)) ?? 'done';
}

/** The step before `step` in a mode's list. */
export function previousStep(step: OnboardingStep, mode: ProtectionMode): OnboardingStep {
  const list = STEPS_BY_MODE[mode];
  const skipped = skippedSteps(mode);
  const index = list.indexOf(step);
  return (
    list
      .slice(0, Math.max(0, index))
      .reverse()
      .find((candidate) => !skipped.has(candidate)) ?? 'mode'
  );
}

/** First step of a new domain: the protection mode (three explained options, D3). */
function ModeStep({
  initial,
  onContinue,
}: {
  initial: ProtectionMode | undefined;
  onContinue: (mode: ProtectionMode) => void;
}) {
  const organization = useOrganizationProtectionMode();
  const entitled = organization.data?.entitled ?? true;
  const fallback = organization.data?.mode ?? 'inline';
  const [mode, setMode] = useState<ProtectionMode | null>(initial ?? null);
  const chosen: ProtectionMode = mode ?? (entitled || fallback === 'inline' ? fallback : 'inline');
  if (organization.isLoading) return <LoadingState label="Loading the protection modes" rows={3} />;
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      <ModeOptions
        legend="How should the gateway protect this domain?"
        value={chosen}
        onChange={(next) => setMode(next as ProtectionMode)}
        entitled={entitled}
      />
      <p className="text-xs text-muted-foreground">
        You can change the mode later on the domain page (audited). The organization mode is{' '}
        {MODE_LABEL[organization.data?.mode ?? 'inline']}.
      </p>
      <StepNav onNext={() => onContinue(chosen)} />
    </div>
  );
}

function AddDomainStep({
  mode,
  onCreated,
  onBack,
}: {
  mode: ProtectionMode;
  onCreated: (id: string) => void;
  onBack: () => void;
}) {
  const form = useZodForm(domainCreateSchema, {
    defaultValues: { name: '', inboundEnabled: true, dkim: { ed25519: false } },
  });
  const [messages, setMessages] = useState<string[]>([]);
  const create = useApiMutation('DomainsController_create_v1', {
    successMessage: 'Domain added.',
    invalidates: ['DomainsController_list_v1'],
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await create.submit({ body: domainCreateBody(values, mode) });
    if (outcome.ok) onCreated(outcome.data.id);
    else setMessages(applyApiErrors(form, outcome.error));
  });
  return (
    <Form {...form}>
      <form
        className="grid max-w-2xl gap-4"
        aria-label="Add domain"
        noValidate
        onSubmit={(event) => void submit(event)}
      >
        <FormErrorSummary
          messages={[
            ...messages,
            ...(protectionModeErrorText(create.error)
              ? [protectionModeErrorText(create.error)!]
              : []),
          ]}
          requestId={create.error?.requestId}
        />
        <p className="text-sm">
          Protection mode: <span className="font-medium">{MODE_LABEL[mode]}</span>.{' '}
          <span className="text-muted-foreground">{MODE_EXPLANATION[mode]}</span>
        </p>
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Domain name (required)</FormLabel>
              <FormControl>
                <Input autoComplete="off" spellCheck={false} placeholder="example.org" {...field} />
              </FormControl>
              <FormDescription>
                The full domain, such as example.org. Internationalized names are converted to
                punycode by the gateway.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        {mode === 'api' ? (
          <p className="text-sm text-muted-foreground" role="note">
            Inbound mail through the gateway stays off in API mode: your MX record keeps pointing to
            Microsoft 365 or Google Workspace and the gateway receives a copy instead.
          </p>
        ) : null}
        {mode !== 'api' ? (
          <FormField
            control={form.control}
            name="inboundEnabled"
            render={({ field }) => (
              <FormItem className="flex flex-row items-start gap-2">
                <FormControl>
                  <Checkbox
                    checked={field.value}
                    onCheckedChange={(v) => field.onChange(v === true)}
                  />
                </FormControl>
                <div className="grid gap-1">
                  <FormLabel className="font-normal">
                    Receive inbound mail for this domain
                  </FormLabel>
                  <FormDescription>Turn off for outbound-only domains.</FormDescription>
                </div>
              </FormItem>
            )}
          />
        ) : null}
        <FormField
          control={form.control}
          name="dkim.ed25519"
          render={({ field }) => (
            <FormItem className="flex flex-row items-start gap-2">
              <FormControl>
                <Checkbox
                  checked={field.value}
                  onCheckedChange={(v) => field.onChange(v === true)}
                />
              </FormControl>
              <div className="grid gap-1">
                <FormLabel className="font-normal">Also create an Ed25519 DKIM key</FormLabel>
                <FormDescription>An RSA 2048 key is always created.</FormDescription>
              </div>
            </FormItem>
          )}
        />
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" variant="ghost" onClick={onBack}>
            Back
          </Button>
          <Button type="submit" disabled={create.isPending || create.retryAfterSeconds > 0}>
            {create.isPending ? 'Adding …' : 'Add domain'}
          </Button>
        </div>
      </form>
    </Form>
  );
}

function Stepper({
  steps,
  current,
  completion,
  skipped,
  selectable,
  onSelect,
}: {
  steps: readonly OnboardingStep[];
  current: OnboardingStep;
  completion: Record<OnboardingStep, boolean>;
  skipped: ReadonlySet<OnboardingStep>;
  selectable: (step: OnboardingStep) => boolean;
  onSelect: (step: OnboardingStep) => void;
}) {
  return (
    <nav aria-label="Onboarding steps">
      <ol className="grid gap-1 sm:grid-cols-2 lg:grid-cols-4">
        {steps
          .filter((step) => step !== 'done')
          .map((step, index) => {
            const active = step === current;
            const isSkipped = skipped.has(step);
            const done = !isSkipped && completion[step];
            const Icon = isSkipped
              ? MinusCircleIcon
              : done
                ? CheckCircle2Icon
                : active
                  ? CircleDotIcon
                  : CircleIcon;
            return (
              <li key={step}>
                <button
                  type="button"
                  aria-current={active ? 'step' : undefined}
                  disabled={isSkipped || !selectable(step)}
                  onClick={() => onSelect(step)}
                  className={cn(
                    'flex w-full items-center gap-2 rounded-md border px-3 py-2 text-left text-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-50',
                    active ? 'border-primary bg-accent' : 'bg-card hover:bg-muted',
                  )}
                >
                  <Icon
                    className={cn(
                      'size-4 shrink-0',
                      done ? 'text-success' : 'text-muted-foreground',
                    )}
                    aria-hidden
                  />
                  <span className="grid">
                    <span className="text-xs text-muted-foreground">
                      Step {index + 1}
                      {isSkipped ? ' · skipped' : ''}
                    </span>
                    <span className="font-medium">{STEP_LABEL[step]}</span>
                    <span className="sr-only">
                      {isSkipped
                        ? ', skipped in this protection mode'
                        : done
                          ? ', complete'
                          : step === 'recipients' || step === 'mailbox'
                            ? ', optional'
                            : ', not complete'}
                    </span>
                  </span>
                </button>
              </li>
            );
          })}
      </ol>
    </nav>
  );
}

function StepNav({
  onBack,
  onNext,
  nextLabel = 'Continue',
  nextDisabled,
  hint,
}: {
  onBack?: () => void;
  onNext?: () => void;
  nextLabel?: string;
  nextDisabled?: boolean;
  hint?: string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {onBack ? (
        <Button variant="ghost" onClick={onBack}>
          Back
        </Button>
      ) : null}
      {onNext ? (
        <Button onClick={onNext} disabled={nextDisabled}>
          {nextLabel}
        </Button>
      ) : null}
      {hint ? <span className="text-xs text-muted-foreground">{hint}</span> : null}
    </div>
  );
}

/** Section title with the step's position in the mode's step list ("3. Publish DNS records"). */
function stepTitle(step: OnboardingStep, mode: ProtectionMode, label = STEP_LABEL[step]): string {
  return `${STEPS_BY_MODE[mode].indexOf(step) + 1}. ${label}`;
}

function ResumedWizard({
  domainId,
  step,
  setStep,
}: {
  domainId: string;
  step: OnboardingStep | undefined;
  setStep: (step: OnboardingStep) => void;
}) {
  const domain = useApiQuery(
    'DomainsController_get_v1',
    { path: { id: domainId } },
    {
      retry: false,
      // A provider ownership check finishes in the worker (B3): poll while it is pending.
      refetchInterval: (query) =>
        query.state.data?.ownership.providerCheck?.status === 'pending' ? 5000 : false,
    },
  );
  const mode: ProtectionMode = domain.data?.protectionMode.effective ?? 'inline';
  const apiSide = domain.isSuccess && mode !== 'inline';
  const destinations = useApiQuery(
    'DomainDestinationsController_get_v1',
    { path: { id: domainId } },
    { enabled: domain.isSuccess && mode !== 'api' },
  );
  const validation = useApiQuery(
    'DomainRecipientsController_get_v1',
    { path: { id: domainId } },
    { enabled: domain.isSuccess && mode !== 'api' },
  );
  const canOnboarding = useCan('ApiModeOnboardingController_domainOnboarding_v1');
  // Never requested on the inline path (B9). The first-copy check polls every 5 s while the
  // review step is open (API4-14).
  const requested = step && step !== 'add' ? step : undefined;
  const onboarding = useApiQuery(
    'ApiModeOnboardingController_domainOnboarding_v1',
    { path: { domainId } },
    {
      enabled: apiSide && canOnboarding,
      refetchInterval: (query) =>
        requested === 'review' && query.state.data?.firstCopy.status !== 'received' ? 5000 : false,
    },
  );

  if (
    domain.isLoading ||
    destinations.isLoading ||
    validation.isLoading ||
    (apiSide && canOnboarding && onboarding.isLoading)
  )
    return <LoadingState label="Loading the domain's onboarding state" rows={5} />;
  if (domain.error) {
    if (domain.error.status === 404) return <NotFoundView />;
    return <ErrorState error={domain.error} onRetry={() => void domain.refetch()} />;
  }
  if (destinations.error)
    return <ErrorState error={destinations.error} onRetry={() => void destinations.refetch()} />;
  if (validation.error)
    return <ErrorState error={validation.error} onRetry={() => void validation.refetch()} />;
  if (onboarding.error)
    return <ErrorState error={onboarding.error} onRetry={() => void onboarding.refetch()} />;
  const data = domain.data;
  if (!data) return null;

  const view = apiSide ? (onboarding.data ?? null) : null;
  const progress: ServerProgress = {
    domain: data,
    hasDestinations: (destinations.data?.servers.length ?? 0) > 0,
    recipientMode: validation.data?.mode ?? null,
    onboarding: view,
  };
  const steps = STEPS_BY_MODE[mode];
  const completion = stepCompletion(progress);
  const skipped = skippedSteps(mode);
  const current =
    requested && steps.includes(requested) && !skipped.has(requested)
      ? requested
      : resumeStep(progress);
  const owned = isOwned(data.status);
  const go = (target: OnboardingStep) => setStep(target);
  const next = (from: OnboardingStep) => go(nextStep(from, mode));
  const back = (from: OnboardingStep) => go(previousStep(from, mode));
  const apiState = (key: ApiStep) => view?.steps.find((s) => s.key === key);
  const needsOnboarding = isApiStep(current) && current !== 'ownership';

  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <Stepper
        steps={steps}
        current={current}
        completion={completion}
        skipped={skipped}
        selectable={(candidate) => candidate !== 'add'}
        onSelect={go}
      />
      <p className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-medium">{data.unicodeName}</span>
        <DomainStatusBadge status={data.status} />
      </p>
      {current === 'mode' ? (
        <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
          <DomainProtectionModePanel domain={data} />
          <StepNav onNext={() => next('add')} />
        </div>
      ) : null}
      {current === 'dns' ? (
        <Section
          title={stepTitle('dns', mode)}
          description="Add the ownership TXT record now; MX, SPF, DKIM and DMARC can follow. Activation needs only the ownership record."
        >
          <DnsRecordsPanel domainId={domainId} />
          <StepNav
            onBack={() => go('mode')}
            onNext={() => go('verify')}
            nextLabel="I have published the records"
          />
        </Section>
      ) : null}
      {current === 'verify' ? (
        <Section
          title={stepTitle('verify', mode)}
          description="The gateway looks up the ownership TXT record. New records can take minutes (sometimes hours) to propagate to every DNS resolver; checks keep running in the background."
        >
          {mode === 'hybrid' ? <ProviderOwnershipCard domain={data} /> : null}
          <VerificationPanel domainId={domainId} />
          <StepNav
            onBack={() => go('dns')}
            onNext={() => next('verify')}
            nextDisabled={!owned}
            hint={owned ? undefined : 'Continue once ownership is verified.'}
          />
        </Section>
      ) : null}
      {current === 'ownership' ? (
        <Section
          title={stepTitle('ownership', mode)}
          description="Prove that your organization owns the domain: publish one TXT record, or verify it automatically through your bound Microsoft 365 or Google Workspace tenant. API mode needs no other DNS change."
        >
          <OwnershipStep domain={data} />
          <StepNav
            onBack={() => go('mode')}
            onNext={() => next('ownership')}
            nextDisabled={!owned}
            hint={owned ? undefined : 'Continue once ownership is verified.'}
          />
        </Section>
      ) : null}
      {current === 'destinations' ? (
        <Section
          title={stepTitle('destinations', mode)}
          description="Where the gateway delivers approved inbound mail: a provider preset or your own servers."
        >
          <DestinationsEditor
            domainId={domainId}
            startEditing={!progress.hasDestinations}
            onSaved={() => go('recipients')}
          />
          <StepNav
            onBack={() => go('verify')}
            onNext={() => go('recipients')}
            nextDisabled={!progress.hasDestinations}
            hint={
              progress.hasDestinations ? undefined : 'Save at least one destination to continue.'
            }
          />
        </Section>
      ) : null}
      {current === 'recipients' ? (
        <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
          <RecipientValidationSection domainId={domainId} />
          <StepNav
            onBack={() => go('destinations')}
            onNext={() => next('recipients')}
            nextLabel={completion.recipients ? 'Continue' : 'Skip for now'}
          />
        </div>
      ) : null}
      {needsOnboarding && !view ? (
        <Section title={stepTitle(current, mode)}>
          <p className="text-sm text-muted-foreground">
            Your role cannot read the onboarding state of API-mode domains; ask an administrator to
            complete this step.
          </p>
          <StepNav onBack={() => back(current)} onNext={() => next(current)} />
        </Section>
      ) : null}
      {view && current === 'connect' ? (
        <Section
          title={stepTitle('connect', mode)}
          description="The domain's Microsoft 365 or Google Workspace connection: link the domain, bind the tenant (read-only mail-flow access) and grant mailbox access for API mode."
        >
          <StepFacts step={apiState('connect')} />
          <ApiConnectStep domain={data} onboarding={view} />
          <StepNav onBack={() => back('connect')} onNext={() => next('connect')} />
        </Section>
      ) : null}
      {view && current === 'intake' ? (
        <Section
          title={stepTitle('intake', mode)}
          description="How copies of delivered mail reach the gateway: a journal copy and/or mailbox feeds."
        >
          <StepFacts step={apiState('intake')} />
          <IntakeStep onboarding={view} />
          <StepNav onBack={() => back('intake')} onNext={() => next('intake')} />
        </Section>
      ) : null}
      {view && current === 'mailboxes' ? (
        <Section
          title={stepTitle('mailboxes', mode)}
          description="Which mailboxes of the domain API-mode protection covers."
        >
          <StepFacts step={apiState('mailboxes')} />
          <MailboxesStep domainId={domainId} />
          <StepNav onBack={() => back('mailboxes')} onNext={() => next('mailboxes')} />
        </Section>
      ) : null}
      {view && current === 'action' ? (
        <Section
          title={stepTitle('action', mode)}
          description="What the gateway does in the mailbox when a copy is a threat or your policies decide against it. Start in detect only: nothing changes in mailboxes while you review the simulated actions."
        >
          <StepFacts step={apiState('action')} />
          <ActionStep domainId={domainId} onboarding={view} />
          <StepNav onBack={() => back('action')} onNext={() => next('action')} />
        </Section>
      ) : null}
      {view && current === 'review' ? (
        <Section
          title={stepTitle('review', mode)}
          description={
            mode === 'api'
              ? 'Check every step, activate the domain, then send a test message. API mode never changes mail flow: your MX record stays with your provider.'
              : 'Check every step, activate the domain, then send a test message. Switch the MX record to the gateway afterwards for the inline part.'
          }
        >
          <StepFacts step={apiState('review')} />
          <ReviewSummary onboarding={view} onEdit={(key) => go(key)} />
          {data.status === 'active' ? (
            <p className="text-sm">The domain is active.</p>
          ) : owned ? (
            <div className="flex flex-wrap gap-2">
              <DomainStatusActions domain={data} />
            </div>
          ) : (
            <p className="text-sm text-muted-foreground" role="status">
              Ownership is not verified yet: the domain can be activated once it is.
            </p>
          )}
          {data.status === 'active' ? <FirstCopyCheck onboarding={view} /> : null}
          <StepNav
            onBack={() => back('review')}
            onNext={completion.review ? () => go('done') : undefined}
          />
        </Section>
      ) : null}
      {current === 'activate' ? (
        <Section
          title={stepTitle('activate', mode)}
          description="Activation starts mail acceptance for the domain. Switch the MX record to the gateway afterwards."
        >
          {data.status === 'active' ? (
            <p className="text-sm">The domain is active.</p>
          ) : owned ? (
            <div className="flex flex-wrap gap-2">
              <DomainStatusActions domain={data} onActivated={() => go('done')} />
            </div>
          ) : (
            <p className="text-sm text-muted-foreground" role="status">
              Ownership is not verified yet: the domain can be activated once the ownership record
              is found.
            </p>
          )}
          <StepNav
            onBack={() => back('activate')}
            onNext={data.status === 'active' ? () => go('done') : undefined}
          />
        </Section>
      ) : null}
      {current === 'done' ? (
        <Section title={completion.done ? 'Onboarding complete' : 'Not finished yet'}>
          <p className="text-sm">
            {!completion.done
              ? 'Some steps are not complete yet; the stepper above shows which.'
              : mode === 'api'
                ? `${data.unicodeName} is protected in API mode. Keep its MX record at your provider; Mailbox protection shows coverage and detections.`
                : mode === 'hybrid'
                  ? `${data.unicodeName} is active in Hybrid mode. Point its MX record to the gateway if you have not yet; Mailbox protection shows the API side.`
                  : `${data.unicodeName} is active. Point its MX record to the gateway if you have not yet; the domain page shows the checks.`}
          </p>
          <Button asChild className="justify-self-start">
            <Link href={`/domains/${domainId}`}>Open {data.unicodeName}</Link>
          </Button>
        </Section>
      ) : null}
    </div>
  );
}

/** `/domains/onboarding` (`?domainId=` resumes): the wizard over the existing domain routes. */
export function DomainOnboardingPage() {
  return (
    <RouteGate gate={['DomainsController_create_v1']}>
      <Onboarding />
    </RouteGate>
  );
}

const NEW_DOMAIN_PROGRESS: ServerProgress = {
  domain: null,
  hasDestinations: false,
  recipientMode: null,
};

function Onboarding() {
  const router = useRouter();
  const [state, setState] = useUrlState(URL_SHAPE);
  const domainId = state.domainId;
  const newStep: OnboardingStep = state.step === 'add' ? 'add' : 'mode';
  const chosenMode: ProtectionMode = state.mode ?? 'inline';
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title="Add a domain"
        breadcrumbs={[{ label: 'Domains', href: '/domains' }, { label: 'Onboarding' }]}
        description="Choose how the gateway protects the domain, add it, publish its DNS records, verify ownership and activate it. You can leave and resume at any step."
      />
      {domainId === undefined ? (
        <>
          <Stepper
            steps={STEPS_BY_MODE[state.mode ?? 'inline']}
            current={newStep}
            completion={stepCompletion(NEW_DOMAIN_PROGRESS)}
            skipped={state.mode ? skippedSteps(state.mode) : new Set()}
            selectable={(step) => step === 'mode' || (step === 'add' && state.mode !== undefined)}
            onSelect={(step) => setState({ step }, { push: true })}
          />
          {newStep === 'mode' ? (
            <Section title={stepTitle('mode', chosenMode)}>
              <ModeStep
                initial={state.mode}
                onContinue={(mode) => setState({ mode, step: 'add' }, { push: true })}
              />
            </Section>
          ) : (
            <Section title={stepTitle('add', chosenMode)}>
              <AddDomainStep
                mode={chosenMode}
                onBack={() => setState({ step: 'mode' }, { push: true })}
                onCreated={(id) =>
                  router.replace(
                    `/domains/onboarding?domainId=${id}&step=${chosenMode === 'api' ? 'ownership' : 'dns'}`,
                  )
                }
              />
            </Section>
          )}
        </>
      ) : !isUuid(domainId) ? (
        <NotFoundView />
      ) : (
        <ResumedWizard
          domainId={domainId}
          step={state.step}
          setStep={(step) => setState({ step }, { push: true })}
        />
      )}
    </div>
  );
}
