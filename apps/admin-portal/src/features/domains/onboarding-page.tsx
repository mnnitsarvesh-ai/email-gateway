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
import { MailboxStep, useMailboxLinks } from './mailbox-step';
import { DestinationsEditor } from './destinations-editor';
import { DnsRecordsPanel } from './dns-records';
import { Section, isUuid } from './kit';
import { DomainStatusBadge, isOwned, normalizeDomainName, type DomainDetail } from './model';
import { RecipientValidationSection } from './recipients-panel';
import { DomainStatusActions } from './status-actions';
import { VerificationPanel } from './verification-panel';

export const ONBOARDING_STEPS = [
  'mode',
  'add',
  'dns',
  'verify',
  'destinations',
  'recipients',
  'mailbox',
  'activate',
  'done',
] as const;
export type OnboardingStep = (typeof ONBOARDING_STEPS)[number];

const STEP_LABEL: Record<OnboardingStep, string> = {
  mode: 'Protection mode',
  add: 'Add domain',
  dns: 'Publish DNS records',
  verify: 'Verify ownership',
  destinations: 'Destination mail server',
  recipients: 'Recipient validation (optional)',
  mailbox: 'Mailbox protection',
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
   * Mailbox step (API and Hybrid): a provider connection linked to the domain has an active
   * mailbox-access grant or a verified journal intake source; `null` while unknown.
   */
  readonly mailboxReady?: boolean | null;
}

/** Steps that do not apply to a mode (D3): API mode has no destinations and recipients. */
export function skippedSteps(mode: ProtectionMode): ReadonlySet<OnboardingStep> {
  if (mode === 'api') return new Set<OnboardingStep>(['destinations', 'recipients']);
  if (mode === 'inline') return new Set<OnboardingStep>(['mailbox']);
  return new Set<OnboardingStep>();
}

/** Completion of each step, from the server state only (never inferred from clicks). */
export function stepCompletion(progress: ServerProgress): Record<OnboardingStep, boolean> {
  const { domain } = progress;
  const owned = domain ? isOwned(domain.status) : false;
  return {
    mode: domain !== null,
    add: domain !== null,
    dns: owned,
    verify: owned,
    destinations: progress.hasDestinations,
    recipients: progress.recipientMode !== null && progress.recipientMode !== 'accept_all',
    mailbox: progress.mailboxReady === true,
    activate: domain?.status === 'active',
    done: domain?.status === 'active',
  };
}

/**
 * The step a resumed wizard opens at: the first one the server says is not done. Skipped steps
 * (D3) and the informational mailbox step never hold the wizard (activation needs ownership
 * only).
 */
export function resumeStep(progress: ServerProgress): OnboardingStep {
  const { domain } = progress;
  if (!domain) return 'mode';
  if (!isOwned(domain.status)) return domain.lastCheckedAt ? 'verify' : 'dns';
  if (domain.protectionMode.effective !== 'api' && !progress.hasDestinations) return 'destinations';
  if (domain.status !== 'active') return 'activate';
  return 'done';
}

/** The step after `step` for a mode (skipped steps are passed over). */
export function nextStep(step: OnboardingStep, mode: ProtectionMode): OnboardingStep {
  const skipped = skippedSteps(mode);
  const index = ONBOARDING_STEPS.indexOf(step);
  return ONBOARDING_STEPS.slice(index + 1).find((candidate) => !skipped.has(candidate)) ?? 'done';
}

/** The step before `step` for a mode. */
export function previousStep(step: OnboardingStep, mode: ProtectionMode): OnboardingStep {
  const skipped = skippedSteps(mode);
  const index = ONBOARDING_STEPS.indexOf(step);
  return (
    ONBOARDING_STEPS.slice(0, index)
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
  current,
  completion,
  skipped,
  selectable,
  onSelect,
}: {
  current: OnboardingStep;
  completion: Record<OnboardingStep, boolean>;
  skipped: ReadonlySet<OnboardingStep>;
  selectable: (step: OnboardingStep) => boolean;
  onSelect: (step: OnboardingStep) => void;
}) {
  return (
    <nav aria-label="Onboarding steps">
      <ol className="grid gap-1 sm:grid-cols-2 lg:grid-cols-4">
        {ONBOARDING_STEPS.filter((step) => step !== 'done').map((step, index) => {
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
                  className={cn('size-4 shrink-0', done ? 'text-success' : 'text-muted-foreground')}
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

/** Section title with the step's position in the full step list ("3. Publish DNS records"). */
function stepTitle(step: OnboardingStep, label = STEP_LABEL[step]): string {
  return `${ONBOARDING_STEPS.indexOf(step) + 1}. ${label}`;
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
    { retry: false },
  );
  const mode: ProtectionMode = domain.data?.protectionMode.effective ?? 'inline';
  const destinations = useApiQuery('DomainDestinationsController_get_v1', {
    path: { id: domainId },
  });
  const validation = useApiQuery('DomainRecipientsController_get_v1', { path: { id: domainId } });
  const mailbox = useMailboxLinks(domainId, domain.isSuccess && mode !== 'inline');

  if (domain.isLoading || destinations.isLoading || validation.isLoading)
    return <LoadingState label="Loading the domain's onboarding state" rows={5} />;
  if (domain.error) {
    if (domain.error.status === 404) return <NotFoundView />;
    return <ErrorState error={domain.error} onRetry={() => void domain.refetch()} />;
  }
  if (destinations.error)
    return <ErrorState error={destinations.error} onRetry={() => void destinations.refetch()} />;
  if (validation.error)
    return <ErrorState error={validation.error} onRetry={() => void validation.refetch()} />;
  const data = domain.data;
  if (!data) return null;

  const progress: ServerProgress = {
    domain: data,
    hasDestinations: (destinations.data?.servers.length ?? 0) > 0,
    recipientMode: validation.data?.mode ?? null,
    mailboxReady: mailbox.ready,
  };
  const completion = stepCompletion(progress);
  const skipped = skippedSteps(mode);
  const requested = step && step !== 'add' && !skipped.has(step) ? step : undefined;
  const current = requested ?? resumeStep(progress);
  const owned = isOwned(data.status);
  const go = (target: OnboardingStep) => setStep(target);
  const next = (from: OnboardingStep) => go(nextStep(from, mode));
  const back = (from: OnboardingStep) => go(previousStep(from, mode));

  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <Stepper
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
          title={stepTitle('dns')}
          description={
            mode === 'api'
              ? 'Add the ownership TXT record now. In API mode the MX record stays with your provider: MX records are not required in API mode. SPF, DKIM and DMARC matter only for mail sent through the gateway.'
              : 'Add the ownership TXT record now; MX, SPF, DKIM and DMARC can follow. Activation needs only the ownership record.'
          }
        >
          <DnsRecordsPanel domainId={domainId} apiMode={mode === 'api'} />
          <StepNav
            onBack={() => go('mode')}
            onNext={() => go('verify')}
            nextLabel="I have published the records"
          />
        </Section>
      ) : null}
      {current === 'verify' ? (
        <Section
          title={stepTitle('verify')}
          description="The gateway looks up the ownership TXT record. New records can take minutes (sometimes hours) to propagate to every DNS resolver; checks keep running in the background."
        >
          <VerificationPanel domainId={domainId} />
          <StepNav
            onBack={() => go('dns')}
            onNext={() => next('verify')}
            nextDisabled={!owned}
            hint={owned ? undefined : 'Continue once ownership is verified.'}
          />
        </Section>
      ) : null}
      {current === 'destinations' ? (
        <Section
          title={stepTitle('destinations')}
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
      {current === 'mailbox' ? (
        <Section
          title={stepTitle('mailbox')}
          description="API-mode protection needs a provider connection linked to this domain with a journal copy or mailbox access. This step is informational: activation does not wait for it."
        >
          <MailboxStep links={mailbox} />
          <StepNav
            onBack={() => back('mailbox')}
            onNext={() => go('activate')}
            nextLabel={completion.mailbox ? 'Continue' : 'Continue without it for now'}
          />
        </Section>
      ) : null}
      {current === 'activate' ? (
        <Section
          title={stepTitle('activate')}
          description={
            mode === 'api'
              ? 'Activation records the domain as active. In API mode your MX record stays with your provider; mail flow is not changed.'
              : 'Activation starts mail acceptance for the domain. Switch the MX record to the gateway afterwards.'
          }
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
        <Section title={data.status === 'active' ? 'Onboarding complete' : 'Not finished yet'}>
          <p className="text-sm">
            {data.status !== 'active'
              ? 'Some steps are not complete yet; the stepper above shows which.'
              : mode === 'api'
                ? `${data.unicodeName} is active in API mode. Keep its MX record at your provider; Mailbox protection shows coverage and detections.`
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
            current={newStep}
            completion={stepCompletion(NEW_DOMAIN_PROGRESS)}
            skipped={state.mode ? skippedSteps(state.mode) : new Set()}
            selectable={(step) => step === 'mode' || (step === 'add' && state.mode !== undefined)}
            onSelect={(step) => setState({ step }, { push: true })}
          />
          {newStep === 'mode' ? (
            <Section title={stepTitle('mode')}>
              <ModeStep
                initial={state.mode}
                onContinue={(mode) => setState({ mode, step: 'add' }, { push: true })}
              />
            </Section>
          ) : (
            <Section title={stepTitle('add')}>
              <AddDomainStep
                mode={chosenMode}
                onBack={() => setState({ step: 'mode' }, { push: true })}
                onCreated={(id) => router.replace(`/domains/onboarding?domainId=${id}&step=dns`)}
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
