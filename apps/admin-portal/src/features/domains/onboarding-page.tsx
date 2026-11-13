'use client';

import { CheckCircle2Icon, CircleIcon, CircleDotIcon } from 'lucide-react';
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
import { DestinationsEditor } from './destinations-editor';
import { DnsRecordsPanel } from './dns-records';
import { Section, isUuid } from './kit';
import { DomainStatusBadge, isOwned, normalizeDomainName, type DomainDetail } from './model';
import { RecipientValidationSection } from './recipients-panel';
import { DomainStatusActions } from './status-actions';
import { VerificationPanel } from './verification-panel';

export const ONBOARDING_STEPS = [
  'add',
  'dns',
  'verify',
  'destinations',
  'recipients',
  'activate',
  'done',
] as const;
export type OnboardingStep = (typeof ONBOARDING_STEPS)[number];

const STEP_LABEL: Record<OnboardingStep, string> = {
  add: 'Add domain',
  dns: 'Publish DNS records',
  verify: 'Verify ownership',
  destinations: 'Destination mail server',
  recipients: 'Recipient validation (optional)',
  activate: 'Activate',
  done: 'Done',
};

const URL_SHAPE = {
  domainId: z.string().optional().catch(undefined),
  step: z.enum(ONBOARDING_STEPS).optional().catch(undefined),
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

export function domainCreateBody(
  values: z.output<typeof domainCreateSchema>,
): RequestBody<'DomainsController_create_v1'> {
  return {
    name: values.name,
    inboundEnabled: values.inboundEnabled,
    dkim: { ed25519: values.dkim.ed25519 },
  };
}

export interface ServerProgress {
  readonly domain: DomainDetail | null;
  readonly hasDestinations: boolean;
  readonly recipientMode: string | null;
}

/** Completion of each step, from the server state only (never inferred from clicks). */
export function stepCompletion(progress: ServerProgress): Record<OnboardingStep, boolean> {
  const { domain } = progress;
  const owned = domain ? isOwned(domain.status) : false;
  return {
    add: domain !== null,
    dns: owned,
    verify: owned,
    destinations: progress.hasDestinations,
    recipients: progress.recipientMode !== null && progress.recipientMode !== 'accept_all',
    activate: domain?.status === 'active',
    done: domain?.status === 'active',
  };
}

/** The step a resumed wizard opens at: the first one the server says is not done. */
export function resumeStep(progress: ServerProgress): OnboardingStep {
  const { domain } = progress;
  if (!domain) return 'add';
  if (!isOwned(domain.status)) return domain.lastCheckedAt ? 'verify' : 'dns';
  if (!progress.hasDestinations) return 'destinations';
  if (domain.status !== 'active') return 'activate';
  return 'done';
}

function AddDomainStep({ onCreated }: { onCreated: (id: string) => void }) {
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
    const outcome = await create.submit({ body: domainCreateBody(values) });
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
        <FormErrorSummary messages={messages} requestId={create.error?.requestId} />
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
                <FormLabel className="font-normal">Receive inbound mail for this domain</FormLabel>
                <FormDescription>Turn off for outbound-only domains.</FormDescription>
              </div>
            </FormItem>
          )}
        />
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
        <Button
          type="submit"
          className="justify-self-start"
          disabled={create.isPending || create.retryAfterSeconds > 0}
        >
          {create.isPending ? 'Adding …' : 'Add domain'}
        </Button>
      </form>
    </Form>
  );
}

function Stepper({
  current,
  completion,
  enabled,
  onSelect,
}: {
  current: OnboardingStep;
  completion: Record<OnboardingStep, boolean>;
  enabled: boolean;
  onSelect: (step: OnboardingStep) => void;
}) {
  return (
    <nav aria-label="Onboarding steps">
      <ol className="grid gap-1 sm:grid-cols-3 lg:grid-cols-6">
        {ONBOARDING_STEPS.filter((step) => step !== 'done').map((step, index) => {
          const active = step === current;
          const done = completion[step];
          const Icon = done ? CheckCircle2Icon : active ? CircleDotIcon : CircleIcon;
          return (
            <li key={step}>
              <button
                type="button"
                aria-current={active ? 'step' : undefined}
                disabled={!enabled && step !== 'add'}
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
                  <span className="text-xs text-muted-foreground">Step {index + 1}</span>
                  <span className="font-medium">{STEP_LABEL[step]}</span>
                  <span className="sr-only">
                    {done ? ', complete' : step === 'recipients' ? ', optional' : ', not complete'}
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
  const destinations = useApiQuery('DomainDestinationsController_get_v1', {
    path: { id: domainId },
  });
  const validation = useApiQuery('DomainRecipientsController_get_v1', { path: { id: domainId } });

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
  };
  const completion = stepCompletion(progress);
  const current = step && step !== 'add' ? step : resumeStep(progress);
  const owned = isOwned(data.status);

  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <Stepper current={current} completion={completion} enabled onSelect={setStep} />
      <p className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-medium">{data.unicodeName}</span>
        <DomainStatusBadge status={data.status} />
      </p>
      {current === 'dns' ? (
        <Section
          title="2. Publish DNS records"
          description="Add the ownership TXT record now; MX, SPF, DKIM and DMARC can follow. Activation needs only the ownership record."
        >
          <DnsRecordsPanel domainId={domainId} />
          <StepNav onNext={() => setStep('verify')} nextLabel="I have published the records" />
        </Section>
      ) : null}
      {current === 'verify' ? (
        <Section
          title="3. Verify ownership"
          description="The gateway looks up the ownership TXT record. New records can take minutes (sometimes hours) to propagate to every DNS resolver; checks keep running in the background."
        >
          <VerificationPanel domainId={domainId} />
          <StepNav
            onBack={() => setStep('dns')}
            onNext={() => setStep('destinations')}
            nextDisabled={!owned}
            hint={owned ? undefined : 'Continue once ownership is verified.'}
          />
        </Section>
      ) : null}
      {current === 'destinations' ? (
        <Section
          title="4. Destination mail server"
          description="Where the gateway delivers approved inbound mail: a provider preset or your own servers."
        >
          <DestinationsEditor
            domainId={domainId}
            startEditing={!progress.hasDestinations}
            onSaved={() => setStep('recipients')}
          />
          <StepNav
            onBack={() => setStep('verify')}
            onNext={() => setStep('recipients')}
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
            onBack={() => setStep('destinations')}
            onNext={() => setStep('activate')}
            nextLabel={completion.recipients ? 'Continue' : 'Skip for now'}
          />
        </div>
      ) : null}
      {current === 'activate' ? (
        <Section
          title="6. Activate"
          description="Activation starts mail acceptance for the domain. Switch the MX record to the gateway afterwards."
        >
          {data.status === 'active' ? (
            <p className="text-sm">The domain is active.</p>
          ) : owned ? (
            <div className="flex flex-wrap gap-2">
              <DomainStatusActions domain={data} onActivated={() => setStep('done')} />
            </div>
          ) : (
            <p className="text-sm text-muted-foreground" role="status">
              Ownership is not verified yet: the domain can be activated once the ownership record
              is found.
            </p>
          )}
          <StepNav
            onBack={() => setStep('recipients')}
            onNext={data.status === 'active' ? () => setStep('done') : undefined}
          />
        </Section>
      ) : null}
      {current === 'done' ? (
        <Section title={data.status === 'active' ? 'Onboarding complete' : 'Not finished yet'}>
          <p className="text-sm">
            {data.status === 'active'
              ? `${data.unicodeName} is active. Point its MX record to the gateway if you have not yet; the domain page shows the checks.`
              : 'Some steps are not complete yet; the stepper above shows which.'}
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

function Onboarding() {
  const router = useRouter();
  const [state, setState] = useUrlState(URL_SHAPE);
  const domainId = state.domainId;
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title="Add a domain"
        breadcrumbs={[{ label: 'Domains', href: '/domains' }, { label: 'Onboarding' }]}
        description="Add the domain, publish its DNS records, verify ownership, choose where mail is delivered and activate it. You can leave and resume at any step."
      />
      {domainId === undefined ? (
        <>
          <Stepper
            current="add"
            completion={stepCompletion({
              domain: null,
              hasDestinations: false,
              recipientMode: null,
            })}
            enabled={false}
            onSelect={() => undefined}
          />
          <Section title="1. Add domain">
            <AddDomainStep
              onCreated={(id) => router.replace(`/domains/onboarding?domainId=${id}&step=dns`)}
            />
          </Section>
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
