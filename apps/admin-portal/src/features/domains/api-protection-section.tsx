'use client';

import Link from 'next/link';
import { DateTime } from '@/components/domain/date-time';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { DetectOnlyEndedBanner } from '@/features/api-mode/parity';
import {
  DETECT_ONLY_THEN_LABEL,
  SCOPE_KIND_LABEL,
  type DomainOnboarding,
} from '@/features/api-mode/parity-model';
import { MODE_TEXT, POLICY_SOURCE_LABEL } from '@/features/api-mode/remediation-model';
import { GrantStatusBadge, PROVIDER_LABEL } from '@/features/integrations/providers/model';
import { intakeSourceHref } from '@/features/journaling/model';
import {
  ACTION_PRESET_LABEL,
  FirstCopyCheck,
  OnboardingStatusBadge,
  presetOf,
} from './api-onboarding-steps';
import { DetailList, Section } from './kit';
import type { DomainDetail } from './model';

/** Whether every API-side onboarding step is done (the header's "Continue onboarding"). */
export function apiOnboardingComplete(view: DomainOnboarding | undefined): boolean {
  return (
    view !== undefined && view.steps.every((s) => s.status === 'done' || s.status === 'skipped')
  );
}

/** The detect-only banner of the domain page (B7): the domain override or the organization policy. */
function DomainDetectOnlyBanner({ domainId, view }: { domainId: string; view: DomainOnboarding }) {
  const canRead = useCan('ApiModeRemediationController_getPolicy_v1');
  const ended = view.action.detectOnly?.ended === true && view.action.mode === 'detect_only';
  const policy = useApiQuery('ApiModeRemediationController_getPolicy_v1', undefined, {
    enabled: canRead && ended,
  });
  if (!ended || !policy.data) return null;
  const override = policy.data.domains.find((d) => d.domainId === domainId);
  if (view.action.source === 'domain' && override)
    return <DetectOnlyEndedBanner target={{ scope: 'domain', view: override }} />;
  return (
    <DetectOnlyEndedBanner target={{ scope: 'organization', view: policy.data.organization }} />
  );
}

/**
 * "API protection" of the domain page (step API-4 B5): the provider connection and its grants,
 * intake, the mailbox scope with counts, the remediation policy with its detect-only period, the
 * first copy and links to coverage and detections. Server state only (`GET /api-mode/domains/
 * {id}/onboarding`).
 */
export function ApiProtectionSection({ domain }: { domain: DomainDetail }) {
  const canRead = useCan('ApiModeOnboardingController_domainOnboarding_v1');
  const onboarding = useApiQuery(
    'ApiModeOnboardingController_domainOnboarding_v1',
    { path: { domainId: domain.id } },
    { enabled: canRead },
  );
  const canWizard = useCan('DomainsController_create_v1');
  if (!canRead) return null;
  return (
    <Section
      title="API protection"
      description="Post-delivery protection of this domain's mailboxes through Microsoft 365 or Google Workspace."
      actions={
        canWizard && onboarding.data && !apiOnboardingComplete(onboarding.data) ? (
          <Button asChild variant="outline" size="sm">
            <Link href={`/domains/onboarding?domainId=${domain.id}`}>Continue onboarding</Link>
          </Button>
        ) : null
      }
    >
      {onboarding.isLoading ? (
        <LoadingState label="Loading API protection" rows={4} />
      ) : onboarding.error ? (
        <ErrorState error={onboarding.error} onRetry={() => void onboarding.refetch()} compact />
      ) : onboarding.data ? (
        <ApiProtectionFacts domain={domain} view={onboarding.data} />
      ) : null}
    </Section>
  );
}

function ApiProtectionFacts({ domain, view }: { domain: DomainDetail; view: DomainOnboarding }) {
  const c = view.connection;
  const preset = presetOf(view.action);
  const steps = view.steps.filter((s) => s.status !== 'skipped');
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      <DomainDetectOnlyBanner domainId={domain.id} view={view} />
      <DetailList
        items={[
          {
            label: 'Connection',
            value: c ? (
              <span className="flex flex-wrap items-center gap-2">
                <Link
                  href={`/integrations/providers/${c.id}`}
                  className="text-primary underline underline-offset-2"
                >
                  {PROVIDER_LABEL[c.provider]} connection
                </Link>
                <span className="text-xs text-muted-foreground">
                  {humanize(c.status)} · {c.bound ? 'tenant bound' : 'tenant not bound'}
                </span>
              </span>
            ) : (
              'None linked'
            ),
          },
          {
            label: 'Grants',
            value: c ? (
              <span className="flex flex-wrap items-center gap-2 text-xs">
                Mail flow{' '}
                {c.mailFlowGrant ? <GrantStatusBadge status={c.mailFlowGrant} /> : 'not granted'} ·
                Mailbox access{' '}
                {c.mailboxAccessGrant ? (
                  <GrantStatusBadge status={c.mailboxAccessGrant} />
                ) : (
                  'not granted'
                )}
              </span>
            ) : (
              '—'
            ),
          },
          {
            label: 'Intake',
            value: (
              <span className="grid gap-0.5">
                <span>
                  {view.intake.journalSources.length === 0
                    ? 'No journal copy'
                    : view.intake.journalSources.map((s, i) => (
                        <Link
                          key={s.id}
                          href={intakeSourceHref(s.id)}
                          className="mr-2 text-primary underline underline-offset-2"
                        >
                          Journal source {view.intake.journalSources.length > 1 ? i + 1 : ''} (
                          {humanize(s.status)}, {humanize(s.health)})
                        </Link>
                      ))}
                </span>
                <span className="text-xs text-muted-foreground">
                  Feeds{' '}
                  {view.intake.feeds.enabled
                    ? `on (${humanize(view.intake.feeds.mode)}), ${formatNumber(view.intake.feeds.activeMailboxes)} of ${formatNumber(view.intake.feeds.inScopeMailboxes)} active`
                    : 'off'}
                </span>
              </span>
            ),
          },
          {
            label: 'Mailbox scope',
            value: `${SCOPE_KIND_LABEL[view.scope.kind]}: ${formatNumber(view.scope.inScope)} in scope, ${formatNumber(view.scope.excluded)} excluded`,
          },
          {
            label: 'Threat action',
            value: (
              <span className="grid gap-0.5">
                <span>
                  {preset ? ACTION_PRESET_LABEL[preset] : 'Custom domain policy'} ·{' '}
                  {MODE_TEXT[view.action.mode]} (
                  {POLICY_SOURCE_LABEL[view.action.source] ?? humanize(view.action.source)})
                </span>
                {view.action.detectOnly ? (
                  <span className="text-xs text-muted-foreground">
                    Detect only {view.action.detectOnly.ended ? 'ended' : 'until'}{' '}
                    <DateTime value={view.action.detectOnly.until} mode="absolute" />, then{' '}
                    {DETECT_ONLY_THEN_LABEL[view.action.detectOnly.then].toLowerCase()}
                  </span>
                ) : null}
              </span>
            ),
          },
          {
            label: 'Onboarding',
            value: (
              <ul className="flex flex-wrap gap-2" aria-label="Onboarding steps state">
                {steps.map((s) => (
                  <li key={s.key} className="flex items-center gap-1 text-xs">
                    {humanize(s.key)} <OnboardingStatusBadge status={s.status} />
                  </li>
                ))}
              </ul>
            ),
          },
        ]}
      />
      {domain.status === 'active' ? <FirstCopyCheck onboarding={view} /> : null}
      <nav aria-label="API protection links" className="flex flex-wrap gap-3 text-sm">
        <Link href="/api-mode?tab=coverage" className="text-primary underline underline-offset-2">
          Coverage
        </Link>
        <Link href="/api-mode?tab=detections" className="text-primary underline underline-offset-2">
          Recent detections
        </Link>
        <Link href="/protection-by-mode" className="text-primary underline underline-offset-2">
          Protection by mode
        </Link>
      </nav>
    </div>
  );
}
