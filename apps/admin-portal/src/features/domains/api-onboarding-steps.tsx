'use client';

import { useQueryClient } from '@tanstack/react-query';
import { RefreshCwIcon } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useId, useState } from 'react';
import { CopyButton } from '@/components/copy-button';
import { VerdictBadge } from '@/components/domain/badges';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Textarea } from '@/components/ui/textarea';
import { callOperation } from '@/lib/api/call';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { OperationId, RequestBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan, useHasPermission } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { FeedsControl } from '@/features/api-mode/coverage-tab';
import {
  MAILBOX_PROFILE,
  MAILBOX_PURPOSE,
  SOURCE_LABEL,
  formatLagMs,
} from '@/features/api-mode/model';
import {
  DEFAULT_POLICY_MAPPING,
  DETECT_ONLY_DEFAULT_DAYS,
  HINT_TEXT,
  MAPPING_KEY_LABEL,
  POLICY_MAPPING_KEYS,
  POLICY_STATE_LABEL,
  SCOPE_KIND_LABEL,
  detectOnlyUntil,
  onboardingCodeText,
  type DomainOnboarding,
  type FirstCopyHint,
  type OnboardingStepView,
  type ScopeKind,
  type ScopeView,
} from '@/features/api-mode/parity-model';
import {
  STATE_LABEL,
  actionLabel,
  detectionHref,
  remediationErrorText,
  ruleConditionText,
  type PolicyDocument,
  type RemediationPolicyView,
} from '@/features/api-mode/remediation-model';
import { ConnectStep } from '@/features/integrations/providers/connect-step';
import { CONNECTION_QUERIES } from '@/features/integrations/providers/mail-flow-dialog';
import {
  GrantStatusBadge,
  MAIL_FLOW_PROFILE,
  PROVIDER_LABEL,
  errorHint,
  type Connection,
} from '@/features/integrations/providers/model';
import {
  intakeSourceHref,
  newIntakeSourceHref,
  IntakeHealthBadge,
  IntakeStatusBadge,
} from '@/features/journaling/model';
import { DetailList, LabelledSelect, MutationError } from './kit';
import { isOwned, type DomainDetail } from './model';

/**
 * The API-mode steps of the add-domain wizard (step API-4 B1, B2, B3, B6, B7, B8): ownership
 * (TXT only, or automatically through the bound provider tenant), connect (8.2 connection,
 * domain link, mail-flow and mailbox-access grants), intake (journal copy, feeds), which
 * mailboxes (scope), threat action (remediation presets, detect only for 7 days by default) and
 * review with activation and the live first-copy check. Every state comes from the api
 * (`GET /api-mode/domains/{id}/onboarding`); the steps never compute completion from clicks.
 * Users without a step's write operation see it read-only with "ask an administrator".
 */

/** Queries a wizard write makes stale. */
export const ONBOARDING_QUERIES: readonly OperationId[] = [
  'ApiModeOnboardingController_domainOnboarding_v1',
  'ApiModeOnboardingController_protectionCoverage_v1',
  'DomainsController_get_v1',
  'DomainsController_list_v1',
];

export const STATUS_TEXT: Record<OnboardingStepView['status'], string> = {
  not_started: 'Not started',
  in_progress: 'In progress',
  done: 'Done',
  blocked: 'Blocked',
  skipped: 'Skipped',
};

const STATUS_TONE = {
  not_started: 'neutral',
  in_progress: 'info',
  done: 'success',
  blocked: 'danger',
  skipped: 'neutral',
} as const;

export function OnboardingStatusBadge({ status }: { status: OnboardingStepView['status'] }) {
  return <ToneBadge tone={STATUS_TONE[status] ?? 'neutral'}>{STATUS_TEXT[status]}</ToneBadge>;
}

/** "Ask an administrator" for a step the user may only read. */
export function AskAdministrator({ what }: { what: string }) {
  return (
    <p role="note" className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
      You can see this step; {what} needs a permission your role does not have. Ask an administrator
      to complete it.
    </p>
  );
}

/** Blockers and the next action of a step, as the api computed them. */
export function StepFacts({ step }: { step: OnboardingStepView | undefined }) {
  if (!step) return null;
  return (
    <div className="grid gap-1 text-sm" aria-label="Step state">
      <span className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">State</span>
        <OnboardingStatusBadge status={step.status} />
      </span>
      {step.blockers.length > 0 ? (
        <ul className="grid gap-0.5 text-sm" aria-label="What is missing">
          {step.blockers.map((b) => (
            <li key={b}>Missing: {onboardingCodeText(b)}</li>
          ))}
        </ul>
      ) : null}
      {step.nextAction ? (
        <p className="text-xs text-muted-foreground">Next: {onboardingCodeText(step.nextAction)}</p>
      ) : null}
    </div>
  );
}

// ---- ownership (B1, B3) ----------------------------------------------------------------------

const PROVIDER_RESULT_TEXT: Record<string, string> = {
  verified: 'listed as verified for e-mail in your provider tenant',
  unverified: 'listed in the provider tenant but not verified there',
  absent: 'not listed in the provider tenant',
  alias: 'listed only as an alias in the provider tenant',
  error: 'the provider could not be asked (try again later)',
};

/**
 * "Verify automatically through <provider> (<connection>)" (B3): asks the integration-worker to
 * look up the domain in the organization's bound provider tenant; polls the domain while the
 * check is pending; the rate limit (429) shows a countdown.
 */
export function ProviderOwnershipCard({ domain }: { domain: DomainDetail }) {
  const selectId = useId();
  const canCheck = useCan('DomainsController_providerOwnershipCheck_v1');
  const canList = useCan('ProviderConnectionsController_list_v1');
  const connections = useApiQuery(
    'ProviderConnectionsController_list_v1',
    { query: { status: 'active', limit: '25' } },
    { enabled: canList && domain.ownership.providerCheckAvailable },
  );
  const [connectionId, setConnectionId] = useState('');
  const check = useApiMutation('DomainsController_providerOwnershipCheck_v1', {
    invalidates: ONBOARDING_QUERIES,
    successMessage: null,
  });
  if (!domain.ownership.providerCheckAvailable) return null;
  const candidates = (connections.data?.data ?? []).filter((c) => c.status === 'active');
  const latest = domain.ownership.providerCheck;
  const via = candidates.find((c) => c.id === (latest?.connectionId ?? connectionId));
  const named = via ?? (candidates.length === 1 ? candidates[0] : undefined);
  const title = named
    ? `Verify automatically through ${PROVIDER_LABEL[named.provider]} (${named.displayName})`
    : 'Verify automatically through Microsoft 365 or Google Workspace';
  const owned = isOwned(domain.status);
  const pending = latest?.status === 'pending';
  const needsChoice =
    candidates.length > 1 ||
    (check.error?.code === 'domain_provider_connection_unavailable' &&
      check.error.details.reason === 'connection_required');
  return (
    <section
      aria-label="Automatic ownership verification"
      className="grid gap-2 rounded-md border border-primary/40 p-3"
    >
      <h3 className="text-sm font-semibold">{title}</h3>
      <p className="text-xs text-muted-foreground">
        Your organization&apos;s provider tenant is already bound to the gateway. If it lists this
        domain as verified for e-mail, ownership is proven without a DNS change.
      </p>
      {latest ? (
        <p className="text-sm" role="status">
          {latest.status === 'pending'
            ? 'Checking with your provider… this page updates by itself.'
            : latest.status === 'verified'
              ? 'Verified: the domain is listed as verified in your provider tenant.'
              : latest.status === 'expired'
                ? 'The last check expired without an answer. Try again.'
                : `Not verified: the domain is ${PROVIDER_RESULT_TEXT[latest.result ?? 'error'] ?? humanize(latest.result ?? 'error')}. Publish the TXT record instead, or try again after fixing it in the provider.`}{' '}
          {latest.checkedAt ? (
            <span className="text-xs text-muted-foreground">
              (checked <DateTime value={latest.checkedAt} />)
            </span>
          ) : null}
        </p>
      ) : null}
      {owned ? null : canCheck ? (
        <div className="grid gap-2">
          {needsChoice && candidates.length > 0 ? (
            <LabelledSelect
              id={selectId}
              label="Connection to check with"
              value={connectionId}
              onChange={setConnectionId}
              options={candidates.map((c) => ({
                value: c.id,
                label: `${c.displayName} (${PROVIDER_LABEL[c.provider]})`,
              }))}
            />
          ) : null}
          <Button
            className="justify-self-start"
            disabled={
              check.isPending ||
              pending ||
              check.retryAfterSeconds > 0 ||
              (needsChoice && candidates.length > 0 && !connectionId)
            }
            onClick={() =>
              void check.submit({
                path: { domainId: domain.id },
                body: connectionId ? { connectionId } : {},
              })
            }
          >
            {check.retryAfterSeconds > 0
              ? `Try again in ${check.retryAfterSeconds} s`
              : pending
                ? 'Checking …'
                : 'Verify automatically'}
          </Button>
          {check.error && check.error.status !== 429 ? <MutationError error={check.error} /> : null}
          {check.error?.status === 429 ? (
            <p role="alert" className="text-sm text-destructive">
              Too many automatic checks this hour; try again when the countdown ends.
            </p>
          ) : null}
        </div>
      ) : (
        <AskAdministrator what="starting an automatic ownership check" />
      )}
    </section>
  );
}

/** API-mode ownership step (B1): only the TXT ownership record, "Check now" and the provider card. */
export function OwnershipStep({ domain }: { domain: DomainDetail }) {
  const queryClient = useQueryClient();
  const canVerify = useCan('DomainDnsController_verify_v1');
  const verify = useApiMutation('DomainDnsController_verify_v1', {
    invalidates: ONBOARDING_QUERIES,
    successMessage: null,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['DomainsController_get_v1'] }),
  });
  const v = domain.verification;
  const owned = isOwned(domain.status);
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      {owned ? (
        <p role="status" className="text-sm">
          Ownership is verified
          {domain.ownership.method === 'provider_tenant'
            ? ' through your provider tenant'
            : domain.ownership.method === 'dns_txt'
              ? ' with the DNS TXT record'
              : ''}
          .
        </p>
      ) : null}
      <ProviderOwnershipCard domain={domain} />
      {v ? (
        <section aria-label="Ownership TXT record" className="grid gap-2 rounded-md border p-3">
          <h3 className="text-sm font-semibold">Ownership TXT record</h3>
          <p className="text-xs text-muted-foreground">
            API mode needs no MX, SPF, DKIM or DMARC change: publish only this record at your DNS
            host.
          </p>
          <DetailList
            items={[
              { label: 'Type', value: 'TXT' },
              {
                label: 'Host',
                value: (
                  <span className="flex flex-wrap items-center gap-2">
                    <code className="font-mono text-xs break-all">{v.host}</code>
                    <CopyButton value={v.host} label="Copy host" />
                  </span>
                ),
              },
              {
                label: 'Value',
                value: (
                  <span className="flex flex-wrap items-center gap-2">
                    <code className="font-mono text-xs break-all">{v.value}</code>
                    <CopyButton value={v.value} label="Copy value" />
                  </span>
                ),
              },
              {
                label: 'Last check',
                value: (
                  <span>
                    <DateTime value={v.lastCheckedAt} emptyLabel="not yet run" />
                    {v.lastOutcome ? ` · ${humanize(v.lastOutcome)}` : ''}
                  </span>
                ),
              },
            ]}
          />
          {owned ? null : canVerify ? (
            <Button
              variant="outline"
              className="justify-self-start"
              disabled={verify.isPending || verify.retryAfterSeconds > 0}
              onClick={() => void verify.submit({ path: { id: domain.id } })}
            >
              <RefreshCwIcon
                aria-hidden
                className={verify.isPending ? 'animate-spin' : undefined}
              />
              {verify.isPending
                ? 'Checking DNS …'
                : verify.retryAfterSeconds > 0
                  ? `Check now (${verify.retryAfterSeconds} s)`
                  : 'Check now'}
            </Button>
          ) : (
            <AskAdministrator what="checking the record" />
          )}
          <MutationError error={verify.error} />
          {!owned ? (
            <p className="text-xs text-muted-foreground" role="status">
              {domain.status === 'failed'
                ? 'Verification failed: check the record and run Check now again.'
                : 'DNS changes can take minutes to hours to reach every resolver; the gateway keeps checking in the background.'}
            </p>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}

// ---- connect (B1, B4) ------------------------------------------------------------------------

function LinkDomainToConnection({ domain }: { domain: DomainDetail }) {
  const selectId = useId();
  const canList = useCan('ProviderConnectionsController_list_v1');
  const canLink = useCan('ProviderDomainsController_replace_v1');
  const list = useApiQuery(
    'ProviderConnectionsController_list_v1',
    { query: { limit: '50' } },
    { enabled: canList },
  );
  const [connectionId, setConnectionId] = useState('');
  const [failure, setFailure] = useState<string | null>(null);
  const link = useApiMutation('ProviderDomainsController_replace_v1', {
    invalidates: [...CONNECTION_QUERIES, ...ONBOARDING_QUERIES],
    successMessage: `${domain.unicodeName} linked. The gateway checks it in the provider tenant now.`,
  });
  const options = (list.data?.data ?? []).filter((c) => c.status !== 'disabled');
  const owned = isOwned(domain.status);
  return (
    <div className="grid gap-3">
      <p className="text-sm">
        No Microsoft 365 or Google Workspace connection is linked to {domain.unicodeName} yet. Link
        it to an existing connection of your provider, or create a new connection (admin consent,
        then link the domain).
      </p>
      {!owned ? (
        <p className="text-xs text-muted-foreground">
          A domain can be linked once its ownership is verified.
        </p>
      ) : null}
      {canLink && canList ? (
        list.isLoading ? (
          <LoadingState label="Loading the provider connections" rows={2} />
        ) : options.length > 0 ? (
          <div className="grid max-w-md gap-2">
            <LabelledSelect
              id={selectId}
              label="Existing connection"
              value={connectionId}
              onChange={setConnectionId}
              options={options.map((c) => ({
                value: c.id,
                label: `${c.displayName} (${PROVIDER_LABEL[c.provider]})`,
              }))}
            />
            <Button
              className="justify-self-start"
              disabled={!connectionId || !owned || link.isPending}
              onClick={() => {
                setFailure(null);
                void (async () => {
                  try {
                    const current = await callOperation('ProviderConnectionsController_get_v1', {
                      path: { id: connectionId },
                    });
                    const ids = [...new Set([...current.domains.map((d) => d.id), domain.id])];
                    await link.submit({ path: { id: connectionId }, body: { domainIds: ids } });
                  } catch {
                    setFailure('The connection could not be read; try again.');
                  }
                })();
              }}
            >
              {link.isPending ? 'Linking …' : `Link ${domain.unicodeName}`}
            </Button>
            {failure ? (
              <p role="alert" className="text-sm text-destructive">
                {failure}
              </p>
            ) : null}
            {link.error ? (
              <div className="grid gap-1">
                <MutationError error={link.error} />
                {errorHint(link.error.code) ? (
                  <p className="text-xs text-muted-foreground">{errorHint(link.error.code)}</p>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">No provider connection exists yet.</p>
        )
      ) : (
        <AskAdministrator what="linking a provider connection" />
      )}
      <Can op="ProviderConnectionsController_create_v1">
        <Button asChild variant="outline" className="justify-self-start">
          <Link href="/integrations/providers/new">Create a new connection</Link>
        </Button>
      </Can>
    </div>
  );
}

function LinkedConnection({
  connectionId,
  onboarding,
}: {
  connectionId: string;
  onboarding: DomainOnboarding;
}) {
  const canRead = useCan('ProviderConnectionsController_get_v1');
  const canWriteRemediation = useHasPermission('remediation:write');
  const connection = useApiQuery(
    'ProviderConnectionsController_get_v1',
    { path: { id: connectionId } },
    {
      enabled: canRead,
      refetchInterval: (query) =>
        query.state.data?.grants.some((g) => g.status === 'verifying') ? 5000 : false,
    },
  );
  const catalog = useApiQuery('ProviderCatalogController_get_v1', undefined, {
    staleTime: 300_000,
    enabled: canRead,
  });
  const view = onboarding.connection!;
  const facts = (
    <DetailList
      items={[
        {
          label: 'Connection',
          value: (
            <Link
              href={`/integrations/providers/${view.id}`}
              className="text-primary underline underline-offset-2"
            >
              {connection.data?.displayName ?? `${PROVIDER_LABEL[view.provider]} connection`}
            </Link>
          ),
        },
        { label: 'Provider', value: PROVIDER_LABEL[view.provider] },
        { label: 'Status', value: humanize(view.status) },
        {
          label: 'Tenant binding',
          value: view.bound
            ? 'Bound (the tenant is proven by a DNS-verified domain)'
            : 'Not bound yet: a DNS-verified domain linked to the connection must be verified in the tenant',
        },
        {
          label: 'Mail-flow grant (read only)',
          value: view.mailFlowGrant ? (
            <GrantStatusBadge status={view.mailFlowGrant} />
          ) : (
            'Not granted'
          ),
        },
        {
          label: 'Mailbox access',
          value: view.mailboxAccessGrant ? (
            <GrantStatusBadge status={view.mailboxAccessGrant} />
          ) : (
            'Not granted'
          ),
        },
      ]}
    />
  );
  if (!canRead) return facts;
  if (connection.isLoading) return <LoadingState label="Loading the connection" rows={3} />;
  if (connection.error)
    return <ErrorState error={connection.error} onRetry={() => void connection.refetch()} />;
  const c: Connection | undefined = connection.data;
  if (!c) return facts;
  const provider = catalog.data?.providers.find((p) => p.provider === c.provider);
  const mailFlowProfile = provider?.profiles.find((p) => p.purpose === 'mail_flow');
  const mailboxProfile = provider?.profiles.find(
    (p) => p.key === MAILBOX_PROFILE[c.provider] || p.purpose === MAILBOX_PURPOSE,
  );
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      {facts}
      {view.mailFlowGrant !== 'active' ? (
        <section aria-label="Mail-flow grant" className="grid gap-2 rounded-md border p-3">
          <h3 className="text-sm font-semibold">Read-only mail-flow access</h3>
          <p className="text-xs text-muted-foreground">
            Needed to bind the tenant and to verify domains through the provider. It reads the
            tenant&apos;s domains and connectors; it never changes mail flow.
          </p>
          <ConnectStep
            connection={c}
            profile={mailFlowProfile}
            profileKey={MAIL_FLOW_PROFILE[c.provider]}
          />
        </section>
      ) : null}
      <section
        aria-label="Mailbox access for API mode"
        className="grid gap-2 rounded-md border p-3"
      >
        <h3 className="text-sm font-semibold">Mailbox access for API mode</h3>
        {!canWriteRemediation ? (
          <AskAdministrator what="granting mailbox access (remediation write)" />
        ) : null}
        {mailboxProfile ? (
          <ConnectStep
            connection={c}
            profile={mailboxProfile}
            profileKey={MAILBOX_PROFILE[c.provider]}
            allowed={canWriteRemediation}
            intro="Lets the gateway read new messages of in-scope mailboxes for scanning and move detected threats out of the mailbox. A separate grant: it does not change mail flow."
          />
        ) : (
          <p className="text-sm text-muted-foreground">
            The provider catalogue does not offer mailbox access on this gateway.
          </p>
        )}
      </section>
      <p className="text-sm">
        <Link
          href={`/integrations/providers/${c.id}`}
          className="text-primary underline underline-offset-2"
        >
          Open the connection
        </Link>{' '}
        for its setup, health and guide.
      </p>
    </div>
  );
}

/** Connect step (B1): link to a connection or create one, then the grants (8.2, API-1 D4). */
export function ApiConnectStep({
  domain,
  onboarding,
}: {
  domain: DomainDetail;
  onboarding: DomainOnboarding;
}) {
  if (onboarding.connection === null) return <LinkDomainToConnection domain={domain} />;
  return <LinkedConnection connectionId={onboarding.connection.id} onboarding={onboarding} />;
}

// ---- intake (B1) -----------------------------------------------------------------------------

export function IntakeStep({ onboarding }: { onboarding: DomainOnboarding }) {
  const canConnections = useCan('ApiModeController_listConnections_v1');
  const connections = useApiQuery('ApiModeController_listConnections_v1', undefined, {
    enabled: canConnections && onboarding.connection !== null,
  });
  const canCreateSource = useCan('IntakeSourcesController_create_v1');
  if (onboarding.connection === null) {
    return (
      <p className="text-sm text-muted-foreground">
        Link the domain to a provider connection first (Connect mailboxes).
      </p>
    );
  }
  const provider = onboarding.connection.provider;
  const row = connections.data?.data.find((c) => c.id === onboarding.connection!.id);
  const sources = onboarding.intake.journalSources;
  const feeds = onboarding.intake.feeds;
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      <p className="text-sm">
        The gateway needs a copy of each delivered message. A <strong>journal copy</strong>{' '}
        (recommended) covers every mailbox at once; <strong>mailbox feeds</strong> read new messages
        through the mailbox-access grant. Either one completes this step.
      </p>
      <section aria-label="Journal copy" className="grid gap-2 rounded-md border p-3">
        <h3 className="text-sm font-semibold">Journal copy (recommended)</h3>
        {sources.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No journal intake source on this connection yet.
          </p>
        ) : (
          <ul className="grid gap-2" aria-label="Journal sources">
            {sources.map((s) => (
              <li key={s.id} className="flex flex-wrap items-center gap-2 text-sm">
                <Link
                  href={intakeSourceHref(s.id)}
                  className="text-primary underline underline-offset-2"
                >
                  Journal source
                  <span className="sr-only"> {s.id}</span>
                </Link>
                <IntakeStatusBadge status={s.status} />
                <IntakeHealthBadge health={s.health} />
                <Link
                  href={intakeSourceHref(s.id, 'guide')}
                  className="text-xs text-primary underline underline-offset-2"
                >
                  Setup guide (journal rule)
                </Link>
                <Link
                  href={intakeSourceHref(s.id, 'address')}
                  className="text-xs text-primary underline underline-offset-2"
                >
                  Journal address
                </Link>
              </li>
            ))}
          </ul>
        )}
        {canCreateSource ? (
          <Button asChild variant="outline" size="sm" className="justify-self-start">
            <Link
              href={newIntakeSourceHref(
                provider === 'microsoft_365' ? 'microsoft_365_journal' : 'google_workspace_copy',
              )}
            >
              Set up a journal copy
            </Link>
          </Button>
        ) : (
          <AskAdministrator what="creating a journal intake source" />
        )}
      </section>
      <section aria-label="Mailbox feeds" className="grid gap-2 rounded-md border p-3">
        <h3 className="text-sm font-semibold">Mailbox feeds</h3>
        <p className="text-sm">
          {feeds.enabled
            ? `On (${humanize(feeds.mode)}): ${formatNumber(feeds.activeMailboxes)} of ${formatNumber(feeds.inScopeMailboxes)} in-scope mailboxes active.`
            : 'Off.'}
        </p>
        {row ? <FeedsControl connection={row} /> : null}
      </section>
    </div>
  );
}

// ---- which mailboxes (B6) --------------------------------------------------------------------

function scopeErrorText(code: string | undefined): string | null {
  switch (code) {
    case 'api_mode_scope_conflict':
      return 'Someone else changed the scope since you opened it. The current scope was loaded; review it and save again.';
    case 'api_mode_scope_department_invalid':
      return 'A chosen department no longer exists.';
    case 'api_mode_scope_mailbox_invalid':
      return 'A chosen mailbox does not belong to this domain.';
    case 'api_mode_scope_domain_not_api':
      return 'The domain is not in API or Hybrid mode.';
    default:
      return null;
  }
}

function MailboxPicker({
  domainId,
  selected,
  onChange,
  disabled,
}: {
  domainId: string;
  selected: ReadonlySet<string>;
  onChange: (next: Set<string>) => void;
  disabled: boolean;
}) {
  const list = useCursorList('ApiModeController_listMailboxes_v1', { domainId }, { limit: 50 });
  if (list.query.isLoading) return <LoadingState label="Loading the domain's mailboxes" rows={3} />;
  if (list.query.error)
    return (
      <ErrorState error={list.query.error} onRetry={() => void list.query.refetch()} compact />
    );
  return (
    <fieldset className="grid gap-2">
      <legend className="text-sm font-medium">Mailboxes of the domain</legend>
      {list.rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No mailbox is known yet: run a mailbox inventory sync or wait for the first journal copy.
        </p>
      ) : (
        <ul className="grid gap-2 sm:grid-cols-2">
          {list.rows.map((m) => {
            const id = `scope-${m.id}`;
            return (
              <li key={m.id} className="flex min-w-0 items-center gap-2">
                <Checkbox
                  id={id}
                  disabled={disabled}
                  checked={selected.has(m.id)}
                  onCheckedChange={(checked) => {
                    const next = new Set(selected);
                    if (checked === true) next.add(m.id);
                    else next.delete(m.id);
                    onChange(next);
                  }}
                />
                <Label htmlFor={id} className="min-w-0 font-normal">
                  <UntrustedText value={m.address} mono maxLength={60} />
                </Label>
              </li>
            );
          })}
        </ul>
      )}
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span>
          Page {list.page} · {formatNumber(selected.size)} selected
        </span>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={!list.hasPrevious}
          onClick={list.previous}
        >
          Previous
        </Button>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={!list.hasNext}
          onClick={list.next}
        >
          Next
        </Button>
      </div>
    </fieldset>
  );
}

type ScopeSave = ReturnType<typeof useScopeSave>;

function useScopeSave() {
  return useApiMutation('ApiModeOnboardingController_putScope_v1', {
    invalidates: ['ApiModeOnboardingController_getScope_v1', ...ONBOARDING_QUERIES],
    successMessage: 'Mailbox scope saved. The gateway applies it within a minute.',
  });
}

function ScopeEditor({
  domainId,
  view,
  save,
}: {
  domainId: string;
  view: ScopeView;
  /** Owned by the step so a CAS conflict's message survives the reload of the scope. */
  save: ScopeSave;
}) {
  const base = useId();
  const queryClient = useQueryClient();
  const canWrite = useCan('ApiModeOnboardingController_putScope_v1');
  const canDepartments = useCan('DepartmentsController_list_v1');
  const departments = useApiQuery(
    'DepartmentsController_list_v1',
    { query: { limit: 100 } },
    { enabled: canDepartments },
  );
  const canMailboxes = useCan('ApiModeController_listMailboxes_v1');
  const initialMailboxes = useApiQuery(
    'ApiModeController_listMailboxes_v1',
    { query: { domainId, limit: '100' } },
    { enabled: canMailboxes && view.kind === 'mailboxes' },
  );
  const [kind, setKind] = useState<ScopeKind>(view.kind);
  const [chosen, setChosen] = useState<Set<string>>(
    () => new Set(view.departments.map((d) => d.id)),
  );
  const [mailboxes, setMailboxes] = useState<Set<string>>(new Set());
  const [touchedMailboxes, setTouchedMailboxes] = useState(false);
  const [reason, setReason] = useState('');
  const [hints, setHints] = useState<string[]>([]);
  // Selected mailboxes are the domain's mailboxes that are in scope (not `out_of_scope`).
  useEffect(() => {
    if (touchedMailboxes || view.kind !== 'mailboxes' || !initialMailboxes.data) return;
    setMailboxes(
      new Set(
        initialMailboxes.data.data.filter((m) => m.coverage !== 'out_of_scope').map((m) => m.id),
      ),
    );
  }, [initialMailboxes.data, touchedMailboxes, view.kind]);
  const submit = () => {
    const problems: string[] = [];
    if (kind === 'departments' && chosen.size === 0)
      problems.push('Choose at least one department.');
    if (kind === 'departments' && chosen.size > 20) problems.push('Choose at most 20 departments.');
    if (!reason.trim()) problems.push('Enter a reason.');
    setHints(problems);
    if (problems.length > 0) return;
    const body: RequestBody<'ApiModeOnboardingController_putScope_v1'> = {
      scope: kind === 'departments' ? { kind, departmentIds: [...chosen] } : { kind },
      ...(kind === 'mailboxes' ? { mailboxIds: [...mailboxes] } : {}),
      reason: reason.trim(),
      expectedRowVersion: view.rowVersion,
    };
    void save.submit({ path: { domainId }, body }).then(async (outcome) => {
      if (!outcome.ok && outcome.error.code === 'api_mode_scope_conflict')
        await queryClient.invalidateQueries({
          queryKey: ['ApiModeOnboardingController_getScope_v1'],
        });
    });
  };
  const errorText = scopeErrorText(save.error?.code);
  const readOnly = !canWrite;
  return (
    <form
      aria-label="Which mailboxes"
      className="grid gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <fieldset className="grid gap-2">
        <legend className="text-sm font-medium">Protect</legend>
        <RadioGroup
          value={kind}
          onValueChange={(value) => setKind(value as ScopeKind)}
          className="grid gap-2"
          disabled={readOnly}
        >
          {(['all', 'departments', 'mailboxes'] as const).map((value) => (
            <div key={value} className="flex items-center gap-2">
              <RadioGroupItem id={`${base}-${value}`} value={value} />
              <Label htmlFor={`${base}-${value}`} className="font-normal">
                {SCOPE_KIND_LABEL[value]}
                {value === 'all' ? ' (recommended)' : ''}
              </Label>
            </div>
          ))}
        </RadioGroup>
        <p className="text-xs text-muted-foreground">
          Mailboxes outside the scope are still recorded for visibility, but never remediated or
          read by feeds. New mailboxes of a department scope are protected until the next
          evaluation.
        </p>
      </fieldset>
      {kind === 'departments' ? (
        canDepartments ? (
          departments.isLoading ? (
            <LoadingState label="Loading the departments" rows={2} />
          ) : (
            <fieldset className="grid gap-2">
              <legend className="text-sm font-medium">Departments (policy directory)</legend>
              {(departments.data?.data ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No department exists yet: add them under Users → Departments.
                </p>
              ) : (
                <ul className="grid gap-2 sm:grid-cols-2">
                  {(departments.data?.data ?? []).map((d) => {
                    const id = `${base}-dept-${d.id}`;
                    return (
                      <li key={d.id} className="flex items-center gap-2">
                        <Checkbox
                          id={id}
                          disabled={readOnly}
                          checked={chosen.has(d.id)}
                          onCheckedChange={(checked) =>
                            setChosen((prev) => {
                              const next = new Set(prev);
                              if (checked === true) next.add(d.id);
                              else next.delete(d.id);
                              return next;
                            })
                          }
                        />
                        <Label htmlFor={id} className="font-normal">
                          <UntrustedText value={d.name} maxLength={80} /> (
                          {formatNumber(d.memberCount)} members)
                        </Label>
                      </li>
                    );
                  })}
                </ul>
              )}
            </fieldset>
          )
        ) : (
          <p className="text-sm text-muted-foreground">
            Listing departments needs the policy directory read permission.
          </p>
        )
      ) : null}
      {kind === 'mailboxes' ? (
        canMailboxes ? (
          <MailboxPicker
            domainId={domainId}
            selected={mailboxes}
            disabled={readOnly}
            onChange={(next) => {
              setTouchedMailboxes(true);
              setMailboxes(next);
            }}
          />
        ) : (
          <p className="text-sm text-muted-foreground">Listing mailboxes needs remediation read.</p>
        )
      ) : null}
      {readOnly ? (
        <AskAdministrator what="changing the mailbox scope (remediation write)" />
      ) : (
        <>
          <div className="grid gap-2">
            <Label htmlFor={`${base}-reason`}>Reason (required)</Label>
            <Textarea
              id={`${base}-reason`}
              rows={2}
              maxLength={500}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
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
              {errorText ? (
                <p className="text-sm font-medium text-destructive">{errorText}</p>
              ) : null}
              <MutationError error={save.error} />
            </div>
          ) : null}
          <Button type="submit" className="justify-self-start" disabled={save.isPending}>
            {save.isPending ? 'Saving …' : 'Save mailbox scope'}
          </Button>
        </>
      )}
    </form>
  );
}

export function MailboxesStep({ domainId }: { domainId: string }) {
  const canRead = useCan('ApiModeOnboardingController_getScope_v1');
  const save = useScopeSave();
  const scope = useApiQuery(
    'ApiModeOnboardingController_getScope_v1',
    { path: { domainId } },
    { enabled: canRead },
  );
  if (!canRead) return <AskAdministrator what="reading the mailbox scope (remediation read)" />;
  if (scope.isLoading) return <LoadingState label="Loading the mailbox scope" rows={3} />;
  if (scope.error) return <ErrorState error={scope.error} onRetry={() => void scope.refetch()} />;
  if (!scope.data) return null;
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      <p className="text-sm" role="status">
        {SCOPE_KIND_LABEL[scope.data.kind]}: {formatNumber(scope.data.inScope)} in scope,{' '}
        {formatNumber(scope.data.excluded)} excluded
        {scope.data.recomputePending ? ' (being re-evaluated)' : ''}.
      </p>
      <ScopeEditor
        key={`${scope.data.rowVersion ?? 'new'}`}
        domainId={domainId}
        view={scope.data}
        save={save}
      />
    </div>
  );
}

// ---- threat action (B1, B7) ------------------------------------------------------------------

export const ACTION_PRESETS = [
  'detectOnlyRemind',
  'detectOnlyEnforce',
  'p1',
  'strict',
  'organization',
] as const;
export type ActionPreset = (typeof ACTION_PRESETS)[number];

export const ACTION_PRESET_LABEL: Record<ActionPreset, string> = {
  detectOnlyRemind: 'Detect only for 7 days, then remind me (recommended)',
  detectOnlyEnforce: 'Detect only for 7 days, then enforce automatically',
  p1: 'Enforce now (standard P1)',
  strict: 'Strict',
  organization: 'Use the organization policy',
};

const ACTION_PRESET_TEXT: Record<ActionPreset, string> = {
  detectOnlyRemind:
    'Decisions are recorded as simulated for 7 days; nothing in mailboxes changes. When the period ends you get a reminder to review the simulated actions and switch to enforce.',
  detectOnlyEnforce:
    'Decisions are simulated for 7 days, then the policy switches to enforce by itself (audited, with an alert).',
  p1: 'Mailbox actions run within seconds of the verdict, with the standard platform rules.',
  strict: 'The standard rules plus spam to Junk; mailbox actions run at once.',
  organization:
    'No domain override: the organization policy (or the platform default) applies to this domain.',
};

/** The preset the stored action corresponds to (server state; `null` = a custom policy). */
export function presetOf(action: DomainOnboarding['action']): ActionPreset | null {
  if (action.source !== 'domain') return 'organization';
  if (action.presetKey === 'strict') return 'strict';
  if (action.presetKey === 'p1') return 'p1';
  if (action.presetKey === 'detectOnlyStart')
    return action.detectOnly?.then === 'enforce' ? 'detectOnlyEnforce' : 'detectOnlyRemind';
  return null;
}

/** The PUT body of a preset (B7: detect only with `until = now + 7 days`). */
export function presetBody(
  preset: Exclude<ActionPreset, 'organization'>,
  presets: RemediationPolicyView['presets'],
  expectedRowVersion: number | null,
  now: number = Date.now(),
): RequestBody<'ApiModeRemediationController_putDomainPolicy_v1'> {
  const reason = `Add-domain wizard: ${ACTION_PRESET_LABEL[preset]}`;
  if (preset === 'detectOnlyRemind' || preset === 'detectOnlyEnforce') {
    return {
      mode: 'detect_only',
      document: presets.detectOnlyStart.document,
      detectOnly: {
        until: detectOnlyUntil(DETECT_ONLY_DEFAULT_DAYS, now),
        then: preset === 'detectOnlyRemind' ? 'remind' : 'enforce',
      },
      reason,
      expectedRowVersion,
    };
  }
  const p = presets[preset];
  return { mode: 'enforce', document: p.document, reason, expectedRowVersion };
}

const VERDICT_ROWS = ['malware', 'phishing', 'suspicious', 'spam'] as const;

/** What a document does for malware, phishing, suspicious and spam (first matching rule). */
function verdictEffect(document: PolicyDocument, verdict: (typeof VERDICT_ROWS)[number]): string {
  const rules = document.rules.filter((r) =>
    (r.when.verdicts as readonly string[]).includes(verdict),
  );
  if (rules.length === 0) return 'No action';
  return rules.map((r) => `${actionLabel(r.action)} (${ruleConditionText(r)})`).join('; then ');
}

function PresetExplanation({
  preset,
  policy,
}: {
  preset: ActionPreset;
  policy: RemediationPolicyView;
}) {
  const document =
    preset === 'organization'
      ? policy.organization.document
      : preset === 'strict'
        ? policy.presets.strict.document
        : preset === 'p1'
          ? policy.presets.p1.document
          : policy.presets.detectOnlyStart.document;
  const mapping =
    preset === 'organization' ? policy.organization.effectivePolicyMapping : DEFAULT_POLICY_MAPPING;
  const simulated = preset === 'detectOnlyRemind' || preset === 'detectOnlyEnforce';
  return (
    <div className="grid gap-2 rounded-md border p-3 text-sm" aria-label="What this choice does">
      <p>{ACTION_PRESET_TEXT[preset]}</p>
      <ul className="grid gap-0.5 text-xs">
        {VERDICT_ROWS.map((verdict) => (
          <li key={verdict}>
            <span className="font-medium">{humanize(verdict)}:</span>{' '}
            {verdictEffect(document, verdict)}
            {simulated ? ' (simulated)' : ''}
          </li>
        ))}
        {POLICY_MAPPING_KEYS.map((key) => (
          <li key={key}>
            <span className="font-medium">{MAPPING_KEY_LABEL[key]}:</span>{' '}
            {actionLabel(mapping[key])}
            {simulated ? ' (simulated)' : ''}
          </li>
        ))}
      </ul>
      <p className="text-xs text-muted-foreground">
        The policy rows apply to your own policy rules and the mandatory platform floor (DLP, hard
        blocks). The platform default&apos;s risk recommendation alone never overrides the verdict
        rows; the stronger of the two applies.
      </p>
    </div>
  );
}

export function ActionStep({
  domainId,
  onboarding,
}: {
  domainId: string;
  onboarding: DomainOnboarding;
}) {
  const base = useId();
  const canRead = useCan('ApiModeRemediationController_getPolicy_v1');
  const canPut = useCan('ApiModeRemediationController_putDomainPolicy_v1');
  const canDelete = useCan('ApiModeRemediationController_deleteDomainPolicy_v1');
  const policy = useApiQuery('ApiModeRemediationController_getPolicy_v1', undefined, {
    enabled: canRead,
  });
  const stored = presetOf(onboarding.action);
  const [preset, setPreset] = useState<ActionPreset>(
    onboarding.action.source === 'platform_default'
      ? 'detectOnlyRemind'
      : (stored ?? 'detectOnlyRemind'),
  );
  const put = useApiMutation('ApiModeRemediationController_putDomainPolicy_v1', {
    invalidates: ['ApiModeRemediationController_getPolicy_v1', ...ONBOARDING_QUERIES],
    successMessage: 'Threat action saved for the domain.',
  });
  const remove = useApiMutation('ApiModeRemediationController_deleteDomainPolicy_v1', {
    invalidates: ['ApiModeRemediationController_getPolicy_v1', ...ONBOARDING_QUERIES],
    successMessage: 'The domain uses the organization policy.',
  });
  if (!canRead)
    return <AskAdministrator what="reading the remediation policy (remediation read)" />;
  if (policy.isLoading) return <LoadingState label="Loading the remediation policy" rows={3} />;
  if (policy.error)
    return <ErrorState error={policy.error} onRetry={() => void policy.refetch()} />;
  if (!policy.data) return null;
  const override = policy.data.domains.find((d) => d.domainId === domainId) ?? null;
  const canWrite = preset === 'organization' ? canDelete || override === null : canPut;
  const error = put.error ?? remove.error;
  const errorText = remediationErrorText(error);
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      <p className="text-sm" role="status">
        Current: {stored ? ACTION_PRESET_LABEL[stored] : 'a custom domain policy'}
        {onboarding.action.detectOnly ? (
          <>
            {' '}
            · detect only until{' '}
            <DateTime value={onboarding.action.detectOnly.until} mode="absolute" />
          </>
        ) : null}
        .
      </p>
      <fieldset className="grid gap-2">
        <legend className="text-sm font-medium">When a threat is detected in a mailbox</legend>
        <RadioGroup
          value={preset}
          onValueChange={(value) => setPreset(value as ActionPreset)}
          className="grid gap-2"
        >
          {ACTION_PRESETS.map((value) => (
            <div key={value} className="flex items-center gap-2">
              <RadioGroupItem id={`${base}-${value}`} value={value} />
              <Label htmlFor={`${base}-${value}`} className="font-normal">
                {ACTION_PRESET_LABEL[value]}
              </Label>
            </div>
          ))}
        </RadioGroup>
      </fieldset>
      <PresetExplanation preset={preset} policy={policy.data} />
      {canWrite ? (
        <Button
          className="justify-self-start"
          disabled={put.isPending || remove.isPending}
          onClick={() => {
            if (preset === 'organization') {
              if (override) void remove.submit({ path: { domainId } });
              return;
            }
            void put.submit({
              path: { domainId },
              body: presetBody(preset, policy.data.presets, override?.rowVersion ?? null),
            });
          }}
        >
          {put.isPending || remove.isPending ? 'Saving …' : 'Save threat action'}
        </Button>
      ) : (
        <AskAdministrator what="choosing the threat action (remediation write)" />
      )}
      {error ? (
        <div role="alert" className="grid gap-1">
          {errorText ? <p className="text-sm font-medium text-destructive">{errorText}</p> : null}
          <MutationError error={error} />
        </div>
      ) : null}
    </div>
  );
}

// ---- review and first copy (B1, B8) -----------------------------------------------------------

/** Hint links of the api, mapped to the portal's pages (WP4 open item). */
export function hintHref(hint: Pick<FirstCopyHint, 'link'>): string | null {
  const link = hint.link;
  if (!link) return null;
  if (link === '/journaling') return '/settings?tab=journaling';
  if (link === '/integrations/providers') return '/integrations';
  if (link.startsWith('/api-mode?tab=connections')) return '/api-mode?tab=coverage';
  return link;
}

export function FirstCopyCheck({ onboarding }: { onboarding: DomainOnboarding }) {
  const first = onboarding.firstCopy;
  if (first.status === 'received' && first.copy) {
    const c = first.copy;
    return (
      <section aria-label="First copy" className="grid gap-2 rounded-md border p-3">
        <h3 className="text-sm font-semibold">First message received</h3>
        <DetailList
          items={[
            { label: 'Verdict', value: <VerdictBadge verdict={c.verdict} /> },
            { label: 'Received', value: <DateTime value={c.receivedAt} mode="absolute" /> },
            { label: 'Lag', value: formatLagMs(c.lagMs) },
            { label: 'Source', value: SOURCE_LABEL[c.source] },
            { label: 'Policy', value: POLICY_STATE_LABEL[c.policyState] },
            { label: 'Remediation', value: STATE_LABEL[c.remediationState] },
          ]}
        />
        <Link
          href={detectionHref(c.detectionId)}
          className="text-sm text-primary underline underline-offset-2"
        >
          Open the detection
        </Link>
      </section>
    );
  }
  return (
    <section
      aria-label="First copy"
      className="grid gap-2 rounded-md border p-3"
      aria-live="polite"
    >
      <h3 className="text-sm font-semibold">Waiting for the first message…</h3>
      <p className="text-sm">
        Send a test message to any mailbox of the domain. This check refreshes every 5 seconds while
        the page is open.
        {first.waitingSinceMinutes !== null
          ? ` Waiting for ${formatNumber(first.waitingSinceMinutes)} minute${first.waitingSinceMinutes === 1 ? '' : 's'}.`
          : ''}
      </p>
      {first.hints.length > 0 ? (
        <ul className="grid gap-1 text-sm" aria-label="Troubleshooting hints">
          {first.hints.map((hint) => {
            const href = hintHref(hint);
            return (
              <li key={hint.code} className="flex flex-wrap items-center gap-2">
                <ToneBadge tone={hint.severity === 'warn' ? 'warning' : 'info'}>
                  {hint.severity === 'warn' ? 'Check' : 'Tip'}
                </ToneBadge>
                <span>{HINT_TEXT[hint.code] ?? humanize(hint.code)}</span>
                {href ? (
                  <Link href={href} className="text-primary underline underline-offset-2">
                    Fix
                    <span className="sr-only"> {humanize(hint.code)}</span>
                  </Link>
                ) : null}
              </li>
            );
          })}
        </ul>
      ) : null}
    </section>
  );
}

export const API_STEP_LABEL: Record<OnboardingStepView['key'], string> = {
  ownership: 'Verify ownership',
  connect: 'Connect mailboxes',
  intake: 'Intake',
  mailboxes: 'Which mailboxes',
  action: 'Threat action',
  review: 'Review and activate',
};

export function ReviewSummary({
  onboarding,
  onEdit,
}: {
  onboarding: DomainOnboarding;
  onEdit: (key: OnboardingStepView['key']) => void;
}) {
  return (
    <ul className="grid gap-2" aria-label="Summary">
      {onboarding.steps
        .filter((s) => s.key !== 'review' && s.status !== 'skipped')
        .map((s) => (
          <li
            key={s.key}
            className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2 text-sm"
          >
            <span className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{API_STEP_LABEL[s.key]}</span>
              <OnboardingStatusBadge status={s.status} />
              {s.blockers.length > 0 ? (
                <span className="text-xs text-muted-foreground">
                  {s.blockers.map(onboardingCodeText).join('; ')}
                </span>
              ) : null}
            </span>
            <Button size="sm" variant="ghost" onClick={() => onEdit(s.key)}>
              Edit <span className="sr-only">{API_STEP_LABEL[s.key]}</span>
            </Button>
          </li>
        ))}
    </ul>
  );
}
