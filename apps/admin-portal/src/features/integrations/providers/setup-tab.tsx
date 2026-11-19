'use client';

import { CheckCircle2Icon, CircleDotIcon, CircleIcon, LockIcon } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useId, useState } from 'react';
import { CopyButton } from '@/components/copy-button';
import { DateTime } from '@/components/domain/date-time';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useApiQuery } from '@/lib/api/hooks';
import { useHasPermission } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { cn } from '@/lib/utils';
import { DetailList, Section } from '@/features/domains/kit';
import { Attestations } from './attestations';
import { ConnectStep } from './connect-step';
import { DomainsStep } from './domains-step';
import { MailFlowDialog } from './mail-flow-dialog';
import {
  OUTBOUND_LABEL,
  PROVIDER_LABEL,
  STEP_LABEL,
  StepStatusBadge,
  blockerText,
  type CatalogProvider,
  type Connection,
  type LinkedDomain,
  type MailFlow,
  type MailFlowChange,
  type Wizard,
  type WizardStepKey,
} from './model';
import { ValidateStep } from './validations';

/** The step to show first: the api's next action, else the first step not done. */
export function initialStep(wizard: Wizard): WizardStepKey {
  if (wizard.nextAction) return wizard.nextAction.step;
  return (
    wizard.steps.find((s) => s.status !== 'done' && s.status !== 'skipped')?.step ?? 'activate'
  );
}

/** Accessible stepper of the server-computed wizard (D13): the browser never decides a state. */
function Stepper({
  wizard,
  current,
  onSelect,
}: {
  wizard: Wizard;
  current: WizardStepKey;
  onSelect: (step: WizardStepKey) => void;
}) {
  return (
    <nav aria-label="Setup steps">
      <ol className="grid gap-1 sm:grid-cols-3 lg:grid-cols-6">
        {wizard.steps.map((step, index) => {
          const active = step.step === current;
          const done = step.status === 'done' || step.status === 'skipped';
          const Icon = done
            ? CheckCircle2Icon
            : step.status === 'blocked'
              ? LockIcon
              : active
                ? CircleDotIcon
                : CircleIcon;
          return (
            <li key={step.step}>
              <button
                type="button"
                aria-current={active ? 'step' : undefined}
                onClick={() => onSelect(step.step)}
                className={cn(
                  'flex w-full items-center gap-2 rounded-md border px-3 py-2 text-left text-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
                  active ? 'border-primary bg-accent' : 'bg-card hover:bg-muted',
                )}
              >
                <Icon
                  className={cn('size-4 shrink-0', done ? 'text-success' : 'text-muted-foreground')}
                  aria-hidden
                />
                <span className="grid">
                  <span className="text-xs text-muted-foreground">Step {index + 1}</span>
                  <span className="font-medium">{STEP_LABEL[step.step]}</span>
                  <span className="sr-only">, {humanize(step.status)}</span>
                </span>
              </button>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

function GuideLink({
  connectionId,
  anchor,
  children,
}: {
  connectionId: string;
  anchor: string;
  children: string;
}) {
  return (
    <Link
      className="text-sm underline"
      href={`/integrations/providers/${connectionId}?tab=guide#${anchor}`}
    >
      {children}
    </Link>
  );
}

/** Wizard step "Inbound" (D13): per-domain current vs proposed destinations, preview/apply. */
function InboundStep({
  connection,
  domains,
  catalog,
}: {
  connection: Connection;
  domains: readonly LinkedDomain[];
  catalog: CatalogProvider | undefined;
}) {
  const canApply = useHasPermission('integration:manage', 'domain:routing_manage');
  const [hosts, setHosts] = useState<Record<string, string>>({});
  const [selected, setSelected] = useState<Set<string>>(
    () =>
      new Set(
        domains.filter((d) => d.destinationProvider !== connection.provider).map((d) => d.id),
      ),
  );
  const [open, setOpen] = useState(false);
  const m365 = connection.provider === 'microsoft_365';
  const pending = domains.filter((d) => d.destinationProvider !== connection.provider);
  const chosen = domains.filter((d) => selected.has(d.id));
  const change: MailFlowChange = {
    kind: 'inbound',
    domainIds: chosen.map((d) => d.id),
    ...(m365
      ? {
          microsoftHosts: Object.fromEntries(
            chosen
              .map((d) => [d.id, (hosts[d.id] ?? d.providerMxHost ?? '').trim()] as const)
              .filter(([, host]) => host.length > 0),
          ),
        }
      : {}),
  };
  const destination = m365
    ? 'the Microsoft 365 host of each domain'
    : 'Google Workspace (aspmx.l.google.com and its alternates)';
  return (
    <div className="grid gap-4">
      <p className="text-sm">
        The gateway delivers inbound mail for the linked domains to{' '}
        {PROVIDER_LABEL[connection.provider]}. This changes only the gateway’s destination servers;
        change your MX records and the provider-side connector yourself (setup guide, section
        Inbound).
      </p>
      {domains.length === 0 ? (
        <p className="text-sm text-muted-foreground">Link a domain first.</p>
      ) : (
        <ul className="grid gap-2">
          {domains.map((d) => {
            const id = `inbound-${d.id}`;
            const done = d.destinationProvider === connection.provider;
            return (
              <li key={d.id} className="grid gap-2 rounded-md border p-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Checkbox
                    id={id}
                    checked={selected.has(d.id)}
                    disabled={!canApply}
                    onCheckedChange={(checked) =>
                      setSelected((prev) => {
                        const next = new Set(prev);
                        if (checked === true) next.add(d.id);
                        else next.delete(d.id);
                        return next;
                      })
                    }
                  />
                  <Label htmlFor={id} className="font-medium">
                    {d.name}
                  </Label>
                  <span className="text-muted-foreground">
                    now delivers to{' '}
                    {d.destinationProvider === null
                      ? 'no destination'
                      : d.destinationProvider === 'custom'
                        ? 'custom servers'
                        : PROVIDER_LABEL[d.destinationProvider]}
                    {done ? ' (applied)' : ''}
                  </span>
                </div>
                {m365 && selected.has(d.id) ? (
                  <div className="grid max-w-md gap-1 pl-6">
                    <Label htmlFor={`${id}-host`} className="text-xs">
                      Microsoft 365 host
                    </Label>
                    <Input
                      id={`${id}-host`}
                      className="font-mono text-xs"
                      spellCheck={false}
                      autoComplete="off"
                      placeholder={d.providerMxHost ?? 'contoso-com.mail.protection.outlook.com'}
                      value={hosts[d.id] ?? d.providerMxHost ?? ''}
                      onChange={(event) =>
                        setHosts((prev) => ({ ...prev, [d.id]: event.target.value }))
                      }
                    />
                    <span className="text-xs text-muted-foreground">
                      {d.providerMxHost
                        ? 'Prefilled from the MX target Microsoft reports for the domain.'
                        : 'Microsoft has not reported an MX target yet; the gateway uses the standard host name when empty.'}
                    </span>
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
      {canApply && domains.length > 0 && connection.status !== 'disabled' ? (
        <Button
          className="justify-self-start"
          disabled={chosen.length === 0}
          onClick={() => setOpen(true)}
        >
          Preview inbound change
        </Button>
      ) : null}
      {!canApply ? (
        <p className="text-xs text-muted-foreground">
          Applying needs both “manage integrations” and “manage domain routing”.
        </p>
      ) : null}
      {pending.length === 0 && domains.length > 0 ? (
        <p className="text-sm">Every linked domain already delivers to the provider.</p>
      ) : null}
      <Attestations
        connection={connection}
        attestations={catalog?.attestations ?? []}
        phases={['inbound', 'lockdown']}
      />
      <GuideLink connectionId={connection.id} anchor="inbound">
        Inbound steps in the setup guide
      </GuideLink>
      <MailFlowDialog
        open={open}
        onOpenChange={setOpen}
        connectionId={connection.id}
        connectionName={connection.displayName}
        change={change}
        title="Apply inbound routing"
        effect={`I understand that all inbound mail for these domains will be delivered to ${destination}.`}
        confirmLabel="Apply inbound routing"
      />
    </div>
  );
}

function ProofPolicy({ mailFlow }: { mailFlow: MailFlow | undefined }) {
  if (!mailFlow) return null;
  const p = mailFlow.relayProof as Record<string, unknown>;
  return (
    <details className="rounded-md border p-3 text-sm">
      <summary className="cursor-pointer font-medium">
        Advanced: tenant proof policy (
        {mailFlow.relayProofIsDefault ? 'provider default' : 'customized'})
      </summary>
      <div className="mt-2 grid gap-2">
        <p className="text-muted-foreground">
          Every relayed message must prove it comes from your tenant: an aligned DKIM signature of a
          linked domain{p.tenantHeader ? ' and the Microsoft 365 tenant header' : ''}. The gateway
          evaluates this; it is shown here for reference.
        </p>
        <DetailList
          items={Object.entries(p).map(([k, v]) => ({ label: humanize(k), value: String(v) }))}
        />
      </div>
    </details>
  );
}

function RelayActivity({ mailFlow }: { mailFlow: MailFlow | undefined }) {
  if (!mailFlow) return null;
  const a = mailFlow.relayActivity24h;
  return (
    <p className="text-sm text-muted-foreground">
      Last 24 hours on the provider relay: {a.accepted} accepted, {a.proofFailed} failed the tenant
      proof, {a.tempFailed} deferred, {a.probes} probes. Last accepted{' '}
      <DateTime value={a.lastAcceptedAt} />.
    </p>
  );
}

/** Wizard step "Outbound and internal" (D7, D13): `off` or the relay in `probe_only`. */
function OutboundStep({
  connection,
  mailFlow,
  catalog,
}: {
  connection: Connection;
  mailFlow: MailFlow | undefined;
  catalog: CatalogProvider | undefined;
}) {
  const canApply = useHasPermission('integration:manage', 'connector:manage');
  const [open, setOpen] = useState(false);
  const off = connection.outboundMode === 'off';
  return (
    <div className="grid gap-4">
      <p className="text-sm">
        Outbound mode: <strong>{OUTBOUND_LABEL[connection.outboundMode]}</strong>.{' '}
        {off
          ? 'Inbound-only setups can keep outbound off. To route outbound and internal mail through the gateway, enable the provider relay in probe mode: the gateway accepts only probe messages until you activate it, and answers other mail with a temporary failure so nothing bounces.'
          : 'The provider relay exists. Configure the outbound connector or routing rule in your provider (setup guide, section Outbound) and validate with a probe.'}
      </p>
      {off && canApply && connection.status !== 'disabled' ? (
        <Button className="justify-self-start" onClick={() => setOpen(true)}>
          Preview: route outbound through the gateway (probe only)
        </Button>
      ) : null}
      {off && !canApply ? (
        <p className="text-xs text-muted-foreground">
          Applying needs both “manage integrations” and “manage SMTP connectors”.
        </p>
      ) : null}
      {!off ? <RelayActivity mailFlow={mailFlow} /> : null}
      <ProofPolicy mailFlow={mailFlow} />
      <Attestations
        connection={connection}
        attestations={catalog?.attestations ?? []}
        phases={['outbound']}
      />
      <GuideLink connectionId={connection.id} anchor="outbound">
        Outbound steps in the setup guide
      </GuideLink>
      <MailFlowDialog
        open={open}
        onOpenChange={setOpen}
        connectionId={connection.id}
        connectionName={connection.displayName}
        change={{ kind: 'outbound', mode: 'probe_only' }}
        title="Enable the provider relay (probe only)"
        effect="I understand that the gateway creates a provider relay connector for this tenant that accepts only probe messages until activation."
        confirmLabel="Enable probe mode"
      />
    </div>
  );
}

/** Wizard step "Activate" (D13): outbound `active` and the internal-routing choice. */
function ActivateStep({
  connection,
  mailFlow,
  catalog,
  validateDone,
}: {
  connection: Connection;
  mailFlow: MailFlow | undefined;
  catalog: CatalogProvider | undefined;
  validateDone: boolean;
}) {
  const internalId = useId();
  const canApply = useHasPermission('integration:manage', 'connector:manage');
  const [internal, setInternal] = useState(connection.internalRouting);
  useEffect(() => setInternal(connection.internalRouting), [connection.internalRouting]);
  const [open, setOpen] = useState(false);
  if (connection.outboundMode === 'off') {
    return (
      <p className="text-sm">
        Outbound routing is off: the setup is inbound only and complete once validation passed.
      </p>
    );
  }
  const token = mailFlow?.routeToken;
  return (
    <div className="grid gap-4">
      <p className="text-sm">
        Activation makes the gateway accept and inspect all outbound
        {internal ? ' and internal' : ''} mail your provider relays. It needs a passing full
        validation including a probe from the last 7 days.
      </p>
      <div className="flex items-start gap-2">
        <Checkbox
          id={internalId}
          checked={internal}
          disabled={!canApply}
          onCheckedChange={(v) => setInternal(v === true)}
        />
        <Label htmlFor={internalId} className="grid gap-0.5 font-normal">
          <span>Also route internal mail through the gateway</span>
          <span className="text-xs text-muted-foreground">
            {connection.provider === 'microsoft_365'
              ? 'Needs two transport rules with the route token (setup guide, Internal routing).'
              : 'Needs a Gmail routing rule for internal sending (setup guide, Internal routing).'}
          </span>
        </Label>
      </div>
      {internal && token && connection.provider === 'microsoft_365' ? (
        <p className="inline-flex flex-wrap items-center gap-1 text-sm">
          Route token (version {token.version}
          {token.pendingVersion ? `, rotating to ${token.pendingVersion}` : ''}):{' '}
          <code className="font-mono text-xs">{token.value ?? token.masked}</code>
          {token.value ? <CopyButton value={token.value} label="Copy route token" /> : null}
        </p>
      ) : null}
      {internal ? (
        <Attestations
          connection={connection}
          attestations={catalog?.attestations ?? []}
          phases={['internal']}
        />
      ) : null}
      {canApply && connection.status !== 'disabled' ? (
        <Button
          className="justify-self-start"
          disabled={!validateDone}
          onClick={() => setOpen(true)}
        >
          {connection.outboundMode === 'active' ? 'Preview changes' : 'Preview activation'}
        </Button>
      ) : null}
      {!validateDone ? (
        <p className="text-xs text-muted-foreground">Finish “Validate” first.</p>
      ) : null}
      <GuideLink connectionId={connection.id} anchor="validate-activate">
        Activation in the setup guide
      </GuideLink>
      <MailFlowDialog
        open={open}
        onOpenChange={setOpen}
        connectionId={connection.id}
        connectionName={connection.displayName}
        change={{ kind: 'activate', outboundMode: 'active', internalRouting: internal }}
        title="Activate outbound routing"
        effect={`I understand that all outbound${internal ? ' and internal' : ''} mail of this tenant is relayed, inspected and delivered by the gateway from now on, and that mail failing the tenant proof is refused.`}
        confirmLabel="Activate"
        destructive
      />
    </div>
  );
}

/** Tab "Setup": the wizard of D13 with server-computed states. */
export function SetupTab({
  connection,
  catalog,
}: {
  connection: Connection;
  catalog: CatalogProvider | undefined;
}) {
  const path = { path: { id: connection.id } };
  const wizard = useApiQuery('ProviderConnectionsController_wizard_v1', path, {
    // Grant verification and domain checks finish in the worker: poll while something is pending.
    refetchInterval: (query) =>
      query.state.data?.steps.some((s) => s.status === 'in_progress') ? 5000 : false,
  });
  const domains = useApiQuery('ProviderDomainsController_list_v1', path);
  const mailFlow = useApiQuery('ProviderMailFlowController_get_v1', path, {
    enabled: connection.status !== 'draft',
  });
  const latest = useApiQuery('ProviderValidationsController_list_v1', {
    path: { id: connection.id },
    query: { limit: '1', kind: 'full' },
  });
  const [step, setStep] = useState<WizardStepKey | null>(null);
  if (wizard.isLoading) return <LoadingState label="Loading the setup steps" rows={4} />;
  if (wizard.error)
    return <ErrorState error={wizard.error} onRetry={() => void wizard.refetch()} />;
  if (!wizard.data) return null;
  const current = step ?? initialStep(wizard.data);
  const state = wizard.data.steps.find((s) => s.step === current);
  const linked = domains.data?.data ?? [];
  const profile = catalog?.profiles.find((p) => p.purpose === 'mail_flow');
  const validateDone = wizard.data.steps.some((s) => s.step === 'validate' && s.status === 'done');

  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      <Stepper wizard={wizard.data} current={current} onSelect={setStep} />
      <Section
        title={`Step ${wizard.data.steps.findIndex((s) => s.step === current) + 1}: ${STEP_LABEL[current]}`}
        actions={state ? <StepStatusBadge status={state.status} /> : null}
      >
        {state && state.blockers.length > 0 ? (
          <ul className="grid gap-1 text-sm" aria-label="What is missing">
            {state.blockers.map((b) => (
              <li key={b}>{blockerText(b)}</li>
            ))}
          </ul>
        ) : null}
        {current === 'connect' ? <ConnectStep connection={connection} profile={profile} /> : null}
        {current === 'domains' ? <DomainsStep connection={connection} linked={linked} /> : null}
        {current === 'inbound' ? (
          <InboundStep connection={connection} domains={linked} catalog={catalog} />
        ) : null}
        {current === 'outbound' ? (
          <OutboundStep connection={connection} mailFlow={mailFlow.data} catalog={catalog} />
        ) : null}
        {current === 'validate' ? (
          <ValidateStep connection={connection} latestRunId={latest.data?.data[0]?.id ?? null} />
        ) : null}
        {current === 'activate' ? (
          <ActivateStep
            connection={connection}
            mailFlow={mailFlow.data}
            catalog={catalog}
            validateDone={validateDone}
          />
        ) : null}
      </Section>
    </div>
  );
}
