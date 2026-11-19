'use client';

import { DateTime } from '@/components/domain/date-time';
import { Button } from '@/components/ui/button';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { Can } from '@/lib/auth/can';
import { humanize } from '@/lib/format';
import { MutationError, QueryView, Section } from '@/features/domains/kit';
import { CheckStatusBadge, HealthBadge, type Connection, type Health } from './model';
import { Remediation } from './validations';

/**
 * Setup-guide anchors of the 8.2 health checks (mirror of `HEALTH_CHECKS[].remediation` in
 * `@email-gateway/provider-integrations`; the health endpoint returns titles, not remediations).
 * Codes added later (8.5) without an entry here simply show no link.
 */
export const HEALTH_REMEDIATION: Readonly<Record<string, string>> = {
  'credentials.token': '#grant-access',
  'permissions.granted': '#grant-access',
  'tenant.identity': '#grant-access',
  'domains.gateway_verified': '#domains',
  'domains.provider_verified': '#domains',
  'dns.mx_gateway': '#inbound-mx',
  'inbound.destination': '#inbound-destination',
  'inbound.destination_matches_provider': '#inbound-destination',
  'inbound.smtp': '#inbound-destination',
  'inbound.recent_deliveries': '#failover',
  'dns.spf_gateway': '#outbound-spf',
  'dns.dkim_provider': '#outbound-dkim',
  'outbound.probe': '#outbound-validate',
  'outbound.relay_activity': '#outbound-connector',
  'routing.no_loops': '#internal-routing',
  'routing.loops': '#internal-routing',
  'lockdown.attested': '#inbound-lockdown',
  'credential.expiry': '#grant-access',
  'egress.ranges_fresh': 'docs/deployment/provider-integrations.md#egress-ranges',
};

function remediationOf(code: string): string | null {
  return HEALTH_REMEDIATION[code] ?? null;
}

function HealthView({ connection, health }: { connection: Connection; health: Health }) {
  const check = useApiMutation('ProviderHealthController_checkNow_v1', {
    invalidates: ['ProviderHealthController_get_v1', 'ProviderConnectionsController_get_v1'],
    successMessage: 'Health check scheduled. Results appear within a minute.',
  });
  const failing = health.checks.filter((c) => c.status === 'fail' || c.status === 'warn');
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <Section
        title="Health"
        description="The gateway checks this connection periodically. Health never changes mail flow by itself: a failing check alerts administrators."
        actions={
          connection.status === 'disabled' ? null : (
            <Can op="ProviderHealthController_checkNow_v1">
              <Button
                variant="outline"
                size="sm"
                disabled={check.isPending}
                onClick={() => void check.submit({ path: { id: connection.id } })}
              >
                Check now
              </Button>
            </Can>
          )
        }
      >
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <HealthBadge status={health.status} />
          <span className="text-muted-foreground">
            Checked <DateTime value={health.checkedAt} />
            {health.nextCheckAt ? (
              <>
                {' '}
                · next check <DateTime value={health.nextCheckAt} />
              </>
            ) : null}
          </span>
        </div>
        <MutationError error={check.error} />
        {failing.length > 0 ? (
          <p className="text-sm">
            {failing.length} check{failing.length === 1 ? '' : 's'} need attention.
          </p>
        ) : null}
        {health.checks.length === 0 ? (
          <p className="text-sm text-muted-foreground">No check has run yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[36rem] text-left text-sm">
              <caption className="sr-only">Health checks</caption>
              <thead>
                <tr className="border-b text-xs text-muted-foreground">
                  <th scope="col" className="py-1 pr-3 font-medium">
                    Check
                  </th>
                  <th scope="col" className="py-1 pr-3 font-medium">
                    Subject
                  </th>
                  <th scope="col" className="py-1 pr-3 font-medium">
                    Result
                  </th>
                  <th scope="col" className="py-1 pr-3 font-medium">
                    Failing since
                  </th>
                  <th scope="col" className="py-1 font-medium">
                    Checked
                  </th>
                </tr>
              </thead>
              <tbody>
                {health.checks.map((c) => {
                  const remediation = remediationOf(c.code);
                  return (
                    <tr key={`${c.code}:${c.subject}`} className="border-b align-top last:border-0">
                      <th scope="row" className="py-2 pr-3 font-normal">
                        <span className="grid gap-0.5">
                          <span className="font-medium">{c.title}</span>
                          <code className="font-mono text-xs text-muted-foreground">{c.code}</code>
                          {remediation && (c.status === 'fail' || c.status === 'warn') ? (
                            <Remediation connectionId={connection.id} remediation={remediation} />
                          ) : null}
                        </span>
                      </th>
                      <td className="py-2 pr-3">{c.subject || '—'}</td>
                      <td className="py-2 pr-3">
                        <span className="grid gap-0.5">
                          <CheckStatusBadge status={c.status} />
                          <span className="text-xs text-muted-foreground">
                            {humanize(c.severity)}
                          </span>
                        </span>
                      </td>
                      <td className="py-2 pr-3">
                        <DateTime value={c.firstFailedAt} emptyLabel="—" />
                      </td>
                      <td className="py-2">
                        <DateTime value={c.checkedAt} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      <Section title="Status changes" description="The last 20 changes of the health status.">
        {health.transitions.length === 0 ? (
          <p className="text-sm text-muted-foreground">No status change yet.</p>
        ) : (
          <ol className="grid gap-2 text-sm" aria-label="Health status changes">
            {health.transitions.map((t) => (
              <li key={`${t.at}:${t.to}`} className="flex flex-wrap items-center gap-2">
                <DateTime value={t.at} />
                <HealthBadge status={t.from} />
                <span aria-hidden>→</span>
                <span className="sr-only">to</span>
                <HealthBadge status={t.to} />
                {t.failingChecks.length > 0 ? (
                  <span className="font-mono text-xs text-muted-foreground">
                    {t.failingChecks.join(', ')}
                  </span>
                ) : null}
              </li>
            ))}
          </ol>
        )}
      </Section>
    </div>
  );
}

/** Tab "Health" (D11): status, checks, transitions, "Check now". */
export function HealthTab({ connection }: { connection: Connection }) {
  const health = useApiQuery(
    'ProviderHealthController_get_v1',
    { path: { id: connection.id } },
    { refetchInterval: 60_000 },
  );
  return (
    <QueryView query={health} label="connection health" notFound="inline">
      {(data) => <HealthView connection={connection} health={data} />}
    </QueryView>
  );
}
