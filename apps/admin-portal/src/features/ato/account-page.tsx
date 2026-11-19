'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';
import { BarChart, type ChartRow } from '@/components/charts';
import { DateTime, ToneBadge } from '@/components/domain';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { UnavailableState } from '@/components/states/unavailable-state';
import { ApiError } from '@/lib/api/errors';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatNumber, humanize } from '@/lib/format';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import {
  CursorPager,
  DetailList,
  EnumBadge,
  FilterMultiSelect,
  FilterSelect,
  Section,
} from '@/features/messages/controls';
import {
  AddTrustedContext,
  OverrideControls,
  ProtectControl,
  RemoveTrustedContext,
  trustedKindLabel,
} from './account-actions';
import {
  AtoScore,
  CapabilityList,
  KindLabel,
  LevelBadge,
  pagerOf,
  ScrollRegion,
} from './components';
import {
  ATO_AUTH_OUTCOMES,
  ATO_SIGNAL_CATEGORIES,
  CATEGORY_LABELS,
  LEVEL_TONE,
  OUTCOME_TONE,
  RESTRICTION_STATUS_TONE,
  SIGNAL_STATUS_TONE,
  SIGNAL_STRENGTH_TONE,
  accountLabel,
  countryName,
  incidentHref,
  labelOf,
  str,
  type AtoAccountDetail,
  type AtoAuthEvent,
  type AtoSignal,
} from './model';

export const ACCOUNT_TABS: readonly TabDefinition[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'sign-ins', label: 'Sign-ins', ops: ['AtoAccountsController_authEvents_v1'] },
  { id: 'network', label: 'Devices and IPs' },
  { id: 'outbound', label: 'Outbound activity', ops: ['AtoAccountsController_activity_v1'] },
  { id: 'mailbox', label: 'Mailbox changes' },
  { id: 'signals', label: 'Detection reasons', ops: ['AtoAccountsController_signals_v1'] },
  { id: 'history', label: 'Score history', ops: ['AtoAccountsController_scoreHistory_v1'] },
  { id: 'trusted', label: 'Trusted contexts' },
];

/** `/ato/accounts/[accountId]`: account details with tabs (step 8.4 §6). */
export function AtoAccountPage({ accountId }: { accountId: string }) {
  return (
    <RouteGate gate={['AtoAccountsController_get_v1']}>
      <AccountContent accountId={accountId} />
    </RouteGate>
  );
}

function AccountContent({ accountId }: { accountId: string }) {
  const account = useApiQuery(
    'AtoAccountsController_get_v1',
    { path: { accountId } },
    { retry: false },
  );
  if (account.isLoading) return <LoadingState label="Loading the account" />;
  if (account.error instanceof ApiError && account.error.status === 404) {
    return <NotFoundView />;
  }
  if (account.error) {
    return <ErrorState error={account.error} onRetry={() => void account.refetch()} />;
  }
  const data = account.data;
  if (!data) return null;
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title={accountLabel(data)}
        breadcrumbs={[
          { label: 'Account takeover', href: '/ato' },
          { label: 'Accounts', href: '/ato/accounts' },
          { label: accountLabel(data) },
        ]}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <KindLabel kind={data.kind} />
            <AtoScore score={data.riskScore} level={data.riskLevel} />
            {data.protected ? <ToneBadge tone="info">Protected</ToneBadge> : null}
            {data.status === 'retired' ? <ToneBadge tone="neutral">Retired</ToneBadge> : null}
          </span>
        }
        actions={
          data.activeIncident ? (
            <Link
              href={incidentHref(data.activeIncident.id)}
              className="inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm text-primary hover:bg-accent"
            >
              Active incident
              <EnumBadge value={data.activeIncident.severity} tones={LEVEL_TONE} />
            </Link>
          ) : null
        }
      />
      <GatedTabs
        tabs={ACCOUNT_TABS}
        label="Account details"
        keepParams={[]}
        render={(tab) => {
          switch (tab) {
            case 'sign-ins':
              return <SignInsTab account={data} />;
            case 'network':
              return <NetworkTab account={data} />;
            case 'outbound':
              return <OutboundTab account={data} />;
            case 'mailbox':
              return (
                <UnavailableState
                  step="8.5"
                  title="Mailbox changes"
                  description="Forwarding rules, inbox rules, delegates and OAuth grants come from the identity provider (Microsoft 365 and Google Workspace adapters). The gateway cannot see them; they arrive with the provider integrations."
                />
              );
            case 'signals':
              return <SignalsTab account={data} />;
            case 'history':
              return <HistoryTab account={data} />;
            case 'trusted':
              return <TrustedTab account={data} />;
            default:
              return <OverviewTab account={data} />;
          }
        }}
      />
    </div>
  );
}

interface Contribution {
  code: string;
  category: string;
  strength: string;
  weight: number;
  contribution: number;
  decayPermille: number;
}

/** The top contributions of the stored `ato-score/1` explanation (lenient: unknown → none). */
export function contributionsOf(structured: unknown): Contribution[] {
  if (!structured || typeof structured !== 'object') return [];
  const top = (structured as { top?: unknown }).top;
  if (!Array.isArray(top)) return [];
  return top.flatMap((c) => {
    const x = c as Record<string, unknown>;
    return typeof x.code === 'string' && typeof x.contribution === 'number'
      ? [
          {
            code: x.code,
            category: str(x.category),
            strength: str(x.strength),
            weight: Number(x.weight ?? 0),
            contribution: x.contribution,
            decayPermille: Number(x.decayPermille ?? 1000),
          },
        ]
      : [];
  });
}

function useRuleTitles(): Map<string, string> {
  const rules = useApiQuery('AtoRulesController_list_v1', undefined, { staleTime: 300_000 });
  return useMemo(
    () => new Map((rules.data?.data ?? []).map((r) => [r.code, r.title])),
    [rules.data],
  );
}

function OverviewTab({ account }: { account: AtoAccountDetail }) {
  const titles = useRuleTitles();
  const contributions = contributionsOf(account.explanation.structured);
  return (
    <div className="grid min-w-0 gap-4 lg:grid-cols-2">
      <Section title="Risk" description="The current account score (0–100) and why.">
        <DetailList
          items={[
            {
              label: 'Score',
              value: <AtoScore score={account.riskScore} level={account.riskLevel} />,
            },
            {
              label: 'Updated',
              value: <DateTime value={account.riskUpdatedAt} emptyLabel="Never" />,
            },
            {
              label: 'Explanation',
              value: account.explanation.text ?? (
                <span className="text-muted-foreground">No contributing signals</span>
              ),
            },
          ]}
        />
        {contributions.length > 0 ? (
          <ScrollRegion label="Top contributions to the score">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Top contributions to the score</caption>
              <thead className="bg-muted/50 text-xs text-muted-foreground">
                <tr>
                  <th scope="col" className="px-2 py-1.5 font-medium">
                    Rule
                  </th>
                  <th scope="col" className="px-2 py-1.5 font-medium">
                    Category
                  </th>
                  <th scope="col" className="px-2 py-1.5 font-medium">
                    Strength
                  </th>
                  <th scope="col" className="px-2 py-1.5 text-right font-medium">
                    Points
                  </th>
                </tr>
              </thead>
              <tbody>
                {contributions.map((c) => (
                  <tr key={c.code} className="border-t">
                    <th scope="row" className="px-2 py-1.5 text-left font-normal">
                      {titles.get(c.code) ?? c.code}
                      <span className="block font-mono text-xs text-muted-foreground">
                        {c.code}
                      </span>
                    </th>
                    <td className="px-2 py-1.5">{labelOf(CATEGORY_LABELS, c.category)}</td>
                    <td className="px-2 py-1.5">
                      <EnumBadge value={c.strength} tones={SIGNAL_STRENGTH_TONE} />
                    </td>
                    <td className="px-2 py-1.5 text-right tabular-nums">+{c.contribution}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </ScrollRegion>
        ) : null}
      </Section>
      <Section
        title="Analyst controls"
        description="Overrides and protection are recorded with your reason and audited."
      >
        <DetailList
          items={[
            {
              label: 'Override',
              value: account.overrideDetail ? (
                <span className="grid gap-0.5">
                  <span>
                    {account.overrideDetail.verdict === 'benign' ? 'Benign' : 'Compromised'} until{' '}
                    <DateTime value={account.overrideDetail.expiresAt} mode="absolute" />
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {account.overrideDetail.reason}
                  </span>
                  {account.overrideDetail.contradictedAt ? (
                    <span className="text-xs font-medium text-destructive">
                      Contradicted by a strong signal at{' '}
                      <DateTime value={account.overrideDetail.contradictedAt} mode="absolute" />:
                      not applied
                    </span>
                  ) : null}
                </span>
              ) : (
                'None'
              ),
            },
            {
              label: 'Protected',
              value: account.protection.protected
                ? `Yes${account.protection.reason ? ` (${account.protection.reason})` : ''}`
                : 'No',
            },
            {
              label: 'Active restrictions',
              value:
                account.restrictions.filter((r) => r.status === 'active').length > 0 ? (
                  <ul className="grid gap-1">
                    {account.restrictions
                      .filter((r) => r.status === 'active')
                      .map((r) => (
                        <li key={r.id} className="flex flex-wrap items-center gap-1.5">
                          <EnumBadge value={r.status} tones={RESTRICTION_STATUS_TONE} />
                          <span>
                            {r.kind === 'send_block'
                              ? 'Sending restricted'
                              : 'SMTP authentication blocked'}{' '}
                            ({humanize(r.scope)}
                            {r.ipCidr ? ` ${r.ipCidr}` : ''}) until{' '}
                            <DateTime value={r.expiresAt} mode="absolute" />
                          </span>
                        </li>
                      ))}
                  </ul>
                ) : (
                  'None'
                ),
            },
            {
              label: 'Linked accounts',
              value:
                account.linkedAccounts.length > 0 ? (
                  <ul className="grid gap-1">
                    {account.linkedAccounts.map((l) => (
                      <li key={l.id} className="flex items-center gap-2">
                        <Link
                          href={`/ato/accounts/${l.id}`}
                          className="text-primary underline-offset-2 hover:underline"
                        >
                          {humanize(l.kind)}
                        </Link>
                        <LevelBadge level={l.riskLevel} />
                      </li>
                    ))}
                  </ul>
                ) : (
                  'None'
                ),
            },
            {
              label: 'First seen',
              value: <DateTime value={account.firstSeenAt} mode="absolute" />,
            },
            { label: 'Last seen', value: <DateTime value={account.lastSeenAt} /> },
          ]}
        />
        <div className="flex flex-wrap gap-2">
          <OverrideControls account={account} />
          <ProtectControl account={account} />
        </div>
      </Section>
      <Section title="Detection capabilities" description="What the detection worker can see.">
        <CapabilityList capabilities={account.capabilities} />
      </Section>
      <Section
        title="Identity-provider identities"
        description="Provider accounts mapped to this account (Microsoft 365, Google Workspace)."
      >
        {account.identities.length > 0 ? (
          <ul className="grid gap-1 text-sm">
            {account.identities.map((i) => (
              <li key={`${i.provider}-${i.userPrincipalName ?? ''}`}>
                {humanize(i.provider)}: {i.userPrincipalName ?? 'unnamed'} (last seen{' '}
                <DateTime value={i.lastSeenAt} />)
              </li>
            ))}
          </ul>
        ) : (
          <UnavailableState
            step="8.5"
            title="No provider identities"
            description="Identity-provider sign-ins and identities arrive with the Microsoft 365 and Google Workspace adapters."
          />
        )}
      </Section>
    </div>
  );
}

const outcomeOptions = ATO_AUTH_OUTCOMES.map((o) => ({ value: o, label: humanize(o) }));

function location(event: AtoAuthEvent): string {
  const g = event.geo;
  if (g.status === 'unavailable') return 'Unavailable (no GeoIP database)';
  if (g.status === 'private') return 'Private network';
  if (g.status === 'not_found') return 'Not found';
  const parts = [g.city, g.region, g.countryCode ? countryName(g.countryCode) : null].filter(
    Boolean,
  );
  const text = parts.length > 0 ? parts.join(', ') : 'Unknown';
  return g.status === 'stale' ? `${text} (database out of date)` : text;
}

function SignInsTab({ account }: { account: AtoAccountDetail }) {
  const [outcomes, setOutcomes] = useState<string[]>([]);
  const filters = useMemo(
    () => ({
      sort: '-occurredAt' as const,
      ...(outcomes.length ? { outcome: outcomes.join(',') } : {}),
    }),
    [outcomes],
  );
  const list = useCursorList('AtoAccountsController_authEvents_v1', filters, {
    path: { accountId: account.id },
    limit: 25,
  });
  return (
    <Section
      title="Sign-ins"
      description="Portal sign-ins, MFA and SMTP authentications of the last 7 days (viewing them is audited). Successful SMTP authentications are aggregated per IP and hour."
      actions={
        <FilterMultiSelect
          label="Outcome"
          values={outcomes}
          options={outcomeOptions}
          onChange={setOutcomes}
        />
      }
    >
      {list.query.isLoading ? (
        <LoadingState label="Loading sign-ins" variant="table" />
      ) : list.query.error ? (
        <ErrorState error={list.query.error} onRetry={() => void list.query.refetch()} compact />
      ) : list.rows.length === 0 ? (
        <EmptyState title="No sign-ins in this range" />
      ) : (
        <ScrollRegion label="Sign-ins of the account">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Sign-ins of the account</caption>
            <thead className="bg-muted/50 text-xs text-muted-foreground">
              <tr>
                {[
                  'Time',
                  'Source',
                  'Outcome',
                  'IP address',
                  'Location',
                  'Network',
                  'Device',
                  'Attempts',
                ].map((h) => (
                  <th key={h} scope="col" className="px-2 py-1.5 font-medium whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {list.rows.map((e) => (
                <tr key={e.id} className="border-t align-top">
                  <td className="px-2 py-1.5 whitespace-nowrap">
                    <DateTime value={e.occurredAt} />
                  </td>
                  <td className="px-2 py-1.5">{humanize(e.source)}</td>
                  <td className="px-2 py-1.5">
                    <EnumBadge value={e.outcome} tones={OUTCOME_TONE} />
                    {e.failureCode ? (
                      <span className="block font-mono text-xs text-muted-foreground">
                        {e.failureCode}
                      </span>
                    ) : null}
                  </td>
                  <td className="px-2 py-1.5 font-mono text-xs">{e.ipAddress ?? '—'}</td>
                  <td className="px-2 py-1.5">{location(e)}</td>
                  <td className="px-2 py-1.5">
                    {e.asn ? `AS${e.asn}${e.asnOrg ? ` ${e.asnOrg}` : ''}` : '—'}
                  </td>
                  <td className="px-2 py-1.5">
                    {e.device?.label ?? (e.device ? 'Unknown device' : '—')}
                  </td>
                  <td className="px-2 py-1.5 text-right tabular-nums">
                    {formatNumber(e.attemptCount)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </ScrollRegion>
      )}
      <CursorPager label="Sign-ins pages" state={pagerOf(list)} />
    </Section>
  );
}

function NetworkTab({ account }: { account: AtoAccountDetail }) {
  const b = account.baseline;
  if (!b) {
    return (
      <EmptyState
        title="No baseline yet"
        description="The behavioural baseline is built daily from the account’s activity of the last weeks; a new account has none."
      />
    );
  }
  const list = (title: string, rows: Array<{ key: string; label: string; count: number }>) => (
    <Section title={title} headingLevel={3}>
      {rows.length > 0 ? (
        <ul className="grid gap-1 text-sm">
          {rows.map((r) => (
            <li key={r.key} className="flex justify-between gap-2">
              <span className="min-w-0 truncate font-mono text-xs">{r.label}</span>
              <span className="tabular-nums">{formatNumber(r.count)}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted-foreground">None seen</p>
      )}
    </Section>
  );
  return (
    <div className="grid min-w-0 gap-4">
      <Section
        title="Baseline"
        description="The account’s usual sign-in context (counts over the baseline window)."
      >
        <DetailList
          items={[
            { label: 'Maturity', value: b.mature ? 'Mature' : 'Immature (still learning)' },
            { label: 'Events', value: formatNumber(b.eventCount) },
            { label: 'Active days', value: formatNumber(b.activeDays) },
            { label: 'Channels', value: b.channels.map(humanize).join(', ') || '—' },
            { label: 'Rebuilt', value: <DateTime value={b.rebuiltAt} emptyLabel="Never" /> },
            { label: 'Time zone', value: b.timeZone },
          ]}
        />
      </Section>
      <div className="grid gap-4 md:grid-cols-2">
        {list(
          'IP networks',
          b.prefixes.map((p) => ({
            key: String(p.prefix),
            label: String(p.prefix),
            count: Number(p.count),
          })),
        )}
        {list(
          'Countries',
          b.countries.map((c) => ({
            key: String(c.countryCode),
            label: countryName(String(c.countryCode)),
            count: Number(c.count),
          })),
        )}
        {list(
          'Networks (ASN)',
          b.asns.map((a) => ({ key: String(a.asn), label: `AS${a.asn}`, count: a.count })),
        )}
        {list(
          'Devices',
          b.devices.map((d) => ({
            key: String(d.deviceHash),
            label: String(d.deviceHash),
            count: Number(d.count),
          })),
        )}
      </div>
      <BarChart
        title="Sign-ins by local hour"
        rows={b.hourHistogram.map((count, hour) => ({
          hour: String(hour).padStart(2, '0'),
          count,
        }))}
        categoryKey="hour"
        categoryLabel={`Hour (${b.timeZone})`}
        series={[{ key: 'count', label: 'Authentications' }]}
      />
    </div>
  );
}

function OutboundTab({ account }: { account: AtoAccountDetail }) {
  const [to] = useState(() => new Date(Math.ceil(Date.now() / 3_600_000) * 3_600_000));
  const from = new Date(to.getTime() - 30 * 86_400_000);
  const activity = useApiQuery('AtoAccountsController_activity_v1', {
    path: { accountId: account.id },
    query: { from: from.toISOString(), to: to.toISOString() },
  });
  if (activity.isLoading) return <LoadingState label="Loading outbound activity" />;
  if (activity.error)
    return <ErrorState error={activity.error} onRetry={() => void activity.refetch()} />;
  const days = activity.data?.days ?? [];
  const rows: ChartRow[] = days.map((d) => ({
    day: d.day.slice(0, 10),
    messages: d.messages,
    externalRecipients: d.externalRecipients,
    findings: d.findings,
  }));
  const domains = new Map<string, number>();
  for (const d of days)
    for (const t of d.topRecipientDomains)
      domains.set(t.domain, (domains.get(t.domain) ?? 0) + t.count);
  const topDomains = [...domains.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  const explorer =
    account.kind === 'mailbox' && account.address
      ? `/messages?${new URLSearchParams({ sender: account.address, direction: 'outbound', range: '30d' }).toString()}`
      : null;
  return (
    <div className="grid min-w-0 gap-4">
      <Section
        title="Outbound activity (30 days)"
        description="Daily messages, external recipients and security findings. Recipients are counted by domain only."
        actions={
          explorer ? (
            <Link
              href={explorer}
              className="text-sm text-primary underline-offset-2 hover:underline"
            >
              Open in the email explorer
            </Link>
          ) : null
        }
      >
        {rows.length > 0 ? (
          <BarChart
            title="Outbound messages per day"
            rows={rows}
            categoryKey="day"
            categoryLabel="Day (UTC)"
            series={[
              { key: 'messages', label: 'Messages' },
              { key: 'externalRecipients', label: 'External recipients' },
              { key: 'findings', label: 'Findings' },
            ]}
          />
        ) : (
          <EmptyState title="No outbound activity in the last 30 days" />
        )}
      </Section>
      <Section title="Top recipient domains" headingLevel={3}>
        {topDomains.length > 0 ? (
          <ol className="grid gap-1 text-sm" aria-label="Top recipient domains">
            {topDomains.map(([domain, count]) => (
              <li key={domain} className="flex justify-between gap-2">
                <span className="font-mono text-xs">{domain}</span>
                <span className="tabular-nums">{formatNumber(count)}</span>
              </li>
            ))}
          </ol>
        ) : (
          <p className="text-sm text-muted-foreground">None</p>
        )}
      </Section>
    </div>
  );
}

const categoryOptions = ATO_SIGNAL_CATEGORIES.map((c) => ({ value: c, label: CATEGORY_LABELS[c] }));

export function SignalTable({ rows, caption }: { rows: readonly AtoSignal[]; caption: string }) {
  return (
    <ScrollRegion label={caption}>
      <table className="w-full text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="bg-muted/50 text-xs text-muted-foreground">
          <tr>
            {['Detected', 'Signal', 'Category', 'Strength', 'Weight', 'Status', 'Explanation'].map(
              (h) => (
                <th key={h} scope="col" className="px-2 py-1.5 font-medium whitespace-nowrap">
                  {h}
                </th>
              ),
            )}
          </tr>
        </thead>
        <tbody>
          {rows.map((s) => (
            <tr key={s.id} className="border-t align-top">
              <td className="px-2 py-1.5 whitespace-nowrap">
                <DateTime value={s.detectedAt} />
              </td>
              <td className="px-2 py-1.5">
                {s.title}
                <span className="block font-mono text-xs text-muted-foreground">{s.ruleCode}</span>
              </td>
              <td className="px-2 py-1.5">{labelOf(CATEGORY_LABELS, s.category)}</td>
              <td className="px-2 py-1.5">
                <EnumBadge value={s.strength} tones={SIGNAL_STRENGTH_TONE} />
              </td>
              <td className="px-2 py-1.5 tabular-nums">{s.weight}</td>
              <td className="px-2 py-1.5">
                <EnumBadge value={s.status} tones={SIGNAL_STATUS_TONE} />
              </td>
              <td className="px-2 py-1.5">
                {s.explanation}
                {s.occurrences > 1 ? (
                  <span className="block text-xs text-muted-foreground">
                    {formatNumber(s.occurrences)} occurrences
                  </span>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </ScrollRegion>
  );
}

function SignalsTab({ account }: { account: AtoAccountDetail }) {
  const [categories, setCategories] = useState<string[]>([]);
  const [status, setStatus] = useState<string | undefined>(undefined);
  const filters = useMemo(
    () => ({
      sort: '-detectedAt' as const,
      ...(categories.length ? { category: categories.join(',') } : {}),
      ...(status ? { status } : {}),
    }),
    [categories, status],
  );
  const list = useCursorList('AtoAccountsController_signals_v1', filters, {
    path: { accountId: account.id },
    limit: 25,
  });
  return (
    <Section
      title="Detection reasons"
      description="Risk signals of the last 30 days with their explanation. Dismissed signals no longer count."
      actions={
        <div className="flex flex-wrap items-end gap-2">
          <FilterMultiSelect
            label="Category"
            values={categories}
            options={categoryOptions}
            onChange={setCategories}
          />
          <FilterSelect
            label="Status"
            value={status}
            options={[
              { value: 'active', label: 'Active' },
              { value: 'dismissed', label: 'Dismissed' },
              { value: 'informational', label: 'Informational' },
            ]}
            onChange={setStatus}
          />
        </div>
      }
    >
      {list.query.isLoading ? (
        <LoadingState label="Loading signals" variant="table" />
      ) : list.query.error ? (
        <ErrorState error={list.query.error} onRetry={() => void list.query.refetch()} compact />
      ) : list.rows.length === 0 ? (
        <EmptyState title="No signals in this range" />
      ) : (
        <SignalTable rows={list.rows} caption="Risk signals of the account" />
      )}
      <CursorPager label="Signal pages" state={pagerOf(list)} />
    </Section>
  );
}

function HistoryTab({ account }: { account: AtoAccountDetail }) {
  const list = useCursorList(
    'AtoAccountsController_scoreHistory_v1',
    { sort: '-computedAt' },
    { path: { accountId: account.id }, limit: 50 },
  );
  const rows: ChartRow[] = [...list.rows]
    .reverse()
    .map((p) => ({ at: p.computedAt, score: p.score }));
  return (
    <Section
      title="Score history"
      description="Every recorded score change with its trigger (30 days)."
    >
      {list.query.isLoading ? (
        <LoadingState label="Loading the score history" variant="table" />
      ) : list.query.error ? (
        <ErrorState error={list.query.error} onRetry={() => void list.query.refetch()} compact />
      ) : list.rows.length === 0 ? (
        <EmptyState title="No score changes in this range" />
      ) : (
        <>
          <BarChart
            title="Score over time"
            rows={rows}
            categoryKey="at"
            categoryLabel="Computed at (UTC)"
            formatCategory={(v) => String(v).slice(0, 16).replace('T', ' ')}
            series={[{ key: 'score', label: 'Score' }]}
          />
          <ScrollRegion label="Score changes">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Score changes</caption>
              <thead className="bg-muted/50 text-xs text-muted-foreground">
                <tr>
                  {['Computed', 'Score', 'Previous', 'Trigger', 'Versions'].map((h) => (
                    <th key={h} scope="col" className="px-2 py-1.5 font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {list.rows.map((p) => (
                  <tr key={p.id} className="border-t">
                    <td className="px-2 py-1.5 whitespace-nowrap">
                      <DateTime value={p.computedAt} />
                    </td>
                    <td className="px-2 py-1.5">
                      <AtoScore score={p.score} level={p.level} />
                    </td>
                    <td className="px-2 py-1.5">
                      {p.previousScore} ({humanize(p.previousLevel)})
                    </td>
                    <td className="px-2 py-1.5">{humanize(p.trigger)}</td>
                    <td className="px-2 py-1.5 font-mono text-xs">
                      {p.scorerVersion} · {p.rulesVersion} · settings v{p.settingsVersion}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </ScrollRegion>
        </>
      )}
      <CursorPager label="Score history pages" state={pagerOf(list)} />
    </Section>
  );
}

function TrustedTab({ account }: { account: AtoAccountDetail }) {
  return (
    <Section
      title="Trusted contexts"
      description="Networks, ASNs, countries and devices that are expected for this account (until they expire)."
      actions={<AddTrustedContext accountId={account.id} />}
    >
      {account.trustedContexts.length === 0 ? (
        <EmptyState title="No trusted contexts" />
      ) : (
        <ul className="grid gap-2" aria-label="Trusted contexts">
          {account.trustedContexts.map((c) => (
            <li
              key={c.id}
              className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2 text-sm"
            >
              <span className="grid gap-0.5">
                <span>
                  {trustedKindLabel(c.kind)}: <span className="font-mono">{c.value}</span>
                </span>
                <span className="text-xs text-muted-foreground">
                  {c.reason} ·{' '}
                  {c.source === 'false_positive_feedback' ? 'false-positive feedback' : 'analyst'} ·
                  expires <DateTime value={c.expiresAt} mode="absolute" />
                </span>
              </span>
              <RemoveTrustedContext accountId={account.id} context={c} />
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
