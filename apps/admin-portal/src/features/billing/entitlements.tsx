'use client';

import type { ReactNode } from 'react';
import { ToneBadge } from '@/components/domain/tone-badge';
import { formatNumber, humanize } from '@/lib/format';

export interface LimitRow {
  readonly key: string;
  readonly value: number;
  readonly source: 'plan' | 'override';
  readonly used?: number | null;
}

export interface FeatureRow {
  readonly key: string;
  readonly enabled: boolean;
  readonly source: 'plan' | 'override';
}

export function SourceBadge({ source }: { source: 'plan' | 'override' }) {
  return source === 'override' ? (
    <ToneBadge tone="purple">Override</ToneBadge>
  ) : (
    <ToneBadge tone="neutral">Plan</ToneBadge>
  );
}

/** Limits with their source (plan or override) and, when the api reports it, the use. */
export function LimitsTable({
  caption,
  limits,
  showUsed = false,
  actions,
}: {
  caption: string;
  limits: readonly LimitRow[];
  showUsed?: boolean;
  actions?: (limit: LimitRow) => ReactNode;
}) {
  if (limits.length === 0) {
    return <p className="text-sm text-muted-foreground">No limits are defined.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <caption className="pb-2 text-left text-sm font-semibold">{caption}</caption>
        <thead>
          <tr className="border-b text-xs text-muted-foreground">
            <th scope="col" className="px-2 py-1.5 text-left font-semibold">
              Limit
            </th>
            {showUsed ? (
              <th scope="col" className="px-2 py-1.5 text-right font-semibold">
                Used
              </th>
            ) : null}
            <th scope="col" className="px-2 py-1.5 text-right font-semibold">
              Value
            </th>
            <th scope="col" className="px-2 py-1.5 text-left font-semibold">
              Source
            </th>
            {actions ? (
              <th scope="col" className="px-2 py-1.5 text-right font-semibold">
                <span className="sr-only">Actions</span>
              </th>
            ) : null}
          </tr>
        </thead>
        <tbody>
          {limits.map((limit) => (
            <tr key={limit.key} className="border-b last:border-0">
              <th scope="row" className="px-2 py-1.5 text-left font-normal">
                <span className="grid">
                  <span>{humanize(limit.key)}</span>
                  <span className="font-mono text-xs text-muted-foreground">{limit.key}</span>
                </span>
              </th>
              {showUsed ? (
                <td className="px-2 py-1.5 text-right tabular-nums">
                  {limit.used === null || limit.used === undefined ? (
                    <span className="text-muted-foreground">Not measured</span>
                  ) : (
                    formatNumber(limit.used)
                  )}
                </td>
              ) : null}
              <td className="px-2 py-1.5 text-right tabular-nums">{formatNumber(limit.value)}</td>
              <td className="px-2 py-1.5">
                <SourceBadge source={limit.source} />
              </td>
              {actions ? <td className="px-2 py-1.5 text-right">{actions(limit)}</td> : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Plan features (enabled or not) with their source. */
export function FeaturesTable({
  caption,
  features,
  actions,
}: {
  caption: string;
  features: readonly FeatureRow[];
  actions?: (feature: FeatureRow) => ReactNode;
}) {
  if (features.length === 0) {
    return <p className="text-sm text-muted-foreground">No features are defined.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <caption className="pb-2 text-left text-sm font-semibold">{caption}</caption>
        <thead>
          <tr className="border-b text-xs text-muted-foreground">
            <th scope="col" className="px-2 py-1.5 text-left font-semibold">
              Feature
            </th>
            <th scope="col" className="px-2 py-1.5 text-left font-semibold">
              State
            </th>
            <th scope="col" className="px-2 py-1.5 text-left font-semibold">
              Source
            </th>
            {actions ? (
              <th scope="col" className="px-2 py-1.5 text-right font-semibold">
                <span className="sr-only">Actions</span>
              </th>
            ) : null}
          </tr>
        </thead>
        <tbody>
          {features.map((feature) => (
            <tr key={feature.key} className="border-b last:border-0">
              <th scope="row" className="px-2 py-1.5 text-left font-normal">
                <span className="grid">
                  <span>{humanize(feature.key)}</span>
                  <span className="font-mono text-xs text-muted-foreground">{feature.key}</span>
                </span>
              </th>
              <td className="px-2 py-1.5">
                {feature.enabled ? (
                  <ToneBadge tone="success">Enabled</ToneBadge>
                ) : (
                  <ToneBadge tone="neutral">Disabled</ToneBadge>
                )}
              </td>
              <td className="px-2 py-1.5">
                <SourceBadge source={feature.source} />
              </td>
              {actions ? <td className="px-2 py-1.5 text-right">{actions(feature)}</td> : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Rolling usage (`GET /usage`, `GET /organizations/{id}/usage`): counts by state. */
export function UsageSummary({
  usage,
}: {
  usage: {
    period: { from: string; to: string };
    users: { total: number; active: number; invited: number; disabled: number; locked: number };
    domains: {
      total: number;
      verified: number;
      pendingVerification: number;
      active: number;
      suspended: number;
    };
    messages: { total: number; inbound: number; outbound: number; internal: number; today: number };
    quarantine: { active: number };
    apiKeys: { active: number };
    sessions: { active: number };
  };
}) {
  const groups: { title: string; items: [string, number][] }[] = [
    {
      title: 'Messages in the period',
      items: [
        ['Total', usage.messages.total],
        ['Inbound', usage.messages.inbound],
        ['Outbound', usage.messages.outbound],
        ['Internal', usage.messages.internal],
        ['Today (UTC)', usage.messages.today],
      ],
    },
    {
      title: 'Users',
      items: [
        ['Total', usage.users.total],
        ['Active', usage.users.active],
        ['Invited', usage.users.invited],
        ['Disabled', usage.users.disabled],
        ['Locked', usage.users.locked],
      ],
    },
    {
      title: 'Domains',
      items: [
        ['Total', usage.domains.total],
        ['Verified', usage.domains.verified],
        ['Pending verification', usage.domains.pendingVerification],
        ['Active', usage.domains.active],
        ['Suspended', usage.domains.suspended],
      ],
    },
    {
      title: 'Other',
      items: [
        ['Active quarantine entries', usage.quarantine.active],
        ['Active API keys', usage.apiKeys.active],
        ['Active sessions', usage.sessions.active],
      ],
    },
  ];
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {groups.map((group) => (
        <div key={group.title} className="rounded-md border p-3">
          <h3 className="pb-2 text-sm font-semibold">{group.title}</h3>
          <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1 text-sm">
            {group.items.map(([label, value]) => (
              <div key={label} className="contents">
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="text-right tabular-nums">{formatNumber(value)}</dd>
              </div>
            ))}
          </dl>
        </div>
      ))}
    </div>
  );
}
