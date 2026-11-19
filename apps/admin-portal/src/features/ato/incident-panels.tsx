'use client';

import Link from 'next/link';
import { useId, useMemo, useState } from 'react';
import { DateTime } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useDebouncedValue } from '@/hooks/use-debounced-value';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { CursorPager, DetailList, EnumBadge, Section } from '@/features/messages/controls';
import type { IncidentCategoryUi, IncidentDetail } from '@/features/incidents/model';
import { TrustedContextFields, trustedKindLabel } from './account-actions';
import { SignalTable } from './account-page';
import { AtoScore, CapabilityList, KindLabel, pagerOf, ScrollRegion } from './components';
import {
  ACTION_LABELS,
  KIND_LABELS,
  OUTCOME_TONE,
  accountLabel,
  atoAccountHref,
  countryName,
  labelOf,
  str,
  policyPresetHref,
  type AtoAccountKind,
  type AtoActionType,
  type TrustedContextKind,
} from './model';
import { RequestResponseButton } from './response-actions';
import { responseColumns } from './responses-page';
import { DataTable } from '@/components/data-table';

/**
 * The account takeover panels of the generic incident page (step 8.4 §6, D12, D13): account and
 * scores, detection reason, risk signals, related sign-ins, IPs/geography/devices, recommended
 * remediation (request buttons, the provider and manual hints, the policy preset link) and the
 * responses with their approval controls; the false-positive feedback of the resolution dialog.
 */

interface AtoDetailAccount {
  id: string;
  kind: AtoAccountKind;
  address: string | null;
  userId: string | null;
  connectorId: string | null;
  riskScore: number;
  riskLevel: string;
  protected: boolean;
}

interface Recommendation {
  actionType: AtoActionType | 'policy_hold_outbound';
  availability: 'available' | 'requires_provider' | 'manual' | 'policy';
  impact: string | null;
  target: { scope?: string; connectorId?: string | null; cidr?: string | null } | null;
  reason: string;
  manual?: string;
  preset?: string;
}

interface AtoDetail {
  account: AtoDetailAccount | null;
  riskScoreAtOpen: number | null;
  peakRiskScore: number | null;
  detectionReason: { codes?: string[]; versions?: Record<string, unknown> } | null;
  detectionReasonText: string[];
  recommendedActions: Recommendation[];
  relatedIps: Array<{
    ip: string;
    country: string | null;
    asn: number | null;
    reputation: string | null;
    count: number;
  }>;
  geoSummary: { countries?: string[] } | null;
  deviceSummary: { devices?: string[] } | null;
  counts: { signals: number; authEvents: number; messages: number; findings: number };
  responses: { total: number; pendingApproval: number } | null;
}

const arr = <T,>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);

/** The ATO detail of an incident, read leniently (the api documents it as a record). */
export function atoDetailOf(incident: IncidentDetail): AtoDetail {
  const d = incident.detail as Record<string, unknown>;
  const counts = (d.counts ?? {}) as Record<string, unknown>;
  return {
    account: (d.account as AtoDetailAccount | null) ?? null,
    riskScoreAtOpen: typeof d.riskScoreAtOpen === 'number' ? d.riskScoreAtOpen : null,
    peakRiskScore: typeof d.peakRiskScore === 'number' ? d.peakRiskScore : null,
    detectionReason: (d.detectionReason as AtoDetail['detectionReason']) ?? null,
    detectionReasonText: arr<string>(d.detectionReasonText),
    recommendedActions: arr<Recommendation>(d.recommendedActions),
    relatedIps: arr(d.relatedIps),
    geoSummary: (d.geoSummary as AtoDetail['geoSummary']) ?? null,
    deviceSummary: (d.deviceSummary as AtoDetail['deviceSummary']) ?? null,
    counts: {
      signals: Number(counts.signals ?? 0),
      authEvents: Number(counts.authEvents ?? 0),
      messages: Number(counts.messages ?? 0),
      findings: Number(counts.findings ?? 0),
    },
    responses: (d.responses as AtoDetail['responses']) ?? null,
  };
}

const MANUAL_TEXT: Record<string, { text: string; href: (a: AtoDetailAccount) => string | null }> =
  {
    rotate_connector_secret: {
      text: 'Rotate the SMTP connector secret (Mail servers → Connectors).',
      href: () => '/mail-servers?tab=connectors',
    },
    revoke_portal_sessions: {
      text: 'Revoke the user’s portal sessions (Users).',
      href: (a) => (a.userId ? `/users/${a.userId}` : '/users'),
    },
    reset_portal_mfa: {
      text: 'Reset the user’s MFA (Users).',
      href: (a) => (a.userId ? `/users/${a.userId}` : '/users'),
    },
    disable_portal_user: {
      text: 'Disable the portal user (Users).',
      href: (a) => (a.userId ? `/users/${a.userId}` : '/users'),
    },
  };

function AccountPanel({ incident, detail }: { incident: IncidentDetail; detail: AtoDetail }) {
  const a = detail.account;
  return (
    <Section title="Account and scores" headingLevel={2}>
      {a ? (
        <DetailList
          items={[
            {
              label: 'Account',
              value: (
                <span className="grid gap-0.5">
                  <Link
                    href={atoAccountHref(a.id)}
                    className="font-medium text-primary underline-offset-2 hover:underline"
                  >
                    {accountLabel({ ...a, displayName: incident.subject.display })}
                  </Link>
                  <KindLabel kind={a.kind} />
                </span>
              ),
            },
            { label: 'Current score', value: <AtoScore score={a.riskScore} level={a.riskLevel} /> },
            { label: 'Score at detection', value: detail.riskScoreAtOpen ?? '—' },
            { label: 'Peak score', value: detail.peakRiskScore ?? '—' },
            { label: 'Protected', value: a.protected ? 'Yes' : 'No' },
            {
              label: 'Evidence',
              value: `${formatNumber(detail.counts.signals)} signals · ${formatNumber(detail.counts.authEvents)} sign-ins · ${formatNumber(detail.counts.messages)} messages · ${formatNumber(detail.counts.findings)} findings`,
            },
          ]}
        />
      ) : (
        <p className="text-sm text-muted-foreground">The account no longer exists (retired).</p>
      )}
    </Section>
  );
}

function ReasonPanel({ detail }: { detail: AtoDetail }) {
  const versions = detail.detectionReason?.versions ?? {};
  return (
    <Section
      title="Detection reason"
      description="The contributions that raised the score when the incident opened."
      headingLevel={2}
    >
      {detail.detectionReasonText.length > 0 ? (
        <ul className="grid gap-1 text-sm" aria-label="Contributions">
          {detail.detectionReasonText.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted-foreground">
          {detail.detectionReason?.codes?.join(', ') || 'Opened manually by an analyst.'}
        </p>
      )}
      {Object.keys(versions).length > 0 ? (
        <p className="font-mono text-xs text-muted-foreground">
          {Object.entries(versions)
            .map(([k, v]) => `${k} ${String(v)}`)
            .join(' · ')}
        </p>
      ) : null}
    </Section>
  );
}

function SignalsPanel({ incident }: { incident: IncidentDetail }) {
  const list = useCursorList(
    'AtoIncidentEvidenceController_signals_v1',
    { sort: '-at' },
    { path: { incidentId: incident.id }, limit: 25 },
  );
  return (
    <Section title="Risk signals" headingLevel={2}>
      {list.query.isLoading ? (
        <LoadingState label="Loading signals" variant="table" />
      ) : list.query.error ? (
        <ErrorState error={list.query.error} onRetry={() => void list.query.refetch()} compact />
      ) : list.rows.length === 0 ? (
        <EmptyState title="No linked signals" />
      ) : (
        <SignalTable rows={list.rows} caption="Signals linked to the incident" />
      )}
      <CursorPager label="Incident signals" state={pagerOf(list)} />
    </Section>
  );
}

function SignInsPanel({ incident }: { incident: IncidentDetail }) {
  const list = useCursorList(
    'AtoIncidentEvidenceController_authEvents_v1',
    { sort: '-at' },
    { path: { incidentId: incident.id }, limit: 25 },
  );
  return (
    <Section title="Related sign-ins" headingLevel={2}>
      {list.query.isLoading ? (
        <LoadingState label="Loading sign-ins" variant="table" />
      ) : list.query.error ? (
        <ErrorState error={list.query.error} onRetry={() => void list.query.refetch()} compact />
      ) : list.rows.length === 0 ? (
        <EmptyState title="No linked sign-ins" />
      ) : (
        <ScrollRegion label="Sign-ins linked to the incident">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Sign-ins linked to the incident</caption>
            <thead className="bg-muted/50 text-xs text-muted-foreground">
              <tr>
                {['Time', 'Source', 'Outcome', 'IP address', 'Country', 'Device'].map((h) => (
                  <th key={h} scope="col" className="px-2 py-1.5 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {list.rows.map((e) => (
                <tr key={e.id} className="border-t">
                  <td className="px-2 py-1.5 whitespace-nowrap">
                    <DateTime value={e.occurredAt} />
                  </td>
                  <td className="px-2 py-1.5">{humanize(e.source)}</td>
                  <td className="px-2 py-1.5">
                    <EnumBadge value={e.outcome} tones={OUTCOME_TONE} />
                  </td>
                  <td className="px-2 py-1.5 font-mono text-xs">{e.ipAddress ?? '—'}</td>
                  <td className="px-2 py-1.5">
                    {e.geo.status === 'unavailable'
                      ? 'Unavailable'
                      : countryName(e.geo.countryCode)}
                  </td>
                  <td className="px-2 py-1.5">{e.device?.label ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </ScrollRegion>
      )}
      <CursorPager label="Incident sign-ins" state={pagerOf(list)} />
    </Section>
  );
}

function ContextPanel({ detail }: { detail: AtoDetail }) {
  const countries = detail.geoSummary?.countries ?? [];
  const devices = detail.deviceSummary?.devices ?? [];
  return (
    <Section title="IPs, geography and devices" headingLevel={2}>
      {detail.relatedIps.length > 0 ? (
        <ScrollRegion label="Related IP addresses">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Related IP addresses</caption>
            <thead className="bg-muted/50 text-xs text-muted-foreground">
              <tr>
                {['IP address', 'Country', 'Network', 'Reputation', 'Attempts'].map((h) => (
                  <th key={h} scope="col" className="px-2 py-1.5 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {detail.relatedIps.map((ip) => (
                <tr key={ip.ip} className="border-t">
                  <td className="px-2 py-1.5 font-mono text-xs">{ip.ip}</td>
                  <td className="px-2 py-1.5">
                    {ip.country ? countryName(ip.country) : 'Unknown'}
                  </td>
                  <td className="px-2 py-1.5">{ip.asn ? `AS${ip.asn}` : '—'}</td>
                  <td className="px-2 py-1.5">
                    {ip.reputation ? humanize(ip.reputation) : 'No finding'}
                  </td>
                  <td className="px-2 py-1.5 tabular-nums">{formatNumber(ip.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </ScrollRegion>
      ) : (
        <p className="text-sm text-muted-foreground">No related sign-in addresses.</p>
      )}
      <DetailList
        items={[
          {
            label: 'Countries',
            value:
              countries.length > 0
                ? countries.map(countryName).join(', ')
                : 'None located (locations need the operator’s GeoIP City database)',
          },
          { label: 'Devices', value: devices.length > 0 ? devices.join(', ') : 'None recorded' },
        ]}
      />
    </Section>
  );
}

function RecommendationsPanel({
  incident,
  detail,
}: {
  incident: IncidentDetail;
  detail: AtoDetail;
}) {
  const account = detail.account;
  const canPolicy = useCan('PolicyManagementController_create_v1');
  const active = !['false_positive', 'resolved'].includes(incident.status);
  return (
    <Section
      title="Recommended remediation"
      description="Recommendations of the detection engine for this account. High-impact responses need a second analyst’s approval."
      headingLevel={2}
    >
      {detail.recommendedActions.length === 0 ? (
        <p className="text-sm text-muted-foreground">No recommendation.</p>
      ) : (
        <ul className="grid gap-2" aria-label="Recommendations">
          {detail.recommendedActions.map((r, i) => {
            const title =
              r.actionType === 'policy_hold_outbound'
                ? 'Hold outbound mail of high-risk accounts'
                : labelOf(ACTION_LABELS, r.actionType);
            return (
              <li
                key={`${r.actionType}-${r.manual ?? ''}-${i}`}
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2 text-sm"
              >
                <span className="grid gap-0.5">
                  <span className="font-medium">{title}</span>
                  <span className="text-xs text-muted-foreground">
                    {r.impact ? `${humanize(r.impact)} impact · ` : ''}because of {r.reason}
                    {r.target?.cidr ? ` · ${r.target.cidr}` : ''}
                  </span>
                </span>
                {r.availability === 'available' && account && active ? (
                  <RequestResponseButton
                    incidentId={incident.id}
                    accountKind={account.kind}
                    label="Request"
                    preset={{
                      actionType: r.actionType as AtoActionType,
                      target: r.target?.scope
                        ? {
                            scope: r.target.scope as
                              'mailbox' | 'connector' | 'connector_ip' | 'account',
                            ...(r.target.cidr ? { cidr: r.target.cidr } : {}),
                          }
                        : undefined,
                    }}
                  />
                ) : r.availability === 'requires_provider' ? (
                  <span className="text-xs text-muted-foreground">
                    Needs an identity-provider adapter (step 8.5)
                  </span>
                ) : r.availability === 'manual' && account ? (
                  <span className="text-xs">
                    {MANUAL_TEXT[r.manual ?? '']?.text ?? 'Act in the administration pages.'}{' '}
                    {MANUAL_TEXT[r.manual ?? '']?.href(account) ? (
                      <Link
                        href={MANUAL_TEXT[r.manual ?? '']!.href(account)!}
                        className="text-primary underline-offset-2 hover:underline"
                      >
                        Open
                      </Link>
                    ) : null}
                  </span>
                ) : r.availability === 'policy' && r.preset ? (
                  canPolicy ? (
                    <Button asChild size="sm" variant="outline">
                      <Link href={policyPresetHref(r.preset)}>Create a hold rule</Link>
                    </Button>
                  ) : (
                    <span className="text-xs text-muted-foreground">Needs policy:manage</span>
                  )
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
    </Section>
  );
}

function ResponsesPanel({ incident, detail }: { incident: IncidentDetail; detail: AtoDetail }) {
  const filters = useMemo(
    () => ({ sort: '-createdAt' as const, incidentId: incident.id }),
    [incident.id],
  );
  const list = useCursorList('AtoResponsesController_list_v1', filters, { limit: 25 });
  const active = !['false_positive', 'resolved'].includes(incident.status);
  return (
    <Section
      title="Responses"
      description="Requested, approved and executed responses of this incident."
      headingLevel={2}
      actions={
        detail.account && active ? (
          <RequestResponseButton incidentId={incident.id} accountKind={detail.account.kind} />
        ) : null
      }
    >
      <DataTable
        tableId="incident-ato-responses"
        caption="Responses of the incident"
        columns={responseColumns().filter((c) => c.id !== 'incident')}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => labelOf(ACTION_LABELS, row.actionType)}
        emptyState={<EmptyState title="No responses yet" />}
      />
    </Section>
  );
}

function AtoIncidentPanels({ incident }: { incident: IncidentDetail }) {
  const detail = atoDetailOf(incident);
  const settings = useApiQuery('AtoSettingsController_get_v1', undefined, { retry: false });
  return (
    <div className="grid min-w-0 gap-4">
      <div className="grid min-w-0 gap-4 xl:grid-cols-2">
        <AccountPanel incident={incident} detail={detail} />
        <ReasonPanel detail={detail} />
      </div>
      <RecommendationsPanel incident={incident} detail={detail} />
      <ResponsesPanel incident={incident} detail={detail} />
      <SignalsPanel incident={incident} />
      <SignInsPanel incident={incident} />
      <ContextPanel detail={detail} />
      {settings.data ? (
        <Section title="Detection capabilities" headingLevel={2}>
          <CapabilityList capabilities={settings.data.capabilities} />
        </Section>
      ) : null}
    </div>
  );
}

interface FeedbackContext {
  kind: TrustedContextKind;
  value: string;
  expiresInDays: number;
  reason: string;
}

/** False-positive feedback (§5.2 I4 `categoryFeedback`): dismiss signals, add trusted contexts. */
function AtoFeedbackFields({
  value,
  onChange,
}: {
  incident: IncidentDetail;
  value: Record<string, unknown>;
  onChange: (value: Record<string, unknown>) => void;
}) {
  const dismissId = useId();
  const contexts = arr<FeedbackContext>(value.trustedContexts);
  const [kind, setKind] = useState<TrustedContextKind>('ip_cidr');
  const [ctxValue, setCtxValue] = useState('');
  const [days, setDays] = useState(90);
  const dismiss = value.dismissSignals !== false;
  return (
    <fieldset className="grid gap-3 rounded-md border p-3">
      <legend className="px-1 text-sm font-semibold">False-positive feedback</legend>
      <div className="flex items-center gap-2">
        <Checkbox
          id={dismissId}
          checked={dismiss}
          onCheckedChange={(checked) => onChange({ ...value, dismissSignals: checked === true })}
        />
        <Label htmlFor={dismissId} className="text-sm">
          Dismiss the incident’s active signals (the account is rescored)
        </Label>
      </div>
      <p className="text-xs text-muted-foreground">
        Optionally trust the context that caused it (at most 20; each expires within 365 days).
      </p>
      <TrustedContextFields
        kind={kind}
        value={ctxValue}
        days={days}
        onKind={setKind}
        onValue={setCtxValue}
        onDays={setDays}
      />
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="justify-self-start"
        disabled={!ctxValue.trim() || days < 1 || days > 365 || contexts.length >= 20}
        onClick={() => {
          onChange({
            ...value,
            trustedContexts: [
              ...contexts,
              {
                kind,
                value: ctxValue.trim(),
                expiresInDays: days,
                reason: 'false positive feedback',
              },
            ],
          });
          setCtxValue('');
        }}
      >
        Add trusted context
      </Button>
      {contexts.length > 0 ? (
        <ul className="grid gap-1 text-sm" aria-label="Trusted contexts to add">
          {contexts.map((c, i) => (
            <li key={`${c.kind}-${c.value}`} className="flex items-center justify-between gap-2">
              <span>
                {trustedKindLabel(c.kind)}: <span className="font-mono">{c.value}</span> (
                {c.expiresInDays} days)
              </span>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                aria-label={`Remove ${c.value}`}
                onClick={() =>
                  onChange({ ...value, trustedContexts: contexts.filter((_, j) => j !== i) })
                }
              >
                Remove
              </Button>
            </li>
          ))}
        </ul>
      ) : null}
    </fieldset>
  );
}

/** Manual incident subject: an account found by address prefix (≥ 2 characters). */
function AtoSubjectPicker({
  value,
  onChange,
}: {
  value: { id: string; label: string } | null;
  onChange: (value: { id: string; label: string } | null) => void;
}) {
  const id = useId();
  const [text, setText] = useState('');
  const q = useDebouncedValue(text.trim(), 300);
  const accounts = useApiQuery(
    'AtoAccountsController_list_v1',
    { query: { q, limit: '10', sort: 'address' } },
    { enabled: q.length >= 2 },
  );
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>Account (address starts with)</Label>
      <Input
        id={id}
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="at least 2 characters"
        autoComplete="off"
        spellCheck={false}
      />
      {value ? (
        <p className="text-sm">
          Selected: <span className="font-medium">{value.label}</span>{' '}
          <Button
            type="button"
            variant="link"
            size="sm"
            className="h-auto p-0"
            onClick={() => onChange(null)}
          >
            Change
          </Button>
        </p>
      ) : q.length >= 2 ? (
        accounts.isLoading ? (
          <p className="text-xs text-muted-foreground">Searching …</p>
        ) : (accounts.data?.data.length ?? 0) === 0 ? (
          <p className="text-xs text-muted-foreground">No monitored account matches.</p>
        ) : (
          <ul className="grid gap-1" aria-label="Matching accounts">
            {accounts.data?.data.map((a) => (
              <li key={a.id}>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => onChange({ id: a.id, label: accountLabel(a) })}
                >
                  {accountLabel(a)} ({labelOf(KIND_LABELS, a.kind)}, score {a.riskScore})
                </Button>
              </li>
            ))}
          </ul>
        )
      ) : null}
    </div>
  );
}

function AtoReportSection({ section }: { section: { id: string; title: string; data: unknown } }) {
  const data = section.data as Record<string, unknown> | unknown[] | null;
  if (section.id === 'ato.signals' && Array.isArray(data)) {
    return (
      <ScrollRegion label={section.title}>
        <table className="w-full text-left text-sm">
          <caption className="sr-only">{section.title}</caption>
          <thead>
            <tr>
              {['Signal', 'Category', 'Strength', 'Status', 'Last seen', 'Explanation'].map((h) => (
                <th key={h} scope="col" className="border-b px-1 py-1 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((s, i) => {
              const x = s as Record<string, unknown>;
              return (
                <tr key={i} className="border-b align-top">
                  <td className="px-1 py-1">{String(x.title ?? x.code)}</td>
                  <td className="px-1 py-1">{humanize(str(x.category))}</td>
                  <td className="px-1 py-1">{humanize(str(x.strength))}</td>
                  <td className="px-1 py-1">{humanize(str(x.status))}</td>
                  <td className="px-1 py-1">
                    {str(x.lastOccurredAt).replace('T', ' ').slice(0, 16)}
                  </td>
                  <td className="px-1 py-1">{str(x.explanation)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </ScrollRegion>
    );
  }
  if (section.id === 'ato.responses' && Array.isArray(data)) {
    return data.length === 0 ? (
      <p className="text-sm">No responses.</p>
    ) : (
      <ul className="grid gap-1 text-sm">
        {data.map((r, i) => {
          const x = r as Record<string, unknown>;
          return (
            <li key={i}>
              {labelOf(ACTION_LABELS, str(x.type))}: {humanize(str(x.status))}
              {x.providerStatus ? ` (${humanize(str(x.providerStatus))})` : ''}, requested{' '}
              {str(x.requestedAt).replace('T', ' ').slice(0, 16)} UTC
            </li>
          );
        })}
      </ul>
    );
  }
  return null;
}

export const ATO_INCIDENT_CATEGORY: IncidentCategoryUi = {
  id: 'account_takeover',
  label: 'Account takeover',
  readPermission: 'ato:read',
  managePermission: 'ato:manage',
  subjectType: 'ato_account',
  subjectLabel: 'Account',
  subjectHref: (subjectId) => atoAccountHref(subjectId),
  SubjectPicker: AtoSubjectPicker,
  DetailPanels: AtoIncidentPanels,
  FeedbackFields: AtoFeedbackFields,
  initialFeedback: () => ({ dismissSignals: true, trustedContexts: [] }),
  ReportSection: AtoReportSection,
};
