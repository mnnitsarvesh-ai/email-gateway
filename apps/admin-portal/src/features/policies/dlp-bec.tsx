'use client';

import Link from 'next/link';
import type { ReactNode } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime, DirectionBadge, UntrustedText } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem, OperationId } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge, Section, YesNo } from '@/features/messages/controls';
import { messageHref } from '@/features/messages/links';
import { ENABLED_TONE } from './semantic';

const enabledBadge = (enabled: boolean) => (
  <EnumBadge value={enabled ? 'enabled' : 'disabled'} tones={ENABLED_TONE} />
);

function Sections<T extends string>({
  label,
  sections,
  labels,
  render,
}: {
  label: string;
  sections: readonly T[];
  labels: Record<T, string>;
  render: (section: T) => ReactNode;
}) {
  const shape = { section: z.enum(sections as unknown as [T, ...T[]]).catch(sections[0] as T) };
  const [state, setState] = useUrlState(shape);
  const current = state.section ?? sections[0];
  return (
    <Tabs value={current} onValueChange={(section) => setState({ section: section as T })}>
      <TabsList aria-label={label}>
        {sections.map((section) => (
          <TabsTrigger key={section} value={section}>
            {labels[section]}
          </TabsTrigger>
        ))}
      </TabsList>
      {sections.map((section) => (
        <TabsContent key={section} value={section}>
          {section === current ? render(section) : null}
        </TabsContent>
      ))}
    </Tabs>
  );
}

function ListTable<Id extends OperationId, Row>({
  operationId,
  tableId,
  caption,
  columns,
  getRowId,
  emptyTitle,
  mobile,
}: {
  operationId: Id;
  tableId: string;
  caption: string;
  columns: DataTableColumn<Row>[];
  getRowId: (row: Row) => string;
  emptyTitle: string;
  mobile: (row: Row) => ReactNode;
}) {
  const list = useCursorList(operationId, undefined, { limit: 25 });
  return (
    <DataTable
      tableId={tableId}
      caption={caption}
      columns={columns}
      list={list as unknown as Parameters<typeof DataTable<Row>>[0]['list']}
      getRowId={getRowId}
      emptyState={<EmptyState title={emptyTitle} />}
      mobileCard={mobile}
    />
  );
}

type DlpPolicy = ListItem<'DlpPoliciesController_list_v1'>;
type DlpPattern = ListItem<'DlpPatternsController_list_v1'>;
type DlpDictionary = ListItem<'DlpDictionariesController_list_v1'>;
type DlpException = ListItem<'DlpExceptionsController_list_v1'>;
type DlpIncident = ListItem<'DlpIncidentsController_list_v1'>;

const DLP_POLICY_COLUMNS: DataTableColumn<DlpPolicy>[] = [
  { id: 'name', header: 'Policy', meta: { label: 'Policy' }, cell: ({ row }) => row.original.name },
  {
    id: 'enabled',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => enabledBadge(row.original.enabled),
  },
  {
    id: 'mode',
    header: 'Mode',
    meta: { label: 'Mode' },
    cell: ({ row }) => humanize(row.original.mode),
  },
  {
    id: 'directions',
    header: 'Directions',
    meta: { label: 'Directions' },
    cell: ({ row }) => row.original.directions.map(humanize).join(', '),
  },
  {
    id: 'rules',
    header: 'Rules',
    meta: { label: 'Rules', className: 'tabular-nums' },
    cell: ({ row }) => formatNumber(row.original.ruleCount),
  },
  {
    id: 'priority',
    header: 'Priority',
    meta: { label: 'Priority', className: 'tabular-nums' },
    cell: ({ row }) => formatNumber(row.original.priority),
  },
  {
    id: 'updated',
    header: 'Updated',
    meta: { label: 'Updated' },
    cell: ({ row }) => <DateTime value={row.original.updatedAt} />,
  },
];

const DLP_PATTERN_COLUMNS: DataTableColumn<DlpPattern>[] = [
  {
    id: 'name',
    header: 'Pattern',
    meta: { label: 'Pattern' },
    cell: ({ row }) => row.original.name,
  },
  {
    id: 'pattern',
    header: 'Expression',
    meta: { label: 'Expression', className: 'max-w-72' },
    cell: ({ row }) => <UntrustedText value={row.original.pattern} mono maxLength={60} />,
  },
  {
    id: 'validator',
    header: 'Validator',
    meta: { label: 'Validator' },
    cell: ({ row }) => humanize(row.original.validator),
  },
  {
    id: 'severity',
    header: 'Severity',
    meta: { label: 'Severity' },
    cell: ({ row }) => humanize(row.original.severity),
  },
  {
    id: 'enabled',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => enabledBadge(row.original.enabled),
  },
];

const DLP_DICTIONARY_COLUMNS: DataTableColumn<DlpDictionary>[] = [
  {
    id: 'name',
    header: 'Dictionary',
    meta: { label: 'Dictionary' },
    cell: ({ row }) => row.original.name,
  },
  {
    id: 'category',
    header: 'Category',
    meta: { label: 'Category' },
    cell: ({ row }) => humanize(row.original.category),
  },
  {
    id: 'terms',
    header: 'Terms',
    meta: { label: 'Terms', className: 'tabular-nums' },
    cell: ({ row }) => formatNumber(row.original.termCount),
  },
  {
    id: 'severity',
    header: 'Severity',
    meta: { label: 'Severity' },
    cell: ({ row }) => humanize(row.original.severity),
  },
  {
    id: 'enabled',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => enabledBadge(row.original.enabled),
  },
];

const DLP_EXCEPTION_COLUMNS: DataTableColumn<DlpException>[] = [
  {
    id: 'scope',
    header: 'Scope',
    meta: { label: 'Scope' },
    cell: ({ row }) => humanize(row.original.scope),
  },
  {
    id: 'value',
    header: 'Value',
    meta: { label: 'Value' },
    cell: ({ row }) => <UntrustedText value={row.original.value} maxLength={60} />,
  },
  {
    id: 'reason',
    header: 'Reason',
    meta: { label: 'Reason', className: 'max-w-72' },
    cell: ({ row }) => <UntrustedText value={row.original.reason} maxLength={80} />,
  },
  {
    id: 'expires',
    header: 'Expires',
    meta: { label: 'Expires' },
    cell: ({ row }) => <DateTime value={row.original.expiresAt} />,
  },
  {
    id: 'status',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) =>
      row.original.expired ? (
        <EnumBadge value="expired" tones={ENABLED_TONE} />
      ) : (
        enabledBadge(row.original.enabled)
      ),
  },
];

function incidentColumns(canMessages: boolean): DataTableColumn<DlpIncident>[] {
  return [
    {
      id: 'detected',
      header: 'Detected',
      meta: { label: 'Detected' },
      cell: ({ row }) => <DateTime value={row.original.detectedAt} />,
    },
    {
      id: 'direction',
      header: 'Direction',
      meta: { label: 'Direction' },
      cell: ({ row }) => <DirectionBadge direction={row.original.direction} />,
    },
    {
      id: 'action',
      header: 'Action',
      meta: { label: 'Action' },
      cell: ({ row }) => humanize(row.original.action),
    },
    {
      id: 'categories',
      header: 'Categories',
      meta: { label: 'Categories' },
      cell: ({ row }) => (
        <CodeList codes={row.original.categories.map((c) => `${c.category} ×${c.count}`)} />
      ),
    },
    {
      id: 'findings',
      header: 'Findings',
      meta: { label: 'Findings', className: 'tabular-nums' },
      cell: ({ row }) => formatNumber(row.original.findingCount),
    },
    {
      id: 'message',
      header: 'Message',
      meta: { label: 'Message' },
      cell: ({ row }) =>
        canMessages ? (
          <Link
            href={messageHref(row.original.messageId)}
            className="text-xs text-primary hover:underline"
          >
            Open message
          </Link>
        ) : (
          <span className="text-xs text-muted-foreground">No access</span>
        ),
    },
  ];
}

const DLP_SECTIONS = [
  'policies',
  'patterns',
  'dictionaries',
  'exceptions',
  'incidents',
  'compliance',
] as const;
const DLP_LABELS: Record<(typeof DLP_SECTIONS)[number], string> = {
  policies: 'Policies',
  patterns: 'Patterns',
  dictionaries: 'Dictionaries',
  exceptions: 'Exceptions',
  incidents: 'Incidents',
  compliance: 'Compliance',
};

/** DLP configuration and incidents (dlp:read), read-only lists. */
export function DlpTab() {
  const canMessages = useCan('MessagesController_detail_v1');
  return (
    <Sections
      label="DLP sections"
      sections={DLP_SECTIONS}
      labels={DLP_LABELS}
      render={(section) => {
        switch (section) {
          case 'policies':
            return (
              <ListTable
                operationId="DlpPoliciesController_list_v1"
                tableId="dlp-policies"
                caption="DLP policies"
                columns={DLP_POLICY_COLUMNS}
                getRowId={(r: DlpPolicy) => r.id}
                emptyTitle="No DLP policies"
                mobile={(r: DlpPolicy) => r.name}
              />
            );
          case 'patterns':
            return (
              <ListTable
                operationId="DlpPatternsController_list_v1"
                tableId="dlp-patterns"
                caption="DLP patterns"
                columns={DLP_PATTERN_COLUMNS}
                getRowId={(r: DlpPattern) => r.id}
                emptyTitle="No custom patterns"
                mobile={(r: DlpPattern) => r.name}
              />
            );
          case 'dictionaries':
            return (
              <ListTable
                operationId="DlpDictionariesController_list_v1"
                tableId="dlp-dictionaries"
                caption="DLP dictionaries"
                columns={DLP_DICTIONARY_COLUMNS}
                getRowId={(r: DlpDictionary) => r.id}
                emptyTitle="No dictionaries"
                mobile={(r: DlpDictionary) => r.name}
              />
            );
          case 'exceptions':
            return (
              <ListTable
                operationId="DlpExceptionsController_list_v1"
                tableId="dlp-exceptions"
                caption="DLP exceptions"
                columns={DLP_EXCEPTION_COLUMNS}
                getRowId={(r: DlpException) => r.id}
                emptyTitle="No exceptions"
                mobile={(r: DlpException) => <UntrustedText value={r.value} />}
              />
            );
          case 'incidents':
            return (
              <ListTable
                operationId="DlpIncidentsController_list_v1"
                tableId="dlp-incidents"
                caption="DLP incidents"
                columns={incidentColumns(canMessages)}
                getRowId={(r: DlpIncident) => `${r.messageId}:${r.scanId}`}
                emptyTitle="No DLP incidents"
                mobile={(r: DlpIncident) => humanize(r.action)}
              />
            );
          default:
            return <DlpCompliance />;
        }
      }}
    />
  );
}

function DlpCompliance() {
  const compliance = useApiQuery('DlpComplianceController_get_v1');
  if (compliance.isLoading) return <LoadingState label="Loading compliance status" rows={4} />;
  if (compliance.error || !compliance.data) {
    return <ErrorState error={compliance.error} onRetry={() => void compliance.refetch()} />;
  }
  const a = compliance.data.aadhaar;
  return (
    <Section
      title="Aadhaar detection"
      description="Aadhaar numbers are detected only with a recorded legal basis."
    >
      <DetailList
        items={[
          { label: 'Enabled', value: <YesNo value={a.enabled} /> },
          { label: 'Active', value: <YesNo value={a.active} /> },
          {
            label: 'Legal basis',
            value: a.basis ? (
              humanize(a.basis)
            ) : (
              <span className="text-muted-foreground">None recorded</span>
            ),
          },
          { label: 'Reference', value: <UntrustedText value={a.reference} emptyLabel="None" /> },
          { label: 'Attested', value: <YesNo value={a.attested} /> },
          {
            label: 'Recorded',
            value: <DateTime value={a.recordedAt} mode="absolute" emptyLabel="Never" />,
          },
          {
            label: 'Review due',
            value: <DateTime value={a.reviewDueAt} mode="absolute" emptyLabel="Not set" />,
          },
        ]}
      />
    </Section>
  );
}

type Executive = ListItem<'BecExecutivesController_list_v1'>;
type Vendor = ListItem<'BecVendorsController_list_v1'>;
type TrustedSender = ListItem<'BecTrustedSendersController_list_v1'>;
type Feedback = ListItem<'BecFeedbackController_list_v1'>;
type Suppression = ListItem<'BecFeedbackController_listSuppressions_v1'>;

const EXECUTIVE_COLUMNS: DataTableColumn<Executive>[] = [
  {
    id: 'name',
    header: 'Executive',
    meta: { label: 'Executive' },
    cell: ({ row }) => row.original.displayName,
  },
  {
    id: 'title',
    header: 'Title',
    meta: { label: 'Title' },
    cell: ({ row }) => row.original.title ?? <span className="text-muted-foreground">None</span>,
  },
  {
    id: 'addresses',
    header: 'Known addresses',
    meta: { label: 'Known addresses', className: 'max-w-72' },
    cell: ({ row }) => <CodeList codes={row.original.knownAddresses} />,
  },
  {
    id: 'aliases',
    header: 'Aliases',
    meta: { label: 'Aliases' },
    cell: ({ row }) => <CodeList codes={row.original.aliases} />,
  },
  {
    id: 'enabled',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => enabledBadge(row.original.enabled),
  },
];

const VENDOR_COLUMNS: DataTableColumn<Vendor>[] = [
  { id: 'name', header: 'Vendor', meta: { label: 'Vendor' }, cell: ({ row }) => row.original.name },
  {
    id: 'domains',
    header: 'Domains',
    meta: { label: 'Domains' },
    cell: ({ row }) => <CodeList codes={row.original.domains} />,
  },
  {
    id: 'senders',
    header: 'Known senders',
    meta: { label: 'Known senders' },
    cell: ({ row }) => <CodeList codes={row.original.knownSenders} />,
  },
  {
    id: 'payment',
    header: 'Payment-change sensitive',
    meta: { label: 'Payment-change sensitive' },
    cell: ({ row }) => <YesNo value={row.original.paymentChangeSensitive} />,
  },
  {
    id: 'enabled',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => enabledBadge(row.original.enabled),
  },
];

const TRUSTED_COLUMNS: DataTableColumn<TrustedSender>[] = [
  {
    id: 'kind',
    header: 'Kind',
    meta: { label: 'Kind' },
    cell: ({ row }) => humanize(row.original.kind),
  },
  {
    id: 'value',
    header: 'Value',
    meta: { label: 'Value' },
    cell: ({ row }) => <UntrustedText value={row.original.value} mono />,
  },
  {
    id: 'reason',
    header: 'Reason',
    meta: { label: 'Reason' },
    cell: ({ row }) => <UntrustedText value={row.original.reason} maxLength={80} />,
  },
  {
    id: 'expires',
    header: 'Expires',
    meta: { label: 'Expires' },
    cell: ({ row }) => <DateTime value={row.original.expiresAt} emptyLabel="Never" />,
  },
];

function feedbackColumns(canMessages: boolean): DataTableColumn<Feedback>[] {
  return [
    {
      id: 'created',
      header: 'Recorded',
      meta: { label: 'Recorded' },
      cell: ({ row }) => <DateTime value={row.original.createdAt} />,
    },
    {
      id: 'kind',
      header: 'Kind',
      meta: { label: 'Kind' },
      cell: ({ row }) => humanize(row.original.kind),
    },
    {
      id: 'codes',
      header: 'Reason codes',
      meta: { label: 'Reason codes' },
      cell: ({ row }) => <CodeList codes={row.original.reasonCodes} />,
    },
    {
      id: 'note',
      header: 'Note',
      meta: { label: 'Note' },
      cell: ({ row }) => (
        <UntrustedText value={row.original.note} emptyLabel="None" maxLength={80} />
      ),
    },
    {
      id: 'message',
      header: 'Message',
      meta: { label: 'Message' },
      cell: ({ row }) =>
        row.original.messageId && canMessages ? (
          <Link
            href={messageHref(row.original.messageId)}
            className="text-xs text-primary hover:underline"
          >
            Open message
          </Link>
        ) : (
          <span className="text-xs text-muted-foreground">None</span>
        ),
    },
  ];
}

const SUPPRESSION_COLUMNS: DataTableColumn<Suppression>[] = [
  {
    id: 'code',
    header: 'Reason code',
    meta: { label: 'Reason code' },
    cell: ({ row }) => <span className="font-mono text-xs">{row.original.reasonCode}</span>,
  },
  {
    id: 'scope',
    header: 'Sender scope',
    meta: { label: 'Sender scope' },
    cell: ({ row }) => humanize(row.original.senderScope),
  },
  {
    id: 'value',
    header: 'Sender',
    meta: { label: 'Sender' },
    cell: ({ row }) => <UntrustedText value={row.original.senderValue} mono />,
  },
  {
    id: 'expires',
    header: 'Expires',
    meta: { label: 'Expires' },
    cell: ({ row }) => <DateTime value={row.original.expiresAt} />,
  },
  {
    id: 'status',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => (row.original.expired ? 'Expired' : 'Active'),
  },
];

const BEC_SECTIONS = ['executives', 'vendors', 'trusted', 'feedback', 'suppressions'] as const;
const BEC_LABELS: Record<(typeof BEC_SECTIONS)[number], string> = {
  executives: 'Executives',
  vendors: 'Vendors',
  trusted: 'Trusted senders',
  feedback: 'Feedback',
  suppressions: 'Suppressions',
};

/** Phishing and BEC tenant data (bec:read), read-only lists. */
export function BecTab() {
  const canMessages = useCan('MessagesController_detail_v1');
  return (
    <Sections
      label="BEC sections"
      sections={BEC_SECTIONS}
      labels={BEC_LABELS}
      render={(section) => {
        switch (section) {
          case 'executives':
            return (
              <ListTable
                operationId="BecExecutivesController_list_v1"
                tableId="bec-executives"
                caption="Protected executives"
                columns={EXECUTIVE_COLUMNS}
                getRowId={(r: Executive) => r.id}
                emptyTitle="No protected executives"
                mobile={(r: Executive) => r.displayName}
              />
            );
          case 'vendors':
            return (
              <ListTable
                operationId="BecVendorsController_list_v1"
                tableId="bec-vendors"
                caption="Vendors"
                columns={VENDOR_COLUMNS}
                getRowId={(r: Vendor) => r.id}
                emptyTitle="No vendors"
                mobile={(r: Vendor) => r.name}
              />
            );
          case 'trusted':
            return (
              <ListTable
                operationId="BecTrustedSendersController_list_v1"
                tableId="bec-trusted"
                caption="Trusted senders"
                columns={TRUSTED_COLUMNS}
                getRowId={(r: TrustedSender) => r.id}
                emptyTitle="No trusted senders"
                mobile={(r: TrustedSender) => <UntrustedText value={r.value} />}
              />
            );
          case 'feedback':
            return (
              <ListTable
                operationId="BecFeedbackController_list_v1"
                tableId="bec-feedback"
                caption="BEC feedback"
                columns={feedbackColumns(canMessages)}
                getRowId={(r: Feedback) => r.id}
                emptyTitle="No feedback recorded"
                mobile={(r: Feedback) => humanize(r.kind)}
              />
            );
          default:
            return (
              <ListTable
                operationId="BecFeedbackController_listSuppressions_v1"
                tableId="bec-suppressions"
                caption="Suppressions"
                columns={SUPPRESSION_COLUMNS}
                getRowId={(r: Suppression) => r.id}
                emptyTitle="No suppressions"
                mobile={(r: Suppression) => r.reasonCode}
              />
            );
        }
      }}
    />
  );
}
