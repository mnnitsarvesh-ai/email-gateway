'use client';

import Link from 'next/link';
import type { ReactNode } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime, DirectionBadge, UntrustedText } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { CodeList } from '@/features/messages/controls';
import { messageHref } from '@/features/messages/links';
import { BEC_CACHE_NOTE, ExecutivesSection, VendorsSection } from './dlp-bec/bec-profiles';
import { SuppressionsSection, TrustedSendersSection } from './dlp-bec/bec-senders';
import { DlpComplianceSection } from './dlp-bec/dlp-compliance';
import { DlpDictionariesSection } from './dlp-bec/dlp-dictionaries';
import { DlpExceptionsSection } from './dlp-bec/dlp-exceptions';
import { DlpPatternsSection } from './dlp-bec/dlp-patterns';
import { DlpPoliciesSection } from './dlp-bec/dlp-policies';
import type { BecFeedback, DlpIncident } from './dlp-bec/model';

/**
 * The DLP and BEC tabs of page 13 (`/policies?tab=dlp|bec`, step 7.3 WP5, design §2 B13): editors
 * over the existing API in sheets and dialogs inside the tabs (no routes of their own). Views need
 * `dlp:read` / `bec:read`; editing controls appear only with `dlp:manage` / `bec:manage` (the
 * Aadhaar basis with `dlp:compliance_manage` and an MFA session); the API stays authoritative.
 * Every section loads only its own list on first render; details load when an editor opens.
 * DLP incidents and BEC feedback stay read-only; DLP evidence is never requested here.
 */

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

/** The cache and permission note above a tab's sections. */
function TabNote({ cache, viewOnly }: { cache: string; viewOnly: string | null }) {
  return (
    <p className="mb-3 text-sm text-muted-foreground">
      {cache}
      {viewOnly ? <> {viewOnly}</> : null}
    </p>
  );
}

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

const DLP_CACHE_NOTE =
  'Changes apply to messages scanned after the DLP engine’s cache refresh (30 seconds by default); finished scans keep their result.';

/** DLP configuration (`dlp:read` views, `dlp:manage` edits) and incidents (read-only). */
export function DlpTab() {
  const canMessages = useCan('MessagesController_detail_v1');
  const canManage = useCan('DlpPoliciesController_create_v1');
  return (
    <div>
      <TabNote
        cache={DLP_CACHE_NOTE}
        viewOnly={canManage ? null : 'View only: changing DLP configuration needs dlp:manage.'}
      />
      <Sections
        label="DLP sections"
        sections={DLP_SECTIONS}
        labels={DLP_LABELS}
        render={(section) => {
          switch (section) {
            case 'policies':
              return <DlpPoliciesSection />;
            case 'patterns':
              return <DlpPatternsSection />;
            case 'dictionaries':
              return <DlpDictionariesSection />;
            case 'exceptions':
              return <DlpExceptionsSection />;
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
              return <DlpComplianceSection />;
          }
        }}
      />
    </div>
  );
}

function feedbackColumns(canMessages: boolean): DataTableColumn<BecFeedback>[] {
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

const BEC_SECTIONS = ['executives', 'vendors', 'trusted', 'feedback', 'suppressions'] as const;
const BEC_LABELS: Record<(typeof BEC_SECTIONS)[number], string> = {
  executives: 'Executives',
  vendors: 'Vendors',
  trusted: 'Trusted senders',
  feedback: 'Feedback',
  suppressions: 'Suppressions',
};

/** Phishing and BEC tenant data (`bec:read` views, `bec:manage` edits; feedback read-only). */
export function BecTab() {
  const canMessages = useCan('MessagesController_detail_v1');
  const canManage = useCan('BecExecutivesController_create_v1');
  return (
    <div>
      <TabNote
        cache={BEC_CACHE_NOTE}
        viewOnly={canManage ? null : 'View only: changing BEC configuration needs bec:manage.'}
      />
      <Sections
        label="BEC sections"
        sections={BEC_SECTIONS}
        labels={BEC_LABELS}
        render={(section) => {
          switch (section) {
            case 'executives':
              return <ExecutivesSection />;
            case 'vendors':
              return <VendorsSection />;
            case 'trusted':
              return <TrustedSendersSection />;
            case 'feedback':
              return (
                <ListTable
                  operationId="BecFeedbackController_list_v1"
                  tableId="bec-feedback"
                  caption="BEC feedback"
                  columns={feedbackColumns(canMessages)}
                  getRowId={(r: BecFeedback) => r.id}
                  emptyTitle="No feedback recorded"
                  mobile={(r: BecFeedback) => humanize(r.kind)}
                />
              );
            default:
              return <SuppressionsSection />;
          }
        }}
      />
    </div>
  );
}
