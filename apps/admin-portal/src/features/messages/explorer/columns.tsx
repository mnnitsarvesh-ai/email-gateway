'use client';

import Link from 'next/link';
import type { VisibilityState } from '@tanstack/react-table';
import type { DataTableColumn } from '@/components/data-table';
import {
  DateTime,
  DirectionBadge,
  RiskScore,
  SensitiveValue,
  UntrustedText,
  VerdictBadge,
} from '@/components/domain';
import type { ListItem } from '@/lib/api/types';
import { formatBytes, formatNumber } from '@/lib/format';
import { EnumBadge } from '../controls';
import { messageHref } from '../links';
import { FINAL_ACTION_TONE, MESSAGE_STATUS_TONE } from '../semantic';

export type MessageRow = ListItem<'MessagesController_list_v1'>;

/** Subjects revealed for this page view (message id → subject; component state only). */
export type RevealedSubjects = ReadonlyMap<string, string | null>;

/** Column ids of the explorer (§2 E10), also the `columns` of a saved view. */
export const EXPLORER_COLUMN_IDS = [
  'receivedAt',
  'direction',
  'from',
  'subject',
  'verdict',
  'action',
  'status',
  'risk',
  'recipients',
  'attachments',
  'size',
] as const;

/** The column that can never be hidden (it links to the details). */
export const FIXED_COLUMN = 'receivedAt';

export function SubjectCell({
  row,
  revealed,
  maxLength = 90,
}: {
  row: MessageRow;
  revealed: RevealedSubjects;
  maxLength?: number;
}) {
  if (revealed.has(row.id)) {
    return (
      <SensitiveValue
        value={revealed.get(row.id) ?? null}
        masked={row.subjectMasked}
        revealed
        maxLength={maxLength}
        emptyLabel="(no subject)"
      />
    );
  }
  if (!row.subjectMasked && !row.subject) {
    return <span className="whitespace-nowrap text-muted-foreground">(no subject)</span>;
  }
  return (
    <SensitiveValue
      value={row.subject}
      masked={row.subjectMasked}
      maxLength={maxLength}
      emptyLabel="(no subject)"
    />
  );
}

export function explorerColumns(revealed: RevealedSubjects): DataTableColumn<MessageRow>[] {
  return [
    {
      id: 'receivedAt',
      header: 'Received',
      meta: { label: 'Received', className: 'whitespace-nowrap', hideable: false },
      cell: ({ row }) => (
        <Link
          href={messageHref(row.original.id)}
          className="font-medium text-primary underline-offset-2 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          <DateTime value={row.original.receivedAt} />
          <span className="sr-only">, open message details</span>
        </Link>
      ),
    },
    {
      id: 'direction',
      header: 'Direction',
      meta: { label: 'Direction' },
      cell: ({ row }) => <DirectionBadge direction={row.original.direction} />,
    },
    {
      id: 'from',
      header: 'From',
      meta: { label: 'From', className: 'min-w-48 max-w-64' },
      cell: ({ row }) => (
        <div className="grid min-w-0">
          <UntrustedText
            value={row.original.envelopeFrom}
            maxLength={60}
            emptyLabel="(null sender)"
          />
          {row.original.headerFrom && row.original.headerFrom !== row.original.envelopeFrom ? (
            <span className="text-xs text-muted-foreground">
              Header: <UntrustedText value={row.original.headerFrom} maxLength={60} />
            </span>
          ) : null}
        </div>
      ),
    },
    {
      id: 'subject',
      header: 'Subject',
      meta: { label: 'Subject', className: 'min-w-48 max-w-80' },
      cell: ({ row }) => <SubjectCell row={row.original} revealed={revealed} />,
    },
    {
      id: 'verdict',
      header: 'Verdict',
      meta: { label: 'Verdict' },
      cell: ({ row }) => <VerdictBadge verdict={row.original.finalVerdict} />,
    },
    {
      id: 'action',
      header: 'Action',
      meta: { label: 'Action' },
      cell: ({ row }) => (
        <EnumBadge
          value={row.original.finalAction}
          tones={FINAL_ACTION_TONE}
          emptyLabel="Pending"
        />
      ),
    },
    {
      id: 'status',
      header: 'Status',
      meta: { label: 'Status' },
      cell: ({ row }) => <EnumBadge value={row.original.status} tones={MESSAGE_STATUS_TONE} />,
    },
    {
      id: 'risk',
      header: 'Risk',
      meta: { label: 'Risk score' },
      cell: ({ row }) => <RiskScore score={row.original.riskScore} />,
    },
    {
      id: 'recipients',
      header: 'Recipients',
      meta: { label: 'Recipients', className: 'text-right tabular-nums' },
      cell: ({ row }) => formatNumber(row.original.recipientCount),
    },
    {
      id: 'attachments',
      header: 'Attachments',
      meta: { label: 'Attachments', className: 'text-right tabular-nums' },
      cell: ({ row }) => formatNumber(row.original.attachmentCount),
    },
    {
      id: 'size',
      header: 'Size',
      meta: { label: 'Size', className: 'text-right tabular-nums whitespace-nowrap' },
      cell: ({ row }) => formatBytes(row.original.sizeBytes),
    },
  ];
}

/** Stacked card of a message below 768 px. */
export function MessageCard({ row, revealed }: { row: MessageRow; revealed: RevealedSubjects }) {
  return (
    <div className="grid min-w-0 gap-1 text-sm">
      <SubjectCell row={row} revealed={revealed} maxLength={70} />
      <UntrustedText value={row.envelopeFrom} maxLength={50} emptyLabel="(null sender)" />
      <div className="flex flex-wrap items-center gap-2">
        <VerdictBadge verdict={row.finalVerdict} />
        <DirectionBadge direction={row.direction} />
        <RiskScore score={row.riskScore} />
      </div>
      <Link
        href={messageHref(row.id)}
        className="text-xs font-medium text-primary underline underline-offset-2"
      >
        <DateTime value={row.receivedAt} />
        <span className="sr-only">, open message details</span>
      </Link>
    </div>
  );
}

/** Visibility state of a saved column set (`null`: every column visible). */
export function visibilityOfColumns(columns: readonly string[] | null): VisibilityState {
  if (!columns) return {};
  return Object.fromEntries(
    EXPLORER_COLUMN_IDS.map((id) => [id, id === FIXED_COLUMN || columns.includes(id)]),
  );
}

/** The column set to save: `null` when every column is visible (the default set). */
export function columnsOfVisibility(visibility: VisibilityState): string[] | null {
  const visible = EXPLORER_COLUMN_IDS.filter((id) => visibility[id] !== false);
  return visible.length === EXPLORER_COLUMN_IDS.length ? null : [...visible];
}
