'use client';

import { DataTable, type DataTableColumn } from '@/components/data-table';
import {
  CopyableId,
  DateTime,
  DeliveryStatusBadge,
  DirectionBadge,
  SensitiveValue,
  UntrustedText,
} from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { DetailList, EnumBadge, Section } from '../controls';
import { FINAL_ACTION_TONE } from '../semantic';
import type { MessageDetailBody } from './summary-section';
import { useRevealed, type RevealedRecipient } from './use-message-reveal';

type RecipientRow = ListItem<'MessagesController_recipients_v1'>;

const RECIPIENT_STATUS_TONE = {
  pending: 'info',
  delivered: 'success',
  quarantined: 'warning',
  discarded: 'danger',
  deferred: 'warning',
  failed: 'danger',
  bounced: 'danger',
} as const;

/** A recipient address: masked by the api, the revealed address by `rcptSeq` when known. */
export function RecipientAddress({
  rcptSeq,
  value,
  masked,
}: {
  rcptSeq: number;
  value: string;
  masked: boolean;
}) {
  const { values } = useRevealed();
  const revealed = values?.recipients.get(rcptSeq);
  return (
    <SensitiveValue
      value={revealed ? revealed.address : value}
      masked={masked}
      revealed={Boolean(revealed)}
      kind="address"
      copy={Boolean(revealed) || !masked}
      copyLabel={`Copy recipient ${rcptSeq}`}
    />
  );
}

function MatchedUser({ revealed }: { revealed: RevealedRecipient | undefined }) {
  if (!revealed) {
    return <span className="text-xs text-muted-foreground">Withheld until revealed</span>;
  }
  return revealed.userId ? (
    <CopyableId value={revealed.userId} label="user ID" />
  ) : (
    <span className="text-xs text-muted-foreground">No matched user</span>
  );
}

function columns(
  revealed: ReadonlyMap<number, RevealedRecipient>,
): DataTableColumn<RecipientRow>[] {
  return [
    {
      id: 'rcptSeq',
      header: '#',
      meta: { label: 'Position', className: 'tabular-nums' },
      cell: ({ row }) => row.original.rcptSeq,
    },
    {
      id: 'address',
      header: 'Recipient',
      meta: { label: 'Recipient', className: 'max-w-72' },
      cell: ({ row }) => (
        <RecipientAddress
          rcptSeq={row.original.rcptSeq}
          value={row.original.address}
          masked={row.original.addressMasked}
        />
      ),
    },
    {
      id: 'status',
      header: 'Status',
      meta: { label: 'Status' },
      cell: ({ row }) => <EnumBadge value={row.original.status} tones={RECIPIENT_STATUS_TONE} />,
    },
    {
      id: 'finalAction',
      header: 'Final action',
      meta: { label: 'Final action' },
      cell: ({ row }) => (
        <EnumBadge
          value={row.original.finalAction}
          tones={FINAL_ACTION_TONE}
          emptyLabel="Pending"
        />
      ),
    },
    {
      id: 'direction',
      header: 'Direction',
      meta: { label: 'Direction' },
      cell: ({ row }) =>
        row.original.direction ? (
          <DirectionBadge direction={row.original.direction} />
        ) : (
          <span className="text-muted-foreground">Unknown</span>
        ),
    },
    {
      id: 'delivery',
      header: 'Latest delivery',
      meta: { label: 'Latest delivery' },
      cell: ({ row }) => {
        const delivery = row.original.latestDelivery;
        if (!delivery) return <span className="text-muted-foreground">No delivery</span>;
        return (
          <div className="grid gap-0.5 text-xs">
            <DeliveryStatusBadge status={delivery.status} />
            <span className="text-muted-foreground">
              sequence {delivery.deliverySeq}
              {delivery.finalSmtpCode !== null ? ` · SMTP ${delivery.finalSmtpCode}` : ''}
            </span>
            {delivery.deliveredAt ? <DateTime value={delivery.deliveredAt} /> : null}
          </div>
        );
      },
    },
    {
      id: 'user',
      header: 'Matched user',
      meta: { label: 'Matched user' },
      cell: ({ row }) => <MatchedUser revealed={revealed.get(row.original.rcptSeq)} />,
    },
  ];
}

/**
 * Section 2: sender and recipients. Senders in clear (triage needs them, ADR-0062); recipients
 * from `MessagesController_recipients` (v1 cursor), masked; the reveal fills them by `rcptSeq`
 * and "Reveal more recipients" continues with the reveal's `recipientsCursor`.
 */
export function PeopleSection({ message }: { message: MessageDetailBody }) {
  const reveal = useRevealed();
  const canReveal = useCan('MessageRevealController_reveal_v1');
  const list = useCursorList('MessagesController_recipients_v1', undefined, {
    path: { messageId: message.id },
    limit: 50,
  });
  const revealed = reveal.values?.recipients ?? new Map<number, RevealedRecipient>();
  return (
    <div className="grid gap-4">
      <Section
        title="Sender and recipients"
        description="Senders are shown in clear; recipient addresses are masked for every user."
      >
        <DetailList
          items={[
            {
              label: 'Envelope sender',
              value: (
                <UntrustedText
                  value={message.envelopeFrom}
                  copy
                  copyLabel="Copy envelope sender"
                  emptyLabel="(null sender)"
                />
              ),
            },
            {
              label: 'Header From',
              value: (
                <UntrustedText
                  value={message.headerFrom}
                  copy
                  copyLabel="Copy header From"
                  emptyLabel="(none)"
                />
              ),
            },
            { label: 'Direction', value: <DirectionBadge direction={message.direction} /> },
            { label: 'Recipients', value: String(message.recipientCount) },
          ]}
        />
      </Section>
      <Section
        title="Recipients"
        headingLevel={3}
        description={
          canReveal
            ? 'Use Reveal at the top of the page to see the addresses and matched users; each reveal is recorded in the audit log.'
            : 'Addresses stay masked: revealing them needs the message:reveal permission.'
        }
        actions={
          reveal.values?.recipientsCursor ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => void reveal.revealMoreRecipients()}
              disabled={reveal.pending || reveal.retryAfterSeconds > 0}
            >
              Reveal more recipients
            </Button>
          ) : null
        }
      >
        {reveal.values && !reveal.values.recipientsCursor && revealed.size > 0 ? (
          <p className="text-xs text-muted-foreground">
            Every recipient address is revealed ({revealed.size}).
          </p>
        ) : null}
        <DataTable
          tableId="message-recipients"
          caption="Recipients"
          columns={columns(revealed)}
          list={list}
          getRowId={(row) => String(row.rcptSeq)}
          getRowLabel={(row) => `recipient ${row.rcptSeq}`}
          emptyState={
            <EmptyState
              title="No recipients"
              description="The message has no recorded recipients."
            />
          }
          mobileCard={(row) => (
            <div className="grid gap-1 text-sm">
              <span className="text-xs text-muted-foreground">Recipient {row.rcptSeq}</span>
              <RecipientAddress
                rcptSeq={row.rcptSeq}
                value={row.address}
                masked={row.addressMasked}
              />
              <span className="text-xs">{humanize(row.status)}</span>
            </div>
          )}
        />
      </Section>
    </div>
  );
}
