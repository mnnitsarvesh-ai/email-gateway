import { InboxIcon, ServerIcon } from 'lucide-react';
import { ToneBadge } from '@/components/domain/tone-badge';
import type { EntrySummary } from './types';

/**
 * Where a quarantine entry's message is (step API-2 R10.5, ADR-0102): held by the gateway, or an
 * API-mode copy moved to a container of the recipient's mailbox. A release of a mailbox entry
 * restores the message to the Inbox through the provider API; nothing is delivered again.
 */

export type EntryLocation = EntrySummary['location'];
export type MailboxLocation = Extract<EntryLocation, { kind: 'mailbox' }>;

export const LOCATIONS = ['gateway', 'mailbox'] as const;

export const LOCATION_LABEL: Record<(typeof LOCATIONS)[number], string> = {
  gateway: 'Gateway',
  mailbox: 'Mailbox',
};

/** The detail block's sentence per container (R15). */
export const CONTAINER_TEXT: Record<MailboxLocation['container'], string> = {
  quarantine_folder: 'In mailbox quarantine folder',
  junk: 'In mailbox Junk folder',
  deleted_items: 'In mailbox deleted items',
};

/** The location of an entry (`undefined` when an older view has none: the gateway). */
export function mailboxLocation(location: EntryLocation | undefined): MailboxLocation | null {
  return location?.kind === 'mailbox' ? location : null;
}

export function isMailboxEntry(entry: { location?: EntryLocation }): boolean {
  return mailboxLocation(entry.location) !== null;
}

/** Compact location cell of the lists ("Mailbox · quarantine folder" or "Gateway"). */
export function LocationBadge({ location }: { location: EntryLocation | undefined }) {
  const mailbox = mailboxLocation(location);
  if (!mailbox) {
    return (
      <ToneBadge tone="neutral">
        <ServerIcon className="size-3" aria-hidden />
        Gateway
      </ToneBadge>
    );
  }
  return (
    <span className="grid justify-items-start gap-0.5">
      <ToneBadge tone="info">
        <InboxIcon className="size-3" aria-hidden />
        Mailbox
      </ToneBadge>
      <span className="text-xs text-muted-foreground">{CONTAINER_TEXT[mailbox.container]}</span>
    </span>
  );
}
