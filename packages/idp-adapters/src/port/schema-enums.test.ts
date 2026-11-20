/**
 * The Prisma enums of the step 8.5 migration (§4.1) mirror the library's value lists (design
 * note §11.2): a stream, mailbox item kind or availability added on one side only fails here.
 */
import {
  AtoMailboxItemChange,
  AtoMailboxItemKind,
  AtoProviderAvailability,
  AtoProviderStreamName,
  AtoProviderStreamRole,
} from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { AVAILABILITIES } from '../core/capabilities';
import { PROVIDER_STREAMS } from './ato-port';
import { MAILBOX_ITEM_KINDS } from './state-ports';

const sorted = (values: Iterable<string>) => [...values].sort();

describe('Prisma enums of ato_provider_streams and ato_provider_mailbox_items', () => {
  it('AtoProviderStreamName equals 8.4 PROVIDER_STREAMS', () => {
    expect(sorted(Object.values(AtoProviderStreamName))).toEqual(sorted(PROVIDER_STREAMS));
  });

  it('AtoMailboxItemKind equals MAILBOX_ITEM_KINDS', () => {
    expect(sorted(Object.values(AtoMailboxItemKind))).toEqual(sorted(MAILBOX_ITEM_KINDS));
  });

  it('AtoProviderAvailability holds unknown plus every probe availability', () => {
    expect(sorted(Object.values(AtoProviderAvailability))).toEqual(
      sorted(['unknown', ...AVAILABILITIES]),
    );
  });

  it('roles and mailbox changes match the library', () => {
    expect(sorted(Object.values(AtoProviderStreamRole))).toEqual([
      'companion',
      'primary',
      'unsupported',
    ]);
    expect(sorted(Object.values(AtoMailboxItemChange))).toEqual(['added', 'changed', 'removed']);
  });
});
