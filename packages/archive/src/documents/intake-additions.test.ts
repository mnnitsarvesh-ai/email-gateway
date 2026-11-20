import { describe, expect, it } from 'vitest';
import { JOURNAL_ENVELOPE_EXAMPLE, JOURNAL_INTAKE_PROOF_EXAMPLE } from '../intake/documents';
import { mergeParties } from './parties-merge';
import {
  ARCHIVE_JOURNAL_EXAMPLE,
  ARCHIVE_PARTIES_EXAMPLE,
  type ArchiveParties,
  archiveJournalSchema,
  archivePartiesSchema,
  archiveRecordObjectsSchema,
} from './records';
import {
  ARCHIVE_SETTINGS_EXAMPLE,
  archiveSettingsSchema,
  resolveArchiveSettings,
} from './settings';

/** Step 8.6 additions to the 8.1 documents: additive, every 8.1 document still parses. */

const UUID = '0190a5d0-0000-7000-8000-0000000000aa';
const REF = { key: 'org/42/archive/x/eml.bin', versionId: 'v1', sha256: 'c'.repeat(64), bytes: 10 };

describe('archive-settings/1 + intake.scanEnabled (D8)', () => {
  it('8.1 documents parse and resolve intake.scanEnabled to false', () => {
    expect(archiveSettingsSchema.safeParse(ARCHIVE_SETTINGS_EXAMPLE).success).toBe(true);
    expect(resolveArchiveSettings(ARCHIVE_SETTINGS_EXAMPLE).intake).toEqual({ scanEnabled: false });
    expect(resolveArchiveSettings(null).intake).toEqual({ scanEnabled: false });
    expect(resolveArchiveSettings({ intake: {} }).intake).toEqual({ scanEnabled: false });
  });

  it('accepts intake.scanEnabled and refuses unknown intake keys', () => {
    expect(resolveArchiveSettings({ intake: { scanEnabled: true } }).intake).toEqual({
      scanEnabled: true,
    });
    expect(archiveSettingsSchema.safeParse({ intake: { scanEnabled: 'yes' } }).success).toBe(false);
    expect(archiveSettingsSchema.safeParse({ intake: { other: true } }).success).toBe(false);
  });
});

describe('archive-parties/1 additions', () => {
  it('8.1 parties parse; recipients may carry field, sources, a NULL direction and journaled', () => {
    expect(archivePartiesSchema.safeParse(ARCHIVE_PARTIES_EXAMPLE).success).toBe(true);
    const intake: ArchiveParties = {
      v: 1,
      from: 'alice@example.com',
      headerFrom: 'Alice <alice@example.com>',
      recipients: [
        {
          seq: 0,
          address: 'x@example.org',
          direction: null,
          status: 'journaled',
          finalAction: null,
          field: 'bcc',
          sources: ['journal_intake'],
        },
      ],
    };
    expect(archivePartiesSchema.parse(intake)).toEqual(intake);
    for (const bad of [
      { field: 'from' },
      { sources: [] },
      { sources: ['mailbox'] },
      { status: 'archived' },
    ]) {
      const doc = { ...intake, recipients: [{ ...intake.recipients[0]!, ...bad }] };
      expect(archivePartiesSchema.safeParse(doc).success, JSON.stringify(bad)).toBe(false);
    }
  });
});

describe('archive-journal/1 additions', () => {
  it('8.1 journals parse; an intake block and mergedFrom are optional and strict', () => {
    expect(archiveJournalSchema.safeParse(ARCHIVE_JOURNAL_EXAMPLE).success).toBe(true);
    const j = {
      ...ARCHIVE_JOURNAL_EXAMPLE,
      envelope: {
        recipients: [
          { seq: 0, address: 'x@example.org', direction: null, status: 'journaled', field: 'to' },
        ],
      },
      intake: {
        sourceId: UUID,
        kind: 'microsoft_365_journal',
        format: 'journal_report',
        envelope: JOURNAL_ENVELOPE_EXAMPLE,
        envelopeMismatch: false,
        proof: JOURNAL_INTAKE_PROOF_EXAMPLE,
      },
      mergedFrom: {
        recordMessageId: UUID,
        recordReceivedAt: '2026-11-16T10:15:00.000Z',
        mergedAt: '2026-11-16T10:20:00.000Z',
        source: 'journal_intake',
        contentVariant: true,
      },
    };
    expect(archiveJournalSchema.safeParse(j).success).toBe(true);
    for (const bad of [
      { ...j, intake: { ...j.intake, kind: 'pst_import' } },
      { ...j, intake: { ...j.intake, format: 'raw' } },
      { ...j, intake: { ...j.intake, token: 'x' } },
      { ...j, mergedFrom: { ...j.mergedFrom, source: 'policy' } },
    ]) {
      expect(archiveJournalSchema.safeParse(bad).success).toBe(false);
    }
  });
});

describe('record objects + merged (≤ 8)', () => {
  const base = { captureId: UUID, eml: REF, journal: REF, scans: [] };
  const copy = {
    messageId: UUID,
    receivedAt: '2026-11-16T10:15:00.000Z',
    source: 'journal_intake',
    journal: REF,
    eml: null,
  };

  it('8.1 objects parse; merged copies are optional, bounded and strict', () => {
    expect(archiveRecordObjectsSchema.safeParse(base).success).toBe(true);
    expect(archiveRecordObjectsSchema.safeParse({ ...base, merged: [] }).success).toBe(true);
    expect(
      archiveRecordObjectsSchema.safeParse({ ...base, merged: [copy, { ...copy, eml: REF }] })
        .success,
    ).toBe(true);
    expect(
      archiveRecordObjectsSchema.safeParse({ ...base, merged: Array(9).fill(copy) }).success,
    ).toBe(false);
    expect(
      archiveRecordObjectsSchema.safeParse({ ...base, merged: [{ ...copy, extra: 1 }] }).success,
    ).toBe(false);
  });
});

describe('mergeParties', () => {
  const gateway: ArchiveParties = {
    v: 1,
    from: 'alice@example.org',
    headerFrom: 'Alice <alice@example.org>',
    recipients: [
      {
        seq: 0,
        address: 'Bob@Example.com',
        direction: 'inbound',
        status: 'delivered',
        finalAction: 'deliver',
      },
      {
        seq: 1,
        address: 'carol@example.com',
        direction: 'inbound',
        status: 'quarantined',
        finalAction: 'quarantine',
      },
    ],
  };
  const journal: ArchiveParties = {
    v: 1,
    from: 'alice@example.org',
    headerFrom: null,
    recipients: [
      {
        seq: 0,
        address: 'bob@example.com',
        direction: 'inbound',
        status: 'journaled',
        finalAction: null,
        field: 'to',
      },
      {
        seq: 1,
        address: 'dave@example.com',
        direction: 'inbound',
        status: 'journaled',
        finalAction: null,
        field: 'bcc',
      },
    ],
  };

  it('unites by lower-cased address, keeps the gateway facts and records sources and fields', () => {
    const r = mergeParties(gateway, journal);
    expect(r.added).toBe(1);
    expect(r.truncated).toBe(false);
    expect(r.parties.headerFrom).toBe('Alice <alice@example.org>');
    expect(r.parties.recipients).toEqual([
      {
        seq: 0,
        address: 'Bob@Example.com',
        direction: 'inbound',
        status: 'delivered',
        finalAction: 'deliver',
        field: 'to',
        sources: ['gateway', 'journal_intake'],
      },
      {
        seq: 1,
        address: 'carol@example.com',
        direction: 'inbound',
        status: 'quarantined',
        finalAction: 'quarantine',
        sources: ['gateway'],
      },
      {
        seq: 2,
        address: 'dave@example.com',
        direction: 'inbound',
        status: 'journaled',
        finalAction: null,
        field: 'bcc',
        sources: ['journal_intake'],
      },
    ]);
    expect(archivePartiesSchema.safeParse(r.parties).success).toBe(true);
  });

  it('a gateway copy merged into an intake record takes over the delivery facts', () => {
    const r = mergeParties(journal, gateway, { aSource: 'journal_intake', bSource: 'gateway' });
    expect(r.parties.recipients[0]).toMatchObject({
      address: 'bob@example.com',
      status: 'delivered',
      finalAction: 'deliver',
      field: 'to',
      sources: ['gateway', 'journal_intake'],
    });
    expect(r.parties.recipients.map((x) => x.seq)).toEqual([0, 1, 2]);
  });

  it('fills a NULL direction, merges idempotently and caps', () => {
    const unknown: ArchiveParties = {
      ...journal,
      recipients: [{ ...journal.recipients[0]!, direction: null }],
    };
    expect(
      mergeParties(unknown, journal, { aSource: 'journal_intake' }).parties.recipients[0]!
        .direction,
    ).toBe('inbound');
    const once = mergeParties(gateway, journal).parties;
    expect(mergeParties(once, journal).parties).toEqual(once);
    const capped = mergeParties(gateway, journal, { max: 2 });
    expect(capped.truncated).toBe(true);
    expect(capped.parties.recipients).toHaveLength(2);
    expect(() => mergeParties(gateway, journal, { max: 0 })).toThrow(RangeError);
  });
});
