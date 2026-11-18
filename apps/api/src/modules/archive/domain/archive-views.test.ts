import { describe, expect, it } from 'vitest';
import { archiveRate } from '../archive-rate-limit';
import { criteriaFor } from '../../ediscovery/domain/ediscovery-views';
import type { RecordRow } from '../repositories/archive-records.repository';
import { Prisma } from '@email-gateway/database';
import {
  engineRowsOfSnapshot,
  holdFactsOf,
  LIST_RECIPIENTS,
  messageViewOfRecord,
  messageViewOfSource,
  partiesOf,
} from './archive-views';

const record = (patch: Partial<RecordRow> = {}): RecordRow =>
  ({
    id: 1n,
    receivedAt: new Date('2026-11-16T10:00:00.000Z'),
    messageId: 7n,
    organizationId: 3n,
    messagePublicId: '0193a1c2-4444-7a00-8000-000000000001',
    direction: 'inbound',
    capturedByJournal: true,
    capturedByPolicy: true,
    policyRuleRef: 'rule-1',
    category: 'delivered',
    status: 'active',
    messageState: 'delivered',
    messageStateReason: null,
    envelopeFrom: 'sender@external.example',
    headerFrom: 'Sender <sender@external.example>',
    subject: 'Secret subject',
    internetMessageId: '<x@y>',
    parties: {
      v: 1,
      from: 'sender@external.example',
      headerFrom: null,
      recipients: [
        {
          seq: 0,
          address: 'alice@corp.example',
          direction: 'inbound',
          status: 'delivered',
          finalAction: 'deliver',
        },
        {
          seq: 1,
          address: 'bob@corp.example',
          direction: 'internal',
          status: 'delivered',
          finalAction: null,
        },
      ],
    },
    recipientCount: 2,
    attachmentCount: 0,
    sizeBytes: 10,
    retainUntil: new Date('2030-01-01T00:00:00.000Z'),
    legalHold: false,
    finalVerdict: 'clean',
    finalAction: 'deliver',
    riskScore: 1,
    malicious: false,
    lockMode: 'none',
    archivedAt: new Date('2026-11-16T10:01:00.000Z'),
    ...patch,
  }) as RecordRow;

describe('archive views (ADR-0062 masking)', () => {
  it('masks every recipient and the subject of a record', () => {
    const view = messageViewOfRecord(record());
    expect(view).toMatchObject({
      subject: null,
      subjectMasked: true,
      recipients: ['a***@corp.example', 'b***@corp.example'],
      sources: ['journal', 'policy'],
      headerFrom: 'sender@external.example',
    });
    expect(JSON.stringify(view)).not.toMatch(/Secret|alice|bob@/);
  });

  it('bounds the recipients of a list item', () => {
    const recipients = Array.from({ length: LIST_RECIPIENTS + 5 }, (_, seq) => ({
      seq,
      address: `u${seq}@corp.example`,
      direction: 'inbound',
      status: 'delivered',
      finalAction: null,
    }));
    const view = messageViewOfRecord(
      record({ parties: { v: 1, from: 'a@b.c', headerFrom: null, recipients } }),
    );
    expect(view.recipients).toHaveLength(LIST_RECIPIENTS);
    expect(view.recipientsTruncated).toBe(true);
  });

  it('unparsable parties never pass through raw', () => {
    expect(partiesOf(record({ parties: { bogus: true } })).recipients).toEqual([]);
  });

  it('maps index documents with masking and drops unknown enum values', () => {
    const view = messageViewOfSource({
      org_id: '3',
      message_id: 'm',
      received_at: '2026-11-16T10:00:00.000Z',
      direction: 'inbound',
      category: 'delivered',
      status: 'active',
      envelope_from: 's@x.example',
      recipients: ['carol@corp.example'],
      verdict: 'not-a-verdict',
      lock_mode: 'weird',
    });
    expect(view).toMatchObject({
      recipients: ['c***@corp.example'],
      verdict: null,
      lockMode: 'none',
      subject: null,
    });
    expect(messageViewOfSource({ message_id: 'm' })).toBeNull();
  });

  it('builds the hold facts from the parties (normalized addresses, recipient directions)', () => {
    expect(holdFactsOf(record())).toMatchObject({
      senderAddresses: ['sender@external.example', 'sender@external.example'],
      recipientAddresses: ['alice@corp.example', 'bob@corp.example'],
      recipientDirections: ['inbound', 'internal'],
    });
  });
});

describe('case search criteria view', () => {
  const criteria = {
    from: '2026-01-01',
    to: '2026-02-01',
    subject: 'x',
    recipients: ['ann@x.example'],
    custodians: ['bo@x.example'],
  };
  it('masks reveal-gated criteria without message:reveal', () => {
    expect(criteriaFor(criteria, false)).toMatchObject({
      subject: null,
      subjectMasked: true,
      recipients: ['a***@x.example'],
      custodians: ['b***@x.example'],
    });
    expect(criteriaFor({ ...criteria, custodians: 'case' }, false).custodians).toBe('case');
  });
  it('shows them to revealers', () => {
    expect(criteriaFor(criteria, true)).toEqual(criteria);
  });
});

describe('archive route limits', () => {
  it('maps each kind to its config key and window', () => {
    const cfg = {
      ARCHIVE_PREVIEW_PER_MINUTE: 1,
      ARCHIVE_REVEAL_PER_MINUTE: 2,
      ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR: 3,
    };
    expect(archiveRate('preview', cfg)).toEqual({
      bucket: 'archive-preview',
      limit: 1,
      windowSeconds: 60,
    });
    expect(archiveRate('reveal', cfg)).toEqual({
      bucket: 'archive-reveal',
      limit: 2,
      windowSeconds: 60,
    });
    expect(archiveRate('download_grant', cfg).windowSeconds).toBe(3600);
    expect(archiveRate('download', cfg).limit).toBe(3);
  });
});

describe('frozen engine rows', () => {
  it('restores the decimal strings the archive-worker freezes (WP3 D2)', () => {
    const [row] = engineRowsOfSnapshot([
      { engine: 'rspamd', score: '4.250', requiredScore: '15.000', attempt: 1 },
    ]);
    expect(Prisma.Decimal.isDecimal(row!.score)).toBe(true);
    expect(row!.score!.toNumber()).toBe(4.25);
    expect(row!.requiredScore!.toNumber()).toBe(15);
    expect(row).toMatchObject({ engine: 'rspamd', attempt: 1 });
  });

  it('keeps null, accepts numbers and drops values that are not decimals', () => {
    const rows = engineRowsOfSnapshot([
      { score: null, requiredScore: undefined },
      { score: 2, requiredScore: 'not-a-number' },
      { score: { toNumber: 'x' }, requiredScore: true },
    ]);
    expect(rows.map((r) => [r.score?.toNumber() ?? null, r.requiredScore])).toEqual([
      [null, null],
      [2, null],
      [null, null],
    ]);
  });

  it('returns no rows for a snapshot without an engines array', () => {
    expect(engineRowsOfSnapshot(undefined)).toEqual([]);
    expect(engineRowsOfSnapshot({})).toEqual([]);
  });
});
