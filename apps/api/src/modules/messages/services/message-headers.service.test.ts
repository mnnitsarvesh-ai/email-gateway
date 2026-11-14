import { PARTITION_REGISTRY } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { MessageRef } from '../repositories/message-data.repository';
import type { MessageHeadersRepository } from '../repositories/message-headers.repository';
import type { MessageDataService } from './message-data.service';
import {
  EMAIL_HEADERS_RETENTION,
  headerAvailability,
  MessageHeadersService,
  toHeaderView,
} from './message-headers.service';
import { messageNotFound } from '../messages.errors';

const scope = systemScope(7n);
const NOW = new Date('2026-11-14T12:00:00.000Z');

describe('EMAIL_HEADERS_RETENTION', () => {
  it('is the email_headers entry of the partitioning registry (3 months, monthly)', () => {
    expect(EMAIL_HEADERS_RETENTION).toBe(
      PARTITION_REGISTRY.find((s) => s.table === 'email_headers'),
    );
    expect(EMAIL_HEADERS_RETENTION).toMatchObject({ granularity: 'month', retention: 3 });
  });
});

describe('headerAvailability (§2 E7)', () => {
  const recent = new Date('2026-11-10T00:00:00.000Z');
  // Cutoff for 2026-11-14 with 3 months: 2026-08-01 (the partition job drops older months).
  const expired = new Date('2026-07-31T23:59:59.999Z');
  const edge = new Date('2026-08-01T00:00:00.000Z');

  it.each([
    [{ parseStatus: 'parsed', rowCount: 3, receivedAt: recent }, 'available'],
    [{ parseStatus: 'parse_limit_exceeded', rowCount: 2, receivedAt: recent }, 'available'],
    [{ parseStatus: null, rowCount: 1, receivedAt: recent }, 'available'],
    [{ parseStatus: null, rowCount: 0, receivedAt: recent }, 'not_parsed'],
    [{ parseStatus: 'parsing', rowCount: 0, receivedAt: recent }, 'not_parsed'],
    [{ parseStatus: 'parse_failed', rowCount: 0, receivedAt: recent }, 'not_parsed'],
    [{ parseStatus: 'parse_limit_exceeded', rowCount: 0, receivedAt: recent }, 'not_parsed'],
    [{ parseStatus: null, rowCount: 0, receivedAt: expired }, 'not_parsed'],
    [{ parseStatus: 'parsed', rowCount: 0, receivedAt: recent }, 'none_stored'],
    [{ parseStatus: 'parsed_with_defects', rowCount: 0, receivedAt: recent }, 'none_stored'],
    [{ parseStatus: 'parsed', rowCount: 0, receivedAt: edge }, 'none_stored'],
    [{ parseStatus: 'parsed', rowCount: 0, receivedAt: expired }, 'retention_expired'],
    [{ parseStatus: 'parsed_with_defects', rowCount: 0, receivedAt: expired }, 'retention_expired'],
  ] as const)('%j → %s', (input, expected) => {
    expect(headerAvailability({ ...input, now: NOW })).toBe(expected);
  });
});

describe('toHeaderView (§2 E7)', () => {
  it('keeps the safe subset in clear and withholds To, Cc, Subject and unknown names', () => {
    expect(toHeaderView({ seq: 0, name: 'From', value: 'A <a@x.example>' })).toEqual({
      seq: 0,
      name: 'From',
      value: 'A <a@x.example>',
      masked: false,
    });
    for (const name of ['To', 'Cc', 'Subject', 'subject', 'Bcc', 'X-Unknown']) {
      expect(toHeaderView({ seq: 4, name, value: 'secret value' })).toEqual({
        seq: 4,
        name,
        value: null,
        masked: true,
      });
    }
  });
});

describe('MessageHeadersService', () => {
  const ref: MessageRef = {
    id: 5n,
    publicId: '0193a1b2-7c3d-7e4f-8a5b-6c7d8e9f0a1b',
    receivedAt: new Date('2026-11-12T08:00:00.000Z'),
    organizationId: 7n,
  };

  function setup(found: MessageRef | null) {
    const messages = {
      messageRef: vi.fn(() => (found ? Promise.resolve(found) : Promise.reject(messageNotFound()))),
    };
    const repository = {
      parseStatus: vi.fn(() => Promise.resolve('parsed')),
      headers: vi.fn(() =>
        Promise.resolve([
          { seq: 0, name: 'From', value: 'Vendor <billing@vendor.example>' },
          { seq: 1, name: 'To', value: 'alice@acme.example' },
          { seq: 2, name: 'Cc', value: 'bob@acme.example' },
          { seq: 3, name: 'Subject', value: 'Pay now' },
          { seq: 4, name: 'Authentication-Results', value: 'mx; spf=pass' },
        ]),
      ),
    };
    const service = new MessageHeadersService(
      messages as unknown as MessageDataService,
      repository as unknown as MessageHeadersRepository,
    );
    service.now = () => NOW;
    return { service, messages, repository };
  }

  it('returns the rows with the masked values withheld, the names and the availability', async () => {
    const t = setup(ref);
    const view = await t.service.headers(scope, ref.publicId);
    expect(view.messageId).toBe(ref.publicId);
    expect(view.availability).toBe('available');
    expect(view.storedHeaderNames).toHaveLength(12);
    expect(view.safeHeaderNames).toContain('Authentication-Results');
    expect(view.safeHeaderNames).not.toContain('To');
    expect(view.headers.map((h) => [h.name, h.value, h.masked])).toEqual([
      ['From', 'Vendor <billing@vendor.example>', false],
      ['To', null, true],
      ['Cc', null, true],
      ['Subject', null, true],
      ['Authentication-Results', 'mx; spf=pass', false],
    ]);
    expect(JSON.stringify(view)).not.toMatch(/alice|bob|Pay now/);
    expect(t.repository.headers).toHaveBeenCalledWith(scope, ref);
  });

  it('404 message_not_found before any header read', async () => {
    const t = setup(null);
    await expect(t.service.headers(scope, ref.publicId)).rejects.toMatchObject({
      code: 'message_not_found',
    });
    expect(t.repository.headers).not.toHaveBeenCalled();
  });

  it('no rows: the availability says why', async () => {
    const t = setup({ ...ref, receivedAt: new Date('2026-05-01T00:00:00.000Z') });
    t.repository.headers.mockResolvedValueOnce([]);
    expect((await t.service.headers(scope, ref.publicId)).availability).toBe('retention_expired');
    t.repository.headers.mockResolvedValueOnce([]);
    t.repository.parseStatus.mockResolvedValueOnce(null as unknown as string);
    expect((await t.service.headers(scope, ref.publicId)).availability).toBe('not_parsed');
  });
});
