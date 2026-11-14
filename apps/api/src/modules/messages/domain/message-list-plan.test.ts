import { describe, expect, it } from 'vitest';
import { filterHash } from '../../../http/listing/filter-hash';
import { MessageListQuerySchema } from '../dto/message-data.schemas';
import {
  DRIVER_KIND,
  DRIVER_PRIORITY,
  driverBinding,
  FILTER_PERMISSIONS,
  forbiddenFilter,
  identifyingFilters,
  identifyingValue,
  MESSAGE_LIST_DRIVERS,
  presentFilters,
  selectMessagePlan,
} from './message-list-plan';

const plan = (query: Record<string, string>) =>
  selectMessagePlan(MessageListQuerySchema.parse(query).filters);

/** One valid value of every `GET /messages` filter (the riskScore operators share one filter). */
const ONE_VALUE: Record<string, string> = {
  internetMessageId: '<x@y>',
  sender: 'a@b.example',
  headerFrom: 'A <a@b.example>',
  recipient: 'r@c.example',
  subject: 'Re: Hello',
  senderDomain: 'b.example',
  recipientDomain: 'c.example',
  subjectPrefix: 'Hel',
  quarantineStatus: 'held',
  deliveryStatus: 'bounced',
  verdict: 'spam',
  direction: 'inbound',
  status: 'delivered',
  action: 'deliver',
  domainId: '01930c2e-7d1a-7000-8000-000000000001',
  'riskScore.gte': '500',
  hasAttachments: 'true',
};
const filterOf = (key: string) => key.split('.')[0]!;
const RESIDUAL_ONLY = [
  'direction',
  'status',
  'action',
  'domainId',
  'riskScore.gte',
  'hasAttachments',
];

describe('GET /messages driver selection (step 7.2 §2 E1)', () => {
  it('no filter (range and sort only) is the none driver (6.1 index plan)', () => {
    const queries: Array<Record<string, string>> = [
      {},
      { from: '2026-11-01T00:00:00Z', to: '2026-11-02T00:00:00Z' },
      { sort: 'receivedAt', limit: '5' },
    ];
    for (const query of queries) {
      expect(plan(query)).toEqual({ driver: 'none', residuals: [], budgeted: false });
    }
  });

  it.each(DRIVER_PRIORITY.map((d) => [d]))(
    '%s alone drives exactly (no residual, no budget)',
    (driver) => {
      const key =
        driver === 'verdict'
          ? 'verdict'
          : Object.keys(ONE_VALUE).find((k) => filterOf(k) === driver)!;
      expect(plan({ [key]: ONE_VALUE[key]! })).toEqual({ driver, residuals: [], budgeted: false });
    },
  );

  it.each(RESIDUAL_ONLY.map((k) => [k]))('%s alone is the budgeted scan driver', (key) => {
    expect(plan({ [key]: ONE_VALUE[key]! })).toEqual({
      driver: 'scan',
      residuals: [filterOf(key)],
      budgeted: true,
    });
  });

  it('several verdicts are a residual, never a driver', () => {
    expect(plan({ verdict: 'phishing,malware' })).toEqual({
      driver: 'scan',
      residuals: ['verdict'],
      budgeted: true,
    });
    expect(plan({ verdict: 'phishing,malware', sender: 'a@b.example' })).toEqual({
      driver: 'sender',
      residuals: ['verdict'],
      budgeted: true,
    });
  });

  it('follows the priority for every pair of driver filters (the higher one drives)', () => {
    for (const [i, high] of DRIVER_PRIORITY.entries()) {
      for (const low of DRIVER_PRIORITY.slice(i + 1)) {
        const keyOf = (f: string) => Object.keys(ONE_VALUE).find((k) => filterOf(k) === f)!;
        const result = plan({
          [keyOf(high)]: ONE_VALUE[keyOf(high)]!,
          [keyOf(low)]: ONE_VALUE[keyOf(low)]!,
        });
        expect(result.driver, `${high} + ${low}`).toBe(high);
        expect(result.residuals, `${high} + ${low}`).toEqual([low]);
        expect(result.budgeted, `${high} + ${low}`).toBe(high !== 'subjectPrefix');
      }
    }
  });

  it.each(DRIVER_PRIORITY.map((d) => [d]))(
    '%s + residual-only filters is budgeted (except the prefix)',
    (driver) => {
      const keyOf = (f: string) => Object.keys(ONE_VALUE).find((k) => filterOf(k) === f)!;
      const query: Record<string, string> = { [keyOf(driver)]: ONE_VALUE[keyOf(driver)]! };
      for (const key of RESIDUAL_ONLY) query[key] = ONE_VALUE[key]!;
      const result = plan(query);
      expect(result.driver).toBe(driver);
      expect(result.residuals).toEqual(RESIDUAL_ONLY.map(filterOf).sort());
      expect(result.budgeted).toBe(driver !== 'subjectPrefix');
    },
  );

  it('every filter at once: internetMessageId drives, the rest are residuals', () => {
    const result = plan(ONE_VALUE);
    expect(result.driver).toBe('internetMessageId');
    expect(result.residuals).toEqual(
      [...new Set(Object.keys(ONE_VALUE).map(filterOf))]
        .filter((n) => n !== 'internetMessageId')
        .sort(),
    );
    expect(result.budgeted).toBe(true);
  });

  it('classifies every driver kind', () => {
    expect(MESSAGE_LIST_DRIVERS).toHaveLength(13);
    expect(Object.keys(DRIVER_KIND).sort()).toEqual([...MESSAGE_LIST_DRIVERS].sort());
    expect(MESSAGE_LIST_DRIVERS.filter((d) => DRIVER_KIND[d] === 'foreign').sort()).toEqual([
      'deliveryStatus',
      'quarantineStatus',
      'recipientDomain',
    ]);
    expect(DRIVER_KIND.recipient).toBe('recipient');
    expect(DRIVER_KIND.subjectPrefix).toBe('prefix');
  });
});

describe('identifying filters, filter permissions and the cursor binding', () => {
  it('lists the present filters and the identifying ones (D11 + subject searches)', () => {
    const filters = MessageListQuerySchema.parse({
      recipient: 'a@b.example',
      sender: 's@b.example',
      direction: 'inbound',
      'riskScore.gte': '1',
      subjectPrefix: 'Inv',
    }).filters;
    expect(presentFilters(filters)).toEqual([
      'direction',
      'recipient',
      'riskScore',
      'sender',
      'subjectPrefix',
    ]);
    expect(identifyingFilters(filters)).toEqual(['sender', 'recipient', 'subjectPrefix']);
    expect(
      identifyingFilters(
        MessageListQuerySchema.parse({ verdict: 'spam', senderDomain: 'a.example' }).filters,
      ),
    ).toEqual([]);
  });

  it('hashes the normalized subject and prefix, the parsed value otherwise', () => {
    const filters = MessageListQuerySchema.parse({
      subject: 'RE:  Pay\tnow ',
      subjectPrefix: 'Fwd: Inv',
      sender: 'A@B.example',
      internetMessageId: '<i@d>',
    }).filters;
    expect(identifyingValue('subject', filters)).toBe('Pay now');
    expect(identifyingValue('subjectPrefix', filters)).toBe('Inv');
    expect(identifyingValue('sender', filters)).toBe('a@b.example');
    expect(identifyingValue('internetMessageId', filters)).toBe('<i@d>');
  });

  it('gates recipient and subject searches on message:reveal and the state filters on their modules', () => {
    expect(FILTER_PERMISSIONS).toEqual({
      recipient: 'message:reveal',
      subject: 'message:reveal',
      subjectPrefix: 'message:reveal',
      deliveryStatus: 'delivery:read',
      quarantineStatus: 'quarantine:read',
    });
    const filters = MessageListQuerySchema.parse({
      subject: 'Hello',
      deliveryStatus: 'bounced',
      quarantineStatus: 'held',
    }).filters;
    expect(forbiddenFilter(filters, new Set(['message:read']))).toEqual({
      filter: 'subject',
      permission: 'message:reveal',
    });
    expect(forbiddenFilter(filters, new Set(['message:read', 'message:reveal']))).toEqual({
      filter: 'deliveryStatus',
      permission: 'delivery:read',
    });
    expect(forbiddenFilter(filters, new Set(['message:reveal', 'delivery:read']))).toEqual({
      filter: 'quarantineStatus',
      permission: 'quarantine:read',
    });
    expect(
      forbiddenFilter(filters, new Set(['message:reveal', 'delivery:read', 'quarantine:read'])),
    ).toBeNull();
    expect(
      forbiddenFilter(MessageListQuerySchema.parse({ sender: 'a@b.example' }).filters, new Set()),
    ).toBeNull();
    // An exact recipient confirms a masked address (ADR-0062); its domain does not.
    const recipient = MessageListQuerySchema.parse({
      recipient: 'Alice@Acme.example',
      subject: 'Hello',
    }).filters;
    expect(forbiddenFilter(recipient, new Set(['message:read']))).toEqual({
      filter: 'recipient',
      permission: 'message:reveal',
    });
    expect(forbiddenFilter(recipient, new Set(['message:read', 'message:reveal']))).toBeNull();
    expect(
      forbiddenFilter(
        MessageListQuerySchema.parse({ recipientDomain: 'acme.example' }).filters,
        new Set(['message:read']),
      ),
    ).toBeNull();
  });

  it('binds the driver into the filter hash (a cursor of another plan is cursor_invalid)', () => {
    const filters = MessageListQuerySchema.parse({ sender: 'a@b.example' }).filters;
    const hash = (driver: Parameters<typeof driverBinding>[0]) =>
      filterHash({
        resource: 'messages',
        filters: { ...filters, ...driverBinding(driver) },
        sort: '-receivedAt',
      });
    expect(hash('sender')).not.toBe(hash('scan'));
    expect(hash('sender')).toBe(hash('sender'));
    expect(hash('sender')).not.toBe(
      filterHash({ resource: 'messages', filters, sort: '-receivedAt' }),
    );
  });
});

describe('GET /messages query schema (step 7.2 §2 E2)', () => {
  const issues = (query: Record<string, string>) => {
    const result = MessageListQuerySchema.safeParse(query);
    return result.success
      ? []
      : result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`);
  };

  it('is strict and bounded', () => {
    expect(MessageListQuerySchema.safeParse({ subjectKey: 'x' }).success).toBe(false);
    expect(MessageListQuerySchema.safeParse({ 'verdict.gte': 'spam' }).success).toBe(false);
    expect(
      MessageListQuerySchema.safeParse({
        status: 'received,persisted,scanning,scanned,approved,expired',
      }).success,
    ).toBe(false);
    expect(MessageListQuerySchema.safeParse({ 'riskScore.gte': '1001' }).success).toBe(false);
    expect(MessageListQuerySchema.safeParse({ sort: '-subject' }).success).toBe(false);
    expect(MessageListQuerySchema.parse({ sender: ' A@B.Example ' }).filters.sender).toEqual({
      values: ['a@b.example'],
    });
  });

  it('accepts the new filters with their value sets', () => {
    const parsed = MessageListQuerySchema.parse({
      subject: 'x'.repeat(998),
      subjectPrefix: 'abc',
      senderDomain: '@Example.COM',
      recipientDomain: 'xn--bcher-kva.example',
      deliveryStatus: 'suppressed',
      quarantineStatus: 'pending_approval',
    }).filters;
    expect(parsed.senderDomain).toEqual({ values: ['example.com'] });
    expect(parsed.deliveryStatus).toEqual({ values: ['suppressed'] });
    expect(parsed.quarantineStatus).toEqual({ values: ['pending_approval'] });
  });

  it.each([
    [{ subject: '' }, 'subject'],
    [{ subject: 'x'.repeat(999) }, 'subject'],
    [{ subject: 'Re: Fwd:  ' }, 'subject: must contain text besides reply markers'],
    [{ subjectPrefix: 'ab' }, 'subjectPrefix: must be 3 to 128 characters'],
    [{ subjectPrefix: 'Re:   ab ' }, 'subjectPrefix: must be 3 to 128 characters'],
    [{ subjectPrefix: 'x'.repeat(129) }, 'subjectPrefix: must be 3 to 128 characters'],
    [{ internetMessageId: '<>' }, 'internetMessageId: must contain more than angle brackets'],
    [{ senderDomain: 'not a domain' }, 'senderDomain'],
    [{ recipientDomain: 'a@b.example' }, 'recipientDomain'],
    [{ deliveryStatus: 'bounced,failed' }, 'deliveryStatus'],
    [{ deliveryStatus: 'lost' }, 'deliveryStatus'],
    [{ quarantineStatus: 'quarantined' }, 'quarantineStatus'],
  ])('refuses %o naming %s', (query, text) => {
    expect(issues(query).join(' | ')).toContain(text);
  });

  it('a prefix of exactly 3 and 128 normalized characters is accepted', () => {
    expect(issues({ subjectPrefix: '  Re: a  b ' })).toEqual([]);
    expect(issues({ subjectPrefix: 'é'.repeat(128) })).toEqual([]);
  });
});
