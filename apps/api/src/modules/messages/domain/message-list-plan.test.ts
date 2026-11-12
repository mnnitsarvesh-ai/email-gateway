import { describe, expect, it } from 'vitest';
import { MessageListQuerySchema } from '../dto/message-data.schemas';
import { identifyingFilters, presentFilters, selectMessagePlan } from './message-list-plan';

const plan = (query: Record<string, string>) =>
  selectMessagePlan(MessageListQuerySchema.parse(query).filters);

const ONE_VALUE: Record<string, string> = {
  direction: 'inbound',
  status: 'delivered',
  action: 'deliver',
  domainId: '01930c2e-7d1a-7000-8000-000000000001',
  sender: 'a@b.example',
  headerFrom: 'A <a@b.example>',
  'riskScore.gte': '500',
  'riskScore.lte': '900',
  riskScore: '10',
  hasAttachments: 'true',
  internetMessageId: '<x@y>',
};

describe('GET /messages plan selection (step 6.1 D5)', () => {
  it('no filter (range and sort only) is the index plan', () => {
    expect(plan({})).toBe('index');
    expect(plan({ from: '2026-11-01T00:00:00Z', to: '2026-11-02T00:00:00Z' })).toBe('index');
    expect(plan({ sort: 'receivedAt', limit: '5' })).toBe('index');
  });

  it('exactly one verdict and nothing else is the verdict plan', () => {
    expect(plan({ verdict: 'phishing' })).toBe('verdict');
    expect(plan({ verdict: 'clean', sort: 'receivedAt' })).toBe('verdict');
  });

  it('several verdicts are scan-bounded', () => {
    expect(plan({ verdict: 'phishing,malware' })).toBe('scan');
  });

  it('only the recipient is the recipient plan', () => {
    expect(plan({ recipient: 'Alice@Acme.Example' })).toBe('recipient');
  });

  it.each(Object.entries(ONE_VALUE))('%s alone is scan-bounded', (name, value) => {
    expect(plan({ [name]: value })).toBe('scan');
  });

  it.each(Object.entries(ONE_VALUE))('verdict + %s is scan-bounded', (name, value) => {
    expect(plan({ verdict: 'spam', [name]: value })).toBe('scan');
  });

  it.each(Object.entries(ONE_VALUE))('recipient + %s is scan-bounded', (name, value) => {
    expect(plan({ recipient: 'a@b.example', [name]: value })).toBe('scan');
  });

  it('verdict + recipient is scan-bounded', () => {
    expect(plan({ verdict: 'spam', recipient: 'a@b.example' })).toBe('scan');
  });

  it('every filter at once is scan-bounded', () => {
    expect(plan({ ...ONE_VALUE, verdict: 'spam', recipient: 'a@b.example' })).toBe('scan');
  });

  it('lists the present filters and the identifying ones (D11)', () => {
    const filters = MessageListQuerySchema.parse({
      recipient: 'a@b.example',
      sender: 's@b.example',
      direction: 'inbound',
      'riskScore.gte': '1',
    }).filters;
    expect(presentFilters(filters)).toEqual(['direction', 'recipient', 'riskScore', 'sender']);
    expect(identifyingFilters(filters)).toEqual(['sender', 'recipient']);
    expect(identifyingFilters(MessageListQuerySchema.parse({ verdict: 'spam' }).filters)).toEqual(
      [],
    );
    expect(
      identifyingFilters(
        MessageListQuerySchema.parse({ headerFrom: 'x', internetMessageId: '<i@d>' }).filters,
      ),
    ).toEqual(['headerFrom', 'internetMessageId']);
  });

  it('the query schema is strict and bounded', () => {
    expect(MessageListQuerySchema.safeParse({ subject: 'x' }).success).toBe(false);
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
});
