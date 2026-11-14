import { describe, expect, it } from 'vitest';
import { parseSearchParams, serializeSearchParams } from '@/hooks/use-url-state';
import {
  CLEARED_EXPLORER_FILTERS,
  DEFAULT_EXPLORER_STATE,
  EXPLORER_URL_SHAPE,
  explorerFilters,
  explorerQuery,
  hasExplorerFilters,
  permittedState,
  rangePatch,
  rangeValueOf,
  riskBoundsError,
  type ExplorerState,
} from './explorer-state';

const NOW = Date.parse('2026-11-14T10:20:30.000Z');
const parse = (query: string): ExplorerState =>
  parseSearchParams(EXPLORER_URL_SHAPE, new URLSearchParams(query));
const state = (patch: Partial<ExplorerState> = {}): ExplorerState => ({
  ...DEFAULT_EXPLORER_STATE,
  ...patch,
});

describe('explorerQuery (the single URL state → GET /messages mapping, §3.6)', () => {
  it('defaults: the last 24 hours ending at the next whole minute, newest first, no filter', () => {
    expect(explorerQuery(state(), NOW)).toEqual({
      from: '2026-11-13T10:21:00.000Z',
      to: '2026-11-14T10:21:00.000Z',
      sort: '-receivedAt',
    });
  });

  it.each([
    ['1h', 3_600_000],
    ['24h', 86_400_000],
    ['7d', 7 * 86_400_000],
    ['30d', 30 * 86_400_000],
  ] as const)('preset %s spans its duration', (range, duration) => {
    const query = explorerQuery(state({ range }), NOW);
    expect(Date.parse(query.to ?? '') - Date.parse(query.from ?? '')).toBe(duration);
    expect(query.to).toBe('2026-11-14T10:21:00.000Z');
  });

  it('a custom range is sent as given (UTC ISO bounds)', () => {
    const query = explorerQuery(
      state({ range: 'custom', from: '2026-11-01T08:00:00.000Z', to: '2026-11-02T17:30:00.000Z' }),
      NOW,
    );
    expect(query.from).toBe('2026-11-01T08:00:00.000Z');
    expect(query.to).toBe('2026-11-02T17:30:00.000Z');
  });

  it('a custom range of exactly 31 days is kept; longer, reversed or incomplete falls back to 24 h', () => {
    const ok = state({
      range: 'custom',
      from: '2026-10-01T00:00:00.000Z',
      to: '2026-11-01T00:00:00.000Z',
    });
    expect(explorerQuery(ok, NOW).from).toBe('2026-10-01T00:00:00.000Z');
    for (const bad of [
      { from: '2026-10-01T00:00:00.000Z', to: '2026-11-01T00:01:00.000Z' },
      { from: '2026-11-02T00:00:00.000Z', to: '2026-11-01T00:00:00.000Z' },
      { from: '2026-11-01T00:00:00.000Z', to: undefined },
    ]) {
      const query = explorerQuery(state({ range: 'custom', ...bad }), NOW);
      expect(Date.parse(query.to ?? '') - Date.parse(query.from ?? '')).toBe(86_400_000);
    }
  });

  it('maps every filter to its api parameter', () => {
    const query = explorerQuery(
      state({
        direction: ['inbound', 'internal'],
        status: ['quarantined', 'delivered'],
        verdict: ['phishing', 'malware'],
        action: ['quarantine'],
        domainId: '01933c3a-1b2c-7d4e-8f00-00000000d001',
        riskMin: 600,
        riskMax: 900,
        attachments: 'true',
        deliveryStatus: 'deferred',
        quarantineStatus: 'held',
        sender: 'a@example.com',
        headerFrom: 'b@example.com',
        recipient: 'c@alpha.example.test',
        subject: 'Invoice 4471',
        subjectPrefix: 'Invoice 44',
        messageId: '<abc@mail.example.test>',
        senderDomain: 'example.com',
        recipientDomain: 'partner.example',
        sort: 'receivedAt',
      }),
      NOW,
    );
    expect(query).toEqual({
      from: '2026-11-13T10:21:00.000Z',
      to: '2026-11-14T10:21:00.000Z',
      sort: 'receivedAt',
      direction: 'inbound,internal',
      status: 'quarantined,delivered',
      verdict: 'phishing,malware',
      action: 'quarantine',
      domainId: '01933c3a-1b2c-7d4e-8f00-00000000d001',
      'riskScore.gte': '600',
      'riskScore.lte': '900',
      hasAttachments: 'true',
      deliveryStatus: 'deferred',
      quarantineStatus: 'held',
      sender: 'a@example.com',
      headerFrom: 'b@example.com',
      recipient: 'c@alpha.example.test',
      subject: 'Invoice 4471',
      subjectPrefix: 'Invoice 44',
      internetMessageId: '<abc@mail.example.test>',
      senderDomain: 'example.com',
      recipientDomain: 'partner.example',
    });
  });

  it('a risk score of 0 is a bound (not "no bound")', () => {
    expect(explorerQuery(state({ riskMin: 0, riskMax: 0 }), NOW)).toMatchObject({
      'riskScore.gte': '0',
      'riskScore.lte': '0',
    });
  });

  it('the view id never reaches the query', () => {
    expect(
      explorerQuery(state({ view: '01933c3a-1b2c-7d4e-8f00-0000000f0001' }), NOW),
    ).not.toHaveProperty('view');
  });
});

describe('explorer URL state', () => {
  it('keeps the 7.1 deep links working (verdict + attachments, and the hasAttachments alias)', () => {
    expect(explorerQuery(parse('verdict=malware&attachments=true'), NOW)).toMatchObject({
      verdict: 'malware',
      hasAttachments: 'true',
    });
    expect(explorerQuery(parse('verdict=malware&hasAttachments=true'), NOW)).toMatchObject({
      verdict: 'malware',
      hasAttachments: 'true',
    });
    expect(parse('range=7d&status=quarantined').status).toEqual(['quarantined']);
  });

  it('falls back silently for invalid values, key by key', () => {
    const parsed = parse(
      'range=2y&verdict=nope&direction=inbound&riskMin=5000&sender=not-an-address&senderDomain=EXAMPLE.COM&domainId=x&sort=size&view=1',
    );
    expect(parsed.range).toBe('24h');
    expect(parsed.verdict).toEqual([]);
    expect(parsed.direction).toEqual(['inbound']);
    expect(parsed.riskMin).toBeUndefined();
    expect(parsed.sender).toBeUndefined();
    expect(parsed.senderDomain).toBe('example.com');
    expect(parsed.domainId).toBeUndefined();
    expect(parsed.sort).toBe('-receivedAt');
    expect(parsed.view).toBeUndefined();
  });

  it('accepts comma lists within the api maxima (status ≤ 5) and removes duplicates', () => {
    expect(parse('status=received,persisted,scanning,scanned,delivered').status).toHaveLength(5);
    expect(parse('status=received,persisted,scanning,scanned,delivered,expired').status).toEqual(
      [],
    );
    expect(parse('verdict=spam,spam').verdict).toEqual(['spam']);
  });

  it('normalizes search values like the api (domain without @, lower-case address)', () => {
    const parsed = parse(
      'recipientDomain=%40Partner.Example&recipient=Jane.Doe%40Alpha.example.test',
    );
    expect(parsed.recipientDomain).toBe('partner.example');
    expect(parsed.recipient).toBe('jane.doe@alpha.example.test');
    expect(parse('subjectPrefix=Re%3A%20ab').subjectPrefix).toBeUndefined();
    expect(parse('messageId=%3C%3E').messageId).toBeUndefined();
  });

  it('writes a custom range with from/to and removes them for presets', () => {
    const custom = serializeSearchParams(
      EXPLORER_URL_SHAPE,
      new URLSearchParams(),
      rangePatch({
        kind: 'custom',
        from: '2026-11-01T08:00:00.000Z',
        to: '2026-11-02T08:00:00.000Z',
      }),
    );
    expect(custom.get('range')).toBe('custom');
    expect(custom.get('from')).toBe('2026-11-01T08:00:00.000Z');
    const preset = serializeSearchParams(EXPLORER_URL_SHAPE, custom, rangePatch({ kind: '7d' }));
    expect(preset.get('range')).toBe('7d');
    expect(preset.has('from')).toBe(false);
    expect(rangeValueOf(parse(custom.toString()))).toEqual({
      kind: 'custom',
      from: '2026-11-01T08:00:00.000Z',
      to: '2026-11-02T08:00:00.000Z',
    });
  });

  it('"Clear filters" removes every filter but keeps range, sort and view', () => {
    const current = new URLSearchParams(
      'range=7d&sort=receivedAt&view=01933c3a-1b2c-7d4e-8f00-0000000f0001&verdict=spam&sender=a%40example.com&hasAttachments=true&quarantineStatus=held',
    );
    const cleared = serializeSearchParams(EXPLORER_URL_SHAPE, current, CLEARED_EXPLORER_FILTERS);
    expect(cleared.toString()).toBe(
      'range=7d&sort=receivedAt&view=01933c3a-1b2c-7d4e-8f00-0000000f0001',
    );
    expect(hasExplorerFilters(parse(cleared.toString()))).toBe(false);
    expect(hasExplorerFilters(parse(current.toString()))).toBe(true);
  });
});

describe('permittedState (filter-level permissions, §2 E2)', () => {
  const linked = state({
    subject: 'Invoice',
    subjectPrefix: 'Inv',
    deliveryStatus: 'bounced',
    quarantineStatus: 'held',
    sender: 'a@example.com',
    recipient: 'c@alpha.example.test',
    recipientDomain: 'alpha.example.test',
  });

  it('drops recipient and subject searches without message:reveal and the status filters without their read permission', () => {
    const { state: allowed, ignored } = permittedState(linked, () => false);
    expect(ignored).toEqual([
      'Recipient',
      'Subject',
      'Subject starts with',
      'Delivery status',
      'Quarantine status',
    ]);
    // The recipient domain stays (the masked address keeps its domain in clear).
    expect(explorerFilters(allowed)).toEqual({
      sender: 'a@example.com',
      recipientDomain: 'alpha.example.test',
    });
  });

  it('keeps everything for a holder of every permission', () => {
    const { state: allowed, ignored } = permittedState(linked, () => true);
    expect(ignored).toEqual([]);
    expect(allowed).toEqual(linked);
  });
});

describe('riskBoundsError', () => {
  it('flags a lowest score above the highest', () => {
    expect(riskBoundsError({ riskMin: 800, riskMax: 300 })).toMatch(/above the highest/);
    expect(riskBoundsError({ riskMin: 300, riskMax: 300 })).toBeNull();
    expect(riskBoundsError({ riskMin: undefined, riskMax: 300 })).toBeNull();
  });
});
