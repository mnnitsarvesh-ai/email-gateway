import { describe, expect, it } from 'vitest';
import { RspamdRequestError } from './errors';
import { buildRequestHeaders, RSPAMD_MAX_RCPT_HEADERS, type RspamdEnvelope } from './headers';

const inbound: RspamdEnvelope = {
  direction: 'inbound',
  organizationId: 42n,
  clientIp: '192.0.2.10',
  clientHelo: 'mx.clean.scan.test',
  clientName: 'mx.clean.scan.test',
  envelopeFrom: 'alice@clean.scan.test',
  recipients: ['bob@customer.scan.test', 'carol@customer.scan.test'],
  queueId: '4jKZVG0PVZz18BX',
};

const names = (headers: Array<[string, string]>) => headers.map(([name]) => name);
const value = (headers: Array<[string, string]>, name: string) =>
  headers.find(([n]) => n === name)?.[1];

describe('buildRequestHeaders', () => {
  it('sends the trusted envelope of an inbound message without User', () => {
    const built = buildRequestHeaders(inbound, { logTag: 'm123r0' });
    expect(built.headers).toEqual([
      ['IP', '192.0.2.10'],
      ['Helo', 'mx.clean.scan.test'],
      ['Hostname', 'mx.clean.scan.test'],
      ['From', 'alice@clean.scan.test'],
      ['Rcpt', 'bob@customer.scan.test'],
      ['Rcpt', 'carol@customer.scan.test'],
      ['Queue-Id', '4jKZVG0PVZz18BX'],
      ['Settings-Id', 'eg_inbound'],
      ['Log-Tag', 'm123r0'],
    ]);
    expect(built.rcptTruncated).toBe(false);
    expect(built.omitted).toEqual([]);
  });

  it('marks outbound and internal mail as authenticated by the organization', () => {
    for (const direction of ['outbound', 'internal'] as const) {
      const built = buildRequestHeaders({ ...inbound, direction }, { logTag: 'm1r0' });
      expect(value(built.headers, 'User')).toBe('org-42');
      expect(value(built.headers, 'Settings-Id')).toBe('eg_outbound');
    }
  });

  it('accepts string and number organization ids and refuses anything else for User', () => {
    expect(
      value(
        buildRequestHeaders(
          { ...inbound, direction: 'outbound', organizationId: '7' },
          { logTag: 'a' },
        ).headers,
        'User',
      ),
    ).toBe('org-7');
    expect(() =>
      buildRequestHeaders(
        { ...inbound, direction: 'outbound', organizationId: '7\r\nX-Evil: 1' },
        { logTag: 'a' },
      ),
    ).toThrow(RspamdRequestError);
    expect(() =>
      buildRequestHeaders(
        { ...inbound, direction: 'outbound', organizationId: 0 },
        { logTag: 'a' },
      ),
    ).toThrow(RspamdRequestError);
  });

  it('sends <> for the null sender', () => {
    for (const envelopeFrom of ['', '<>']) {
      expect(
        value(buildRequestHeaders({ ...inbound, envelopeFrom }, { logTag: 'a' }).headers, 'From'),
      ).toBe('<>');
    }
  });

  it('caps Rcpt at 100 headers and flags the truncation', () => {
    const recipients = Array.from({ length: 150 }, (_, i) => `user${i}@customer.scan.test`);
    const built = buildRequestHeaders({ ...inbound, recipients }, { logTag: 'a' });
    expect(built.headers.filter(([n]) => n === 'Rcpt')).toHaveLength(RSPAMD_MAX_RCPT_HEADERS);
    expect(built.rcptTruncated).toBe(true);
    const exactly = buildRequestHeaders(
      { ...inbound, recipients: recipients.slice(0, 100) },
      { logTag: 'a' },
    );
    expect(exactly.rcptTruncated).toBe(false);
  });

  it('omits optional values that carry CR/LF, control characters or are too long', () => {
    const built = buildRequestHeaders(
      {
        ...inbound,
        clientIp: 'not-an-ip',
        clientHelo: 'evil\r\nX-Injected: 1',
        clientName: 'a'.repeat(256),
        queueId: 'Q\nID',
        recipients: ['ok@customer.scan.test', 'bad\r\n@customer.scan.test', 'no-at-sign'],
      },
      { logTag: 'a' },
    );
    expect(names(built.headers)).toEqual(['From', 'Rcpt', 'Settings-Id', 'Log-Tag']);
    expect(built.omitted).toEqual(['IP', 'Helo', 'Hostname', 'Rcpt', 'Queue-Id']);
    for (const [, v] of built.headers) expect(v).not.toMatch(/[\r\n]/);
  });

  it('omits recipients with a comma (fetch joins repeated headers with ", ")', () => {
    const built = buildRequestHeaders(
      { ...inbound, recipients: ['"a,b"@customer.scan.test', 'ok@customer.scan.test'] },
      { logTag: 'a' },
    );
    expect(built.headers.filter(([n]) => n === 'Rcpt')).toEqual([
      ['Rcpt', 'ok@customer.scan.test'],
    ]);
    expect(built.omitted).toContain('Rcpt');
  });

  it('omits absent optional values', () => {
    const built = buildRequestHeaders(
      { ...inbound, clientIp: null, clientHelo: null, clientName: null, queueId: null },
      { logTag: 'a' },
    );
    expect(names(built.headers)).not.toContain('IP');
    expect(names(built.headers)).not.toContain('Hostname');
    expect(built.omitted).toEqual(['IP', 'Helo', 'Hostname', 'Queue-Id']);
  });

  it('accepts IPv6 client addresses and passes Postfix "unknown" host names through', () => {
    const built = buildRequestHeaders(
      { ...inbound, clientIp: '2001:db8::25', clientName: 'unknown' },
      { logTag: 'a' },
    );
    expect(value(built.headers, 'IP')).toBe('2001:db8::25');
    expect(value(built.headers, 'Hostname')).toBe('unknown');
  });

  it('refuses an envelope sender that cannot be sent safely', () => {
    for (const envelopeFrom of [
      'a\r\nb@c.test',
      'no-domain',
      'a b@c.test',
      `${'x'.repeat(320)}@c.test`,
    ]) {
      expect(() => buildRequestHeaders({ ...inbound, envelopeFrom }, { logTag: 'a' })).toThrow(
        RspamdRequestError,
      );
    }
  });

  it('refuses invalid log tags and settings ids without echoing them', () => {
    try {
      buildRequestHeaders(inbound, { logTag: 'secret value\r\n' });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(RspamdRequestError);
      expect((error as Error).message).not.toContain('secret');
      expect((error as RspamdRequestError).retryable).toBe(false);
    }
    expect(() => buildRequestHeaders(inbound, { logTag: 'a', settingsId: 'Bad-Id' })).toThrow(
      RspamdRequestError,
    );
    expect(
      value(
        buildRequestHeaders(inbound, { logTag: 'a', settingsId: 'eg_custom' }).headers,
        'Settings-Id',
      ),
    ).toBe('eg_custom');
  });

  it('encodes UTF-8 envelope values as UTF-8 bytes', () => {
    const built = buildRequestHeaders(
      { ...inbound, envelopeFrom: 'josé@exämple.scan.test' },
      { logTag: 'a' },
    );
    const sent = value(built.headers, 'From')!;
    expect(Buffer.from(sent, 'latin1').toString('utf8')).toBe('josé@exämple.scan.test');
  });
});
