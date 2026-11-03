import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { inferTimestamp, parsePostfixLogLine, type ParsedLine } from './postfix-log-parser';

/** Lines exactly as Postfix 3.7.11 printed them (docs/deployment/mail-routing.md, WP2). */
const FIXTURE = readFileSync(
  join(__dirname, '__fixtures__', 'postfix-3.7-reference.maillog.txt'),
  'utf8',
)
  .split('\n')
  .filter((line) => line.length > 0);
const NOW = new Date('2026-11-03T12:00:00Z');
const line = (needle: string): string => {
  const found = FIXTURE.find((l) => l.includes(needle));
  if (!found) throw new Error(`fixture line not found: ${needle}`);
  return found;
};
const parse = (needle: string): ParsedLine => parsePostfixLogLine(line(needle), NOW)!;

describe('parsePostfixLogLine over the captured Postfix 3.7 lines', () => {
  it('parses every fixture line with its timestamp (no line is unparseable)', () => {
    for (const l of FIXTURE) {
      const parsed = parsePostfixLogLine(l, NOW);
      expect(parsed, l).not.toBeNull();
      expect(parsed!.timestamp.getUTCFullYear()).toBe(2026);
      expect(parsed!.timestamp.getUTCMonth()).toBe(10);
    }
  });

  it('binds the queue id to the token only on the reinjection listeners', () => {
    expect(parse('4jJdlD6Cp2zrsd: client=email-gateway')).toEqual({
      kind: 'bind',
      queueId: '4jJdlD6Cp2zrsd',
      token: 'dw1-c0722beaeab545ec8914353368ec6afb',
      listener: 'reinject_outbound',
      program: 'postfix/reinject-outbound/smtpd',
      rawTimestamp: 'Nov 03 06:22:00',
      precisionMs: 1000,
      timestamp: new Date('2026-11-03T06:22:00Z'),
    });
    expect(parse('4jJdnb6VPDzs5m: client=')).toMatchObject({
      kind: 'bind',
      listener: 'reinject_inbound',
      token: 'dw1-89290587de5847d890bc0688ef786d21',
    });
    // orig_client=unknown, and IDENT/SOURCE only (no orig_client=).
    expect(parse('4jJdnb56vBzs5S: client=')).toMatchObject({
      kind: 'bind',
      token: 'dw1-124412a52ae34e32aa06b9cf0eeb48b1',
    });
    expect(parse('4jJdpq5F5kzBLhX: client=')).toMatchObject({
      kind: 'bind',
      token: 'dw1-35989ee0182e44c3aff447469f299f30',
    });
    // The same text from any other syslog name never binds.
    const forged = line('4jJdnb6VPDzs5m: client=').replace(
      'postfix/reinject-inbound/smtpd',
      'postfix/smtpd',
    );
    expect(parsePostfixLogLine(forged, NOW)?.kind).toBe('other');
    const submission = line('4jJdnb6VPDzs5m: client=').replace('reinject-inbound', 'submission');
    expect(parsePostfixLogLine(submission, NOW)?.kind).toBe('other');
  });

  it('parses qmgr queue active, including DSNs and postmaster copies', () => {
    expect(parse('4jJdlD6Cp2zrsd: from=<alice')).toMatchObject({
      kind: 'queue_active',
      queueId: '4jJdlD6Cp2zrsd',
      sender: 'alice@it-wp2-e13b06-out.sink.test',
      size: 466,
      nrcpt: 2,
    });
    expect(parse('4jJdnb5qBvzs5Z: from=<>')).toMatchObject({ kind: 'queue_active', sender: '' });
    expect(parse('from=<double-bounce@')).toMatchObject({
      kind: 'queue_active',
      queueId: '4jJdnb5qlPzs5c',
    });
  });

  it('parses status=sent with relay, DSN and the remote reply', () => {
    expect(parse('to=<user@it-wp2-e13b06-t.sink.test>, relay=mx.sink.test')).toMatchObject({
      kind: 'recipient_result',
      queueId: '4jJdlD6Cp2zrsd',
      address: 'user@it-wp2-e13b06-t.sink.test',
      origAddress: null,
      relay: { host: 'mx.sink.test', ip: '172.31.250.25', port: 25 },
      dsn: '2.0.0',
      status: 'sent',
      text: '250 2.0.0 Ok: queued as 05221156A60',
      smtpCode: 250,
      remoteAttempt: true,
      delaySeconds: 0.16,
    });
    expect(parse('Mixed.Case@orcpt')).toMatchObject({
      address: 'Mixed.Case@orcpt-e13b06.sink.test',
      status: 'sent',
    });
    expect(parse('4jJf6j4YqHzBYty')).toMatchObject({
      relay: { host: 'alt1.aspmx.l.google.com' },
      status: 'sent',
    });
  });

  it('parses the deferred variants (remote 4xx, relay=none connection failures, TLS, greeting timeout, error transport)', () => {
    expect(parse('soft-bounce@ext-e13b06.sink.test>, relay')).toMatchObject({
      status: 'deferred',
      dsn: '4.2.1',
      smtpCode: 450,
      remoteAttempt: true,
    });
    expect(
      parse('4jJdpq6K4yzBLhZ: to=<user@it-wp2-e13b06-refused.sink.test>, relay=none, delay=0.01'),
    ).toMatchObject({
      status: 'deferred',
      relay: null,
      dsn: '4.4.1',
      smtpCode: null,
      text: 'connect to mx.sink.test[172.31.250.25]:2526: Connection refused',
      // relay=none but a connection-level failure: a remote attempt.
      remoteAttempt: true,
    });
    expect(parse('4jJdxB42pbzs5Q: to=<user@it-wp2-e13b06-t.sink.test>, relay=none')).toMatchObject({
      text: expect.stringContaining('No route to host'),
    });
    expect(parse('timed out while receiving the initial server greeting')).toMatchObject({
      dsn: '4.4.2',
      status: 'deferred',
    });
    expect(parse('4jJf3r68sxzBLhX: to=<v@v3m.test>')).toMatchObject({
      dsn: '4.7.5',
      text: 'Server certificate not verified',
    });
    expect(parse('postfix/error[255]')).toMatchObject({
      kind: 'recipient_result',
      program: 'postfix/error',
      relay: null,
      text: 'Destination not configured',
      remoteAttempt: false,
    });
  });

  it('parses status=bounced', () => {
    expect(parse('hard-bounce@ext-e13b06.sink.test>, relay')).toMatchObject({
      status: 'bounced',
      dsn: '5.1.1',
      smtpCode: 550,
      remoteAttempt: true,
    });
  });

  it('parses the message-level expiry line (WP2 deviation V5)', () => {
    expect(parse('4jJdpq6K4yzBLhZ: from=<ext@example.org>, status=expired')).toEqual({
      kind: 'message_expired',
      queueId: '4jJdpq6K4yzBLhZ',
      sender: 'ext@example.org',
      program: 'postfix/qmgr',
      rawTimestamp: 'Nov 03 06:26:23',
      precisionMs: 1000,
      timestamp: new Date('2026-11-03T06:26:23Z'),
    });
  });

  it('parses DSN notification lines', () => {
    expect(parse('sender non-delivery notification: 4jJdnb5qBvzs5Z')).toMatchObject({
      kind: 'notification',
      queueId: '4jJdnb56vBzs5S',
      recipient: 'sender',
      type: 'non_delivery',
      dsnQueueId: '4jJdnb5qBvzs5Z',
    });
    expect(parse('postmaster non-delivery notification')).toMatchObject({
      recipient: 'postmaster',
      type: 'non_delivery',
    });
    expect(parse('sender delay notification')).toMatchObject({
      recipient: 'sender',
      type: 'delay',
    });
    expect(parse('postmaster delay notification')).toMatchObject({
      recipient: 'postmaster',
      type: 'delay',
    });
  });

  it('parses removed from qmgr and postsuper', () => {
    expect(parse('4jJdlD6Cp2zrsd: removed')).toMatchObject({
      kind: 'removed',
      queueId: '4jJdlD6Cp2zrsd',
      program: 'postfix/qmgr',
    });
    expect(parse('4jJdxB4cnGzsFw: removed')).toMatchObject({
      kind: 'removed',
      program: 'postfix/postsuper',
    });
  });

  it('classifies everything else as other (never guessed)', () => {
    for (const needle of [
      'connect to mx.sink.test[172.31.250.25]:2526',
      'server certificate verification failed',
      'NOQUEUE: reject',
      'requeued',
      'orig_id=',
      'message-id=',
    ]) {
      expect(parse(needle).kind, needle).toBe('other');
    }
    expect(parsePostfixLogLine('garbage', NOW)).toBeNull();
    expect(parsePostfixLogLine('Nov 03 06:22:00 out sshd[1]: hello', NOW)).toBeNull();
    expect(parsePostfixLogLine('Foo 03 06:22:00 out postfix/qmgr[1]: x', NOW)).toBeNull();
  });

  it('accepts a CR before the line end and an optional fraction of a second', () => {
    expect(parsePostfixLogLine(`${line('4jJdlD6Cp2zrsd: removed')}\r`, NOW)?.kind).toBe('removed');
    const micro = line('4jJdlD6Cp2zrsd: removed').replace(
      'Nov 03 06:22:04',
      'Nov 03 06:22:04.123456',
    );
    expect(parsePostfixLogLine(micro, NOW)).toMatchObject({
      kind: 'removed',
      rawTimestamp: 'Nov 03 06:22:04.123456',
      precisionMs: 1,
      timestamp: new Date('2026-11-03T06:22:04.123Z'),
    });
    const spaced = line('4jJdlD6Cp2zrsd: removed').replace('Nov 03', 'Nov  3');
    expect(parsePostfixLogLine(spaced, NOW)?.timestamp).toEqual(new Date('2026-11-03T06:22:04Z'));
  });
});

describe('inferTimestamp (year rollover)', () => {
  it('uses the current year normally', () => {
    expect(inferTimestamp(10, 3, 6, 0, 0, 0, NOW)).toEqual(new Date('2026-11-03T06:00:00Z'));
  });

  it('a December line read in January belongs to the previous year', () => {
    const january = new Date('2027-01-01T00:00:05Z');
    expect(inferTimestamp(11, 31, 23, 59, 58, 0, january)).toEqual(
      new Date('2026-12-31T23:59:58Z'),
    );
    const line = 'Dec 31 23:59:58 out postfix/qmgr[212]: 4jJdlD6Cp2zrsd: removed';
    expect(parsePostfixLogLine(line, january)?.timestamp).toEqual(new Date('2026-12-31T23:59:58Z'));
  });

  it('a January line read on 31 December (clock skew) belongs to the next year', () => {
    const december = new Date('2026-12-31T23:59:59Z');
    expect(inferTimestamp(0, 1, 0, 0, 1, 0, december)).toEqual(new Date('2027-01-01T00:00:01Z'));
  });

  it('a line slightly in the future (clock skew) stays in the current year', () => {
    expect(inferTimestamp(10, 3, 12, 30, 0, 0, NOW)).toEqual(new Date('2026-11-03T12:30:00Z'));
  });
});
