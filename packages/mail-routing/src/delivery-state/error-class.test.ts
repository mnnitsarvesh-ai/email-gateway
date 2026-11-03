import { describe, expect, it } from 'vitest';
import { classifyDeliveryError, DELIVERY_ERROR_CLASSES } from './error-class';

describe('classifyDeliveryError', () => {
  it.each([
    ['connect to mx.ext.example[203.0.113.25]:25: Connection refused', '4.4.1', 'connect'],
    ['connect to mx.ext.example[203.0.113.25]:25: Connection timed out', '4.4.1', 'connect'],
    ['connect to mx.ext.example[2001:db8::25]:25: No route to host', '4.4.1', 'connect'],
    ['connect to mx.ext.example[203.0.113.25]:25: Network is unreachable', '4.4.1', 'connect'],
    [
      'Host or domain name not found. Name service error for name=nx.example type=MX: Host not found, try again',
      '4.4.3',
      'dns',
    ],
    [
      'Host or domain name not found. Name service error for name=nx.example type=A: Host not found',
      '5.4.4',
      'dns',
    ],
    ['TLS is required, but was not offered by host mx.ext.example[203.0.113.25]', '4.7.4', 'tls'],
    ['TLS is required, but our TLS engine is unavailable', '4.7.5', 'tls'],
    ['Server certificate not verified', '4.7.5', 'tls'],
    ['Server certificate not trusted', '4.7.5', 'tls'],
    ['Cannot start TLS: handshake failure', '4.7.5', 'tls'],
    [
      'conversation with mx.ext.example[203.0.113.25] timed out while receiving the initial server greeting',
      '4.4.2',
      'timeout',
    ],
    [
      'conversation with mx.ext.example[203.0.113.25] timed out while sending end of data -- message may be sent more than once',
      '4.4.2',
      'timeout',
    ],
    [
      'lost connection with mx.ext.example[203.0.113.25] while sending end of data -- message may be sent more than once',
      '4.4.2',
      'timeout',
    ],
    [
      'lost connection with mx.ext.example[203.0.113.25] while receiving the initial server greeting',
      '4.4.2',
      'timeout',
    ],
    [
      'host mx.ext.example[203.0.113.25] said: 451 4.3.0 Temporary server error. Please try again later (in reply to end of DATA command)',
      '4.3.0',
      'remote_4xx',
    ],
    [
      'host mx.ext.example[203.0.113.25] said: 421 4.7.0 Try again later, closing connection. (in reply to MAIL FROM command)',
      '4.7.0',
      'remote_4xx',
    ],
    [
      'host mx.ext.example[203.0.113.25] said: 550 5.1.1 <hard-bounce@ext.example>: Recipient address rejected: User unknown in local recipient table (in reply to RCPT TO command)',
      '5.1.1',
      'remote_5xx',
    ],
    [
      'host mx.ext.example[203.0.113.25] said: 530 5.7.0 Must issue a STARTTLS command first (in reply to MAIL FROM command)',
      '5.7.0',
      'remote_5xx',
    ],
    [
      'host mx.ext.example[203.0.113.25] refused to talk to me: 554 5.7.1 Service unavailable; Client host blocked',
      '5.7.1',
      'remote_5xx',
    ],
    [
      'host mx.ext.example[203.0.113.25] refused to talk to me: 421 4.7.0 Too many connections',
      '4.7.0',
      'remote_4xx',
    ],
    ['Destination not configured', '4.4.1', 'no_destination'],
    ['mail for gateway.test loops back to myself', '5.4.6', 'loop'],
    ['550 5.1.1 User unknown', '5.1.1', 'remote_5xx'],
    ['452 4.2.2 Mailbox full', '4.2.2', 'remote_4xx'],
    ['delivery temporarily suspended: unknown reason', '4.4.1', 'connect'],
    ['delivery temporarily suspended: something odd', '4.4.2', 'timeout'],
    ['unusual failure', '4.4.6', 'loop'],
    ['message has been in the queue too long', '4.4.7', 'other'],
    ['something completely different', null, 'other'],
    ['', null, 'other'],
  ] as const)('%s → %s', (text, dsn, expected) => {
    expect(classifyDeliveryError(text, dsn)).toBe(expected);
    expect(DELIVERY_ERROR_CLASSES).toContain(expected);
  });

  it('lists the R9.2 classes', () => {
    expect(DELIVERY_ERROR_CLASSES).toEqual([
      'connect',
      'dns',
      'tls',
      'timeout',
      'remote_4xx',
      'remote_5xx',
      'no_destination',
      'loop',
      'gateway_rate_limited',
      'gateway_rate_limit_unavailable',
      'gateway_hold',
      'reinjection_4xx',
      'reinjection_error',
      'other',
    ]);
  });
});
