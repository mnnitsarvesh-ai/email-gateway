import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import {
  CLICK_DECISION_VALUES,
  EventTypes,
  URL_EVENT_MAX_LENGTH,
  URL_HOST_PATTERN,
  URL_NAVIGATION_KINDS,
  URL_VERDICT_VALUES,
  urlClickedV1,
  urlInspectionCompletedV1,
  urlInspectionRequestedV1,
} from './events';
import { EXAMPLE_EVENT_PAYLOADS } from './examples';
import { EVENT_REGISTRY } from './registry';

/** Step 4.3 U2: the three URL events. */
const organizationId = '42';

function envelope(payload: unknown, eventType: string) {
  return {
    eventId: randomUUID(),
    eventType,
    occurredAt: new Date().toISOString(),
    correlationId: 'corr-12345678',
    organizationId,
    payload,
  };
}

describe('URL event types (step 4.3 U2)', () => {
  it('are registered on email.security with aggregate message', () => {
    expect(EventTypes).toMatchObject({
      UrlInspectionRequested: 'mail.url.inspection_requested.v1',
      UrlInspectionCompleted: 'mail.url.inspection_completed.v1',
      UrlClicked: 'mail.url.clicked.v1',
    });
    for (const type of [
      EventTypes.UrlInspectionRequested,
      EventTypes.UrlInspectionCompleted,
      EventTypes.UrlClicked,
    ]) {
      expect(EVENT_REGISTRY[type]).toMatchObject({
        exchange: 'email.security',
        aggregateType: 'message',
        version: 1,
      });
    }
  });

  it('mirror the URL verdicts and click decisions of security-contracts', () => {
    expect([...URL_VERDICT_VALUES]).toEqual(['clean', 'suspicious', 'malicious', 'unknown']);
    expect([...CLICK_DECISION_VALUES]).toEqual([
      'allowed',
      'warned',
      'blocked',
      'continued',
      'expired',
      'not_found',
    ]);
    expect([...URL_NAVIGATION_KINDS]).toEqual(['initial', 'http', 'js', 'meta']);
  });

  it('accept ASCII hosts and refuse anything else', () => {
    for (const host of [
      'clean-site.test',
      'xn--exmplebank-3oh.test',
      '203.0.113.10',
      '[::1]',
      '[2001:db8::1]',
      'localhost',
      'a_b.example',
    ]) {
      expect(URL_HOST_PATTERN.test(host), host).toBe(true);
    }
    for (const host of [
      '',
      'Clean-Site.test',
      'exаmplebank.test',
      'a..b',
      '-a.test',
      'a-.test',
      'a.test.',
      'a b.test',
      'host:80',
      `${'a'.repeat(64)}.test`,
      `${'a.'.repeat(126)}aa`,
    ]) {
      expect(URL_HOST_PATTERN.test(host), host).toBe(false);
    }
  });
});

describe('mail.url.inspection_requested.v1', () => {
  const base = EXAMPLE_EVENT_PAYLOADS['mail.url.inspection_requested.v1'] as Record<
    string,
    unknown
  >;
  const payload = (overrides: Record<string, unknown> = {}) => ({ ...base, ...overrides });
  const parse = (value: unknown) =>
    parseEvent(envelope(value, EventTypes.UrlInspectionRequested), urlInspectionRequestedV1);

  it('accepts the example and http(s) URLs up to 2 048 characters', () => {
    expect(parse(payload()).payload.url).toBe('https://short-link.test/s/evil#top');
    expect(parse(payload({ url: 'http://203.0.113.10:8080/a?b=c' })).payload.urlSeq).toBe(2);
    expect(parse(payload({ url: 'http://[2001:db8::1]/' })).payload.url).toBe(
      'http://[2001:db8::1]/',
    );
    const long = `https://clean-site.test/${'a'.repeat(URL_EVENT_MAX_LENGTH - 24)}`;
    expect(long).toHaveLength(URL_EVENT_MAX_LENGTH);
    expect(parse(payload({ url: long })).payload.url).toBe(long);
    expect(() => parse(payload({ url: `${long}a` }))).toThrow();
  });

  it('refuses other schemes, userinfo, whitespace, relative and malformed URLs', () => {
    for (const url of [
      'ftp://clean-site.test/',
      'javascript:alert(1)',
      'data:text/html,x',
      'file:///etc/passwd',
      'https://user:pass@clean-site.test/',
      'https://user@clean-site.test/',
      'https://clean-site.test/a b',
      'https://clean-site.test/\u0000',
      ' https://clean-site.test/',
      '//clean-site.test/',
      '/relative',
      'https://',
      'HTTPS://clean-site.test/',
      '',
    ]) {
      expect(() => parse(payload({ url })), url).toThrow();
    }
  });

  it('requires decimal ids, a hex SHA-256, bounded seq/round and a deadline after the request', () => {
    for (const [key, value] of [
      ['inspectionId', '0'],
      ['inspectionId', 701],
      ['messageId', '01'],
      ['scanId', ''],
      ['urlSeq', 65_536],
      ['urlSeq', -1],
      ['urlSeq', 1.5],
      ['lifecycleRound', 65_536],
      ['urlSha256', 'D'.repeat(64)],
      ['urlSha256', 'd'.repeat(63)],
      ['receivedAt', '2026-11-01'],
      ['deadlineAt', base.requestedAt],
      ['deadlineAt', '2026-11-01T10:00:00.000Z'],
    ] as const) {
      expect(() => parse(payload({ [key]: value })), `${key}=${String(value)}`).toThrow();
    }
    expect(parse(payload({ urlSeq: 65_535, lifecycleRound: 65_535 })).payload.urlSeq).toBe(65_535);
  });

  it('is strict: no extra field (no anchor text, no title, no organization in the payload)', () => {
    for (const extra of ['anchorText', 'title', 'organizationId', 'html']) {
      expect(() => parse(payload({ [extra]: 'x' })), extra).toThrow();
    }
  });
});

describe('mail.url.inspection_completed.v1', () => {
  const base = EXAMPLE_EVENT_PAYLOADS['mail.url.inspection_completed.v1'] as Record<
    string,
    unknown
  > & { signals: Record<string, unknown> };
  const payload = (overrides: Record<string, unknown> = {}) => ({ ...base, ...overrides });
  const signals = (overrides: Record<string, unknown>) => ({
    signals: { ...base.signals, ...overrides },
  });
  const parse = (value: unknown) =>
    parseEvent(envelope(value, EventTypes.UrlInspectionCompleted), urlInspectionCompletedV1);

  it('accepts the example, a failure with an error code and a result without final URL', () => {
    expect(parse(payload()).payload.status).toBe('completed');
    const failed = parse(
      payload({
        status: 'failed',
        errorCode: 'navigation_timeout',
        finalUrlSha256: null,
        finalHost: null,
        navigations: [],
      }),
    ).payload;
    expect(failed.errorCode).toBe('navigation_timeout');
    for (const errorCode of ['deadline_passed', 'proxy_refused', 'browser_crash', 'job_timeout']) {
      expect(parse(payload({ status: 'failed', errorCode })).payload.errorCode).toBe(errorCode);
    }
  });

  it('pairs status with errorCode and finalHost with finalUrlSha256', () => {
    expect(() => parse(payload({ status: 'failed', errorCode: null }))).toThrow(
      /failed requires errorCode/,
    );
    expect(() => parse(payload({ errorCode: 'navigation_timeout' }))).toThrow(
      /completed carries no errorCode/,
    );
    expect(() => parse(payload({ finalHost: null }))).toThrow(/both set or both null/);
    expect(() => parse(payload({ finalUrlSha256: null }))).toThrow(/both set or both null/);
    for (const errorCode of ['Timeout', 'a-b', 'x'.repeat(33), '1abc']) {
      expect(() => parse(payload({ status: 'failed', errorCode })), errorCode).toThrow();
    }
  });

  it('bounds navigations, hosts, brand ids and counters', () => {
    const nav = { host: 'redirect-chain.test', status: 302, kind: 'http' };
    expect(parse(payload({ navigations: Array(10).fill(nav) })).payload.navigations).toHaveLength(
      10,
    );
    expect(() => parse(payload({ navigations: Array(11).fill(nav) }))).toThrow();
    for (const kind of URL_NAVIGATION_KINDS) {
      expect(parse(payload({ navigations: [{ ...nav, kind }] })).payload.navigations[0]?.kind).toBe(
        kind,
      );
    }
    expect(parse(payload({ navigations: [{ ...nav, status: null }] }))).toBeDefined();
    for (const bad of [
      { ...nav, kind: 'websocket' },
      { ...nav, status: 99 },
      { ...nav, status: 600 },
      { ...nav, host: 'https://redirect-chain.test/' },
      { ...nav, path: '/a' },
    ]) {
      expect(() => parse(payload({ navigations: [bad] })), JSON.stringify(bad)).toThrow();
    }
    expect(() =>
      parse(
        payload(
          signals({
            formActionHosts: ['a.test', 'b.test', 'c.test', 'd.test', 'e.test', 'f.test'],
          }),
        ),
      ),
    ).toThrow();
    expect(() => parse(payload(signals({ formActionHosts: ['a.test', 'a.test'] })))).toThrow(
      /Duplicate host/,
    );
    expect(() => parse(payload(signals({ titleBrandMatches: ['paypal', 'paypal'] })))).toThrow(
      /Duplicate brand id/,
    );
    expect(() => parse(payload(signals({ titleBrandMatches: ['PayPal'] })))).toThrow();
    for (const [key, value] of [
      ['passwordFields', 1001],
      ['forms', -1],
      ['dialogs', 1.5],
      ['requests', 100_001],
      ['blockedRequests', 100_001],
      ['bytes', -1],
      ['jsRedirect', 'yes'],
    ] as const) {
      expect(() => parse(payload(signals({ [key]: value }))), key).toThrow();
    }
    expect(
      parse(payload(signals({ passwordFields: 1000, requests: 100_000, dialogs: 1000 }))).payload
        .signals.requests,
    ).toBe(100_000);
  });

  it('carries no content: strict payload and strict signals', () => {
    for (const extra of ['title', 'body', 'screenshot', 'url', 'finalUrl']) {
      expect(() => parse(payload({ [extra]: 'x' })), extra).toThrow();
    }
    expect(() => parse(payload(signals({ title: 'Sign in' })))).toThrow();
    expect(() => parse(payload({ workerVersion: '' }))).toThrow();
    expect(() => parse(payload({ browserVersion: 'x'.repeat(65) }))).toThrow();
    expect(() => parse(payload({ browserVersion: 'chromium\n131' }))).toThrow();
  });
});

describe('mail.url.clicked.v1', () => {
  const base = EXAMPLE_EVENT_PAYLOADS['mail.url.clicked.v1'] as Record<string, unknown>;
  const payload = (overrides: Record<string, unknown> = {}) => ({ ...base, ...overrides });
  const parse = (value: unknown) =>
    parseEvent(envelope(value, EventTypes.UrlClicked), urlClickedV1);

  it('accepts every decision and verdict', () => {
    for (const decision of ['allowed', 'warned', 'blocked', 'continued'] as const) {
      for (const verdict of [...URL_VERDICT_VALUES, null]) {
        expect(parse(payload({ decision, verdict })).payload.decision).toBe(decision);
      }
    }
    for (const decision of ['expired', 'not_found']) {
      expect(parse(payload({ decision, verdict: null, reasonCodes: [] })).payload.verdict).toBe(
        null,
      );
    }
  });

  it('refuses a verdict on expired/not_found, duplicate or too many reason codes, bad ids', () => {
    expect(() => parse(payload({ decision: 'expired' }))).toThrow(/expired carries no verdict/);
    expect(() => parse(payload({ decision: 'not_found', verdict: 'clean' }))).toThrow(
      /not_found carries no verdict/,
    );
    expect(() => parse(payload({ reasonCodes: ['url.shortened', 'url.shortened'] }))).toThrow(
      /Duplicate reason code/,
    );
    const many = Array.from({ length: 17 }, (_, i) => `url.code_${i}`);
    expect(() => parse(payload({ reasonCodes: many }))).toThrow();
    expect(parse(payload({ reasonCodes: many.slice(0, 16) })).payload.reasonCodes).toHaveLength(16);
    for (const [key, value] of [
      ['clickId', 'not-a-uuid'],
      ['decision', 'invalid'],
      ['verdict', 'spam'],
      ['reasonCodes', ['URL.SHORTENED']],
      ['urlSeq', 70_000],
      ['clickedAt', 'yesterday'],
    ] as const) {
      expect(() => parse(payload({ [key]: value })), key).toThrow();
    }
  });

  it('carries no URL, address or user identity (strict)', () => {
    for (const extra of ['url', 'clientIp', 'clientNetwork', 'userAgent', 'userId', 'recipient']) {
      expect(() => parse(payload({ [extra]: 'x' })), extra).toThrow();
    }
  });
});
