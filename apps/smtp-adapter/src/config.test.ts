import { describe, expect, it } from 'vitest';
import { destinationHostOptions, loadSmtpAdapterConfig, parseDeniedSuffixes } from './config';
import { journalIntakeDomain } from './journal-intake/journal-intake.config';

const BASE = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  GATEWAY_TRACE_SECRET: 'test-trace-secret-0123456789abcdef0123456789',
  SMTP_ATO_USERNAME_HASH_KEY: 'test-ato-username-hash-key'.padEnd(40, '0'),
};

describe('routing configuration (step 2.3 R3)', () => {
  it('defaults: public destinations only, no extra suffixes, 10 next hops', () => {
    const config = loadSmtpAdapterConfig(BASE);
    expect(config.ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS).toBe(false);
    expect(config.ROUTING_DENIED_DESTINATION_SUFFIXES).toEqual([]);
    expect(config.ROUTING_MAX_DESTINATIONS_PER_DOMAIN).toBe(10);
  });

  it('treats an empty suffix list as none', () => {
    const config = loadSmtpAdapterConfig({ ...BASE, ROUTING_DENIED_DESTINATION_SUFFIXES: '' });
    expect(config.ROUTING_DENIED_DESTINATION_SUFFIXES).toEqual([]);
  });

  it('parses the flag, the suffix list and the cap', () => {
    const config = loadSmtpAdapterConfig({
      ...BASE,
      ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS: 'true',
      ROUTING_DENIED_DESTINATION_SUFFIXES: '.test, Example ,invalid.',
      ROUTING_MAX_DESTINATIONS_PER_DOMAIN: '3',
    });
    expect(config.ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS).toBe(true);
    expect(config.ROUTING_DENIED_DESTINATION_SUFFIXES).toEqual(['test', 'example', 'invalid']);
    expect(config.ROUTING_MAX_DESTINATIONS_PER_DOMAIN).toBe(3);
  });

  it.each([
    ['ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS', 'yes'],
    ['ROUTING_DENIED_DESTINATION_SUFFIXES', 'bad suffix'],
    ['ROUTING_DENIED_DESTINATION_SUFFIXES', 'ok.test,-bad.test'],
    ['ROUTING_MAX_DESTINATIONS_PER_DOMAIN', '0'],
    ['ROUTING_MAX_DESTINATIONS_PER_DOMAIN', '11'],
  ])('refuses %s=%s', (key, value) => {
    expect(() => loadSmtpAdapterConfig({ ...BASE, [key]: value })).toThrow(key);
  });

  it('parseDeniedSuffixes skips empty entries and throws on invalid ones', () => {
    expect(parseDeniedSuffixes(undefined)).toEqual([]);
    expect(parseDeniedSuffixes(' , .corp ,')).toEqual(['corp']);
    expect(() => parseDeniedSuffixes('a..b')).toThrow('Invalid');
  });

  it('builds the validateDestinationHost options from the gateway names', () => {
    const config = loadSmtpAdapterConfig({
      ...BASE,
      GATEWAY_MX_HOSTS: '10:MX1.Gateway.Example,20:mx2.gateway.example',
      POSTFIX_MYHOSTNAME: 'mx.gw.test',
      POSTFIX_OUTBOUND_MYHOSTNAME: 'out.gw.test',
      POSTFIX_BOUNCE_DOMAIN: 'bounces.gw.test',
      ROUTING_DENIED_DESTINATION_SUFFIXES: 'corp',
    });
    const options = destinationHostOptions(config);
    expect([...options.gatewayHosts].sort()).toEqual(
      ['mx1.gateway.example', 'mx2.gateway.example', 'mx.gw.test', 'out.gw.test'].sort(),
    );
    expect(options.bounceDomain).toBe('bounces.gw.test');
    expect(options.deniedSuffixes).toEqual(['corp']);
    expect(options.allowNonPublic).toBe(false);
  });
});

describe('journal intake configuration (step 8.6 §4.4)', () => {
  it('is off without a domain and normalizes the domain', () => {
    const off = loadSmtpAdapterConfig(BASE);
    expect(off.JOURNAL_INTAKE_DOMAIN).toBeUndefined();
    expect(journalIntakeDomain(off)).toBeNull();
    expect(
      journalIntakeDomain(loadSmtpAdapterConfig({ ...BASE, JOURNAL_INTAKE_DOMAIN: '' })),
    ).toBeNull();
    const on = loadSmtpAdapterConfig({ ...BASE, JOURNAL_INTAKE_DOMAIN: ' Journal.Gateway.TEST. ' });
    expect(journalIntakeDomain(on)).toBe('journal.gateway.test');
    expect(on).toMatchObject({
      LMTP_JOURNAL_PORT: 10053,
      JOURNAL_INTAKE_MAX_MESSAGE_BYTES: 52_428_800,
      JOURNAL_INTAKE_ENVELOPE_MAX_BYTES: 1_048_576,
      JOURNAL_INTAKE_MAX_RECIPIENTS: 10_000,
      JOURNAL_INTAKE_SOURCE_CACHE_SECONDS: 30,
      JOURNAL_INTAKE_RATE_PER_SOURCE_PER_MINUTE: 6000,
      JOURNAL_INTAKE_COUNTER_FLUSH_SECONDS: 30,
    });
    const disabled = loadSmtpAdapterConfig({
      ...BASE,
      JOURNAL_INTAKE_DOMAIN: 'journal.gateway.test',
      JOURNAL_INTAKE_ENABLED: 'false',
    });
    expect(journalIntakeDomain(disabled)).toBeNull();
  });

  it.each([
    ['JOURNAL_INTAKE_DOMAIN', 'localhost'],
    ['JOURNAL_INTAKE_DOMAIN', 'bad domain.test'],
    ['JOURNAL_INTAKE_MAX_RECIPIENTS', '10001'],
    ['JOURNAL_INTAKE_SOURCE_CACHE_SECONDS', '0'],
    ['LMTP_JOURNAL_PORT', '70000'],
  ])('refuses %s=%s', (key, value) => {
    expect(() => loadSmtpAdapterConfig({ ...BASE, [key]: value })).toThrow(key);
  });

  it('refuses an intake domain overlapping the bounce or probe domain', () => {
    expect(() =>
      loadSmtpAdapterConfig({
        ...BASE,
        JOURNAL_INTAKE_DOMAIN: 'journal.bounces.gateway.internal',
        POSTFIX_BOUNCE_DOMAIN: 'bounces.gateway.internal',
      }),
    ).toThrow('POSTFIX_BOUNCE_DOMAIN');
    expect(() =>
      loadSmtpAdapterConfig({ ...BASE, JOURNAL_INTAKE_DOMAIN: 'probe.mail-gateway.test' }),
    ).toThrow('PROVIDER_PROBE_DOMAIN');
  });
});
