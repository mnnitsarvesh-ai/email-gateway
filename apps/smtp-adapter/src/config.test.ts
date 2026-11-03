import { describe, expect, it } from 'vitest';
import { destinationHostOptions, loadSmtpAdapterConfig, parseDeniedSuffixes } from './config';

const BASE = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  GATEWAY_TRACE_SECRET: 'test-trace-secret-0123456789abcdef0123456789',
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
