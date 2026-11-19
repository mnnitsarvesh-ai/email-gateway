import { describe, expect, it } from 'vitest';
import { TEST_ENV } from '../../integration/in-session-support/fakes';
import { loadSmtpAdapterConfig } from '../config';
import { parseDnsServers, parseExtraEgressRanges } from './provider-relay.config';

const load = (env: Record<string, string>) => loadSmtpAdapterConfig({ ...TEST_ENV, ...env });

describe('provider relay configuration (§4.4)', () => {
  it('has the documented defaults', () => {
    const config = load({});
    expect(config).toMatchObject({
      PROVIDER_RELAY_ENABLED: true,
      PROVIDER_RELAY_DNS_SERVERS: [],
      PROVIDER_RELAY_DNS_TIMEOUT_MS: 2000,
      PROVIDER_RELAY_MARKER_TTL_SECONDS: 432_000,
      PROVIDER_EGRESS_CACHE_SECONDS: 60,
      PROVIDER_RELAY_COUNTER_FLUSH_SECONDS: 30,
      PROVIDER_RELAY_DKIM_REPLAY_WINDOW_SECONDS: 604_800,
      PROVIDER_EGRESS_EXTRA_RANGES: {},
      PROVIDER_PROBE_DOMAIN: 'probe.mail-gateway.test',
      PROVIDER_PROBE_TTL_SECONDS: 86_400,
    });
  });

  it('parses DNS servers with and without ports', () => {
    expect(parseDnsServers('172.31.250.53, 127.0.0.1:5353,::1,[::1]:53')).toEqual([
      '172.31.250.53',
      '127.0.0.1:5353',
      '::1',
      '[::1]:53',
    ]);
    expect(() => parseDnsServers('dns.example.test')).toThrow();
    expect(() => parseDnsServers('127.0.0.1:70000')).toThrow();
    expect(() => load({ PROVIDER_RELAY_DNS_SERVERS: 'resolver' })).toThrow(
      /PROVIDER_RELAY_DNS_SERVERS/,
    );
  });

  it('accepts extra egress ranges only in local and ci', () => {
    const extra = '{"microsoft_365":["172.31.250.70/32"],"google_workspace":["172.31.250.71/32"]}';
    for (const appEnv of ['local', 'ci']) {
      expect(
        load({ APP_ENV: appEnv, PROVIDER_EGRESS_EXTRA_RANGES: extra }).PROVIDER_EGRESS_EXTRA_RANGES,
      ).toEqual({
        microsoft_365: ['172.31.250.70/32'],
        google_workspace: ['172.31.250.71/32'],
      });
    }
    for (const appEnv of ['staging', 'production']) {
      expect(() => load({ APP_ENV: appEnv, PROVIDER_EGRESS_EXTRA_RANGES: extra })).toThrow(
        /allowed only when APP_ENV is local or ci/,
      );
      expect(load({ APP_ENV: appEnv }).PROVIDER_EGRESS_EXTRA_RANGES).toEqual({});
    }
  });

  it('refuses malformed extra ranges', () => {
    expect(() => parseExtraEgressRanges('not json')).toThrow();
    expect(() => parseExtraEgressRanges('{"microsoft_365":["172.31.250.70"]}')).toThrow();
    expect(() => parseExtraEgressRanges('{"microsoft_365":["172.31.250.71/24"]}')).toThrow();
    expect(() => parseExtraEgressRanges('{"aws":["10.0.0.0/8"]}')).toThrow();
    expect(() => load({ PROVIDER_EGRESS_EXTRA_RANGES: '[1]' })).toThrow(
      /PROVIDER_EGRESS_EXTRA_RANGES/,
    );
  });

  it('validates the probe domain and bounded numbers', () => {
    expect(load({ PROVIDER_PROBE_DOMAIN: 'Probe.Gateway.Example.' }).PROVIDER_PROBE_DOMAIN).toBe(
      'probe.gateway.example',
    );
    expect(() => load({ PROVIDER_PROBE_DOMAIN: 'localhost' })).toThrow(/PROVIDER_PROBE_DOMAIN/);
    expect(() => load({ PROVIDER_RELAY_MARKER_TTL_SECONDS: '10' })).toThrow();
    expect(() => load({ PROVIDER_RELAY_DKIM_REPLAY_WINDOW_SECONDS: '60' })).toThrow();
    expect(load({ PROVIDER_RELAY_ENABLED: 'false' }).PROVIDER_RELAY_ENABLED).toBe(false);
  });
});
