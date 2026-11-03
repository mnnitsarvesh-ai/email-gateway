import { describe, expect, it } from 'vitest';
import {
  mailDestinationPresetSchema,
  matchesProviderHost,
  renderTlsPolicy,
  renderTransportNexthops,
  strictestTlsMode,
} from './providers';

const row = (overrides: Record<string, unknown> = {}) => ({
  provider: 'google_workspace',
  displayName: 'Google Workspace (Gmail)',
  hostPatterns: ['^(?:aspmx\\.l|alt[1-4]\\.aspmx\\.l)\\.google\\.com$'],
  hostHint: null,
  defaultServers: [
    { host: 'aspmx.l.google.com', priority: 1 },
    { host: 'alt1.aspmx.l.google.com', priority: 5 },
  ],
  port: 25,
  tlsMode: 'verify',
  tlsVerifyNames: 'nexthop:mx.google.com:.aspmx.l.google.com',
  maxServers: 5,
  documentationUrl: 'docs/domains/destination-servers.md#google-workspace',
  // Extra Prisma columns are ignored.
  enabled: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

describe('mailDestinationPresetSchema', () => {
  it('parses a preset row and compiles the host patterns', () => {
    const preset = mailDestinationPresetSchema.parse(row());
    expect(preset.provider).toBe('google_workspace');
    expect(preset.hostPatterns).toHaveLength(1);
    expect(preset.hostPatterns[0]).toBeInstanceOf(RegExp);
    expect(preset.defaultServers).toHaveLength(2);
    expect(preset).not.toHaveProperty('enabled');
    expect(matchesProviderHost(preset, 'alt3.aspmx.l.google.com')).toBe(true);
    expect(matchesProviderHost(preset, 'alt3.aspmx.l.google.com.evil.test')).toBe(false);
    expect(matchesProviderHost(preset, 'xaspmx.l.google.com')).toBe(false);
  });

  it('accepts a preset without default servers (customer-supplied host)', () => {
    expect(
      mailDestinationPresetSchema.parse(row({ defaultServers: null, maxServers: 1 }))
        .defaultServers,
    ).toBeNull();
  });

  it('rejects malformed configuration rows', () => {
    for (const overrides of [
      { provider: 'yahoo' },
      { hostPatterns: [] },
      { hostPatterns: ['aspmx\\.l\\.google\\.com'] }, // not anchored
      { hostPatterns: ['^(unclosed$'] },
      { hostPatterns: 'not-an-array' },
      { port: 0 },
      { tlsMode: 'strict' },
      { tlsVerifyNames: 'nexthop protocols=TLSv1' },
      { tlsVerifyNames: '' },
      { maxServers: 1 }, // fewer than the default servers
      { defaultServers: [{ host: 'aspmx.l.google.com', priority: -1 }] },
      { displayName: '' },
    ]) {
      expect(
        () => mailDestinationPresetSchema.parse(row(overrides)),
        JSON.stringify(overrides),
      ).toThrow();
    }
  });
});

describe('renderTransportNexthops', () => {
  it('renders a Postfix next-hop list in the given order, without spaces', () => {
    expect(renderTransportNexthops([{ host: 'mx1.acme.com', port: 25 }])).toBe(
      'smtp:[mx1.acme.com]:25',
    );
    expect(
      renderTransportNexthops([
        { host: 'mx1.acme.com', port: 25 },
        { host: 'mx2.acme.com', port: 2525 },
        { host: '2001:4860::8888', port: 25 },
      ]),
    ).toBe('smtp:[mx1.acme.com]:25,[mx2.acme.com]:2525,[2001:4860::8888]:25');
  });

  it('refuses an empty list, unnormalized hosts and bad ports', () => {
    expect(() => renderTransportNexthops([])).toThrow();
    for (const server of [
      { host: 'MX1.acme.com', port: 25 },
      { host: 'mx1.acme.com,[evil.com]', port: 25 },
      { host: 'mx1 acme.com', port: 25 },
      { host: 'mx1.acme.com]:25', port: 25 },
      { host: '', port: 25 },
      { host: 'mx1.acme.com', port: 0 },
      { host: 'mx1.acme.com', port: 65_536 },
    ]) {
      expect(() => renderTransportNexthops([server]), JSON.stringify(server)).toThrow();
    }
  });
});

describe('renderTlsPolicy', () => {
  it('renders every mode', () => {
    expect(renderTlsPolicy('none', null)).toBe('none');
    expect(renderTlsPolicy('opportunistic', null)).toBe('may');
    expect(renderTlsPolicy('required', null)).toBe('encrypt protocols=>=TLSv1.2');
    expect(renderTlsPolicy('verify', null)).toBe('secure match=nexthop protocols=>=TLSv1.2');
    expect(
      renderTlsPolicy('verify', 'nexthop:mail.protection.outlook.com:.mail.protection.outlook.com'),
    ).toBe(
      'secure match=nexthop:mail.protection.outlook.com:.mail.protection.outlook.com protocols=>=TLSv1.2',
    );
  });

  it('refuses verify names that could inject policy attributes', () => {
    for (const names of [
      'nexthop protocols=TLSv1',
      'a=b',
      '',
      'x'.repeat(513),
      'host\nname',
      'a,b',
    ]) {
      expect(() => renderTlsPolicy('verify', names), JSON.stringify(names)).toThrow();
    }
  });
});

describe('strictestTlsMode', () => {
  it('returns the strictest mode, or null for none', () => {
    expect(strictestTlsMode([])).toBeNull();
    expect(strictestTlsMode(['none'])).toBe('none');
    expect(strictestTlsMode(['opportunistic', 'none'])).toBe('opportunistic');
    expect(strictestTlsMode(['opportunistic', 'required', 'none'])).toBe('required');
    expect(strictestTlsMode(['verify', 'opportunistic', 'required'])).toBe('verify');
  });
});
