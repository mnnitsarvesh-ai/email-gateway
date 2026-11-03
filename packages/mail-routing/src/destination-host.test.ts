import { describe, expect, it } from 'vitest';
import {
  BUILT_IN_DENIED_SUFFIXES,
  DEFAULT_ALLOWED_DESTINATION_PORTS,
  DENIED_DESTINATION_PORTS,
  normalizeHostForComparison,
  parseAllowedDestinationPorts,
  validateDestinationHost,
  type ValidateDestinationHostOptions,
} from './destination-host';
import { mailDestinationPresetSchema } from './providers';

const options: ValidateDestinationHostOptions = {
  allowNonPublic: false,
  deniedSuffixes: [],
  gatewayHosts: new Set(['mx.gateway.local', 'MX2.Gateway.Example.', 'out.gateway.local']),
  bounceDomain: 'bounces.gateway.example',
};
const reason = (host: string, port = 25, extra: Partial<ValidateDestinationHostOptions> = {}) => {
  const result = validateDestinationHost(host, port, { ...options, ...extra });
  return result.ok ? null : result.reason;
};

const m365 = mailDestinationPresetSchema.parse({
  provider: 'microsoft_365',
  displayName: 'Microsoft 365 (Exchange Online)',
  hostPatterns: [
    '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.mail\\.protection\\.outlook\\.com$',
    '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.(?:[a-z0-9-]+\\.)?mx\\.microsoft$',
  ],
  hostHint: '<domain-key>.mail.protection.outlook.com',
  defaultServers: null,
  port: 25,
  tlsMode: 'verify',
  tlsVerifyNames: 'nexthop:mail.protection.outlook.com:.mail.protection.outlook.com',
  maxServers: 1,
  documentationUrl: 'docs/domains/destination-servers.md#microsoft-365',
});
const google = mailDestinationPresetSchema.parse({
  provider: 'google_workspace',
  displayName: 'Google Workspace (Gmail)',
  hostPatterns: ['^(?:aspmx\\.l|alt[1-4]\\.aspmx\\.l)\\.google\\.com$'],
  hostHint: null,
  defaultServers: [{ host: 'aspmx.l.google.com', priority: 1 }],
  port: 25,
  tlsMode: 'verify',
  tlsVerifyNames: 'nexthop:mx.google.com:.aspmx.l.google.com',
  maxServers: 5,
  documentationUrl: null,
});

describe('validateDestinationHost: normalization', () => {
  it('lower-cases, strips one trailing dot and converts IDN to ASCII', () => {
    expect(validateDestinationHost('Mail.Acme.COM.', 25, options)).toEqual({
      ok: true,
      host: 'mail.acme.com',
      port: 25,
    });
    expect(validateDestinationHost('  mx1.acme.com  ', 2525, options)).toEqual({
      ok: true,
      host: 'mx1.acme.com',
      port: 2525,
    });
    expect(validateDestinationHost('mx.Bücher.de', 25, options)).toEqual({
      ok: true,
      host: 'mx.xn--bcher-kva.de',
      port: 25,
    });
    expect(validateDestinationHost('xn--bcher-kva.de', 25, options)).toMatchObject({ ok: true });
  });

  it('refuses malformed names as invalid_host', () => {
    for (const host of [
      '',
      '   ',
      '.',
      'mx..acme.com',
      'mx.acme.com..',
      '.mx.acme.com',
      '-mx.acme.com',
      'mx-.acme.com',
      'mx_1.acme.com',
      'mx 1.acme.com',
      'mx.acme.com:25',
      'user@acme.com',
      '*.acme.com',
      'mx.acme.com/x',
      `${'a'.repeat(64)}.com`,
      `${'a.'.repeat(127)}com`,
      'x'.repeat(1025),
      '127.1', // legacy inet_aton form: numeric last label
      '0x7f.1',
      '10.0.0.256',
      '1.2.3.4.5',
      '[mx.acme.com]',
      '[]',
      'mx.acme.123',
    ]) {
      expect(reason(host), JSON.stringify(host.slice(0, 40))).toBe('invalid_host');
    }
  });

  it('enforces the port range', () => {
    for (const port of [0, -1, 65_536, 25.5, Number.NaN]) {
      expect(reason('mx.acme.com', port), String(port)).toBe('port_not_allowed');
    }
    expect(reason('mx.acme.com', 1, { allowedPorts: [1] })).toBeNull();
    expect(reason('mx.acme.com', 65_535, { allowedPorts: [65_535] })).toBeNull();
  });

  it('allows only the allowed ports (default 25, 587, 2525)', () => {
    for (const port of DEFAULT_ALLOWED_DESTINATION_PORTS) {
      expect(reason('mx.acme.com', port), String(port)).toBeNull();
    }
    for (const port of [1, 24, 465, 8080, 65_535]) {
      expect(reason('mx.acme.com', port), String(port)).toBe('port_not_allowed');
    }
    expect(reason('mx.acme.com', 2526, { allowedPorts: [25, 2526] })).toBeNull();
    expect(reason('mx.acme.com', 587, { allowedPorts: [25, 2526] })).toBe('port_not_allowed');
  });

  it("never allows the gateway's internal listener ports, even when listed", () => {
    const allowedPorts = [25, ...DENIED_DESTINATION_PORTS];
    for (const port of [10026, 10027, 10040, 10041, 10042, 10051, 10052, 11332, 53, 3306, 6379]) {
      expect(DENIED_DESTINATION_PORTS).toContain(port);
      expect(reason('evil.example.com', port, { allowedPorts }), String(port)).toBe(
        'port_not_allowed',
      );
    }
  });
});

describe('validateDestinationHost: IP literals', () => {
  it('accepts public IPv4 and IPv6, with or without brackets, canonicalized', () => {
    expect(validateDestinationHost('8.8.8.8', 25, options)).toEqual({
      ok: true,
      host: '8.8.8.8',
      port: 25,
    });
    expect(validateDestinationHost('[8.8.8.8]', 25, options)).toMatchObject({ host: '8.8.8.8' });
    expect(validateDestinationHost('[2001:4860:4860:0:0:0:0:8888]', 25, options)).toMatchObject({
      host: '2001:4860:4860::8888',
    });
    expect(validateDestinationHost('2606:4700:4700::1111', 25, options)).toMatchObject({
      ok: true,
    });
  });

  it('refuses non-public addresses unless allowNonPublic', () => {
    for (const host of [
      '10.1.2.3',
      '[192.168.1.10]',
      '127.0.0.1',
      '100.64.1.1',
      '172.20.0.5',
      '192.0.2.1',
      '198.18.0.1',
      '224.0.0.5',
      '0.0.0.0',
      '255.255.255.255',
      '::1',
      '[fd00::25]',
      'fe80::1',
      '::ffff:10.0.0.1',
      '64:ff9b::a00:1',
      '2001:db8::25',
    ]) {
      expect(reason(host), host).toBe('ip_not_public');
      expect(reason(host, 25, { allowNonPublic: true }), host).toBeNull();
    }
  });

  it('refuses metadata addresses even with allowNonPublic', () => {
    for (const host of [
      '169.254.169.254',
      '[169.254.169.254]',
      '169.254.170.2',
      'fd00:ec2::254',
      '[fd00:ec2::254]',
      '100.100.100.200',
      '::ffff:169.254.169.254',
    ]) {
      expect(reason(host), host).toBe('metadata_address');
      expect(reason(host, 25, { allowNonPublic: true }), host).toBe('metadata_address');
    }
  });

  it('refuses a gateway host given as an IP literal', () => {
    const gatewayHosts = new Set(['203.0.113.10', '[2001:4860::1]']);
    expect(reason('203.0.113.10', 25, { allowNonPublic: true, gatewayHosts })).toBe('gateway_host');
    expect(reason('2001:4860:0::1', 25, { gatewayHosts })).toBe('gateway_host');
  });
});

describe('validateDestinationHost: names', () => {
  it('refuses single-label names (Compose and Kubernetes service names)', () => {
    for (const host of [
      'mysql',
      'redis',
      'smtp-adapter',
      'postfix-outbound',
      'localhost',
      'LOCALHOST.',
    ]) {
      expect(reason(host), host).toBe('single_label');
    }
  });

  it('refuses the built-in internal suffixes, at and under the suffix', () => {
    expect(BUILT_IN_DENIED_SUFFIXES).toEqual([
      'local',
      'localhost',
      'localdomain',
      'internal',
      'intranet',
      'lan',
      'home.arpa',
      'svc',
      'cluster.local',
      'consul',
    ]);
    for (const host of [
      'printer.local',
      'foo.localhost',
      'mail.localdomain',
      'ip-10-0-0-1.ec2.internal',
      'mx.corp.intranet',
      'nas.lan',
      'router.home.arpa',
      'home.arpa',
      'mysql.default.svc',
      'mysql.default.svc.cluster.local',
      'redis.service.consul',
    ]) {
      expect(reason(host), host).toBe('internal_suffix');
    }
    // Lookalikes are fine.
    expect(reason('mail.locally.com')).toBeNull();
    expect(reason('internal.example.com')).toBeNull();
    expect(reason('mysvc.com')).toBeNull();
  });

  it('refuses configured suffixes (any case, with or without a leading dot)', () => {
    const deniedSuffixes = ['.test', 'Example', ' invalid. ', ''];
    for (const host of ['mx.sink.test', 'test', 'mail.example', 'a.b.invalid']) {
      expect(reason(host, 25, { deniedSuffixes }), host).toBe(
        host === 'test' ? 'single_label' : 'internal_suffix',
      );
    }
    expect(reason('mx.sink.test')).toBeNull();
    expect(reason('mx.example.com', 25, { deniedSuffixes })).toBeNull();
  });

  it('refuses metadata service names', () => {
    expect(reason('metadata.google.internal')).toBe('metadata_address');
    expect(reason('METADATA.google.internal.')).toBe('metadata_address');
    expect(reason('instance-data')).toBe('metadata_address');
    expect(reason('instance-data.example.com')).toBeNull();
  });

  it('refuses gateway hosts and the bounce domain', () => {
    expect(reason('mx.gateway.local')).toBe('internal_suffix'); // .local wins, still refused
    expect(reason('mx2.gateway.example')).toBe('gateway_host');
    expect(reason('MX2.GATEWAY.EXAMPLE.')).toBe('gateway_host');
    expect(reason('bounces.gateway.example')).toBe('gateway_host');
    expect(reason('x.bounces.gateway.example')).toBe('gateway_host');
    expect(reason('gateway.example')).toBeNull();
    expect(reason('mx2.gateway.example', 25, { gatewayHosts: new Set() })).toBeNull();
    expect(reason('bounces.gateway.example', 25, { bounceDomain: undefined })).toBeNull();
  });
});

describe('validateDestinationHost: provider presets', () => {
  it('accepts hosts matching the preset patterns on the preset port', () => {
    expect(
      validateDestinationHost('Contoso-com.mail.protection.outlook.com', 25, {
        ...options,
        provider: m365,
      }),
    ).toEqual({ ok: true, host: 'contoso-com.mail.protection.outlook.com', port: 25 });
    expect(reason('contoso-com.o-v1.mx.microsoft', 25, { provider: m365 })).toBeNull();
    expect(reason('contoso-com.mx.microsoft', 25, { provider: m365 })).toBeNull();
    for (const host of [
      'aspmx.l.google.com',
      'alt1.aspmx.l.google.com',
      'alt4.aspmx.l.google.com',
    ]) {
      expect(reason(host, 25, { provider: google }), host).toBeNull();
    }
  });

  it('refuses other hosts, other ports and IP literals for a preset', () => {
    for (const host of [
      'mail.protection.outlook.com',
      'contoso.mail.protection.outlook.com.evil.example',
      'a.b.mail.protection.outlook.com',
      'mx.acme.com',
    ]) {
      expect(reason(host, 25, { provider: m365 }), host).toBe('host_not_allowed_for_provider');
    }
    for (const host of [
      'alt5.aspmx.l.google.com',
      'aspmx2.googlemail.com',
      'gmail-smtp-in.l.google.com',
    ]) {
      expect(reason(host, 25, { provider: google }), host).toBe('host_not_allowed_for_provider');
    }
    expect(reason('aspmx.l.google.com', 587, { provider: google })).toBe('port_not_allowed');
    expect(reason('8.8.8.8', 25, { provider: google })).toBe('host_not_allowed_for_provider');
    // Safety rules still apply first.
    expect(reason('10.0.0.1', 25, { provider: google })).toBe('ip_not_public');
  });
});

describe('normalizeHostForComparison', () => {
  it('normalizes names and IP literals', () => {
    expect(normalizeHostForComparison(' MX.Gateway.Local. ')).toBe('mx.gateway.local');
    expect(normalizeHostForComparison('[2001:DB8:0::1]')).toBe('2001:db8::1');
    expect(normalizeHostForComparison('203.0.113.1')).toBe('203.0.113.1');
  });
});

describe('parseAllowedDestinationPorts', () => {
  it('defaults to 25, 587, 2525 and dedupes', () => {
    expect(parseAllowedDestinationPorts(undefined)).toEqual([25, 587, 2525]);
    expect(parseAllowedDestinationPorts(' ')).toEqual([25, 587, 2525]);
    expect(parseAllowedDestinationPorts('25, 2526,25')).toEqual([25, 2526]);
  });

  it('refuses invalid, out-of-range and internal ports', () => {
    for (const value of ['abc', '25,x', '0', '70000', '10052', '25,10026', '11332']) {
      expect(() => parseAllowedDestinationPorts(value), value).toThrow();
    }
  });
});
