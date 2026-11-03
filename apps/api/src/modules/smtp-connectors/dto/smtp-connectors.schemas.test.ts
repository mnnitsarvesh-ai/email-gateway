import { describe, expect, it } from 'vitest';
import { formatZodIssues } from '../../../validation/zod-validation.pipe';
import { CreateConnectorSchema, UpdateConnectorSchema } from './smtp-connectors.schemas';

const issues = (
  schema: typeof CreateConnectorSchema | typeof UpdateConnectorSchema,
  v: unknown,
) => {
  const result = schema.safeParse(v);
  return result.success ? [] : formatZodIssues(result.error);
};

describe('CreateConnectorSchema (D10)', () => {
  it('canonicalizes networks and fingerprints', () => {
    expect(
      CreateConnectorSchema.parse({
        name: '  Exchange relay ',
        authType: 'source_ip',
        networks: ['192.0.2.9/24', '2001:DB8:1::/48'],
      }),
    ).toEqual({
      name: 'Exchange relay',
      authType: 'source_ip',
      networks: ['192.0.2.0/24', '2001:db8:1::/48'],
    });
    const fp = Array.from({ length: 32 }, () => 'AB').join(':');
    expect(
      CreateConnectorSchema.parse({
        name: 'cert',
        authType: 'client_certificate',
        certificateFingerprintSha256: fp,
      }).certificateFingerprintSha256,
    ).toBe('ab'.repeat(32));
  });

  it.each([
    [{ name: 'x', authType: 'source_ip' }, 'networks: is required for source_ip'],
    [{ name: 'x', authType: 'source_ip', networks: [] }, 'networks: Too small'],
    [
      {
        name: 'x',
        authType: 'source_ip',
        networks: Array.from({ length: 21 }, (_, i) => `10.0.${i}.0/24`),
      },
      'networks: Too big',
    ],
    [
      { name: 'x', authType: 'source_ip', networks: ['10.0.0.0/8'] },
      'networks.0: must not be larger than /16 for IPv4 networks',
    ],
    [
      { name: 'x', authType: 'source_ip', networks: ['10.0.0.0/24', '10.0.0.128/25'] },
      'networks.1: overlaps networks.0',
    ],
    [
      { name: 'x', authType: 'sasl', networks: ['10.0.0.0/24'] },
      'networks: is not allowed for sasl',
    ],
    [
      { name: 'x', authType: 'client_certificate' },
      'certificateFingerprintSha256: is required for client_certificate',
    ],
    [
      { name: 'x', authType: 'sasl', certificateFingerprintSha256: 'ab'.repeat(32) },
      'certificateFingerprintSha256: is only allowed for client_certificate',
    ],
    [
      { name: 'x', authType: 'client_certificate', certificateFingerprintSha256: 'abc' },
      'certificateFingerprintSha256: must be a SHA-256 fingerprint',
    ],
    [
      { name: 'x', authType: 'sasl', requireTls: false },
      'requireTls: cannot be false: TLS is always required for sasl and client_certificate',
    ],
    [{ name: '', authType: 'sasl' }, 'name: Too small'],
    [{ name: 'a\u0000b', authType: 'sasl' }, 'name: must not contain control characters'],
    [{ name: 'x', authType: 'password' }, 'authType: Invalid option'],
    [
      { name: 'x', authType: 'sasl', organizationId: '1' },
      '(root): Unrecognized key: "organizationId"',
    ],
  ])('refuses %j', (body, message) => {
    expect(issues(CreateConnectorSchema, body).join('\n')).toContain(message);
  });

  it('allows source_ip connectors without TLS', () => {
    expect(
      CreateConnectorSchema.parse({
        name: 'x',
        authType: 'source_ip',
        networks: ['10.1.0.0/16'],
        requireTls: false,
      }).requireTls,
    ).toBe(false);
  });
});

describe('UpdateConnectorSchema', () => {
  it('needs at least one field and validates networks like create', () => {
    expect(issues(UpdateConnectorSchema, {})).toEqual(['(root): must change at least one field']);
    expect(issues(UpdateConnectorSchema, { networks: ['10.0.0.0/24', '10.0.0.1'] })).toEqual([
      'networks.1: overlaps networks.0',
    ]);
    expect(UpdateConnectorSchema.parse({ networks: [] })).toEqual({ networks: [] });
    expect(issues(UpdateConnectorSchema, { status: 'deleted' }).join()).toContain('status');
  });
});
