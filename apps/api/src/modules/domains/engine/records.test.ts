import { describe, expect, it } from 'vitest';
import { TEST_DOMAIN_ENV } from '../../../../test/support/test-env';
import { loadApiConfig } from '../../../config';
import { type GatewayDnsConfig, gatewayDnsConfigFrom } from './gateway-dns-config';
import {
  buildExpectedRecords,
  instructionsFor,
  parseMxRecordValue,
  relativeName,
  requirementOf,
} from './records';

const gateway: GatewayDnsConfig = {
  mxHosts: [
    { priority: 10, host: 'mx1.mail-gateway.test' },
    { priority: 20, host: 'mx2.mail-gateway.test' },
  ],
  spfInclude: '_spf.mail-gateway.test',
  dmarcRua: ['mailto:dmarc-reports@mail-gateway.test'],
  dmarcRuf: [],
  verificationLabel: '_emailgateway-verify',
};

describe('gatewayDnsConfigFrom', () => {
  it('exposes the parsed D16 keys', () => {
    const config = loadApiConfig({
      ...TEST_DOMAIN_ENV,
      DATABASE_URL: 'mysql://u:p@mysql:3306/db',
      REDIS_URL: 'redis://redis:6379',
      S3_REGION: 'ap-south-1',
      S3_BUCKET_MAIL: 'mail',
      S3_BUCKET_ARCHIVE: 'archive',
      AUTH_JWT_SECRET: 'j'.repeat(64),
      AUTH_TOKEN_PEPPER: 'p'.repeat(64),
      DATA_ENCRYPTION_KEY: 'a'.repeat(64),
      GATEWAY_DMARC_RUA: 'mailto:dmarc-reports@mail-gateway.test',
    });
    expect(gatewayDnsConfigFrom(config)).toEqual(gateway);
  });
});

describe('buildExpectedRecords', () => {
  const keys = [
    {
      selector: 'egr20261102abcd',
      algorithm: 'rsa_2048' as const,
      publicKeyDns: 'MIIBrsa',
      status: 'active',
    },
    {
      selector: 'ege20261102wxyz',
      algorithm: 'ed25519' as const,
      publicKeyDns: 'ed25519key',
      status: 'pending',
    },
    {
      selector: 'egr20250101old1',
      algorithm: 'rsa_2048' as const,
      publicKeyDns: 'old',
      status: 'retired',
    },
  ];

  it('builds the D6 table with stable record keys', () => {
    const records = buildExpectedRecords({
      domain: 'acme.test',
      verificationToken: 'f'.repeat(40),
      dkimKeys: keys,
      gateway,
    });
    expect(records).toEqual([
      {
        recordKey: 'verification',
        purpose: 'verification',
        type: 'TXT',
        host: '_emailgateway-verify.acme.test',
        value: `emailgateway-verification=${'f'.repeat(40)}`,
      },
      {
        recordKey: 'mx:mx1.mail-gateway.test',
        purpose: 'mx',
        type: 'MX',
        host: 'acme.test',
        value: '10 mx1.mail-gateway.test',
      },
      {
        recordKey: 'mx:mx2.mail-gateway.test',
        purpose: 'mx',
        type: 'MX',
        host: 'acme.test',
        value: '20 mx2.mail-gateway.test',
      },
      {
        recordKey: 'spf',
        purpose: 'spf',
        type: 'TXT',
        host: 'acme.test',
        value: 'v=spf1 include:_spf.mail-gateway.test ~all',
      },
      {
        recordKey: 'dkim:egr20261102abcd',
        purpose: 'dkim',
        type: 'TXT',
        host: 'egr20261102abcd._domainkey.acme.test',
        value: 'v=DKIM1; k=rsa; p=MIIBrsa',
        dkimSelector: 'egr20261102abcd',
      },
      {
        recordKey: 'dkim:ege20261102wxyz',
        purpose: 'dkim',
        type: 'TXT',
        host: 'ege20261102wxyz._domainkey.acme.test',
        value: 'v=DKIM1; k=ed25519; p=ed25519key',
        dkimSelector: 'ege20261102wxyz',
      },
      {
        recordKey: 'dmarc',
        purpose: 'dmarc',
        type: 'TXT',
        host: '_dmarc.acme.test',
        value: 'v=DMARC1; p=none; rua=mailto:dmarc-reports@mail-gateway.test; fo=1',
      },
    ]);
  });

  it('omits the verification record without a token and uses given recommendations', () => {
    const records = buildExpectedRecords({
      domain: 'acme.test',
      verificationToken: null,
      dkimKeys: [],
      gateway: { ...gateway, dmarcRua: [] },
      recommendations: { spf: 'v=spf1 include:_spf.mail-gateway.test mx -all' },
    });
    expect(records.map((r) => r.recordKey)).toEqual([
      'mx:mx1.mail-gateway.test',
      'mx:mx2.mail-gateway.test',
      'spf',
      'dmarc',
    ]);
    expect(records.find((r) => r.recordKey === 'spf')?.value).toBe(
      'v=spf1 include:_spf.mail-gateway.test mx -all',
    );
    expect(records.find((r) => r.recordKey === 'dmarc')?.value).toBe(
      'v=DMARC1; p=none; rua=mailto:dmarc-reports@acme.test; fo=1',
    );
  });

  it('splits stored MX values', () => {
    expect(parseMxRecordValue('10 mx1.mail-gateway.test')).toEqual({
      priority: 10,
      host: 'mx1.mail-gateway.test',
    });
    expect(parseMxRecordValue('mx1.mail-gateway.test')).toBeNull();
  });
});

describe('requirementOf / relativeName / instructionsFor', () => {
  it('derives the requirement from the purpose', () => {
    expect(requirementOf('verification')).toBe('activation');
    expect(requirementOf('mx')).toBe('inbound');
    expect(requirementOf('spf')).toBe('outbound');
    expect(requirementOf('dkim')).toBe('outbound');
    expect(requirementOf('dmarc')).toBe('recommended');
  });

  it('names hosts relative to the domain', () => {
    expect(relativeName('acme.test', 'acme.test')).toBe('@');
    expect(relativeName('_dmarc.acme.test', 'acme.test')).toBe('_dmarc');
    expect(relativeName('sel._domainkey.Acme.test.', 'acme.test')).toBe('sel._domainkey');
    expect(relativeName('other.test', 'acme.test')).toBe('other.test');
    expect(relativeName('notacme.test', 'acme.test')).toBe('notacme.test');
  });

  it('gives one plain sentence per purpose', () => {
    for (const purpose of ['verification', 'mx', 'spf', 'dkim', 'dmarc'] as const) {
      const text = instructionsFor(purpose);
      expect(text).toMatch(/^[A-Z].*\.$/);
      expect(text.split('. ')).toHaveLength(1);
    }
    expect(instructionsFor('spf')).toBe(
      'Add this include to your existing SPF record; do not create a second SPF record.',
    );
  });
});
