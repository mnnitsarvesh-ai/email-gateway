import {
  grantsForCheck,
  healthCheckByCode,
  validationResultsSchema,
} from '@email-gateway/provider-integrations';
import { describe, expect, it } from 'vitest';
import { boundResults } from '../tasks/validation-runner';
import { checkResult } from './checks';
import { attestedCodes } from './context';

describe('checkResult', () => {
  it('takes severity and remediation from the registry (D10)', () => {
    expect(
      checkResult('credentials.token', 'm365.mail_flow', 'fail', { code: 'invalid_client' }),
    ).toEqual({
      code: 'credentials.token',
      subject: 'm365.mail_flow',
      status: 'fail',
      severity: 'critical',
      evidence: { code: 'invalid_client' },
      remediation: '#grant-access',
    });
    expect(checkResult('dns.dkim_provider', 'example.com', 'warn').severity).toBe('warning');
    expect(checkResult('egress.ranges_fresh', '', 'fail').severity).toBe('warning');
    expect(checkResult('inbound.smtp', 'h', 'pass').severity).toBe('info');
    expect(checkResult('tenant.identity', '', 'error').severity).toBe('critical');
    expect(checkResult('routing.loops', '', 'skipped').severity).toBe('info');
  });

  it('bounds evidence to 2 KiB and subjects to 253 characters', () => {
    const result = checkResult('inbound.smtp', 'x'.repeat(400), 'fail', {
      banner: 'b'.repeat(5_000),
      names: Array.from({ length: 50 }, (_, i) => `n${i}.example.com`),
    });
    expect(result.subject).toHaveLength(253);
    expect(Buffer.byteLength(JSON.stringify(result.evidence))).toBeLessThanOrEqual(2_048);
    expect(validationResultsSchema.safeParse([result]).success).toBe(true);
  });
});

describe('boundResults (provider-validation/1: ≤ 64 entries, ≤ 64 KiB)', () => {
  it('drops entries from the end until the list is valid', () => {
    const many = Array.from({ length: 80 }, (_, i) =>
      checkResult('domains.gateway_verified', `d${i}.example.com`, 'pass', {
        note: 'n'.repeat(200),
      }),
    );
    const bounded = boundResults(many);
    expect(bounded.length).toBeLessThanOrEqual(64);
    expect(validationResultsSchema.safeParse(bounded).success).toBe(true);
    expect(bounded[0]).toEqual(many[0]);
  });
});

describe('attestedCodes (provider-attestations/1)', () => {
  it('reads recorded statements; a later attested=false withdraws a code', () => {
    expect(
      attestedCodes([
        { code: 'm365.inbound_connector_created', userId: 'u', at: '2026-11-18T00:00:00Z' },
        { code: 'm365.direct_delivery_locked_down', userId: 'u', at: '2026-11-18T00:00:00Z' },
        { code: 'm365.inbound_connector_created', attested: false, userId: 'u', at: 'x' },
        { nope: true },
        'junk',
      ]),
    ).toEqual(['m365.direct_delivery_locked_down']);
    expect(attestedCodes(null)).toEqual([]);
    expect(attestedCodes({ items: [{ code: 'google.reject_non_gateway_enabled' }] })).toEqual([
      'google.reject_non_gateway_enabled',
    ]);
  });
});

describe('8.2 per-grant checks skip non-mail_flow grants (R2; step API-1 D4)', () => {
  const grants = [
    { profile: 'm365.mail_flow' },
    { profile: 'm365.ato_telemetry' },
    { profile: 'm365.mailbox_remediation' },
    { profile: 'google.mailbox_remediation' },
    { profile: 'google.mail_flow' },
  ];
  it.each(['credentials.token', 'permissions.granted'])(
    '%s covers the mail-flow grants only (mailbox access is verified by verifyAuxiliary)',
    (code) => {
      const definition = healthCheckByCode(code);
      expect(definition).toBeDefined();
      expect(grantsForCheck(definition!, grants).map((g) => g.profile)).toEqual([
        'm365.mail_flow',
        'google.mail_flow',
      ]);
    },
  );
});
