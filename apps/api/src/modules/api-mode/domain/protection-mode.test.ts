import { describe, expect, it } from 'vitest';
import { effectiveModeCounts } from '../../../tenancy/api-mode-status.service';
import {
  decideCreateMode,
  decideDomainModeChange,
  decideOrganizationModeChange,
  type DomainModeFacts,
  effectiveModeOf,
  MX_CONFLICT_DETAIL_LIMIT,
} from './protection-mode';

const domain = (patch: Partial<DomainModeFacts> = {}): DomainModeFacts => ({
  publicId: '0192f3a0-2222-7000-8000-000000000002',
  name: 'contoso.example',
  configured: null,
  mxPointsToGateway: false,
  ...patch,
});

describe('effective protection mode (step API-1 D1)', () => {
  it('is the domain’s own mode, else the organization’s', () => {
    expect(effectiveModeOf(null, 'inline')).toBe('inline');
    expect(effectiveModeOf(null, 'api')).toBe('api');
    expect(effectiveModeOf('hybrid', 'api')).toBe('hybrid');
    expect(effectiveModeOf('inline', 'hybrid')).toBe('inline');
  });

  it('counts domains per effective mode', () => {
    expect(
      effectiveModeCounts('hybrid', [
        { mode: null, count: 3 },
        { mode: 'inline', count: 1 },
        { mode: 'api', count: 2 },
      ]),
    ).toEqual({ inline: 1, api: 2, hybrid: 3 });
    expect(effectiveModeCounts('inline', [])).toEqual({ inline: 0, api: 0, hybrid: 0 });
  });
});

describe('decideDomainModeChange (D2)', () => {
  it.each([
    ['inherit → inherit', null, 'inherit'],
    ['api → api', 'api', 'api'],
    ['inline → inline', 'inline', 'inline'],
  ] as const)('%s is unchanged (no audit)', (_n, configured, requested) => {
    expect(
      decideDomainModeChange({
        domain: domain({ configured }),
        organizationMode: 'inline',
        requested,
        entitled: false,
      }),
    ).toMatchObject({ kind: 'unchanged' });
  });

  it('inherit → api with entitlement and no MX conflict changes both values', () => {
    expect(
      decideDomainModeChange({
        domain: domain(),
        organizationMode: 'inline',
        requested: 'api',
        entitled: true,
      }),
    ).toEqual({
      kind: 'change',
      fromConfigured: null,
      toConfigured: 'api',
      fromEffective: 'inline',
      toEffective: 'api',
    });
  });

  it('api and hybrid need the feature; inline never does', () => {
    for (const requested of ['api', 'hybrid'] as const) {
      expect(
        decideDomainModeChange({
          domain: domain(),
          organizationMode: 'inline',
          requested,
          entitled: false,
        }),
      ).toEqual({ kind: 'refused', refusal: { code: 'api_mode_not_enabled' } });
    }
    expect(
      decideDomainModeChange({
        domain: domain({ configured: 'api' }),
        organizationMode: 'inline',
        requested: 'inline',
        entitled: false,
      }),
    ).toMatchObject({ kind: 'change', toEffective: 'inline' });
  });

  it('inherit into an api organization needs the feature (the effective mode becomes api)', () => {
    expect(
      decideDomainModeChange({
        domain: domain({ configured: 'inline' }),
        organizationMode: 'api',
        requested: 'inherit',
        entitled: false,
      }),
    ).toEqual({ kind: 'refused', refusal: { code: 'api_mode_not_enabled' } });
  });

  it('refuses becoming effective api while MX points to the gateway, naming the domain', () => {
    expect(
      decideDomainModeChange({
        domain: domain({ mxPointsToGateway: true }),
        organizationMode: 'inline',
        requested: 'api',
        entitled: true,
      }),
    ).toEqual({
      kind: 'refused',
      refusal: {
        code: 'protection_mode_mx_points_to_gateway',
        domains: [{ id: '0192f3a0-2222-7000-8000-000000000002', name: 'contoso.example' }],
      },
    });
  });

  it('hybrid is allowed with MX at the gateway; staying effective api is not a new conflict', () => {
    expect(
      decideDomainModeChange({
        domain: domain({ mxPointsToGateway: true }),
        organizationMode: 'inline',
        requested: 'hybrid',
        entitled: true,
      }),
    ).toMatchObject({ kind: 'change', toEffective: 'hybrid' });
    // Inherited api → explicit api: the effective mode does not change.
    expect(
      decideDomainModeChange({
        domain: domain({ mxPointsToGateway: true }),
        organizationMode: 'api',
        requested: 'api',
        entitled: true,
      }),
    ).toMatchObject({ kind: 'change', fromEffective: 'api', toEffective: 'api' });
  });
});

describe('decideOrganizationModeChange (D2)', () => {
  const domains: DomainModeFacts[] = [
    domain({ publicId: 'a', name: 'b.example' }),
    domain({ publicId: 'b', name: 'a.example' }),
    domain({ publicId: 'c', name: 'own.example', configured: 'inline', mxPointsToGateway: true }),
  ];

  it('same value: unchanged', () => {
    expect(
      decideOrganizationModeChange({ from: 'api', to: 'api', entitled: false, domains }),
    ).toEqual({ kind: 'unchanged' });
  });

  it('reports inheriting and effective api domains', () => {
    expect(
      decideOrganizationModeChange({ from: 'inline', to: 'api', entitled: true, domains }),
    ).toEqual({
      kind: 'change',
      from: 'inline',
      to: 'api',
      inheritingDomains: 2,
      effectiveApiDomains: 2,
    });
    expect(
      decideOrganizationModeChange({ from: 'api', to: 'inline', entitled: false, domains }),
    ).toMatchObject({ kind: 'change', effectiveApiDomains: 0 });
  });

  it('needs the feature for api and hybrid', () => {
    expect(
      decideOrganizationModeChange({ from: 'inline', to: 'hybrid', entitled: false, domains }),
    ).toEqual({ kind: 'refused', refusal: { code: 'api_mode_not_enabled' } });
  });

  it('checks MX over every INHERITING domain that becomes api, sorted, at most 20 names', () => {
    const many = Array.from({ length: 25 }, (_, i) =>
      domain({
        publicId: `id-${i}`,
        name: `d${String(i).padStart(2, '0')}.example`,
        mxPointsToGateway: true,
      }),
    );
    const decision = decideOrganizationModeChange({
      from: 'hybrid',
      to: 'api',
      entitled: true,
      domains: [...many].reverse(),
    });
    expect(decision.kind).toBe('refused');
    if (
      decision.kind !== 'refused' ||
      decision.refusal.code !== 'protection_mode_mx_points_to_gateway'
    ) {
      throw new Error('expected an MX conflict');
    }
    expect(decision.refusal.domains).toHaveLength(MX_CONFLICT_DETAIL_LIMIT);
    expect(decision.refusal.domains[0]).toEqual({ id: 'id-0', name: 'd00.example' });
    // A domain with its own mode does not follow the organization: no conflict.
    expect(
      decideOrganizationModeChange({ from: 'inline', to: 'api', entitled: true, domains }),
    ).toMatchObject({ kind: 'change' });
  });

  it('hybrid never conflicts on MX; api → api is unchanged', () => {
    const atGateway = [domain({ mxPointsToGateway: true })];
    expect(
      decideOrganizationModeChange({
        from: 'inline',
        to: 'hybrid',
        entitled: true,
        domains: atGateway,
      }),
    ).toMatchObject({ kind: 'change' });
  });
});

describe('decideCreateMode (D2, POST /domains)', () => {
  it('absent = inherit; inbound default true unless the effective mode is api', () => {
    expect(
      decideCreateMode({
        requested: undefined,
        inboundEnabled: undefined,
        organizationMode: 'inline',
        entitled: false,
      }),
    ).toEqual({ kind: 'ok', configured: null, inboundEnabled: true });
    expect(
      decideCreateMode({
        requested: undefined,
        inboundEnabled: undefined,
        organizationMode: 'api',
        entitled: false,
      }),
    ).toEqual({ kind: 'ok', configured: null, inboundEnabled: false });
  });

  it('api: inbound off by default, explicit inbound on is a conflict', () => {
    expect(
      decideCreateMode({
        requested: 'api',
        inboundEnabled: undefined,
        organizationMode: 'inline',
        entitled: true,
      }),
    ).toEqual({ kind: 'ok', configured: 'api', inboundEnabled: false });
    expect(
      decideCreateMode({
        requested: 'api',
        inboundEnabled: true,
        organizationMode: 'inline',
        entitled: true,
      }),
    ).toEqual({ kind: 'refused', code: 'protection_mode_inbound_conflict' });
  });

  it('api and hybrid need the feature; hybrid keeps inbound on', () => {
    expect(
      decideCreateMode({
        requested: 'hybrid',
        inboundEnabled: undefined,
        organizationMode: 'inline',
        entitled: false,
      }),
    ).toEqual({ kind: 'refused', code: 'api_mode_not_enabled' });
    expect(
      decideCreateMode({
        requested: 'hybrid',
        inboundEnabled: undefined,
        organizationMode: 'inline',
        entitled: true,
      }),
    ).toEqual({ kind: 'ok', configured: 'hybrid', inboundEnabled: true });
    expect(
      decideCreateMode({
        requested: 'inline',
        inboundEnabled: false,
        organizationMode: 'api',
        entitled: false,
      }),
    ).toEqual({ kind: 'ok', configured: 'inline', inboundEnabled: false });
  });
});
