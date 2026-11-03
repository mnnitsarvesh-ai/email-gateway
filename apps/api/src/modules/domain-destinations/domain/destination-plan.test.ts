import { MAIL_DESTINATION_PRESETS } from '@email-gateway/database';
import { mailDestinationPresetSchema } from '@email-gateway/mail-routing';
import { describe, expect, it } from 'vitest';
import { type HostRules, planDestinations } from './destination-plan';

const presets = MAIL_DESTINATION_PRESETS.map((preset) =>
  mailDestinationPresetSchema.parse({
    ...preset,
    hostPatterns: [...preset.hostPatterns],
    defaultServers: preset.defaultServers ? [...preset.defaultServers] : null,
  }),
);

const rules: HostRules = {
  allowNonPublic: false,
  deniedSuffixes: ['corp'],
  gatewayHosts: new Set(['mx1.gateway.example', 'mx.gateway.local', 'out.gateway.local']),
  bounceDomain: 'bounces.gateway.example',
};

describe('planDestinations (step 2.3 R2, R3)', () => {
  it('custom: normalizes hosts and applies the defaults', () => {
    const plan = planDestinations(
      {
        provider: 'custom',
        servers: [
          {
            host: 'MX1.Tenant.Example.',
            tlsMode: 'verify',
            tlsVerifyNames: 'nexthop:.tenant.example',
          },
          { host: 'bücher.example', port: 2525, priority: 20 },
          { host: '[2001:4860:4860::8888]', tlsMode: 'required' },
        ],
      },
      presets,
      rules,
    );
    expect(plan).toEqual({
      ok: true,
      provider: 'custom',
      servers: [
        {
          host: 'mx1.tenant.example',
          port: 25,
          priority: 10,
          tlsMode: 'verify',
          tlsVerifyNames: 'nexthop:.tenant.example',
          provider: 'custom',
        },
        {
          host: 'xn--bcher-kva.example',
          port: 2525,
          priority: 20,
          tlsMode: 'opportunistic',
          tlsVerifyNames: null,
          provider: 'custom',
        },
        {
          host: '2001:4860:4860::8888',
          port: 25,
          priority: 10,
          tlsMode: 'required',
          tlsVerifyNames: null,
          provider: 'custom',
        },
      ],
    });
  });

  it.each([
    ['10.0.0.5', 'ip_not_public'],
    ['[fd00::1]', 'ip_not_public'],
    ['169.254.169.254', 'metadata_address'],
    ['metadata.google.internal', 'metadata_address'],
    ['mysql', 'single_label'],
    ['smtp.cluster.local', 'internal_suffix'],
    ['mail.svc', 'internal_suffix'],
    ['mail.intranet.corp', 'internal_suffix'],
    ['mx1.gateway.example', 'gateway_host'],
    ['MX.Gateway.Local.', 'gateway_host'],
    ['out.gateway.local', 'gateway_host'],
    ['x.bounces.gateway.example', 'gateway_host'],
    ['bad_host.example', 'invalid_host'],
  ])('custom: %s → %s (field of the server)', (host, reason) => {
    const plan = planDestinations(
      { provider: 'custom', servers: [{ host: 'ok.example' }, { host }] },
      presets,
      rules,
    );
    expect(plan).toEqual({ ok: false, reason, field: 'servers.1.host' });
  });

  it('custom: non-public literals are allowed with ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS', () => {
    const open = { ...rules, allowNonPublic: true };
    expect(
      planDestinations({ provider: 'custom', servers: [{ host: '10.0.0.5' }] }, presets, open).ok,
    ).toBe(true);
    expect(
      planDestinations(
        { provider: 'custom', servers: [{ host: '169.254.169.254' }] },
        presets,
        open,
      ),
    ).toMatchObject({ ok: false, reason: 'metadata_address' });
  });

  it('custom: the same host:port twice (after normalization) is duplicate_server', () => {
    expect(
      planDestinations(
        { provider: 'custom', servers: [{ host: 'a.example' }, { host: 'A.example.', port: 25 }] },
        presets,
        rules,
      ),
    ).toEqual({ ok: false, reason: 'duplicate_server', field: 'servers.1.host' });
    expect(
      planDestinations(
        { provider: 'custom', servers: [{ host: 'a.example' }, { host: 'a.example', port: 2525 }] },
        presets,
        rules,
      ).ok,
    ).toBe(true);
  });

  it.each([
    ['aspmx.l.google.com', 'verify'],
    ['ALT2.aspmx.l.google.com.', 'opportunistic'],
    ['contoso-com.mail.protection.outlook.com', 'verify'],
  ] as const)(
    'custom: a preset host (%s) is host_reserved_for_provider, whatever its TLS',
    (host, tlsMode) => {
      expect(
        planDestinations(
          {
            provider: 'custom',
            servers: [{ host: 'ok.example' }, { host, tlsMode, tlsVerifyNames: 'bogus.invalid' }],
          },
          presets,
          rules,
        ),
      ).toEqual({ ok: false, reason: 'host_reserved_for_provider', field: 'servers.1.host' });
    },
  );

  it('custom: ports outside ROUTING_ALLOWED_DESTINATION_PORTS are port_not_allowed', () => {
    for (const port of [10052, 10051, 11332, 8080]) {
      expect(
        planDestinations(
          { provider: 'custom', servers: [{ host: 'evil.example.com', port }] },
          presets,
          { ...rules, allowedPorts: [25, 587, 2525, 8080].filter((p) => p !== 8080) },
        ),
        String(port),
      ).toEqual({ ok: false, reason: 'port_not_allowed', field: 'servers.0.port' });
    }
    expect(
      planDestinations(
        { provider: 'custom', servers: [{ host: 'mx.tenant.example', port: 587 }] },
        presets,
        rules,
      ).ok,
    ).toBe(true);
  });

  it('microsoft_365: one host of the preset patterns, verify with the preset names', () => {
    expect(
      planDestinations(
        { provider: 'microsoft_365', host: 'Contoso-com.mail.protection.outlook.com' },
        presets,
        rules,
      ),
    ).toEqual({
      ok: true,
      provider: 'microsoft_365',
      servers: [
        {
          host: 'contoso-com.mail.protection.outlook.com',
          port: 25,
          priority: 10,
          tlsMode: 'verify',
          tlsVerifyNames: 'nexthop:mail.protection.outlook.com:.mail.protection.outlook.com',
          provider: 'microsoft_365',
        },
      ],
    });
  });

  it.each([
    ['mail.contoso.com', 'host_not_allowed_for_provider'],
    ['aspmx.l.google.com', 'host_not_allowed_for_provider'],
    ['a.b.mail.protection.outlook.com', 'host_not_allowed_for_provider'],
    ['40.92.0.1', 'host_not_allowed_for_provider'],
    ['10.0.0.1', 'ip_not_public'],
  ])('microsoft_365: %s → %s', (host, reason) => {
    expect(planDestinations({ provider: 'microsoft_365', host }, presets, rules)).toEqual({
      ok: false,
      reason,
      field: 'host',
    });
  });

  it('google_workspace: the preset servers with their priorities', () => {
    const plan = planDestinations({ provider: 'google_workspace' }, presets, rules);
    expect(plan.ok && plan.servers.map((s) => [s.host, s.priority, s.port, s.tlsMode])).toEqual([
      ['aspmx.l.google.com', 1, 25, 'verify'],
      ['alt1.aspmx.l.google.com', 5, 25, 'verify'],
      ['alt2.aspmx.l.google.com', 5, 25, 'verify'],
      ['alt3.aspmx.l.google.com', 10, 25, 'verify'],
      ['alt4.aspmx.l.google.com', 10, 25, 'verify'],
    ]);
    expect(plan.ok && plan.servers[0]!.tlsVerifyNames).toBe(
      'nexthop:mx.google.com:.aspmx.l.google.com',
    );
  });

  it('a missing (disabled) preset is provider_unavailable', () => {
    expect(planDestinations({ provider: 'google_workspace' }, [], rules)).toEqual({
      ok: false,
      reason: 'provider_unavailable',
      field: 'provider',
    });
    expect(
      planDestinations(
        { provider: 'microsoft_365', host: 'x.mail.protection.outlook.com' },
        [],
        rules,
      ),
    ).toMatchObject({ reason: 'provider_unavailable' });
  });

  it('preset data refused by the host rules is never written', () => {
    const denyGoogle = { ...rules, deniedSuffixes: ['google.com'] };
    expect(planDestinations({ provider: 'google_workspace' }, presets, denyGoogle)).toMatchObject({
      ok: false,
      reason: 'provider_unavailable',
    });
  });
});
