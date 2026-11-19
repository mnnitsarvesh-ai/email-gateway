import { describe, expect, it } from 'vitest';
import { HEALTH_CHECKS } from '../health';
import type { IntegrationProvider, ProviderAuthMethod, ProviderOutboundMode } from '../types';
import {
  ATTESTATIONS,
  attestationsFor,
  inboundRequiredAttestations,
  internalRoutingAttestation,
  lockdownAttestations,
} from './attestations';
import { renderSetupGuideMarkdown, setupGuideFileName } from './markdown';
import {
  defaultMicrosoftMxHost,
  exampleSetupGuideInput,
  generateSetupGuide,
  maskRouteToken,
  SetupGuideInputError,
  type SetupGuide,
  type SetupGuideInput,
} from './setup-guide';

// Built from parts so the test file itself carries none of the patterns it forbids.
const FORBIDDEN = [
  'wh' + 'sec_',
  'AK' + 'IA',
  'gh' + 'p_',
  's' + 'k-',
  'eg' + 'k_',
  '-----' + 'BEGIN',
];
const TOKEN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const PENDING = 'QRSTUVWXYZ234567ABCDEFGHIJKLMNOP';

const methods: Record<IntegrationProvider, ProviderAuthMethod[]> = {
  microsoft_365: ['platform_app', 'customer_app_secret'],
  google_workspace: ['platform_service_account', 'customer_service_account'],
};

function input(
  provider: IntegrationProvider,
  outboundMode: ProviderOutboundMode,
  internalRouting: boolean,
  authMethod: ProviderAuthMethod,
): SetupGuideInput {
  const example = exampleSetupGuideInput(provider);
  return {
    ...example,
    connection: { ...example.connection, outboundMode, internalRouting },
    grant: { authMethod, status: 'active', subjectEmail: example.grant!.subjectEmail },
    domains: [
      ...example.domains,
      {
        name: 'example.org',
        gatewayStatus: 'active',
        providerVerification: 'unverified',
        providerMxHost: null,
      },
    ],
    probeAddress:
      outboundMode === 'off' ? null : 'eg-probe-abcdefghijklmnopqrstuvwxyz@probe.mail-gateway.test',
    routeToken:
      provider === 'microsoft_365' ? { current: TOKEN, pending: null, reveal: true } : null,
    attestations: [
      {
        code:
          provider === 'microsoft_365'
            ? 'm365.inbound_connector_created'
            : 'google.inbound_gateway_configured',
        at: '2026-11-17T10:00:00.000Z',
      },
    ],
  };
}

const combos = (['microsoft_365', 'google_workspace'] as const).flatMap((provider) =>
  (['off', 'probe_only'] as const).flatMap((mode) =>
    [false, true].flatMap((internal) =>
      methods[provider].map((method) => [provider, mode, internal, method] as const),
    ),
  ),
);

describe('generateSetupGuide', () => {
  it.each(combos)('%s / outbound %s / internal %s / %s', (provider, mode, internal, method) => {
    const guide = generateSetupGuide(input(provider, mode, internal, method));
    const markdown = renderSetupGuideMarkdown(guide);
    expect(markdown).toMatchSnapshot();
    const everything = JSON.stringify(guide) + markdown;
    for (const needle of FORBIDDEN) expect(everything).not.toContain(needle);
  });

  it('has every D14 section in order, numbered, and the anchors health remediations link to', () => {
    for (const provider of ['microsoft_365', 'google_workspace'] as const) {
      const guide = generateSetupGuide(exampleSetupGuideInput(provider));
      expect(guide.schema).toBe('setup-guide/1');
      expect(guide.sections.map((s) => s.id)).toEqual([
        'overview',
        'grant-access',
        'domains',
        'inbound',
        'outbound',
        'internal-routing',
        'validate-activate',
        'failover',
        'disconnect',
      ]);
      expect(guide.sections.map((s) => s.number)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      const anchors = new Set(guide.sections.flatMap((s) => [s.id, ...s.steps.map((st) => st.id)]));
      for (const check of HEALTH_CHECKS) {
        if (
          check.remediation.startsWith('#') &&
          (check.provider === 'any' || check.provider === provider)
        ) {
          expect(anchors.has(check.remediation.slice(1)), `${provider} ${check.code}`).toBe(true);
        }
      }
      expect(guide.notice).toMatch(/attestations/);
    }
  });

  it('Microsoft 365: PowerShell for connectors, Enhanced Filtering, DKIM and the D9 rules', () => {
    const guide = generateSetupGuide(input('microsoft_365', 'probe_only', true, 'platform_app'));
    const code = guide.sections
      .flatMap((s) => s.steps.flatMap((st) => (st.commands ?? []).map((c) => c.code)))
      .join('\n');
    expect(code).toContain(
      "New-InboundConnector -Name 'Email security gateway' -ConnectorType Partner -SenderDomains * -RequireTls $true -TlsSenderCertificateName 'relay.gateway.example.net' -RestrictDomainsToCertificate $true",
    );
    expect(code).toContain(
      "-SenderIPAddresses '192.0.2.0/28','2001:db8::/64' -RestrictDomainsToIPAddresses $true",
    );
    expect(code).toContain(
      "Set-InboundConnector -Identity 'Email security gateway' -EFSkipLastIP $true",
    );
    expect(code).toContain("New-DkimSigningConfig -DomainName 'example.com' -Enabled $true");
    expect(code).toContain(
      "New-OutboundConnector -Name 'Email security gateway outbound' -ConnectorType Partner -RecipientDomains * -SmartHosts 'relay1.gateway.example.net','relay2.gateway.example.net' -UseMXRecord $false -TlsSettings DomainValidation -TlsDomain 'relay.gateway.example.net' -IsTransportRuleScoped $false",
    );
    expect(code).toContain('-FromScope InOrganization -SentToScope InOrganization');
    expect(code).toContain(
      `-ExceptIfHeaderMatchesMessageHeader 'X-EG-Route-Token' -ExceptIfHeaderMatchesPatterns '^${TOKEN}$'`,
    );
    expect(code).toContain(`-HeaderContainsWords '${TOKEN}' -RemoveHeader 'X-EG-Route-Token'`);
    expect(code).toContain('example.com. 3600 IN MX 10 mx1.gateway.example.net.');
    expect(code).toContain('include:spf.protection.outlook.com include:spf.gateway.example.net');
    // The unverified domain without a reported MX target gets the conventional endpoint.
    const destination = guide.sections
      .find((s) => s.id === 'inbound')!
      .steps.find((s) => s.id === 'inbound-destination')!;
    expect(destination.values).toEqual([
      { label: 'example.com', value: 'example-com.mail.protection.outlook.com' },
      { label: 'example.org', value: 'example-org.mail.protection.outlook.com' },
    ]);
    expect(defaultMicrosoftMxHost('my-domain.co.uk')).toBe(
      'my--domain-co-uk.mail.protection.outlook.com',
    );
    const validate = guide.sections
      .find((s) => s.id === 'outbound')!
      .steps.find((s) => s.id === 'outbound-validate')!;
    expect(validate.paragraphs.join(' ')).toContain(
      'eg-probe-abcdefghijklmnopqrstuvwxyz@probe.mail-gateway.test',
    );
  });

  it('masks the route token for callers without integration:manage, including during rotation', () => {
    const base = input('microsoft_365', 'probe_only', true, 'platform_app');
    const masked = generateSetupGuide({
      ...base,
      routeToken: { current: TOKEN, pending: PENDING, reveal: false },
    });
    const text = JSON.stringify(masked) + renderSetupGuideMarkdown(masked);
    expect(text).not.toContain(TOKEN);
    expect(text).not.toContain(PENDING);
    expect(text).toContain(maskRouteToken(TOKEN));
    expect(maskRouteToken(TOKEN)).toBe('••••4567');
    const revealed = generateSetupGuide({
      ...base,
      routeToken: { current: TOKEN, pending: PENDING, reveal: true },
    });
    const rules = revealed.sections
      .find((s) => s.id === 'internal-routing')!
      .steps.find((s) => s.id === 'internal-rules')!;
    expect(rules.commands![0]!.code).toContain(`'^(${TOKEN}|${PENDING})$'`);
    expect(rules.commands![0]!.code).toContain(`-HeaderContainsWords '${TOKEN}','${PENDING}'`);
    expect(rules.attestation!.code).toBe('m365.internal_routing_rules_updated');
  });

  it('Google Workspace: delegation, inbound gateway, hosts, routing and SMTP relay', () => {
    const guide = generateSetupGuide(
      input('google_workspace', 'probe_only', true, 'platform_service_account'),
    );
    const all = JSON.stringify(guide);
    expect(all).toContain('Manage domain-wide delegation');
    expect(all).toContain(
      'https://www.googleapis.com/auth/admin.directory.customer.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly',
    );
    expect(all).toContain('111122223333444455556');
    expect(all).toContain('Reject all mail not from gateway IPs');
    expect(all).toContain('Require CA signed certificate');
    expect(all).toContain('Internal - sending');
    expect(all).toContain('SMTP relay service');
    expect(all).toContain('aspmx.l.google.com (1)');
    expect(all).not.toContain('X-EG-Route-Token');
    const attestations = guide.sections.flatMap((s) =>
      s.steps.map((st) => st.attestation?.code).filter(Boolean),
    );
    expect(attestations.sort()).toEqual(
      attestationsFor('google_workspace')
        .map((a) => a.code)
        .sort(),
    );
  });

  it('records attestation state and shows no attestation as a proof', () => {
    const guide = generateSetupGuide(input('microsoft_365', 'off', false, 'customer_app_secret'));
    const steps = guide.sections.flatMap((s) => s.steps);
    expect(steps.find((s) => s.id === 'inbound-connector')!.attestation).toMatchObject({
      attested: true,
      attestedAt: '2026-11-17T10:00:00.000Z',
    });
    expect(steps.find((s) => s.id === 'inbound-enhanced-filtering')!.attestation).toMatchObject({
      attested: false,
      attestedAt: null,
    });
    const markdown = renderSetupGuideMarkdown(guide);
    expect(markdown).toContain('(your statement, not a gateway check)');
    expect(markdown).toContain('Internal routing is off for this connection.');
    expect(markdown).toContain('Outbound routing through the gateway is currently off');
  });

  it('refuses values that would be unsafe in commands', () => {
    const base = input('microsoft_365', 'off', false, 'platform_app');
    expect(() =>
      generateSetupGuide({
        ...base,
        domains: [{ ...base.domains[0]!, name: "x'; Remove-Mailbox *; '" }],
      }),
    ).toThrow(SetupGuideInputError);
    expect(() =>
      generateSetupGuide({ ...base, gateway: { ...base.gateway, relayHosts: ['bad host'] } }),
    ).toThrow(SetupGuideInputError);
    expect(() =>
      generateSetupGuide({
        ...base,
        routeToken: { current: "abc'def", pending: null, reveal: true },
      }),
    ).toThrow(SetupGuideInputError);
  });

  it('accepts an SPF include whose labels start with an underscore, and nothing else with one', () => {
    const base = input('microsoft_365', 'active', false, 'platform_app');
    const guide = generateSetupGuide({
      ...base,
      gateway: { ...base.gateway, spfInclude: '_spf.mail-gateway.test' },
    });
    expect(renderSetupGuideMarkdown(guide)).toContain('include:_spf.mail-gateway.test');
    expect(() =>
      generateSetupGuide({
        ...base,
        gateway: { ...base.gateway, spfInclude: '_spf._netblocks.example.net' },
      }),
    ).not.toThrow();
    for (const spfInclude of ['_spf', 'spf._example', '__spf.example.net', '_spf.example.net;x']) {
      expect(() =>
        generateSetupGuide({ ...base, gateway: { ...base.gateway, spfInclude } }),
      ).toThrow(SetupGuideInputError);
    }
    expect(() =>
      generateSetupGuide({
        ...base,
        gateway: { ...base.gateway, relayTlsName: '_out.example.net' },
      }),
    ).toThrow(SetupGuideInputError);
    expect(() =>
      generateSetupGuide({
        ...base,
        gateway: { ...base.gateway, relayHosts: ['_out.example.net'] },
      }),
    ).toThrow(SetupGuideInputError);
  });

  it('Markdown rendering escapes text and names the download', () => {
    const guide: SetupGuide = generateSetupGuide({
      ...exampleSetupGuideInput('google_workspace'),
      connection: {
        ...exampleSetupGuideInput('google_workspace').connection,
        displayName: 'Acme *Mail* | <b>Prod</b>',
      },
    });
    const markdown = renderSetupGuideMarkdown(guide);
    expect(markdown).toContain('Acme \\*Mail\\* \\| \\<b\\>Prod\\</b\\>');
    expect(markdown).toContain('<a id="inbound-gateway"></a>');
    expect(setupGuideFileName(guide)).toBe('setup-google-workspace-acme-mail-b-prod-b.md');
    expect(
      setupGuideFileName({
        provider: 'microsoft_365',
        connection: { ...guide.connection, displayName: '***' },
      }),
    ).toBe('setup-microsoft-365-connection.md');
  });
});

describe('attestation codes', () => {
  it('are unique, provider-prefixed and drive the wizard requirements', () => {
    expect(new Set(ATTESTATIONS.map((a) => a.code)).size).toBe(ATTESTATIONS.length);
    for (const a of ATTESTATIONS)
      expect(a.code.startsWith(a.provider === 'microsoft_365' ? 'm365.' : 'google.')).toBe(true);
    expect(inboundRequiredAttestations('microsoft_365')).toEqual([
      'm365.inbound_connector_created',
      'm365.enhanced_filtering_enabled',
    ]);
    expect(inboundRequiredAttestations('google_workspace')).toEqual([
      'google.inbound_gateway_configured',
    ]);
    expect(lockdownAttestations('microsoft_365')).toEqual(['m365.direct_delivery_locked_down']);
    expect(lockdownAttestations('google_workspace')).toEqual(['google.reject_non_gateway_enabled']);
    expect(internalRoutingAttestation('microsoft_365')).toBe('m365.internal_routing_rules_created');
  });
});
