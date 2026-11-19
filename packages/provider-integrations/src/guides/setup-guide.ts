import { mailFlowProfileFor } from '../profiles';
import type {
  IntegrationProvider,
  ProviderAuthMethod,
  ProviderDomainVerification,
  ProviderGrantStatus,
  ProviderOutboundMode,
} from '../types';
import { attestationsFor } from './attestations';

/**
 * Customer-specific setup guides (`setup-guide/1`, D14, ADR-0080), generated purely from the
 * connection's own values. Every customer-side change is an instruction (with an attestation
 * code where the gateway cannot observe the result); the gateway never applies one (I3).
 */
export const SETUP_GUIDE_SCHEMA = 'setup-guide/1';

/** Names of the customer-side objects the guide creates (stable: the cleanup steps name them). */
export const M365_INBOUND_CONNECTOR_NAME = 'Email security gateway';
export const M365_OUTBOUND_CONNECTOR_NAME = 'Email security gateway outbound';
export const M365_INTERNAL_CONNECTOR_NAME = 'Email security gateway internal';
export const M365_ROUTE_RULE_NAME = 'Route internal mail through the email security gateway';
export const M365_REMOVE_TOKEN_RULE_NAME = 'Remove the gateway route token';
export const GOOGLE_HOST_NAME = 'Email security gateway';
export const ROUTE_TOKEN_HEADER_NAME = 'X-EG-Route-Token';

/** Google Workspace MX hosts (the `google_workspace` preset's defaults, step 2.3). */
export const GOOGLE_MX_HOSTS: readonly { host: string; priority: number }[] = Object.freeze([
  { host: 'aspmx.l.google.com', priority: 1 },
  { host: 'alt1.aspmx.l.google.com', priority: 5 },
  { host: 'alt2.aspmx.l.google.com', priority: 5 },
  { host: 'alt3.aspmx.l.google.com', priority: 10 },
  { host: 'alt4.aspmx.l.google.com', priority: 10 },
]);

export interface SetupGuideDomainInput {
  name: string;
  /** Gateway status (`active`, `pending_verification`, …). */
  gatewayStatus: string;
  providerVerification: ProviderDomainVerification;
  /** Microsoft 365: the tenant's MX target (`provider_mx_host`). */
  providerMxHost: string | null;
  /** The destination servers the gateway delivers to (default: the provider preset's). */
  destinations?: readonly { host: string; priority: number }[];
}

export interface SetupGuideInput {
  provider: IntegrationProvider;
  connection: {
    publicId: string;
    displayName: string;
    tenantId: string | null;
    tenantName: string | null;
    outboundMode: ProviderOutboundMode;
    internalRouting: boolean;
  };
  /** The connection's mail-flow grant (null before one is created). */
  grant: {
    authMethod: ProviderAuthMethod;
    status: ProviderGrantStatus;
    /** Delegated admin (Google); shown masked by the api if it chooses to pass it masked. */
    subjectEmail: string | null;
  } | null;
  /** The platform app / service account client id of the mail-flow profile (null if none). */
  platformClientId: string | null;
  domains: readonly SetupGuideDomainInput[];
  gateway: {
    /** `GATEWAY_MX_HOSTS`. */
    mxHosts: readonly string[];
    /** `GATEWAY_EGRESS_NETWORKS`. */
    egressNetworks: readonly string[];
    /** `GATEWAY_RELAY_HOSTS`. */
    relayHosts: readonly string[];
    /** `GATEWAY_RELAY_TLS_NAME`. */
    relayTlsName: string;
    /** `GATEWAY_SPF_INCLUDE`. */
    spfInclude: string;
  };
  /** The active probe address of a run awaiting a probe, if any. */
  probeAddress: string | null;
  /**
   * Microsoft 365 route tokens (D9): `reveal` only for callers with `integration:manage`;
   * otherwise the guide shows `••••` + the last 4 characters.
   */
  routeToken: { current: string; pending: string | null; reveal: boolean } | null;
  attestations: readonly { code: string; at: string | Date }[];
  generatedAt: Date;
}

export interface SetupGuideCommand {
  language: 'powershell' | 'dns' | 'text';
  code: string;
}

export interface SetupGuideStep {
  /** Anchor (stable; remediation links of health checks point at these). */
  id: string;
  title: string;
  paragraphs: string[];
  values?: { label: string; value: string }[];
  commands?: SetupGuideCommand[];
  warning?: string;
  attestation?: { code: string; statement: string; attested: boolean; attestedAt: string | null };
}

export interface SetupGuideSection {
  id: string;
  number: number;
  title: string;
  paragraphs: string[];
  steps: SetupGuideStep[];
}

export interface SetupGuide {
  schema: typeof SETUP_GUIDE_SCHEMA;
  provider: IntegrationProvider;
  connection: {
    id: string;
    displayName: string;
    tenantId: string | null;
    tenantName: string | null;
  };
  generatedAt: string;
  /** Always shown: attestations are statements, not proofs. */
  notice: string;
  sections: SetupGuideSection[];
}

const MASK = '••••';

/** `••••` + the last 4 characters (D14). */
export const maskRouteToken = (token: string): string => `${MASK}${token.slice(-4)}`;

const ROUTE_TOKEN = /^[A-Za-z0-9]{8,64}$/;
const SAFE_HOST =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
/**
 * An SPF `include:` target: a host name whose non-final labels may start with `_` (SPF
 * conventions such as `_spf.example.net` or `_netblocks.example.net`); everything else as SAFE_HOST.
 */
const SAFE_SPF_INCLUDE =
  /^(?:_?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const SAFE_CIDR = /^[0-9a-f:.]{2,45}(?:\/\d{1,3})?$/i;

export class SetupGuideInputError extends Error {
  override readonly name = 'SetupGuideInputError';
}

function assertSafe(values: readonly string[], pattern: RegExp, what: string): void {
  for (const value of values) {
    if (!pattern.test(value)) throw new SetupGuideInputError(`${what} contains an unusable value`);
  }
}

/** PowerShell single-quoted string literal. */
const ps = (value: string): string => `'${value.replace(/'/g, "''")}'`;
const psList = (values: readonly string[]): string => values.map(ps).join(',');

/** The Microsoft 365 MX endpoint naming convention (`contoso-com.mail.protection.outlook.com`). */
export const defaultMicrosoftMxHost = (domain: string): string =>
  `${domain.replace(/-/g, '--').replace(/\./g, '-')}.mail.protection.outlook.com`;

export function generateSetupGuide(input: SetupGuideInput): SetupGuide {
  const domainNames = input.domains.map((d) => d.name.toLowerCase());
  assertSafe(domainNames, SAFE_HOST, 'domains');
  assertSafe(input.gateway.mxHosts, SAFE_HOST, 'GATEWAY_MX_HOSTS');
  assertSafe(input.gateway.relayHosts, SAFE_HOST, 'GATEWAY_RELAY_HOSTS');
  assertSafe([input.gateway.relayTlsName], SAFE_HOST, 'gateway names');
  assertSafe([input.gateway.spfInclude], SAFE_SPF_INCLUDE, 'GATEWAY_SPF_INCLUDE');
  assertSafe(input.gateway.egressNetworks, SAFE_CIDR, 'GATEWAY_EGRESS_NETWORKS');
  for (const d of input.domains) {
    assertSafe(
      [
        ...(d.destinations ?? []).map((s) => s.host),
        ...(d.providerMxHost ? [d.providerMxHost] : []),
      ],
      SAFE_HOST,
      'destinations',
    );
  }
  if (input.routeToken) {
    const tokens = [
      input.routeToken.current,
      ...(input.routeToken.pending ? [input.routeToken.pending] : []),
    ];
    assertSafe(tokens, ROUTE_TOKEN, 'route token');
  }

  const attested = new Map(
    input.attestations.map(
      (a) => [a.code, a.at instanceof Date ? a.at.toISOString() : a.at] as const,
    ),
  );
  const ctx: Ctx = { input, domainNames, attested };
  const sections =
    input.provider === 'microsoft_365' ? microsoftSections(ctx) : googleSections(ctx);
  return {
    schema: SETUP_GUIDE_SCHEMA,
    provider: input.provider,
    connection: {
      id: input.connection.publicId,
      displayName: input.connection.displayName,
      tenantId: input.connection.tenantId,
      tenantName: input.connection.tenantName,
    },
    generatedAt: input.generatedAt.toISOString(),
    notice:
      'This guide contains the values of your own connection. The gateway never changes your ' +
      (input.provider === 'microsoft_365' ? 'Microsoft 365' : 'Google Workspace') +
      ' configuration: you apply every step yourself. Confirmations you record in the console are ' +
      'your statements (attestations), not proofs the gateway has checked.',
    sections: sections.map((s, i) => ({ ...s, number: i + 1 })),
  };
}

interface Ctx {
  input: SetupGuideInput;
  domainNames: string[];
  attested: Map<string, string>;
}

type SectionDraft = Omit<SetupGuideSection, 'number'>;

function attestation(ctx: Ctx, code: string): SetupGuideStep['attestation'] {
  const def = attestationsFor(ctx.input.provider).find((a) => a.code === code);
  if (!def) throw new SetupGuideInputError(`unknown attestation ${code}`);
  const at = ctx.attested.get(code) ?? null;
  return { code, statement: def.statement, attested: at !== null, attestedAt: at };
}

const providerName = (p: IntegrationProvider) =>
  p === 'microsoft_365' ? 'Microsoft 365' : 'Google Workspace';

function overviewSection(ctx: Ctx): SectionDraft {
  const name = providerName(ctx.input.provider);
  return {
    id: 'overview',
    title: 'Overview and what the gateway will never do',
    paragraphs: [
      `This guide connects ${name} to the email security gateway for the connection ` +
        `"${ctx.input.connection.displayName}". Inbound mail reaches the gateway first (your MX ` +
        `records), is inspected and then delivered to ${name}. Outbound and, optionally, internal ` +
        `mail is routed by ${name} to the gateway, inspected and delivered.`,
      `The gateway requests read-only access only: it reads your tenant identity and the ` +
        `verification state of your domains. It never reads or sends mail on your behalf, never ` +
        `reads users or mailboxes and never changes your ${name} configuration. Every change in ` +
        `${name} below is made by you.`,
      'Changes on the gateway side (where the gateway delivers your mail, whether it accepts ' +
        'your outbound mail) are applied only after you review a preview and confirm it in the console.',
    ],
    steps: [],
  };
}

function domainsSection(ctx: Ctx): SectionDraft {
  const name = providerName(ctx.input.provider);
  const label = (v: ProviderDomainVerification) =>
    ({
      verified: 'verified',
      unverified: 'not verified',
      absent: 'not found',
      alias: 'domain alias',
      unknown: 'not checked yet',
    })[v];
  return {
    id: 'domains',
    title: 'Domains',
    paragraphs: [
      'Each linked domain must be verified at the gateway (DNS TXT record) and verified in your ' +
        `${name} tenant. The gateway's own verification is authoritative; the ${name} ` +
        'verification proves the domain belongs to this tenant.',
    ],
    steps: [
      {
        id: 'domains-status',
        title: 'Linked domains',
        paragraphs:
          ctx.input.domains.length === 0
            ? ['No domain is linked yet. Link at least one verified domain in the console.']
            : [],
        values: ctx.input.domains.map((d) => ({
          label: d.name,
          value: `gateway: ${d.gatewayStatus}; ${name}: ${label(d.providerVerification)}`,
        })),
      },
    ],
  };
}

function mxStep(ctx: Ctx): SetupGuideStep {
  const mx = ctx.input.gateway.mxHosts.map((h, i) => ({ host: h, priority: (i + 1) * 10 }));
  return {
    id: 'inbound-mx',
    title: 'Point your MX records to the gateway',
    paragraphs: [
      'At your DNS provider, replace the MX records of each linked domain with the gateway hosts ' +
        'below. Lower the TTL a day in advance to shorten the switch-over.',
    ],
    commands: [
      {
        language: 'dns',
        code:
          ctx.domainNames
            .flatMap((d) => mx.map((m) => `${d}. 3600 IN MX ${m.priority} ${m.host}.`))
            .join('\n') ||
          mx.map((m) => `<your domain>. 3600 IN MX ${m.priority} ${m.host}.`).join('\n'),
      },
    ],
  };
}

function outboundModeNote(ctx: Ctx): string[] {
  return ctx.input.connection.outboundMode === 'off'
    ? [
        'Outbound routing through the gateway is currently off for this connection. Prepare these steps now or skip them; they take effect only after you choose outbound routing in the console.',
      ]
    : [];
}

function probeStepParagraph(ctx: Ctx, how: string): string[] {
  return ctx.input.probeAddress
    ? [
        `${how} Use the probe address ${ctx.input.probeAddress} (valid for this validation run only).`,
      ]
    : [`${how} Start an outbound validation in the console to get a probe address.`];
}

function spfStep(ctx: Ctx, providerInclude: string): SetupGuideStep {
  return {
    id: 'outbound-spf',
    title: 'Add the gateway to your SPF records',
    paragraphs: [
      'Keep your existing mechanisms and add the gateway include, so receivers accept mail the ' +
        'gateway relays for you. One SPF record per domain; at most 10 DNS lookups in total.',
    ],
    commands: [
      {
        language: 'dns',
        code: (ctx.domainNames.length > 0 ? ctx.domainNames : ['<your domain>'])
          .map(
            (d) =>
              `${d}. 3600 IN TXT "v=spf1 include:${providerInclude} include:${ctx.input.gateway.spfInclude} ~all"`,
          )
          .join('\n'),
      },
    ],
  };
}

function validateSection(): SectionDraft {
  return {
    id: 'validate-activate',
    title: 'Validate and activate',
    paragraphs: [
      'Run a full validation in the console. It checks your access, the domains, MX and SPF ' +
        'records, the gateway destination (an SMTP connection without sending mail), the outbound ' +
        'probe and mail loops. What it cannot observe is listed as an attestation.',
      'When every required check passes, activate outbound routing (and, if you want it, internal ' +
        'routing) in the console. Activation is a gateway-side change: review the preview and confirm it.',
    ],
    steps: [],
  };
}

function failoverSection(ctx: Ctx, providerQueue: string, bypass: string[]): SectionDraft {
  return {
    id: 'failover',
    title: 'Failover and outages',
    paragraphs: [
      `Every gateway relay host (${ctx.input.gateway.relayHosts.join(', ')}) is listed in your ` +
        'configuration, so mail moves to the next host when one is unavailable.',
      `${providerQueue} This is the provider's documented behaviour, not a guarantee of the gateway.`,
      'The gateway delivers inbound mail to every destination host in priority order and retries ' +
        'deferred mail for up to 5 days.',
      'The gateway never falls back to delivering around itself. An emergency bypass is a change ' +
        'you make on your side, and mail then leaves without inspection:',
      ...bypass,
    ],
    steps: [],
  };
}

// ---------------------------------------------------------------------------------------------
// Microsoft 365
// ---------------------------------------------------------------------------------------------

function microsoftSections(ctx: Ctx): SectionDraft[] {
  const { input } = ctx;
  const profile = mailFlowProfileFor('microsoft_365');
  const g = input.gateway;
  const domainsOrPlaceholder = ctx.domainNames.length > 0 ? ctx.domainNames : ['<your domain>'];

  const grantSteps: SetupGuideStep[] = [];
  const method = input.grant?.authMethod ?? null;
  if (method === null || method === 'platform_app') {
    grantSteps.push({
      id: 'grant-admin-consent',
      title: 'Grant admin consent to the gateway application (recommended)',
      paragraphs: [
        'In the console, choose "Grant consent in Microsoft". Sign in as a Global Administrator or ' +
          'Privileged Role Administrator of your tenant and accept. The application requests only ' +
          'the read-only application permissions listed below.',
      ],
      values: [
        ...(input.platformClientId
          ? [{ label: 'Application (client) ID', value: input.platformClientId }]
          : []),
        { label: 'Microsoft Graph application permissions', value: profile.permissions.join(', ') },
      ],
    });
  }
  if (method === null || method === 'customer_app_secret') {
    grantSteps.push({
      id: 'grant-app-registration',
      title: 'Or: register your own application',
      paragraphs: [
        'In the Microsoft Entra admin center, open App registrations → New registration, single ' +
          'tenant. Under API permissions add exactly the Microsoft Graph application permissions ' +
          'below (no delegated permissions, nothing else) and choose "Grant admin consent".',
        'Under Certificates & secrets create a client secret with an expiry (the console warns 30 ' +
          'days before it expires). Upload the tenant id, the application (client) id, the secret ' +
          'and its expiry in the console. The secret is encrypted and never shown again.',
      ],
      values: [
        { label: 'Microsoft Graph application permissions', value: profile.permissions.join(', ') },
      ],
    });
  }

  const destinationValues = input.domains.map((d) => {
    const hosts = d.destinations?.length
      ? d.destinations.map((s) => s.host)
      : [d.providerMxHost ?? defaultMicrosoftMxHost(d.name)];
    return { label: d.name, value: hosts.join(', ') };
  });

  const routeTokenValues = (): { current: string; pending: string | null } | null => {
    const t = input.routeToken;
    if (!t) return null;
    return t.reveal
      ? { current: t.current, pending: t.pending }
      : {
          current: maskRouteToken(t.current),
          pending: t.pending ? maskRouteToken(t.pending) : null,
        };
  };
  const tokens = routeTokenValues();
  const pattern = tokens
    ? tokens.pending
      ? `^(${tokens.current}|${tokens.pending})$`
      : `^${tokens.current}$`
    : '^<route token>$';
  const words = tokens
    ? [tokens.current, ...(tokens.pending ? [tokens.pending] : [])]
    : ['<route token>'];

  return [
    overviewSection(ctx),
    {
      id: 'grant-access',
      title: 'Grant read-only access',
      paragraphs: [
        'The gateway needs to read your tenant id and your domains. Choose one of the methods ' +
          'below; both grant exactly the same read-only permissions.',
      ],
      steps: grantSteps,
    },
    domainsSection(ctx),
    {
      id: 'inbound',
      title: 'Inbound mail',
      paragraphs: [
        'Inbound mail arrives at the gateway (MX), is inspected and is delivered to Exchange Online ' +
          'through a partner connector that trusts only the gateway.',
      ],
      steps: [
        mxStep(ctx),
        {
          id: 'inbound-destination',
          title: 'Gateway destination',
          paragraphs: [
            'In the console, apply the Microsoft 365 destination for each domain (preview, then ' +
              "confirm). The host is your tenant's MX endpoint as Microsoft reports it.",
          ],
          values: destinationValues,
        },
        {
          id: 'inbound-connector',
          title: 'Create the inbound partner connector',
          paragraphs: [
            'In Exchange Online PowerShell (Connect-ExchangeOnline), create a partner connector that ' +
              'accepts mail only from the gateway, identified by its TLS certificate. If you prefer ' +
              'IP addresses, use the second command instead.',
          ],
          commands: [
            {
              language: 'powershell',
              code:
                `New-InboundConnector -Name ${ps(M365_INBOUND_CONNECTOR_NAME)} -ConnectorType Partner ` +
                `-SenderDomains * -RequireTls $true -TlsSenderCertificateName ${ps(g.relayTlsName)} ` +
                '-RestrictDomainsToCertificate $true',
            },
            {
              language: 'powershell',
              code:
                `New-InboundConnector -Name ${ps(M365_INBOUND_CONNECTOR_NAME)} -ConnectorType Partner ` +
                `-SenderDomains * -RequireTls $true -SenderIPAddresses ${psList(g.egressNetworks)} ` +
                '-RestrictDomainsToIPAddresses $true',
            },
          ],
          attestation: attestation(ctx, 'm365.inbound_connector_created'),
        },
        {
          id: 'inbound-enhanced-filtering',
          title: 'Enable Enhanced Filtering for Connectors',
          paragraphs: [
            'Enhanced Filtering lets Exchange Online evaluate SPF, DKIM and DMARC against the original ' +
              'sender instead of the gateway.',
          ],
          commands: [
            {
              language: 'powershell',
              code: `Set-InboundConnector -Identity ${ps(M365_INBOUND_CONNECTOR_NAME)} -EFSkipLastIP $true`,
            },
          ],
          attestation: attestation(ctx, 'm365.enhanced_filtering_enabled'),
        },
        {
          id: 'inbound-lockdown',
          title: 'Lock down direct delivery',
          paragraphs: [
            "Senders can still reach your tenant's MX endpoint directly, bypassing inspection. Reject " +
              'or quarantine mail that does not arrive through the inbound connector, for example with a ' +
              'transport rule that applies to messages from outside the organization unless the message ' +
              'was received through the connector above. Exclude the providers that must reach you ' +
              'directly (if any) explicitly.',
          ],
          attestation: attestation(ctx, 'm365.direct_delivery_locked_down'),
        },
      ],
    },
    {
      id: 'outbound',
      title: 'Outbound mail',
      paragraphs: [
        'Exchange Online sends outbound mail through an outbound connector to the gateway relay. The ' +
          'gateway accepts it only when the message proves your tenant: the tenant id Exchange Online ' +
          'stamps on it and a DKIM signature of your own domain.',
        ...outboundModeNote(ctx),
      ],
      steps: [
        {
          id: 'outbound-dkim',
          title: 'Enable DKIM signing for each linked domain',
          paragraphs: [
            'Publish the two selector CNAME records Microsoft shows, then enable signing. Mail without ' +
              'an aligned DKIM signature is refused by the gateway relay.',
          ],
          commands: [
            {
              language: 'powershell',
              code: domainsOrPlaceholder
                .map(
                  (d) =>
                    `New-DkimSigningConfig -DomainName ${ps(d)} -Enabled $true\n` +
                    `# If a configuration already exists:\nSet-DkimSigningConfig -Identity ${ps(d)} -Enabled $true`,
                )
                .join('\n'),
            },
          ],
        },
        spfStep(ctx, 'spf.protection.outlook.com'),
        {
          id: 'outbound-connector',
          title: 'Create the outbound connector to the gateway',
          paragraphs: [
            'The connector sends mail for all recipient domains to the gateway relay hosts over TLS ' +
              'with certificate validation. Non-delivery reports (empty sender) are not accepted by ' +
              'the gateway relay and stay on the direct path.',
          ],
          commands: [
            {
              language: 'powershell',
              code:
                `New-OutboundConnector -Name ${ps(M365_OUTBOUND_CONNECTOR_NAME)} -ConnectorType Partner ` +
                `-RecipientDomains * -SmartHosts ${psList(g.relayHosts)} -UseMXRecord $false ` +
                `-TlsSettings DomainValidation -TlsDomain ${ps(g.relayTlsName)} -IsTransportRuleScoped $false`,
            },
          ],
          attestation: attestation(ctx, 'm365.outbound_connector_created'),
        },
        {
          id: 'outbound-validate',
          title: 'Validate the outbound connector',
          paragraphs: probeStepParagraph(
            ctx,
            'In the Exchange admin center open Mail flow → Connectors → the outbound connector → ' +
              'Validate this connector, and enter the probe address.',
          ),
        },
      ],
    },
    {
      id: 'internal-routing',
      title: 'Internal routing',
      paragraphs: [
        ...(input.connection.internalRouting
          ? []
          : [
              'Internal routing is off for this connection. These steps apply only after you enable it when activating.',
            ]),
        'Internal mail is routed to the gateway by a transport rule through a connector that only ' +
          'that rule uses. The gateway marks the copies it delivers back with a route token header, ' +
          'which the rule exempts, so mail does not loop; a second rule removes the header before ' +
          'delivery to mailboxes, so users never see the token.',
        ...(input.routeToken && !input.routeToken.reveal
          ? [
              'The route token is masked. A user with permission to manage integrations sees the full value.',
            ]
          : []),
        ...(input.routeToken?.pending
          ? [
              'A new route token is pending: update both rules (they accept the current and the new token) and record the update in the console.',
            ]
          : []),
      ],
      steps: [
        {
          id: 'internal-connector',
          title: 'Create the rule-scoped connector',
          paragraphs: [],
          commands: [
            {
              language: 'powershell',
              code:
                `New-OutboundConnector -Name ${ps(M365_INTERNAL_CONNECTOR_NAME)} -ConnectorType Partner ` +
                `-RecipientDomains * -SmartHosts ${psList(g.relayHosts)} -UseMXRecord $false ` +
                `-TlsSettings DomainValidation -TlsDomain ${ps(g.relayTlsName)} -IsTransportRuleScoped $true`,
            },
          ],
        },
        {
          id: 'internal-rules',
          title: 'Create the two transport rules',
          paragraphs: [
            'Rule A (highest priority) routes internal mail to the gateway unless it carries the route ' +
              'token; rule B (lowest priority) removes the token header.',
          ],
          values: tokens
            ? [
                { label: 'Route token', value: tokens.current },
                ...(tokens.pending ? [{ label: 'New route token', value: tokens.pending }] : []),
              ]
            : [],
          commands: [
            {
              language: 'powershell',
              code:
                `New-TransportRule -Name ${ps(M365_ROUTE_RULE_NAME)} -Priority 0 -FromScope InOrganization ` +
                `-SentToScope InOrganization -RouteMessageOutboundConnector ${ps(M365_INTERNAL_CONNECTOR_NAME)} ` +
                `-ExceptIfHeaderMatchesMessageHeader ${ps(ROUTE_TOKEN_HEADER_NAME)} ` +
                `-ExceptIfHeaderMatchesPatterns ${ps(pattern)}\n` +
                `New-TransportRule -Name ${ps(M365_REMOVE_TOKEN_RULE_NAME)} ` +
                `-HeaderContainsMessageHeader ${ps(ROUTE_TOKEN_HEADER_NAME)} ` +
                `-HeaderContainsWords ${psList(words)} -RemoveHeader ${ps(ROUTE_TOKEN_HEADER_NAME)}\n` +
                '# Rule B must be the last rule:\n' +
                `Set-TransportRule -Identity ${ps(M365_REMOVE_TOKEN_RULE_NAME)} -Priority ((Get-TransportRule).Count - 1)`,
            },
          ],
          attestation: attestation(
            ctx,
            input.routeToken?.pending
              ? 'm365.internal_routing_rules_updated'
              : 'm365.internal_routing_rules_created',
          ),
        },
      ],
    },
    validateSection(),
    failoverSection(
      ctx,
      'While the gateway is unreachable, Exchange Online queues outbound mail and retries for about 24 to 48 hours.',
      [
        `Emergency bypass: Set-OutboundConnector -Identity ${ps(M365_OUTBOUND_CONNECTOR_NAME)} -Enabled $false ` +
          `and Disable-TransportRule -Identity ${ps(M365_ROUTE_RULE_NAME)}. Re-enable both when the gateway is back.`,
      ],
    ),
    {
      id: 'disconnect',
      title: 'Disconnect and clean up',
      paragraphs: [
        'Disconnecting in the console stops the gateway relay for this tenant and removes its access; ' +
          'the gateway keeps delivering inbound mail to Microsoft 365 until you change your MX records.',
        'Before you disconnect: point the MX records back to Microsoft 365, then remove the objects ' +
          'below. Remove the gateway application (Enterprise applications) or your own app registration.',
      ],
      steps: [
        {
          id: 'disconnect-commands',
          title: 'Remove the Exchange Online objects',
          paragraphs: [],
          commands: [
            {
              language: 'dns',
              code: domainsOrPlaceholder
                .map((d) => {
                  const own = input.domains.find((x) => x.name.toLowerCase() === d);
                  return `${d}. 3600 IN MX 0 ${own?.providerMxHost ?? defaultMicrosoftMxHost(d)}.`;
                })
                .join('\n'),
            },
            {
              language: 'powershell',
              code: [
                `Remove-TransportRule -Identity ${ps(M365_ROUTE_RULE_NAME)}`,
                `Remove-TransportRule -Identity ${ps(M365_REMOVE_TOKEN_RULE_NAME)}`,
                `Remove-OutboundConnector -Identity ${ps(M365_INTERNAL_CONNECTOR_NAME)}`,
                `Remove-OutboundConnector -Identity ${ps(M365_OUTBOUND_CONNECTOR_NAME)}`,
                `Remove-InboundConnector -Identity ${ps(M365_INBOUND_CONNECTOR_NAME)}`,
              ].join('\n'),
            },
          ],
        },
      ],
    },
  ];
}

// ---------------------------------------------------------------------------------------------
// Google Workspace
// ---------------------------------------------------------------------------------------------

function googleSections(ctx: Ctx): SectionDraft[] {
  const { input } = ctx;
  const profile = mailFlowProfileFor('google_workspace');
  const g = input.gateway;
  const domainsOrPlaceholder = ctx.domainNames.length > 0 ? ctx.domainNames : ['<your domain>'];
  const method = input.grant?.authMethod ?? null;

  const delegationSteps: SetupGuideStep[] = [];
  if (method === null || method === 'platform_service_account') {
    delegationSteps.push({
      id: 'grant-delegation',
      title: 'Authorize the gateway service account (recommended)',
      paragraphs: [
        'In the Google Admin console open Security → Access and data control → API controls → ' +
          'Manage domain-wide delegation → Add new. Enter the client ID and the scopes below ' +
          '(comma-separated) and authorize.',
      ],
      values: [
        ...(input.platformClientId ? [{ label: 'Client ID', value: input.platformClientId }] : []),
        { label: 'OAuth scopes', value: profile.permissions.join(',') },
      ],
    });
  }
  if (method === null || method === 'customer_service_account') {
    delegationSteps.push({
      id: 'grant-own-service-account',
      title: 'Or: use your own service account',
      paragraphs: [
        'In a Google Cloud project of your organization enable the Admin SDK API, create a service ' +
          "account and a JSON key. Authorize the service account's client ID for the scopes below " +
          'under domain-wide delegation, then upload the key in the console. The key is encrypted ' +
          'and never shown again.',
      ],
      values: [{ label: 'OAuth scopes', value: profile.permissions.join(',') }],
    });
  }
  delegationSteps.push({
    id: 'grant-delegated-admin',
    title: 'Name a delegated administrator',
    paragraphs: [
      'The service account reads the directory on behalf of an administrator of your domain. Use a ' +
        'dedicated administrator with a custom role that has only read access to domain settings and ' +
        'organization information, enter its address in the console and choose "I have authorized".',
    ],
    ...(input.grant?.subjectEmail
      ? { values: [{ label: 'Delegated administrator', value: input.grant.subjectEmail }] }
      : {}),
  });

  return [
    overviewSection(ctx),
    {
      id: 'grant-access',
      title: 'Grant read-only access (domain-wide delegation)',
      paragraphs: [
        'The gateway needs to read your customer id and your domains. Google Workspace grants this ' +
          'through domain-wide delegation of read-only Admin SDK scopes.',
      ],
      steps: delegationSteps,
    },
    domainsSection(ctx),
    {
      id: 'inbound',
      title: 'Inbound mail',
      paragraphs: [
        'Inbound mail arrives at the gateway (MX), is inspected and is delivered to Gmail. Gmail is ' +
          'told that the gateway is your inbound gateway, so it evaluates the original sender.',
      ],
      steps: [
        mxStep(ctx),
        {
          id: 'inbound-destination',
          title: 'Gateway destination',
          paragraphs: [
            'In the console, apply the Google Workspace destination for each domain (preview, then ' +
              'confirm). The gateway delivers to the Google MX hosts in priority order.',
          ],
          values: input.domains.map((d) => ({
            label: d.name,
            value: (d.destinations?.length ? d.destinations : GOOGLE_MX_HOSTS)
              .map((s) => `${s.host} (${s.priority})`)
              .join(', '),
          })),
        },
        {
          id: 'inbound-gateway',
          title: 'Configure the Gmail inbound gateway',
          paragraphs: [
            'In the Google Admin console open Apps → Google Workspace → Gmail → Spam, phishing and ' +
              'malware → Inbound gateway. Add the gateway addresses below and turn on "Require TLS for ' +
              'connections from the email gateways listed above".',
          ],
          values: [{ label: 'Gateway IP addresses', value: g.egressNetworks.join(', ') }],
          attestation: attestation(ctx, 'google.inbound_gateway_configured'),
        },
        {
          id: 'inbound-lockdown',
          title: 'Reject mail that bypasses the gateway',
          paragraphs: [
            'In the same Inbound gateway setting turn on "Reject all mail not from gateway IPs", so ' +
              'senders cannot deliver to Google directly around inspection.',
          ],
          attestation: attestation(ctx, 'google.reject_non_gateway_enabled'),
        },
      ],
    },
    {
      id: 'outbound',
      title: 'Outbound mail',
      paragraphs: [
        'Gmail sends outbound mail to the gateway relay through a host and a routing rule. The gateway ' +
          'accepts it only with a fresh DKIM signature of your own domain.',
        ...outboundModeNote(ctx),
      ],
      steps: [
        {
          id: 'outbound-dkim',
          title: 'Turn on DKIM for each linked domain',
          paragraphs: [
            'In Apps → Google Workspace → Gmail → Authenticate email, generate a 2048-bit key for each ' +
              'domain below, publish the TXT record and choose "Start authentication".',
          ],
          values: domainsOrPlaceholder.map((d) => ({ label: 'Domain', value: d })),
        },
        spfStep(ctx, '_spf.google.com'),
        {
          id: 'outbound-hosts',
          title: 'Add the gateway as a host',
          paragraphs: [
            'In Apps → Google Workspace → Gmail → Hosts → Add route, name the route "' +
              GOOGLE_HOST_NAME +
              '", choose multiple hosts (or a single host if there is one), port 25, and turn on ' +
              '"Require mail to be transmitted via a secure (TLS) connection" and "Require CA signed ' +
              'certificate" with host name validation. Turn off "Perform MX lookup on host".',
          ],
          values: g.relayHosts.map((h) => ({ label: 'Host', value: `${h}:25` })),
        },
        {
          id: 'outbound-connector',
          title: 'Route outbound mail through the gateway',
          paragraphs: [
            'In Apps → Google Workspace → Gmail → Routing → Configure, add a rule: messages to affect ' +
              '"Outbound" and "Internal - sending"; "Change route" to "' +
              GOOGLE_HOST_NAME +
              '". (Alternatively set the Outbound gateway under Spam, phishing and malware; a routing ' +
              'rule is preferred because it can also cover internal mail.)',
          ],
          attestation: attestation(ctx, 'google.outbound_route_configured'),
        },
        {
          id: 'outbound-smtp-relay',
          title: 'SMTP relay service for devices and applications',
          paragraphs: [
            'If devices or applications send through smtp-relay.gmail.com, open Routing → SMTP relay ' +
              'service and allow only addresses in your domains, require SMTP authentication and ' +
              'require TLS. Relayed mail then follows the same routing rule to the gateway.',
          ],
          attestation: attestation(ctx, 'google.smtp_relay_configured'),
        },
        {
          id: 'outbound-validate',
          title: 'Send a probe message',
          paragraphs: probeStepParagraph(
            ctx,
            'Send any message from a user of a linked domain to the probe address.',
          ),
        },
      ],
    },
    {
      id: 'internal-routing',
      title: 'Internal routing',
      paragraphs: [
        ...(input.connection.internalRouting
          ? []
          : [
              'Internal routing is off for this connection. These steps apply only after you enable it when activating.',
            ]),
        'The routing rule above includes "Internal - sending", so internal mail goes through the ' +
          'gateway. Mail returning from the gateway arrives through the inbound gateway as received ' +
          "mail and is not routed again; the gateway's hop limits stop any loop.",
      ],
      steps: [
        {
          id: 'internal-rules',
          title: 'Confirm internal sending is routed',
          paragraphs: ['Check that the routing rule affects "Internal - sending" messages.'],
          attestation: attestation(ctx, 'google.internal_routing_configured'),
        },
      ],
    },
    validateSection(),
    failoverSection(
      ctx,
      'While the gateway is unreachable, Gmail queues outbound mail and retries for up to 5 days.',
      [
        'Emergency bypass: disable the routing rule (Apps → Google Workspace → Gmail → Routing). ' +
          'Re-enable it when the gateway is back.',
      ],
    ),
    {
      id: 'disconnect',
      title: 'Disconnect and clean up',
      paragraphs: [
        'Disconnecting in the console stops the gateway relay for this customer and removes its ' +
          'access; the gateway keeps delivering inbound mail to Gmail until you change your MX records.',
        'Before you disconnect: point the MX records back to Google, turn off "Reject all mail not ' +
          'from gateway IPs" and remove the inbound gateway, the routing rule and the host, then ' +
          'remove the domain-wide delegation entry.',
      ],
      steps: [
        {
          id: 'disconnect-commands',
          title: 'Restore the Google MX records',
          paragraphs: [],
          commands: [
            {
              language: 'dns',
              code: domainsOrPlaceholder
                .flatMap((d) =>
                  GOOGLE_MX_HOSTS.map((m) => `${d}. 3600 IN MX ${m.priority} ${m.host}.`),
                )
                .join('\n'),
            },
          ],
        },
      ],
    },
  ];
}

// ---------------------------------------------------------------------------------------------
// Example input (docs templates, D14)
// ---------------------------------------------------------------------------------------------

/**
 * The placeholder input of the documentation templates (`docs/integrations/*.md`, D14):
 * `example.com`, `gateway.example.net`, `11111111-2222-3333-4444-555555555555`, documentation
 * address ranges. No secret-shaped value.
 */
export function exampleSetupGuideInput(provider: IntegrationProvider): SetupGuideInput {
  return {
    provider,
    connection: {
      publicId: '11111111-2222-3333-4444-555555555555',
      displayName:
        provider === 'microsoft_365' ? 'Example Microsoft 365' : 'Example Google Workspace',
      tenantId: provider === 'microsoft_365' ? '11111111-2222-3333-4444-555555555555' : 'C0123abcd',
      tenantName: 'Example Organization',
      outboundMode: 'probe_only',
      internalRouting: true,
    },
    grant: {
      authMethod: provider === 'microsoft_365' ? 'platform_app' : 'platform_service_account',
      status: 'active',
      subjectEmail: provider === 'google_workspace' ? 'gateway-reader@example.com' : null,
    },
    platformClientId:
      provider === 'microsoft_365'
        ? '11111111-2222-3333-4444-555555555555'
        : '111122223333444455556',
    domains: [
      {
        name: 'example.com',
        gatewayStatus: 'active',
        providerVerification: 'verified',
        providerMxHost:
          provider === 'microsoft_365' ? 'example-com.mail.protection.outlook.com' : null,
      },
    ],
    gateway: {
      mxHosts: ['mx1.gateway.example.net', 'mx2.gateway.example.net'],
      egressNetworks: ['192.0.2.0/28', '2001:db8::/64'],
      relayHosts: ['relay1.gateway.example.net', 'relay2.gateway.example.net'],
      relayTlsName: 'relay.gateway.example.net',
      spfInclude: 'spf.gateway.example.net',
    },
    probeAddress: null,
    routeToken:
      provider === 'microsoft_365'
        ? { current: 'EXAMPLEROUTETOKEN0000000000000000', pending: null, reveal: false }
        : null,
    attestations: [],
    generatedAt: new Date('2026-11-18T00:00:00.000Z'),
  };
}
