import { intakeAttestationsFor, type JournalIntakeKind } from './attestations';
import { SetupGuideInputError, type SetupGuideSection, type SetupGuideStep } from './setup-guide';

/**
 * Customer-specific journal intake guides (`journal-intake-guide/1`, step 8.6 D10, ADR-0087),
 * generated purely from one intake source's own values with the 8.2 guide framework (sections,
 * steps, commands, attestations and the shared Markdown renderer). Every customer-side change is
 * an instruction the customer applies; the gateway never changes the customer's Microsoft 365,
 * Google Workspace, Exchange or mail server configuration.
 *
 * The intake address and the Google header token are credentials: they appear in the guide only
 * when `reveal` is true (callers holding `journal:manage`); otherwise every occurrence, commands
 * included, is masked (`journal-••••<last 4>@…`, `••••<last 4>`).
 */
export const JOURNAL_INTAKE_GUIDE_SCHEMA = 'journal-intake-guide/1';

/** Names of the customer-side objects the guide creates (stable). */
export const JOURNAL_RULE_NAME = 'Email security gateway journal';
export const JOURNAL_CONTACT_NAME = 'Email security gateway journal';
export const JOURNAL_SEND_CONNECTOR_NAME = 'Email security gateway journal';
export const GOOGLE_JOURNAL_ROUTE_NAME = 'Email security gateway journal';
export const JOURNAL_TOKEN_HEADER = 'X-EG-Journal-Token';

export const JOURNAL_INTAKE_KIND_LABELS: Readonly<Record<JournalIntakeKind, string>> =
  Object.freeze({
    microsoft_365_journal: 'Microsoft 365 journaling',
    google_workspace_copy: 'Google Workspace copies',
    exchange_onprem_journal: 'On-premises Exchange journaling',
    smtp_bcc: 'Generic SMTP BCC copies',
  });

export interface JournalIntakeGuideInput {
  kind: JournalIntakeKind;
  source: { publicId: string; displayName: string };
  /** The intake address `journal-<token>@<JOURNAL_INTAKE_DOMAIN>` (derived by the api). */
  address: string;
  /** Google Workspace: the `X-EG-Journal-Token` value (derived by the api); null otherwise. */
  headerToken: string | null;
  /** Show the address and token (caller holds `journal:manage`); masked otherwise. */
  reveal: boolean;
  /** Provider kinds: the bound 8.2 connection. */
  connection: { displayName: string; tenantId: string | null } | null;
  /** The organization's verified domains (provider kinds: the domains linked to the connection). */
  domains: readonly string[];
  /** On-premises kinds: the source's registered networks (`intake-networks/1`). */
  networks: readonly string[];
  requireTls: boolean;
  gateway: {
    /** The inbound hosts the intake domain's MX points to (`GATEWAY_MX_HOSTS`). */
    mxHosts: readonly string[];
  };
  attestations: readonly { code: string; at: string | Date }[];
  generatedAt: Date;
}

export interface JournalIntakeGuideAttestation {
  code: string;
  statement: string;
  attested: boolean;
  attestedAt: string | null;
}

export interface JournalIntakeGuide {
  schema: typeof JOURNAL_INTAKE_GUIDE_SCHEMA;
  kind: JournalIntakeKind;
  source: { id: string; displayName: string; kind: JournalIntakeKind };
  /** Revealed only when the input said so. */
  address: string;
  /** Google Workspace only. */
  headerToken?: string;
  revealed: boolean;
  /** Always shown: the gateway never applies a step; attestations are statements. */
  notice: string;
  sections: SetupGuideSection[];
  attestations: JournalIntakeGuideAttestation[];
  generatedAt: string;
}

const MASK = '••••';
const TOKEN = /^[a-z2-7]{26}$/;
const ADDRESS = /^journal-([a-z2-7]{26})@([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)$/;
const SAFE_HOST =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const SAFE_CIDR = /^[0-9a-f:.]{2,45}(?:\/\d{1,3})?$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function assertSafe(values: readonly string[], pattern: RegExp, what: string): void {
  for (const value of values) {
    if (!pattern.test(value)) throw new SetupGuideInputError(`${what} contains an unusable value`);
  }
}

/** PowerShell single-quoted string literal. */
const ps = (value: string): string => `'${value.replace(/'/g, "''")}'`;
const psList = (values: readonly string[]): string => values.map(ps).join(',');

/** `journal-••••<last 4>@domain`. */
export const maskJournalIntakeAddress = (address: string): string => {
  const m = ADDRESS.exec(address);
  return m ? `journal-${MASK}${m[1]!.slice(-4)}@${m[2]}` : MASK;
};

/** `••••<last 4>`. */
export const maskJournalIntakeToken = (token: string): string =>
  TOKEN.test(token) ? `${MASK}${token.slice(-4)}` : MASK;

interface Ctx {
  input: JournalIntakeGuideInput;
  /** The address as shown (revealed or masked). */
  address: string;
  /** The header token as shown, or null. */
  token: string | null;
  intakeDomain: string;
  /** A mailbox placeholder in the customer's first domain. */
  ndrMailbox: string;
  attested: Map<string, string>;
}

type SectionDraft = Omit<SetupGuideSection, 'number'>;

function attestation(ctx: Ctx, code: string): SetupGuideStep['attestation'] {
  const def = intakeAttestationsFor(ctx.input.kind).find((a) => a.code === code);
  if (!def) throw new SetupGuideInputError(`unknown attestation ${code}`);
  const at = ctx.attested.get(code) ?? null;
  return { code, statement: def.statement, attested: at !== null, attestedAt: at };
}

export function generateJournalIntakeGuide(input: JournalIntakeGuideInput): JournalIntakeGuide {
  const m = ADDRESS.exec(input.address);
  if (!m) throw new SetupGuideInputError('intake address contains an unusable value');
  if (!UUID.test(input.source.publicId)) {
    throw new SetupGuideInputError('source id contains an unusable value');
  }
  const google = input.kind === 'google_workspace_copy';
  if (google) {
    if (input.headerToken === null || !TOKEN.test(input.headerToken)) {
      throw new SetupGuideInputError('header token contains an unusable value');
    }
  }
  const domains = input.domains.map((d) => d.toLowerCase());
  assertSafe(domains, SAFE_HOST, 'domains');
  assertSafe(input.gateway.mxHosts, SAFE_HOST, 'GATEWAY_MX_HOSTS');
  assertSafe(input.networks, SAFE_CIDR, 'networks');
  const address = input.reveal ? input.address : maskJournalIntakeAddress(input.address);
  const token =
    google && input.headerToken !== null
      ? input.reveal
        ? input.headerToken
        : maskJournalIntakeToken(input.headerToken)
      : null;
  const ctx: Ctx = {
    input,
    address,
    token,
    intakeDomain: m[2]!,
    ndrMailbox: `journal-ndr@${domains[0] ?? 'example.com'}`,
    attested: new Map(
      input.attestations.map(
        (a) => [a.code, a.at instanceof Date ? a.at.toISOString() : a.at] as const,
      ),
    ),
  };
  const kindSections: Record<JournalIntakeKind, () => SectionDraft[]> = {
    microsoft_365_journal: () => microsoftSections(ctx),
    google_workspace_copy: () => googleSections(ctx),
    exchange_onprem_journal: () => onPremisesSections(ctx),
    smtp_bcc: () => smtpSections(ctx),
  };
  const sections = [
    overviewSection(ctx),
    addressSection(ctx),
    ...kindSections[input.kind](),
    verifySection(ctx),
  ];
  return {
    schema: JOURNAL_INTAKE_GUIDE_SCHEMA,
    kind: input.kind,
    source: { id: input.source.publicId, displayName: input.source.displayName, kind: input.kind },
    address,
    ...(token !== null ? { headerToken: token } : {}),
    revealed: input.reveal,
    notice:
      'This guide contains the values of your own journal intake source. The gateway never ' +
      'changes your mail system: you apply every step yourself. Confirmations you record in the ' +
      'console are your statements (attestations), not proofs the gateway has checked.' +
      (input.reveal
        ? ' The intake address and token in this guide are credentials: share the guide only with the administrators who apply it.'
        : ' The intake address and token are masked: a user with journaling management rights can reveal them in the console.'),
    sections: sections.map((s, i) => ({ ...s, number: i + 1 })),
    attestations: intakeAttestationsFor(input.kind).map((a) => attestation(ctx, a.code)!),
    generatedAt: input.generatedAt.toISOString(),
  };
}

function overviewSection(ctx: Ctx): SectionDraft {
  const label = JOURNAL_INTAKE_KIND_LABELS[ctx.input.kind];
  return {
    id: 'overview',
    title: 'Overview and what the gateway will never do',
    paragraphs: [
      `This guide sets up the journal intake source "${ctx.input.source.displayName}" ` +
        `(${label}). Your mail system sends a copy of every message to the intake address below; ` +
        'the gateway archives the copy (encrypted, retained and searchable under your archive ' +
        'settings). Your MX records and mail flow do not change.',
      'The gateway only receives copies. It never delivers, forwards, quarantines or bounces a ' +
        'journaled message, and it never changes your configuration. Copies that fail the sender ' +
        'checks are discarded and shown in the source health; they are never returned to the sender.',
    ],
    steps: [],
  };
}

function addressSection(ctx: Ctx): SectionDraft {
  const input = ctx.input;
  const values = [
    { label: 'Intake address', value: ctx.address },
    ...(ctx.token !== null
      ? [{ label: `${JOURNAL_TOKEN_HEADER} header value`, value: ctx.token }]
      : []),
    { label: 'Source', value: input.source.displayName },
    ...(input.connection
      ? [
          {
            label: 'Provider connection',
            value: input.connection.tenantId
              ? `${input.connection.displayName} (${input.connection.tenantId})`
              : input.connection.displayName,
          },
        ]
      : []),
    { label: 'TLS required', value: input.requireTls ? 'yes' : 'no' },
  ];
  return {
    id: 'intake-address',
    title: 'Your intake address',
    paragraphs: [
      'The intake address identifies this source. Treat it like a password: anyone who knows it ' +
        'and sends from your authorized systems can add copies to your archive. You can rotate it ' +
        'in the console at any time; the previous address keeps working for a short overlap.',
    ],
    steps: [
      {
        id: 'intake-address-values',
        title: 'Values for this source',
        paragraphs: input.reveal
          ? []
          : [
              'The address is masked in this guide. A user with journaling management rights can ' +
                'reveal it in the console before applying the steps below.',
            ],
        values,
      },
    ],
  };
}

function microsoftSections(ctx: Ctx): SectionDraft[] {
  return [
    {
      id: 'm365-journaling',
      title: 'Microsoft 365 journal rule',
      paragraphs: [
        'Journal rules are managed in the Microsoft Purview portal (Data lifecycle management, ' +
          'Exchange (legacy), Journal rules) or with Exchange Online PowerShell (Connect-ExchangeOnline).',
      ],
      steps: [
        {
          id: 'm365-ndr-mailbox',
          title: 'Set the mailbox for undeliverable journal reports',
          paragraphs: [
            'Exchange Online requires an alternate mailbox that receives journal reports which cannot ' +
              'be delivered (for example while the intake address is paused). Use a dedicated mailbox ' +
              'in your tenant that is itself not journaled, and review it regularly.',
          ],
          commands: [
            {
              language: 'powershell',
              code: `Set-TransportConfig -JournalingReportNdrTo ${ps(ctx.ndrMailbox)}`,
            },
          ],
          attestation: attestation(ctx, 'journal.m365.ndr_mailbox_set'),
        },
        {
          id: 'm365-journal-rule',
          title: 'Create the journal rule',
          paragraphs: [
            `In Purview, create a journal rule named "${JOURNAL_RULE_NAME}" that sends journal ` +
              'reports to the intake address, for messages sent or received from everyone, and the ' +
              'message types you want to archive (all messages, internal only or external only).',
          ],
          values: [{ label: 'Send journal reports to', value: ctx.address }],
          commands: [
            {
              language: 'powershell',
              code:
                `New-JournalRule -Name ${ps(JOURNAL_RULE_NAME)} -JournalEmailAddress ${ps(ctx.address)} ` +
                '-Scope Global -Enabled $true',
            },
          ],
          warning:
            'Journal rules journal only the mail of mailboxes in your tenant. Exchange Online does not ' +
            'journal to an Exchange Online mailbox; the intake address is external to your tenant, ' +
            'which is what Exchange Online requires. A new rule can take up to an hour to apply.',
          attestation: attestation(ctx, 'journal.m365.rule_created'),
        },
        {
          id: 'm365-dkim',
          title: 'Optional: sign with DKIM',
          paragraphs: [
            'The gateway accepts journal reports only from Microsoft 365 servers and checks that each ' +
              'report carries your bound tenant id. DKIM signatures of your domains are recorded as ' +
              'additional evidence when present; enabling DKIM signing in Microsoft Defender is ' +
              'recommended but not required.',
          ],
          values: ctx.input.domains.map((d) => ({
            label: d.toLowerCase(),
            value: 'DKIM signing recommended',
          })),
        },
      ],
    },
  ];
}

function googleSections(ctx: Ctx): SectionDraft[] {
  return [
    {
      id: 'google-routing',
      title: 'Google Workspace routing rule',
      paragraphs: [
        'In the Google Admin console, open Apps, Google Workspace, Gmail, Routing, and add a ' +
          'routing setting at the top-level organizational unit.',
      ],
      steps: [
        {
          id: 'google-route',
          title: 'Add the "Also deliver to" route',
          paragraphs: [
            `Name the setting "${GOOGLE_JOURNAL_ROUTE_NAME}". Under "Email messages to affect" select ` +
              'Inbound, Outbound, Internal - sending and Internal - receiving. Under "Also deliver to", ' +
              'add the intake address as an additional recipient.',
          ],
          values: [{ label: 'Also deliver to', value: ctx.address }],
          attestation: attestation(ctx, 'journal.google.route_created'),
        },
        {
          id: 'google-headers',
          title: 'Add the journal headers',
          paragraphs: [
            'In the same setting, under "Headers", select "Add X-Gm-Original-To header" and "Add ' +
              'custom headers", and add the custom header below. Copies without a matching header ' +
              'are discarded.',
          ],
          values: [
            { label: 'Custom header name', value: JOURNAL_TOKEN_HEADER },
            { label: 'Custom header value', value: ctx.token ?? MASK },
          ],
          warning:
            'Google copies carry the recipient Gmail routed the message to (X-Gm-Original-To), not ' +
            'the full envelope of the original message: a blind-copied recipient is known only from ' +
            'the copy routed for that recipient.',
          attestation: attestation(ctx, 'journal.google.headers_added'),
        },
      ],
    },
  ];
}

function networksStep(ctx: Ctx): SetupGuideStep {
  return {
    id: 'source-networks',
    title: 'Registered sending networks',
    paragraphs: [
      'The gateway accepts copies for this source only from these networks' +
        (ctx.input.requireTls ? ', and only over TLS' : '') +
        '. Mail from any other address is refused in the SMTP session (550 5.7.1). Update the ' +
        'networks in the console before your servers change addresses.',
    ],
    values:
      ctx.input.networks.length > 0
        ? ctx.input.networks.map((n, i) => ({ label: `Network ${i + 1}`, value: n }))
        : [{ label: 'Networks', value: 'none registered yet' }],
  };
}

function onPremisesSections(ctx: Ctx): SectionDraft[] {
  const hosts = ctx.input.gateway.mxHosts;
  return [
    {
      id: 'onprem-journaling',
      title: 'Exchange Server journaling',
      paragraphs: [
        'Run these commands in the Exchange Management Shell of your organization. Premium ' +
          'journaling (journal rules) needs Exchange Enterprise client access licenses; standard ' +
          'journaling configures the journal recipient per mailbox database instead.',
      ],
      steps: [
        {
          id: 'onprem-journal-recipient',
          title: 'Create the journal recipient',
          paragraphs: [
            'Create a mail contact for the intake address, so journal rules and mailbox databases can ' +
              'name it as their journal recipient.',
          ],
          commands: [
            {
              language: 'powershell',
              code: `New-MailContact -Name ${ps(JOURNAL_CONTACT_NAME)} -ExternalEmailAddress ${ps(ctx.address)}`,
            },
          ],
          attestation: attestation(ctx, 'journal.onprem.journal_recipient_created'),
        },
        {
          id: 'onprem-journal-rule',
          title: 'Create the journal rule (or database journaling)',
          paragraphs: [
            'Create a journal rule for all messages, set the mailbox for undeliverable journal ' +
              'reports, or, for standard journaling, set the journal recipient on each mailbox database.',
          ],
          commands: [
            {
              language: 'powershell',
              code:
                `New-JournalRule -Name ${ps(JOURNAL_RULE_NAME)} -JournalEmailAddress ${ps(JOURNAL_CONTACT_NAME)} ` +
                '-Scope Global -Enabled $true',
            },
            {
              language: 'powershell',
              code: `Set-TransportConfig -JournalingReportNdrTo ${ps(ctx.ndrMailbox)}`,
            },
            {
              language: 'powershell',
              code: `Get-MailboxDatabase | Set-MailboxDatabase -JournalRecipient ${ps(JOURNAL_CONTACT_NAME)}`,
            },
          ],
        },
        {
          id: 'onprem-send-connector',
          title: 'Send journal reports to the gateway over TLS',
          paragraphs: [
            'Create a Send connector for the intake domain that delivers to the gateway hosts and ' +
              'requires TLS with a certificate valid for the intake domain.',
          ],
          commands: [
            {
              language: 'powershell',
              code:
                `New-SendConnector -Name ${ps(JOURNAL_SEND_CONNECTOR_NAME)} -Usage Custom ` +
                `-AddressSpaces ${ps(`SMTP:${ctx.intakeDomain};1`)} -DNSRoutingEnabled $false ` +
                `-SmartHosts ${psList(hosts)} -RequireTLS $true -TlsAuthLevel DomainValidation ` +
                `-TlsDomain ${ps(ctx.intakeDomain)}`,
            },
          ],
          attestation: attestation(ctx, 'journal.onprem.send_connector_tls'),
        },
        networksStep(ctx),
      ],
    },
  ];
}

function smtpSections(ctx: Ctx): SectionDraft[] {
  return [
    {
      id: 'smtp-bcc',
      title: 'BCC copies from your mail server',
      paragraphs: [
        'Configure your mail server to send a blind copy of every message to the intake address. ' +
          'The Postfix settings below are an example; other servers have equivalent options.',
      ],
      steps: [
        {
          id: 'smtp-bcc-config',
          title: 'Send a copy of every message',
          paragraphs: [
            'Use always_bcc for all mail, or sender_bcc_maps / recipient_bcc_maps to copy a subset. ' +
              'Require TLS for the intake domain.',
          ],
          commands: [
            {
              language: 'text',
              code: [
                '# /etc/postfix/main.cf',
                `always_bcc = ${ctx.address}`,
                'smtp_tls_policy_maps = hash:/etc/postfix/tls_policy',
                '',
                '# /etc/postfix/tls_policy (then: postmap /etc/postfix/tls_policy)',
                `${ctx.intakeDomain} encrypt`,
              ].join('\n'),
            },
          ],
          warning:
            'BCC copies carry only the recipients named in the To and Cc headers: blind-copied ' +
            'recipients of the original message are not known to the archive.',
          attestation: attestation(ctx, 'journal.smtp.bcc_configured'),
        },
        networksStep(ctx),
      ],
    },
  ];
}

function verifySection(ctx: Ctx): SectionDraft {
  return {
    id: 'verify',
    title: 'Verify and monitor',
    paragraphs: [],
    steps: [
      {
        id: 'verify-first-message',
        title: 'Send a test message',
        paragraphs: [
          'Send a message that your configuration copies. The source becomes verified with the first ' +
            'accepted copy; the message then appears in archive search with the source "journal intake".',
        ],
      },
      {
        id: 'monitor-health',
        title: 'Watch the source health',
        paragraphs: [
          'The console shows accepted and refused copies per day. When no copy arrives for the ' +
            'configured silence period, or copies are refused or discarded, the source turns silent or ' +
            'failing and your alert recipients are notified.',
        ],
      },
      {
        id: 'rotate-address',
        title: 'Rotate the address',
        paragraphs: [
          'Rotating creates a new address' +
            (ctx.input.kind === 'google_workspace_copy' ? ' and header token' : '') +
            '; the previous values stay valid for a short overlap. Update the steps above with the new ' +
            'values within the overlap.',
        ],
      },
    ],
  };
}

// ---------------------------------------------------------------------------------------------
// Example input (docs templates, tests)
// ---------------------------------------------------------------------------------------------

/**
 * The placeholder input of the documentation templates: `example.com`, `gateway.example.net`,
 * `11111111-2222-3333-4444-555555555555`, documentation address ranges and an obviously synthetic
 * token (`exampleexampleexampleexamp`). No secret-shaped value. `reveal` is false, as for a
 * reader without `journal:manage`.
 */
export function exampleJournalIntakeGuideInput(kind: JournalIntakeKind): JournalIntakeGuideInput {
  const provider = kind === 'microsoft_365_journal' || kind === 'google_workspace_copy';
  return {
    kind,
    source: {
      publicId: '11111111-2222-3333-4444-555555555555',
      displayName: `Example ${JOURNAL_INTAKE_KIND_LABELS[kind]}`,
    },
    address: 'journal-exampleexampleexampleexamp@journal.gateway.example.net',
    headerToken: kind === 'google_workspace_copy' ? 'exampletokenexampletokenex' : null,
    reveal: false,
    connection: provider
      ? {
          displayName:
            kind === 'microsoft_365_journal' ? 'Example Microsoft 365' : 'Example Google Workspace',
          tenantId:
            kind === 'microsoft_365_journal' ? '11111111-2222-3333-4444-555555555555' : null,
        }
      : null,
    domains: ['example.com'],
    networks: provider ? [] : ['198.51.100.0/24', '2001:db8:10::/48'],
    requireTls: true,
    gateway: { mxHosts: ['mx1.gateway.example.net', 'mx2.gateway.example.net'] },
    attestations: [],
    generatedAt: new Date('2026-11-20T00:00:00.000Z'),
  };
}
