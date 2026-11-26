import type { IntegrationProvider, ProviderAuthMethod } from '../types';
import {
  GOOGLE_MAILBOX_REMEDIATION_PROFILE,
  M365_MAILBOX_REMEDIATION_PROFILE,
} from '../profiles/mailbox';
import { apiModeAttestationsFor, type JournalIntakeKind } from './attestations';
import { JOURNAL_INTAKE_KIND_LABELS } from './journal-intake-guide';
import { renderGuideMarkdown } from './markdown';
import { SetupGuideInputError, type SetupGuideSection, type SetupGuideStep } from './setup-guide';

/**
 * Customer-specific API-mode guides (`api-mode-guide/1`, step API-1 D4, D12; ADR-0098..0100),
 * generated purely from one provider connection's own values with the 8.2 guide framework
 * (sections, steps, commands, attestations and the shared Markdown renderer).
 *
 * API mode protects mailboxes without an MX change: a journal copy (8.6 intake) and, optionally,
 * mailbox change feeds give the gateway a copy of each message, scanned in detect mode. The
 * guide covers the mailbox-access consent (`*.mailbox_remediation`), the journal rule, the
 * optional Exchange Online scoping, the change feeds, coverage, revocation and troubleshooting.
 * Every customer-side change is an instruction the customer applies; the gateway never changes
 * the tenant. The journal intake address appears only masked; no secret ever appears.
 */
export const API_MODE_GUIDE_SCHEMA = 'api-mode-guide/1';

/** Display name of the operator's mailbox-access application / service account (stable). */
export const API_MODE_APP_NAME = 'Email security gateway mailbox access';
/** Name of the optional Exchange Online management scope (stable). */
export const API_MODE_EXCHANGE_SCOPE_NAME = 'Email security gateway API mode';

export interface ApiModeGuideInput {
  provider: IntegrationProvider;
  connection: { publicId: string; displayName: string; tenantId: string | null };
  /** The connection's verified domains (linked at the gateway). */
  domains: readonly string[];
  /** The provider journal intake source bound to the connection, if any (address masked). */
  journalSource: {
    publicId: string;
    displayName: string;
    kind: JournalIntakeKind;
    /** `maskJournalIntakeAddress(...)`: never the revealed address. */
    addressMasked: string;
  } | null;
  /**
   * Client id of the operator's platform app / service account (`PROVIDER_M365_MAILBOX_APP_
   * CLIENT_ID`, `PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID`), or null when not configured.
   */
  platformClientId: string | null;
  /** Auth method of the mailbox-access grant, when one exists. */
  authMethod: ProviderAuthMethod | null;
  /** Client id of the grant (customer-owned app or service account), when known. */
  grantClientId: string | null;
  /** Google: the delegated administrator the directory reads impersonate. */
  delegatedAdmin: string | null;
  feeds: { enabled: boolean; mode: 'poll' | 'notify' };
  attestations: readonly { code: string; at: string | Date }[];
  generatedAt: Date;
}

export interface ApiModeGuideAttestation {
  code: string;
  statement: string;
  attested: boolean;
  attestedAt: string | null;
}

export interface ApiModeGuide {
  schema: typeof API_MODE_GUIDE_SCHEMA;
  provider: IntegrationProvider;
  connection: { id: string; displayName: string };
  /** Always shown: the gateway never applies a step; attestations are statements. */
  notice: string;
  sections: SetupGuideSection[];
  attestations: ApiModeGuideAttestation[];
  journalSource?: { id: string; kind: JournalIntakeKind; addressMasked: string };
  platformClientId?: string;
  /** The mailbox-access profile's permissions (Graph application permissions / OAuth scopes). */
  permissions: string[];
  generatedAt: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GOOGLE_CLIENT_ID = /^\d{10,32}$/;
const SAFE_HOST =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const MASKED_ADDRESS = /^(?:journal-••••[a-z2-7]{4}@[a-z0-9.-]{1,253}|••••)$/;
const EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}$/;
const MS_DOCS_PLACEHOLDER = '<application-client-id>';

/** PowerShell single-quoted string literal. */
const ps = (value: string): string => `'${value.replace(/'/g, "''")}'`;

interface Ctx {
  input: ApiModeGuideInput;
  attested: Map<string, string>;
  microsoft: boolean;
  /** The client id the customer works with (grant's own, else the platform app's), or null. */
  clientId: string | null;
}

type SectionDraft = Omit<SetupGuideSection, 'number'>;

function attestation(ctx: Ctx, code: string): SetupGuideStep['attestation'] {
  const def = apiModeAttestationsFor(ctx.input.provider).find((a) => a.code === code);
  if (!def) throw new SetupGuideInputError(`unknown attestation ${code}`);
  const at = ctx.attested.get(code) ?? null;
  return { code, statement: def.statement, attested: at !== null, attestedAt: at };
}

function validate(input: ApiModeGuideInput): void {
  if (!UUID.test(input.connection.publicId)) {
    throw new SetupGuideInputError('connection id contains an unusable value');
  }
  if (
    input.connection.tenantId !== null &&
    !/^[A-Za-z0-9-]{1,64}$/.test(input.connection.tenantId)
  ) {
    throw new SetupGuideInputError('tenant id contains an unusable value');
  }
  for (const domain of input.domains) {
    if (!SAFE_HOST.test(domain))
      throw new SetupGuideInputError('domains contains an unusable value');
  }
  const microsoft = input.provider === 'microsoft_365';
  for (const id of [input.platformClientId, input.grantClientId]) {
    if (id === null) continue;
    if (microsoft ? !UUID.test(id) : !GOOGLE_CLIENT_ID.test(id)) {
      throw new SetupGuideInputError('client id contains an unusable value');
    }
  }
  if (input.delegatedAdmin !== null && !EMAIL.test(input.delegatedAdmin)) {
    throw new SetupGuideInputError('delegated administrator contains an unusable value');
  }
  if (input.journalSource) {
    if (!UUID.test(input.journalSource.publicId)) {
      throw new SetupGuideInputError('journal source id contains an unusable value');
    }
    // Guides are readable with remediation:read: the intake address is only ever masked here.
    if (!MASKED_ADDRESS.test(input.journalSource.addressMasked)) {
      throw new SetupGuideInputError('journal intake address must be masked');
    }
  }
}

export function generateApiModeGuide(input: ApiModeGuideInput): ApiModeGuide {
  validate(input);
  const microsoft = input.provider === 'microsoft_365';
  const ctx: Ctx = {
    input,
    microsoft,
    clientId: input.grantClientId ?? input.platformClientId,
    attested: new Map(
      input.attestations.map(
        (a) => [a.code, a.at instanceof Date ? a.at.toISOString() : a.at] as const,
      ),
    ),
  };
  const profile = microsoft ? M365_MAILBOX_REMEDIATION_PROFILE : GOOGLE_MAILBOX_REMEDIATION_PROFILE;
  const sections: SectionDraft[] = microsoft
    ? [
        overviewSection(ctx),
        journalSection(ctx),
        microsoftAccessSection(ctx),
        microsoftScopingSection(ctx),
        feedsSection(ctx),
        verifySection(ctx),
        microsoftRevokeSection(ctx),
        troubleshootingSection(ctx),
      ]
    : [
        overviewSection(ctx),
        journalSection(ctx),
        googleDelegationSection(ctx),
        feedsSection(ctx),
        verifySection(ctx),
        googleRevokeSection(ctx),
        troubleshootingSection(ctx),
      ];
  return {
    schema: API_MODE_GUIDE_SCHEMA,
    provider: input.provider,
    connection: { id: input.connection.publicId, displayName: input.connection.displayName },
    notice:
      'This guide contains the values of your own provider connection. The gateway never changes ' +
      'your Microsoft 365 or Google Workspace configuration: you apply every step yourself. ' +
      'Confirmations you record in the console are your statements (attestations), not proofs the ' +
      'gateway has checked. Never send client secrets or service-account keys by email or chat: ' +
      'upload them only in the console.',
    sections: sections.map((s, i) => ({ ...s, number: i + 1 })),
    attestations: apiModeAttestationsFor(input.provider).map((a) => attestation(ctx, a.code)!),
    ...(input.journalSource
      ? {
          journalSource: {
            id: input.journalSource.publicId,
            kind: input.journalSource.kind,
            addressMasked: input.journalSource.addressMasked,
          },
        }
      : {}),
    ...(input.platformClientId !== null ? { platformClientId: input.platformClientId } : {}),
    permissions: [...profile.permissions],
    generatedAt: input.generatedAt.toISOString(),
  };
}

function overviewSection(ctx: Ctx): SectionDraft {
  const input = ctx.input;
  const provider = ctx.microsoft ? 'Microsoft 365' : 'Google Workspace';
  return {
    id: 'overview',
    title: 'Overview and what API mode never does',
    paragraphs: [
      `API mode protects the mailboxes of "${input.connection.displayName}" (${provider}) ` +
        'without an MX change. Mail keeps flowing directly to your mailboxes; the gateway receives ' +
        'a copy of each message (a journal copy and, optionally, the mailbox change feeds), scans it ' +
        'with every engine and records a verdict per mailbox. Detections, coverage, intake lag and ' +
        'throttling are shown on the Mailbox protection page.',
      'What API mode never does: it never changes your MX records or mail flow; it never delivers, ' +
        'forwards, delays, quarantines or bounces a message; it never changes your tenant ' +
        'configuration (you apply every step of this guide); it never reads existing mailbox content ' +
        '(no backfill: only messages that arrive after the feeds start); and it never stores ' +
        'credentials outside the encrypted credential store of the gateway.',
      'In this release the gateway only reads mailboxes. The mailbox-access permission is ' +
        'write-capable because automatic removal of detected threats (move to a quarantine ' +
        'folder or label, tag) comes in a later release; every such action will be recorded and ' +
        'reversible. Mailbox access is a separate consent from the mail-flow and account takeover ' +
        'grants and can be revoked at any time.',
    ],
    steps: [
      {
        id: 'overview-values',
        title: 'Values for this connection',
        paragraphs: [],
        values: [
          { label: 'Connection', value: input.connection.displayName },
          ...(input.connection.tenantId
            ? [
                {
                  label: ctx.microsoft ? 'Tenant ID' : 'Customer ID',
                  value: input.connection.tenantId,
                },
              ]
            : []),
          {
            label: 'Domains',
            value: input.domains.length > 0 ? input.domains.join(', ') : 'none linked yet',
          },
          {
            label: 'Change feeds',
            value: input.feeds.enabled
              ? `on (${input.feeds.mode === 'notify' ? 'change notifications' : 'polling'})`
              : 'off',
          },
        ],
      },
    ],
  };
}

function journalSection(ctx: Ctx): SectionDraft {
  const source = ctx.input.journalSource;
  const kind: JournalIntakeKind = ctx.microsoft ? 'microsoft_365_journal' : 'google_workspace_copy';
  const docs = ctx.microsoft
    ? 'docs/integrations/journal-intake-microsoft-365.md'
    : 'docs/integrations/journal-intake-google-workspace.md';
  return {
    id: 'journal',
    title: ctx.microsoft
      ? 'Journal copies (primary intake): the journal rule'
      : 'Journal copies (primary intake): the "Also deliver to" routing',
    paragraphs: [
      'The journal copy is the primary intake of API mode: it covers every mailbox, every folder ' +
        'and the full recipient list without per-mailbox API calls. It uses the journal intake ' +
        `source of type "${JOURNAL_INTAKE_KIND_LABELS[kind]}" bound to this connection; copies of ` +
        'API-mode domains are scanned in detect mode and never delivered or archived unless ' +
        'journaling is enabled.',
    ],
    steps: [
      {
        id: 'journal-source',
        title: 'Create or check the journal intake source',
        paragraphs: source
          ? [
              `The source "${source.displayName}" is bound to this connection. Its own setup guide ` +
                '(Settings, Journaling, the source, Setup guide) has the exact steps and reveals the ' +
                'intake address to users with journaling management rights.',
            ]
          : [
              'No journal intake source is bound to this connection yet. Create one in Settings, ' +
                `Journaling (type "${JOURNAL_INTAKE_KIND_LABELS[kind]}", this connection), then ` +
                'follow its setup guide. Without a journal source, coverage depends on the change ' +
                'feeds alone.',
            ],
        values: source
          ? [
              { label: 'Journal intake source', value: source.displayName },
              { label: 'Intake address (masked)', value: source.addressMasked },
            ]
          : [{ label: 'Journal intake source', value: 'none bound yet' }],
      },
      ctx.microsoft
        ? {
            id: 'journal-rule',
            title: 'Create the journal rule',
            paragraphs: [
              'In the Microsoft Purview portal (Data lifecycle management, Exchange (legacy), ' +
                'Journal rules), create a journal rule for messages sent or received from everyone ' +
                'that sends journal reports to the intake address of the source, exactly as its ' +
                `setup guide shows (template: ${docs}). Messages that mailbox rules move out of the ` +
                'Inbox are covered by the journal copy, not by the change feeds.',
            ],
          }
        : {
            id: 'journal-route',
            title: 'Add the "Also deliver to" routing setting',
            paragraphs: [
              'In the Google Admin console (Apps, Google Workspace, Gmail, Routing), add the ' +
                'routing setting of the source with "Also deliver to" the intake address and the ' +
                `journal headers, exactly as its setup guide shows (template: ${docs}).`,
            ],
          },
    ],
  };
}

/** Which option the existing grant uses (empty before a grant exists). */
function grantMethodParagraph(ctx: Ctx): string[] {
  const method = ctx.input.authMethod;
  if (method === null) return [];
  const own = method === 'customer_app_secret' || method === 'customer_service_account';
  return [
    `The mailbox-access grant of this connection uses ${own ? 'your own' : 'the operator'} ` +
      (ctx.microsoft ? 'application' : 'service account') +
      ` (option ${own ? 'B' : 'A'} below).`,
  ];
}

function microsoftAccessSection(ctx: Ctx): SectionDraft {
  const input = ctx.input;
  const permissions = M365_MAILBOX_REMEDIATION_PROFILE.permissions;
  return {
    id: 'mailbox-access',
    title: 'Mailbox access consent',
    paragraphs: [
      'The gateway reads the user directory (coverage totals, address resolution), the Inbox ' +
        'changes and the content of new messages through Microsoft Graph with the application ' +
        `permissions ${permissions.join(' and ')}. Grant them in the console: Integrations, this ` +
        'connection, Grants, "Mailbox access for API mode". Granting needs the integration ' +
        'management and API-mode management rights in the console and a Global Administrator or ' +
        'Privileged Role Administrator in Microsoft Entra.',
      ...grantMethodParagraph(ctx),
    ],
    steps: [
      {
        id: 'access-platform-app',
        title: 'Option A: consent to the operator application',
        paragraphs: [
          'Choose the operator application as the method of the grant. The console opens the ' +
            `Microsoft admin consent page of "${API_MODE_APP_NAME}"; review the two application ` +
            'permissions and accept. The gateway then verifies the permissions in a token for your tenant.',
        ],
        values: [
          {
            label: 'Application (client) ID',
            value: input.platformClientId ?? 'not offered by this gateway operator (use option B)',
          },
          ...permissions.map((p) => ({
            label: 'Microsoft Graph application permission',
            value: p,
          })),
        ],
      },
      {
        id: 'access-customer-app',
        title: 'Option B: register your own application',
        paragraphs: [
          'In the Microsoft Entra admin center, open App registrations, New registration, and ' +
            `create a single-tenant application (for example "${API_MODE_APP_NAME}"). Under API ` +
            'permissions add the Microsoft Graph application permissions below and choose "Grant ' +
            'admin consent". Under Certificates & secrets create a client secret, then enter the ' +
            'application (client) ID and the secret in the console. The secret is stored only in ' +
            'the encrypted credential store; renew it before it expires.',
        ],
        values: permissions.map((p) => ({
          label: 'Microsoft Graph application permission',
          value: p,
        })),
        warning:
          'Mail.ReadWrite applies to every mailbox of the tenant unless you scope it (next section). ' +
          'Grant it only to the application used for API mode, never to the mail-flow or account ' +
          'takeover applications.',
      },
    ],
  };
}

function microsoftScopingSection(ctx: Ctx): SectionDraft {
  const appId = ctx.clientId ?? MS_DOCS_PLACEHOLDER;
  return {
    id: 'mailbox-scope',
    title: 'Optional: limit mailbox access with Exchange Online RBAC for Applications',
    paragraphs: [
      'You can limit which mailboxes the application may access with an Exchange Online ' +
        'management scope instead of the tenant-wide Microsoft Graph consent. Mailboxes outside ' +
        'the scope are not inventoried or followed by the change feeds; unless journal copies ' +
        'for them arrive, they appear as coverage gaps on the Mailbox protection page.',
    ],
    steps: [
      {
        id: 'mailbox-scope-commands',
        title: 'Create the scope and the role assignment',
        paragraphs: [
          'Run these commands in Exchange Online PowerShell (Connect-ExchangeOnline) with the ' +
            "application's client ID, the object ID of its enterprise application and a group that " +
            'contains the protected mailboxes. Then remove the tenant-wide Mail.ReadWrite consent ' +
            'of the application in Microsoft Entra (keep User.Read.All): RBAC for Applications ' +
            'adds to Entra consents, it does not restrict them.',
        ],
        commands: [
          {
            language: 'powershell',
            code: [
              `New-ServicePrincipal -AppId ${ps(appId)} -ObjectId '<enterprise-application-object-id>' -DisplayName ${ps(API_MODE_APP_NAME)}`,
              `New-ManagementScope -Name ${ps(API_MODE_EXCHANGE_SCOPE_NAME)} -RecipientRestrictionFilter "MemberOfGroup -eq '<protected-mailboxes-group-distinguished-name>'"`,
              `New-ManagementRoleAssignment -App ${ps(appId)} -Role 'Application Mail.ReadWrite' -CustomResourceScope ${ps(API_MODE_EXCHANGE_SCOPE_NAME)}`,
            ].join('\n'),
          },
        ],
        warning:
          'Role assignments of RBAC for Applications are not listed in the access token, so the ' +
          "console's permission check reports Mail.ReadWrite as missing for this grant once the " +
          'Entra consent is removed. Scoped access is an advanced setup: check the coverage page ' +
          'after the change.',
        attestation: attestation(ctx, 'api_mode.m365.app_access_scoped'),
      },
    ],
  };
}

function googleDelegationSection(ctx: Ctx): SectionDraft {
  const input = ctx.input;
  const scopes = GOOGLE_MAILBOX_REMEDIATION_PROFILE.permissions;
  return {
    id: 'mailbox-access',
    title: 'Mailbox access: domain-wide delegation',
    paragraphs: [
      'The gateway reads the user directory (coverage totals, address resolution) as a delegated ' +
        'administrator and the Gmail history and new Inbox messages of each mailbox as that ' +
        'mailbox, through domain-wide delegation of the two OAuth scopes below. Set it up in the ' +
        'console: Integrations, this connection, Grants, "Mailbox access for API mode".',
      ...grantMethodParagraph(ctx),
    ],
    steps: [
      {
        id: 'delegation-client',
        title: 'Choose the service account',
        paragraphs: [
          'Option A: use the operator service account (its client ID is shown below when offered). Option B: ' +
            'create your own: in the Google Cloud console create a service account, enable the Gmail API ' +
            'and the Admin SDK API for its project, create a JSON key and upload the key in the ' +
            'console. The key is stored only in the encrypted credential store.',
        ],
        values: [
          {
            label: 'Operator service account client ID',
            value: input.platformClientId ?? 'not offered by this gateway operator (use your own)',
          },
          ...(input.grantClientId !== null
            ? [{ label: 'Client ID of this grant', value: input.grantClientId }]
            : []),
        ],
      },
      {
        id: 'delegation-add',
        title: 'Add the client ID to domain-wide delegation',
        paragraphs: [
          'In the Google Admin console open Security, Access and data control, API controls, ' +
            'Manage Domain Wide Delegation, and choose Add new. Enter the client ID and exactly the ' +
            'scopes below (comma-separated, nothing else), then Authorize. Changes can take some ' +
            'time to apply.',
        ],
        values: [
          { label: 'Client ID', value: ctx.clientId ?? '<service-account-client-id>' },
          { label: 'OAuth scopes', value: scopes.join(',') },
        ],
        warning:
          'gmail.modify allows changing messages of every mailbox of the domain. API mode only ' +
          'reads in this release; never add the scopes to a client ID used for anything else.',
        attestation: attestation(ctx, 'api_mode.google.delegation_added'),
      },
      {
        id: 'delegation-admin',
        title: 'Name the delegated administrator',
        paragraphs: [
          'Directory reads impersonate an administrator account of your domain that may read ' +
            'users (a super administrator, or a delegated administrator with the Users read ' +
            'privilege). Enter its address with the grant in the console.',
        ],
        values: [
          {
            label: 'Delegated administrator',
            value: input.delegatedAdmin ?? 'not set yet',
          },
        ],
      },
    ],
  };
}

function feedsSection(ctx: Ctx): SectionDraft {
  const input = ctx.input;
  return {
    id: 'feeds',
    title: 'Optional: mailbox change feeds',
    paragraphs: [
      ctx.microsoft
        ? 'Change feeds are off by default. When you turn them on for this connection (Mailbox ' +
          'protection, Coverage, Feeds), the gateway follows the Inbox of every in-scope mailbox ' +
          'with the Microsoft Graph delta query, starting from the moment the feed starts (no ' +
          'backfill). With "polling" each Inbox is checked every few minutes; with "change ' +
          'notifications" Microsoft Graph notifies the gateway of new messages (the gateway still ' +
          'polls hourly as a safety net). Content is fetched only for messages no journal copy ' +
          'already delivered for that mailbox.'
        : 'Change feeds are off by default. When you turn them on for this connection (Mailbox ' +
          'protection, Coverage, Feeds), the gateway follows the Gmail history (new messages with ' +
          'the INBOX label) of every in-scope mailbox by polling every few minutes, starting from ' +
          'the moment the feed starts (no backfill). Content is fetched only for messages no ' +
          'journal copy already delivered for that mailbox.',
    ],
    steps: [
      {
        id: 'feeds-state',
        title: 'Feed settings of this connection',
        paragraphs: [
          'Feeds need the active mailbox-access grant. Messages larger than the configured limit ' +
            'are recorded as too large and not scanned.',
        ],
        values: [
          { label: 'Feeds', value: input.feeds.enabled ? 'on' : 'off' },
          {
            label: 'Mode',
            value: ctx.microsoft
              ? input.feeds.mode === 'notify'
                ? 'change notifications'
                : 'polling'
              : 'polling (Gmail history)',
          },
        ],
      },
    ],
  };
}

function verifySection(ctx: Ctx): SectionDraft {
  return {
    id: 'verify',
    title: 'Verify coverage',
    paragraphs: [],
    steps: [
      {
        id: 'verify-inventory',
        title: 'Check the mailbox inventory and coverage',
        paragraphs: [
          'After the grant is verified, the gateway lists the users of your ' +
            (ctx.microsoft ? 'tenant' : 'domain') +
            ' every few hours (or when you choose "Sync inventory") and keeps the mailboxes of your ' +
            'API-mode domains. A mailbox is covered when its change feed synced recently or a ' +
            'journal copy for it arrived within the last seven days; otherwise it is a gap.',
        ],
      },
      {
        id: 'verify-message',
        title: 'Send a test message',
        paragraphs: [
          'Send a message from outside your organization to a protected mailbox. Within minutes it ' +
            'appears under Mailbox protection, Detections, with its verdict and the lag from ' +
            'delivery to verdict. It is delivered normally: API mode never holds it.',
        ],
      },
    ],
  };
}

function microsoftRevokeSection(ctx: Ctx): SectionDraft {
  return {
    id: 'revoke',
    title: 'Revoke mailbox access',
    paragraphs: [
      'In the console (Integrations, this connection, Grants, "Mailbox access for API mode", ' +
        'Revoke) the gateway deletes the stored credentials and stops the feeds and the inventory ' +
        'at once; detection of journal copies continues.',
    ],
    steps: [
      {
        id: 'revoke-provider',
        title: 'Remove the access in Microsoft Entra',
        paragraphs: [
          `Operator application: in the Microsoft Entra admin center open Enterprise applications, ` +
            `"${API_MODE_APP_NAME}", and delete it (or remove its Mail.ReadWrite and User.Read.All ` +
            'permissions under Permissions). Your own application: delete its client secret or the ' +
            'app registration. If you scoped access, also remove the role assignment.',
        ],
        values: ctx.clientId ? [{ label: 'Application (client) ID', value: ctx.clientId }] : [],
        commands: [
          {
            language: 'powershell',
            code: `Get-ManagementRoleAssignment -RoleAssignee ${ps(ctx.clientId ?? MS_DOCS_PLACEHOLDER)} | Remove-ManagementRoleAssignment`,
          },
        ],
      },
    ],
  };
}

function googleRevokeSection(ctx: Ctx): SectionDraft {
  return {
    id: 'revoke',
    title: 'Revoke mailbox access',
    paragraphs: [
      'In the console (Integrations, this connection, Grants, "Mailbox access for API mode", ' +
        'Revoke) the gateway deletes the stored credentials and stops the feeds and the inventory ' +
        'at once; detection of journal copies continues.',
    ],
    steps: [
      {
        id: 'revoke-provider',
        title: 'Remove the client ID from domain-wide delegation',
        paragraphs: [
          'In the Google Admin console open Security, Access and data control, API controls, ' +
            'Manage Domain Wide Delegation, and delete the entry of the client ID. For your own ' +
            'service account, also delete its key in the Google Cloud console.',
        ],
        values: ctx.clientId ? [{ label: 'Client ID', value: ctx.clientId }] : [],
      },
    ],
  };
}

function troubleshootingSection(ctx: Ctx): SectionDraft {
  return {
    id: 'troubleshooting',
    title: 'Troubleshooting lag and throttling',
    paragraphs: [],
    steps: [
      {
        id: 'troubleshoot-lag',
        title: 'Intake lag',
        paragraphs: [
          'The lag is the time from provider delivery to the verdict. High lag usually means ' +
            'delayed journal copies (check the journal source health) or a paused feed. ' +
            (ctx.microsoft
              ? 'Microsoft 365 may delay journal reports under load.'
              : 'Google Workspace routes the copy as an additional delivery; check the routing setting.'),
        ],
      },
      {
        id: 'troubleshoot-throttling',
        title: 'Throttling',
        paragraphs: [
          (ctx.microsoft
            ? 'Microsoft Graph limits requests per application and mailbox. '
            : 'The Gmail API limits requests per user and project. ') +
            'The gateway keeps a per-connection request budget and, when the provider answers with ' +
            'a throttling response, pauses the calls of that API for this connection for the time the provider ' +
            'asks (at most ten minutes) before it continues. Sustained throttling raises a health ' +
            'warning; other applications using the same quota can be the cause.',
        ],
      },
      {
        id: 'troubleshoot-cursor',
        title: 'Feed restarts and gaps',
        paragraphs: [
          (ctx.microsoft
            ? 'When Microsoft Graph no longer accepts the stored delta state of an Inbox, '
            : 'When Gmail no longer has the stored history position of a mailbox, ') +
            'the gateway restarts the feed from the current state without backfill and marks a ' +
            'gap for that mailbox; the journal copy covers the interval.' +
            (ctx.microsoft
              ? ' With change notifications, the notification endpoint of the gateway must be ' +
                'reachable from Microsoft Graph; missed notifications are caught by the safety poll.'
              : ''),
        ],
      },
    ],
  };
}

/** The Markdown download of an API-mode guide (`text/markdown; charset=utf-8`). */
export function renderApiModeGuideMarkdown(guide: ApiModeGuide): string {
  const provider = guide.provider === 'microsoft_365' ? 'Microsoft 365' : 'Google Workspace';
  const text = (value: string): string => value.replace(/([\\`*_[\]<>|#])/g, '\\$1');
  return renderGuideMarkdown(
    [
      `# ${provider} API-mode guide: ${text(guide.connection.displayName)}`,
      '',
      `Generated ${guide.generatedAt} (\`${guide.schema}\`).`,
      `Permissions: ${guide.permissions.map((p) => `\`${p}\``).join(', ')}.`,
      '',
      `> ${text(guide.notice)}`,
      '',
    ],
    guide.sections,
  );
}

/** `api-mode-<provider>-<connection-name-slug>.md`. */
export function apiModeGuideFileName(guide: Pick<ApiModeGuide, 'provider' | 'connection'>): string {
  const slug =
    guide.connection.displayName
      .normalize('NFKD')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 64) || 'connection';
  const provider = guide.provider === 'microsoft_365' ? 'microsoft-365' : 'google-workspace';
  return `api-mode-${provider}-${slug}.md`;
}

// ---------------------------------------------------------------------------------------------
// Example input (docs templates, tests)
// ---------------------------------------------------------------------------------------------

/**
 * The placeholder input of the documentation templates: `example.com`, `gateway.example.net`
 * (the masked intake address), `11111111-2222-3333-4444-555555555555` for ids, a synthetic
 * numeric Google client id and no secret-shaped value.
 */
export function exampleApiModeGuideInput(provider: IntegrationProvider): ApiModeGuideInput {
  const microsoft = provider === 'microsoft_365';
  return {
    provider,
    connection: {
      publicId: '11111111-2222-3333-4444-555555555555',
      displayName: microsoft ? 'Example Microsoft 365' : 'Example Google Workspace',
      tenantId: microsoft ? '11111111-2222-3333-4444-555555555555' : 'C0example',
    },
    domains: ['example.com'],
    journalSource: {
      publicId: '11111111-2222-3333-4444-555555555555',
      displayName: microsoft
        ? 'Example Microsoft 365 journaling'
        : 'Example Google Workspace copies',
      kind: microsoft ? 'microsoft_365_journal' : 'google_workspace_copy',
      addressMasked: 'journal-••••xamp@journal.gateway.example.net',
    },
    platformClientId: microsoft ? '11111111-2222-3333-4444-555555555555' : '111122223333444455556',
    authMethod: microsoft ? 'platform_app' : 'platform_service_account',
    grantClientId: null,
    delegatedAdmin: microsoft ? null : 'admin@example.com',
    feeds: { enabled: false, mode: 'poll' },
    attestations: [],
    generatedAt: new Date('2026-11-26T00:00:00.000Z'),
  };
}
