/**
 * Synthetic Microsoft directory for the simulators (design note D12): Entra directory
 * `11111111-2222-4333-8444-555555555555`, domain `contoso-it.example`, documentation IP ranges
 * only (RFC 5737 IPv4, RFC 3849 IPv6). No real tenant, user, credential or address.
 *
 * Timestamps are relative to `now` so each poll window of the adapter sees the intended records:
 * sign-ins and risk detections 10 minutes ago, consent audits 20 minutes ago, Exchange audit
 * blobs 40 minutes ago (all inside the first window of their family, D7.2).
 */
import type {
  MsAuditBlob,
  MsDirectory,
  MsDirectoryAudit,
  MsExchangeRecord,
  MsRiskDetection,
  MsSignIn,
  MsUser,
} from '../simulators/types';

export const MS_TENANT_ID = '11111111-2222-4333-8444-555555555555';
export const MS_DOMAIN = 'contoso-it.example';
export const MS_EXTERNAL_DOMAIN = 'evil-mail.example';
export const MS_MFA_GROUP_ID = '99999999-8888-4777-8666-555555555555';

export const MS_USERS = {
  alex: 'aaaaaaaa-0000-4000-8000-000000000001',
  blake: 'aaaaaaaa-0000-4000-8000-000000000002',
  casey: 'aaaaaaaa-0000-4000-8000-000000000003',
  drew: 'aaaaaaaa-0000-4000-8000-000000000004',
  erin: 'aaaaaaaa-0000-4000-8000-000000000005',
  frank: 'aaaaaaaa-0000-4000-8000-000000000006',
  gale: 'aaaaaaaa-0000-4000-8000-000000000007',
} as const;

export const MS_SERVICE_PRINCIPALS = {
  unverified: 'bbbbbbbb-0000-4000-8000-000000000001',
  verified: 'bbbbbbbb-0000-4000-8000-000000000002',
} as const;

export const MS_IPS = {
  office: '192.0.2.10',
  home: '198.51.100.20',
  attacker: '203.0.113.30',
  v6: '2001:db8::1',
} as const;

export function minutesAgo(now: Date, minutes: number): string {
  return new Date(now.getTime() - minutes * 60_000).toISOString();
}

function user(key: keyof typeof MS_USERS, overrides: Partial<MsUser> = {}): MsUser {
  return {
    id: MS_USERS[key],
    userPrincipalName: `${key}@${MS_DOMAIN}`,
    mail: `${key}@${MS_DOMAIN}`,
    displayName: key.charAt(0).toUpperCase() + key.slice(1),
    accountEnabled: true,
    onPremisesSyncEnabled: null,
    proxyAddresses: [`SMTP:${key}@${MS_DOMAIN}`],
    ...overrides,
  };
}

let sequence = 0;
function guid(prefix: string): string {
  sequence += 1;
  return `${prefix}-0000-4000-8000-${sequence.toString(16).padStart(12, '0')}`;
}

export function msSignIn(
  now: Date,
  overrides: Partial<MsSignIn> & { minutesAgo?: number } = {},
): MsSignIn {
  const { minutesAgo: ago = 10, ...rest } = overrides;
  return {
    id: guid('cccccccc'),
    createdDateTime: minutesAgo(now, ago),
    userId: MS_USERS.alex,
    userPrincipalName: `alex@${MS_DOMAIN}`,
    appDisplayName: 'Office 365 Exchange Online',
    ipAddress: MS_IPS.office,
    clientAppUsed: 'Browser',
    status: { errorCode: 0 },
    deviceDetail: {
      deviceId: 'EXAMPLE-device-0001',
      operatingSystem: 'Windows 10',
      browser: 'Edge 120.0',
    },
    location: {
      city: 'Example City',
      countryOrRegion: 'DE',
      geoCoordinates: { latitude: 52.5, longitude: 13.4 },
    },
    riskLevelDuringSignIn: 'none',
    ...rest,
  };
}

export function msRiskDetection(
  now: Date,
  overrides: Partial<MsRiskDetection> & { minutesAgo?: number } = {},
): MsRiskDetection {
  const { minutesAgo: ago = 10, ...rest } = overrides;
  const at = minutesAgo(now, ago);
  return {
    id: guid('dddddddd'),
    riskEventType: 'unfamiliarFeatures',
    riskLevel: 'high',
    riskState: 'atRisk',
    detectedDateTime: at,
    lastUpdatedDateTime: at,
    activityDateTime: at,
    userId: MS_USERS.alex,
    userPrincipalName: `alex@${MS_DOMAIN}`,
    ipAddress: MS_IPS.attacker,
    location: { city: 'Elsewhere', countryOrRegion: 'BR' },
    ...rest,
  };
}

export function msConsentAudit(
  now: Date,
  overrides: {
    minutesAgo?: number;
    activity?: string;
    userKey?: keyof typeof MS_USERS;
    servicePrincipalId?: string;
    appName?: string;
    scopes?: string;
    adminConsent?: boolean;
    result?: string;
  } = {},
): MsDirectoryAudit {
  const userKey = overrides.userKey ?? 'alex';
  return {
    id: `Directory_${guid('eeeeeeee')}`,
    activityDateTime: minutesAgo(now, overrides.minutesAgo ?? 20),
    activityDisplayName: overrides.activity ?? 'Consent to application',
    category: 'ApplicationManagement',
    result: overrides.result ?? 'success',
    initiatedBy: {
      user: {
        id: MS_USERS[userKey],
        userPrincipalName: `${userKey}@${MS_DOMAIN}`,
        ipAddress: MS_IPS.attacker,
      },
    },
    targetResources: [
      {
        id: overrides.servicePrincipalId ?? MS_SERVICE_PRINCIPALS.unverified,
        displayName: overrides.appName ?? 'Mail Helper Example',
        type: 'ServicePrincipal',
        modifiedProperties: [
          {
            displayName: 'ConsentContext.IsAdminConsent',
            newValue: `"${overrides.adminConsent ? 'True' : 'False'}"`,
          },
          {
            displayName: 'ConsentAction.Permissions',
            newValue: `"[] => [[Id: EXAMPLE, ClientId: EXAMPLE, PrincipalId: EXAMPLE, ResourceId: EXAMPLE, ConsentType: Principal, Scope: ${overrides.scopes ?? 'Mail.Read Mail.Send offline_access'}, CreatedDateTime: , LastModifiedDateTime ]]; "`,
          },
        ],
      },
    ],
  };
}

export function msExchangeRecord(
  now: Date,
  overrides: Partial<MsExchangeRecord> & { minutesAgo?: number } = {},
): MsExchangeRecord {
  const { minutesAgo: ago = 40, ...rest } = overrides;
  return {
    Id: guid('ffffffff'),
    CreationTime: minutesAgo(now, ago).replace(/\.\d{3}Z$/, ''),
    Operation: 'MailboxLogin',
    Workload: 'Exchange',
    RecordType: 1,
    UserId: `alex@${MS_DOMAIN}`,
    ResultStatus: 'Succeeded',
    ClientIP: `${MS_IPS.attacker}:443`,
    MailboxOwnerUPN: `alex@${MS_DOMAIN}`,
    LogonType: 0,
    ...rest,
  };
}

export function msAuditBlob(
  now: Date,
  records: MsExchangeRecord[],
  overrides: { minutesAgo?: number; contentId?: string } = {},
): MsAuditBlob {
  return {
    contentId: overrides.contentId ?? `EXAMPLE${guid('blob').replace(/-/g, '')}`,
    contentCreated: minutesAgo(now, overrides.minutesAgo ?? 40),
    records,
  };
}

/** The Exchange audit records of the default dataset (one per mapped case of §3.2). */
export function defaultExchangeRecords(now: Date): MsExchangeRecord[] {
  return [
    msExchangeRecord(now, {
      Operation: 'New-InboxRule',
      ObjectId: `alex@${MS_DOMAIN}\\Invoices`,
      Parameters: [
        { Name: 'Name', Value: 'Invoices' },
        { Name: 'ForwardTo', Value: `collector@${MS_EXTERNAL_DOMAIN}` },
        { Name: 'SubjectContainsWords', Value: 'invoice;payment' },
        { Name: 'MoveToFolder', Value: 'RSS Feeds' },
        { Name: 'MarkAsRead', Value: 'True' },
      ],
    }),
    msExchangeRecord(now, { Operation: 'MailboxLogin', LogonType: 0 }),
    msExchangeRecord(now, {
      Operation: 'MailItemsAccessed',
      LogonType: 2,
      UserId: `blake@${MS_DOMAIN}`,
      ClientInfoString: 'Client=OWA;Action=ViaProxy',
    }),
    msExchangeRecord(now, {
      Operation: 'Set-Mailbox',
      Parameters: [
        { Name: 'Identity', Value: `alex@${MS_DOMAIN}` },
        { Name: 'ForwardingSmtpAddress', Value: `smtp:collector@${MS_EXTERNAL_DOMAIN}` },
        { Name: 'DeliverToMailboxAndForward', Value: 'False' },
      ],
    }),
    msExchangeRecord(now, {
      Operation: 'Add-MailboxPermission',
      Parameters: [
        { Name: 'Identity', Value: `alex@${MS_DOMAIN}` },
        { Name: 'User', Value: `blake@${MS_DOMAIN}` },
        { Name: 'AccessRights', Value: 'FullAccess' },
      ],
    }),
    msExchangeRecord(now, {
      Operation: 'Add-RecipientPermission',
      Parameters: [
        { Name: 'Identity', Value: `alex@${MS_DOMAIN}` },
        { Name: 'Trustee', Value: `outsider@${MS_EXTERNAL_DOMAIN}` },
        { Name: 'AccessRights', Value: 'SendAs' },
      ],
    }),
    msExchangeRecord(now, {
      Operation: 'Set-Mailbox',
      Parameters: [
        { Name: 'Identity', Value: `alex@${MS_DOMAIN}` },
        { Name: 'GrantSendOnBehalfTo', Value: `blake@${MS_DOMAIN}` },
      ],
    }),
    msExchangeRecord(now, { Operation: 'Send', LogonType: 0 }),
  ];
}

/** A complete synthetic Microsoft directory (fresh objects on every call). */
export function microsoftDirectory(now: Date, overrides: Partial<MsDirectory> = {}): MsDirectory {
  return {
    tenantId: MS_TENANT_ID,
    domains: [MS_DOMAIN],
    licenses: { entraP1: true, entraP2: true, unifiedAudit: true },
    users: [
      user('alex'),
      user('blake'),
      user('casey', { privileged: true }),
      user('drew', { onPremisesSyncEnabled: true }),
      user('erin', {
        mail: null,
        proxyAddresses: [`SMTP:erin@${MS_DOMAIN}`, `smtp:erin.alias@${MS_DOMAIN}`],
      }),
      user('frank', {
        userPrincipalName: `frank_partner-org.example#EXT#@${MS_DOMAIN}`,
        mail: 'frank@partner-org.example',
        proxyAddresses: [],
      }),
      user('gale', { accountEnabled: false }),
    ],
    signIns: [
      msSignIn(now),
      msSignIn(now, {
        userId: MS_USERS.blake,
        userPrincipalName: `blake@${MS_DOMAIN}`,
        ipAddress: MS_IPS.attacker,
        status: { errorCode: 50126, failureReason: 'Invalid username or password.' },
        deviceDetail: null,
        riskLevelDuringSignIn: 'medium',
      }),
      msSignIn(now, {
        ipAddress: MS_IPS.v6,
        status: { errorCode: 50074 },
        riskLevelDuringSignIn: 'hidden',
      }),
    ],
    riskDetections: [
      msRiskDetection(now),
      msRiskDetection(now, { riskEventType: 'anomalousToken', riskLevel: 'medium' }),
      msRiskDetection(now, { riskEventType: 'leakedCredentials', riskState: 'dismissed' }),
    ],
    directoryAudits: [
      msConsentAudit(now),
      msConsentAudit(now, {
        activity: 'Add delegated permission grant',
        servicePrincipalId: MS_SERVICE_PRINCIPALS.verified,
        appName: 'Verified Example App',
        scopes: 'User.Read',
        adminConsent: true,
      }),
    ],
    exchange: {
      subscribed: false,
      blobs: [msAuditBlob(now, defaultExchangeRecords(now))],
    },
    messageRules: {
      [MS_USERS.alex]: [
        {
          id: 'AQAAAJ5dZqA=',
          displayName: 'Invoices',
          sequence: 1,
          isEnabled: true,
          conditions: { subjectContains: ['invoice'] },
          actions: {
            forwardTo: [{ emailAddress: { address: `collector@${MS_EXTERNAL_DOMAIN}` } }],
            stopProcessingRules: true,
          },
        },
        {
          id: 'AQAAAJ5dZqB=',
          displayName: 'Newsletters',
          sequence: 2,
          isEnabled: true,
          conditions: { senderContains: ['news'] },
          actions: { moveToFolder: 'Archive' },
        },
      ],
      [MS_USERS.blake]: [],
    },
    groups: [{ id: MS_MFA_GROUP_ID, displayName: 'MFA enforced (example)', members: [] }],
    oauth2PermissionGrants: [
      {
        id: 'grant-alex-unverified',
        clientId: MS_SERVICE_PRINCIPALS.unverified,
        consentType: 'Principal',
        principalId: MS_USERS.alex,
        resourceId: 'bbbbbbbb-0000-4000-8000-0000000000ff',
        scope: 'Mail.Read Mail.Send offline_access',
      },
      {
        id: 'grant-alex-verified',
        clientId: MS_SERVICE_PRINCIPALS.verified,
        consentType: 'Principal',
        principalId: MS_USERS.alex,
        resourceId: 'bbbbbbbb-0000-4000-8000-0000000000ff',
        scope: 'User.Read',
      },
    ],
    servicePrincipals: [
      {
        id: MS_SERVICE_PRINCIPALS.unverified,
        appId: 'bbbbbbbb-1111-4000-8000-000000000001',
        displayName: 'Mail Helper Example',
        verifiedPublisher: { displayName: null, verifiedPublisherId: null },
      },
      {
        id: MS_SERVICE_PRINCIPALS.verified,
        appId: 'bbbbbbbb-1111-4000-8000-000000000002',
        displayName: 'Verified Example App',
        verifiedPublisher: { displayName: 'Example Publisher', verifiedPublisherId: '1000001' },
      },
    ],
    ...overrides,
  };
}

/** Permissions of the three Microsoft ATO profiles (D5), as the simulators grant them. */
export const MS_PROFILE_PERMISSIONS = {
  'm365.ato_telemetry': [
    'AuditLog.Read.All',
    'Directory.Read.All',
    'IdentityRiskEvent.Read.All',
    'User.Read.All',
    'MailboxSettings.Read',
    'ActivityFeed.Read',
  ],
  'm365.ato_response': [
    'User.Read.All',
    'User.RevokeSessions.All',
    'User.EnableDisableAccount.All',
    'User-PasswordProfile.ReadWrite.All',
    'MailboxSettings.ReadWrite',
  ],
  'm365.ato_response_extended': [
    'User.Read.All',
    'GroupMember.ReadWrite.All',
    'DelegatedPermissionGrant.ReadWrite.All',
  ],
} as const;
