/**
 * Synthetic Google Workspace customer for the simulators (design note D12): customer id
 * `Cexample01` (8.2's validated format), domain `fabrikam-it.example`, documentation IP ranges only
 * (RFC 5737 IPv4, RFC 3849 IPv6). No real customer, user, credential, client id or address.
 *
 * Timestamps are relative to `now` so the first Reports window of the adapter
 * (`[now − 60 min, now − 5 min]`, D7.2) sees the intended activities (10–30 minutes ago).
 */
import type {
  GsActivity,
  GsActivityEvent,
  GsCustomer,
  GsGmailSettings,
  GsUser,
} from '../simulators/google-types';

export const GS_CUSTOMER_ID = 'Cexample01';
export const GS_DOMAIN = 'fabrikam-it.example';
/** Linked at the gateway but not verified in the Google tenant (linked-domain guard). */
export const GS_UNVERIFIED_DOMAIN = 'fabrikam-labs.example';
export const GS_EXTERNAL_DOMAIN = 'exfil-mail.example';
/** Delegated administrator the Admin SDK calls impersonate (the grants' `subjectEmail`). */
export const GS_ADMIN_EMAIL = `ato-admin@${GS_DOMAIN}`;
/** Tenant-designated organizational unit enforcing 2-Step Verification (PQ2). */
export const GS_MFA_OU = '/Security/2SV-Enforced';

export const GS_USERS = {
  admin: '100000000000000000001',
  alex: '100000000000000000002',
  blake: '100000000000000000003',
  casey: '100000000000000000004',
  drew: '100000000000000000005',
  erin: '100000000000000000006',
  frank: '100000000000000000007',
  root: '100000000000000000008',
  gale: '100000000000000000009',
} as const;
export type GsUserKey = keyof typeof GS_USERS;

/** Synthetic OAuth client ids (not real applications). */
export const GS_CLIENTS = {
  mailSync: '123456789012-mailsync.apps.googleusercontent.com',
  calendar: '210987654321-calendar.apps.googleusercontent.com',
  notes: '555555555555-notes.apps.googleusercontent.com',
} as const;

export const GS_IPS = {
  office: '192.0.2.10',
  home: '198.51.100.20',
  attacker: '203.0.113.30',
  v6: '2001:db8::1',
} as const;

export function gsEmail(key: GsUserKey): string {
  if (key === 'admin') return GS_ADMIN_EMAIL;
  return `${key}@${key === 'frank' ? GS_UNVERIFIED_DOMAIN : GS_DOMAIN}`;
}

function user(key: GsUserKey, overrides: Partial<GsUser> = {}): GsUser {
  return {
    id: GS_USERS[key],
    primaryEmail: gsEmail(key),
    aliases: [],
    suspended: false,
    orgUnitPath: '/Staff',
    changePasswordAtNextLogin: false,
    isAdmin: false,
    gmailEnabled: true,
    ...overrides,
  };
}

export function gsMinutesAgo(now: Date, minutes: number): string {
  return new Date(now.getTime() - minutes * 60_000).toISOString();
}

let qualifier = 0;
/** A Reports activity of `key` at `now − minutesAgo` (Reports `uniqueQualifier` is an int64). */
export function gsActivity(
  now: Date,
  input: {
    user?: GsUserKey | null;
    application?: 'login' | 'token';
    minutesAgo?: number;
    ip?: string;
    regionCode?: string;
    events: GsActivityEvent[];
    uniqueQualifier?: string;
  },
): GsActivity {
  qualifier += 1;
  const key = input.user === undefined ? 'alex' : input.user;
  return {
    id: {
      time: gsMinutesAgo(now, input.minutesAgo ?? 10),
      uniqueQualifier: input.uniqueQualifier ?? `-${(4_200_000_000 + qualifier).toString()}`,
      applicationName: input.application ?? 'login',
      customerId: GS_CUSTOMER_ID,
    },
    actor:
      key === null
        ? { email: `unknown@${GS_DOMAIN}`, callerType: 'USER' }
        : { email: gsEmail(key), profileId: GS_USERS[key], callerType: 'USER' },
    ...(input.ip ? { ipAddress: input.ip } : {}),
    ...(input.regionCode ? { networkInfo: { regionCode: input.regionCode } } : {}),
    events: input.events,
  };
}

const param = (name: string, value: string) => ({ name, value });

/** The `login` activities of the default dataset (10–30 minutes ago). */
export function gsLoginActivities(now: Date): GsActivity[] {
  return [
    gsActivity(now, {
      user: 'alex',
      minutesAgo: 30,
      ip: GS_IPS.office,
      regionCode: 'US',
      events: [
        {
          type: 'login',
          name: 'login_success',
          parameters: [
            param('login_type', 'google_password'),
            { name: 'is_suspicious', boolValue: false },
          ],
        },
      ],
    }),
    gsActivity(now, {
      user: 'alex',
      minutesAgo: 25,
      ip: GS_IPS.attacker,
      events: [
        {
          type: 'login',
          name: 'login_failure',
          parameters: [
            param('login_type', 'google_password'),
            param('login_failure_type', 'login_failure_invalid_password'),
          ],
        },
      ],
    }),
    gsActivity(now, {
      user: 'blake',
      minutesAgo: 24,
      ip: GS_IPS.home,
      events: [
        {
          type: 'login',
          name: 'login_challenge',
          parameters: [
            param('login_challenge_method', 'idv_preregistered_phone'),
            param('login_challenge_status', 'Challenge Failed'),
          ],
        },
      ],
    }),
    gsActivity(now, {
      user: 'blake',
      minutesAgo: 23,
      ip: GS_IPS.home,
      events: [
        {
          type: 'login',
          name: 'login_challenge',
          parameters: [param('login_challenge_status', 'Challenge Passed')],
        },
      ],
    }),
    gsActivity(now, {
      user: 'alex',
      minutesAgo: 22,
      ip: GS_IPS.office,
      events: [{ type: 'logout', name: 'logout' }],
    }),
    gsActivity(now, {
      user: 'alex',
      minutesAgo: 21,
      ip: GS_IPS.attacker,
      events: [
        {
          type: 'login',
          name: 'suspicious_login',
          parameters: [param('login_type', 'google_password')],
        },
      ],
    }),
    gsActivity(now, {
      user: 'erin',
      minutesAgo: 20,
      events: [{ type: 'account_warning', name: 'account_disabled_hijacked' }],
    }),
    gsActivity(now, {
      user: 'erin',
      minutesAgo: 19,
      events: [{ type: 'login', name: 'login_verification' }],
    }),
    gsActivity(now, {
      user: null, // no profileId: no identity, dropped as invalid
      minutesAgo: 18,
      ip: GS_IPS.attacker,
      events: [{ type: 'login', name: 'login_failure' }],
    }),
    gsActivity(now, {
      user: 'erin',
      minutesAgo: 17,
      ip: GS_IPS.v6,
      events: [{ type: 'login', name: 'login_success' }],
    }),
    gsActivity(now, {
      user: 'root',
      minutesAgo: 16,
      events: [{ type: 'account_warning', name: 'gov_attack_warning' }],
    }),
    gsActivity(now, {
      user: 'gale',
      minutesAgo: 15,
      events: [{ type: 'account_warning', name: 'account_disabled_spamming_through_relay' }],
    }),
  ];
}

/** The `token` activities of the default dataset (OAuth authorizations, 10–14 minutes ago). */
export function gsTokenActivities(now: Date): GsActivity[] {
  return [
    gsActivity(now, {
      user: 'alex',
      application: 'token',
      minutesAgo: 14,
      ip: GS_IPS.attacker,
      events: [
        {
          type: 'auth',
          name: 'authorize',
          parameters: [
            param('client_id', GS_CLIENTS.mailSync),
            param('app_name', 'Mail Sync Pro (example)'),
            {
              name: 'scope',
              multiValue: [
                'https://mail.google.com/',
                'https://www.googleapis.com/auth/gmail.readonly',
              ],
            },
          ],
        },
      ],
    }),
    gsActivity(now, {
      user: 'blake',
      application: 'token',
      minutesAgo: 13,
      events: [
        {
          type: 'auth',
          name: 'revoke',
          parameters: [param('client_id', GS_CLIENTS.calendar)],
        },
      ],
    }),
    gsActivity(now, {
      user: 'erin',
      application: 'token',
      minutesAgo: 12,
      events: [
        {
          type: 'auth',
          name: 'authorize',
          parameters: [
            param('client_id', GS_CLIENTS.notes),
            { name: 'scope', multiValue: ['https://www.googleapis.com/auth/drive.file'] },
          ],
        },
      ],
    }),
  ];
}

function gmail(overrides: Partial<GsGmailSettings> = {}): GsGmailSettings {
  return { autoForwarding: { enabled: false }, filters: [], delegates: [], ...overrides };
}

/** The default synthetic customer. */
export function googleCustomer(now: Date): GsCustomer {
  return {
    customerId: GS_CUSTOMER_ID,
    domains: [GS_DOMAIN, GS_UNVERIFIED_DOMAIN],
    users: [
      user('admin', { isDelegatedAdmin: true, orgUnitPath: '/IT' }),
      user('alex'),
      user('blake'),
      user('casey', { suspended: true }),
      user('drew', { gmailEnabled: false }),
      user('erin', { aliases: [`erin.alias@${GS_DOMAIN}`] }),
      user('frank'),
      user('root', { isAdmin: true, orgUnitPath: '/IT' }),
      user('gale', { changePasswordAtNextLogin: true, orgUnitPath: GS_MFA_OU }),
    ],
    orgUnits: [
      { orgUnitId: 'id:03ph8a2z0000001', orgUnitPath: '/', name: 'Fabrikam IT (example)' },
      { orgUnitId: 'id:03ph8a2z0000002', orgUnitPath: '/Staff', name: 'Staff' },
      { orgUnitId: 'id:03ph8a2z0000003', orgUnitPath: '/IT', name: 'IT' },
      { orgUnitId: 'id:03ph8a2z0000004', orgUnitPath: '/Security', name: 'Security' },
      { orgUnitId: 'id:03ph8a2z0000005', orgUnitPath: GS_MFA_OU, name: '2SV-Enforced' },
    ],
    activities: [...gsLoginActivities(now), ...gsTokenActivities(now)],
    tokens: {
      [GS_USERS.alex]: [
        {
          clientId: GS_CLIENTS.mailSync,
          displayText: 'Mail Sync Pro (example)',
          scopes: ['https://mail.google.com/'],
        },
        {
          clientId: GS_CLIENTS.calendar,
          displayText: 'Calendar Helper (example)',
          scopes: ['https://www.googleapis.com/auth/calendar.readonly'],
        },
      ],
      [GS_USERS.blake]: [
        {
          clientId: GS_CLIENTS.calendar,
          displayText: 'Calendar Helper (example)',
          scopes: ['https://www.googleapis.com/auth/calendar.readonly'],
        },
      ],
    },
    gmail: {
      [GS_USERS.admin]: gmail(),
      [GS_USERS.alex]: gmail({
        filters: [
          {
            id: 'ANe1BmgAlex0001',
            criteria: { subject: 'invoice' },
            action: { forward: `pay@${GS_EXTERNAL_DOMAIN}`, removeLabelIds: ['INBOX'] },
          },
          {
            id: 'ANe1BmgAlex0002',
            criteria: { from: `news@${GS_DOMAIN}` },
            action: { addLabelIds: ['Label_7'] },
          },
        ],
      }),
      [GS_USERS.blake]: gmail({
        autoForwarding: {
          enabled: true,
          emailAddress: `drop@${GS_EXTERNAL_DOMAIN}`,
          disposition: 'archive',
        },
        filters: [
          {
            id: 'ANe1BmgBlake001',
            criteria: { query: 'password reset' },
            action: { addLabelIds: ['TRASH'] },
          },
        ],
      }),
      [GS_USERS.erin]: gmail({
        delegates: [
          { delegateEmail: `alex@${GS_DOMAIN}`, verificationStatus: 'accepted' },
          { delegateEmail: `pending@${GS_DOMAIN}`, verificationStatus: 'pending' },
        ],
      }),
    },
  };
}
