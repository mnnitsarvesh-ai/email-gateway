import 'server-only';
import type { SuccessBody } from '@/lib/api/types';
import {
  PLATFORM_ROLE_KEYS,
  ROLE_PERMISSIONS,
  SYSTEM_ROLE_KEYS,
  type SystemRoleKey,
} from '@/test/roles';
import { SeededRandom, fixtureAnchor, paginate, stableUuid } from '../generator';
import {
  apiError,
  noContent,
  ok,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Session, account and tenant-switcher fixtures (WP2). Dev-only login hint: the local part of
 * the email selects the user, any password is accepted (no credential exists in fixture mode):
 *   `<role key>@example.com`      signs in with that system role (e.g. read_only_user@example.com)
 *   `mfa.<role key>@example.com`  the same user with MFA enabled: any 6-digit code works
 *   `enroll.<role key>@example.com` organization requires MFA and the user has not enrolled
 * Platform roles (`super_admin`, `platform_admin`) belong to the platform organization.
 */

type Organization = SuccessBody<'OrganizationsController_get_v1'>;

interface FixtureUser {
  id: string;
  email: string;
  displayName: string;
  role: SystemRoleKey;
  mfaEnabled: boolean;
  mfaEnrollmentRequired: boolean;
}

interface FixtureSession {
  id: string;
  user: FixtureUser;
  mfaAuthenticated: boolean;
  createdAt: string;
  override: { id: string; organizationId: string; reason: string; expiresAt: string } | null;
}

const anchor = fixtureAnchor();

function organization(
  slug: string,
  name: string,
  kind: 'customer' | 'platform',
  plan: string,
): Organization {
  const created = new Date(anchor - 120 * 86_400_000).toISOString();
  return {
    id: stableUuid(`org:${slug}`),
    slug,
    name,
    kind,
    status: 'active',
    statusReason: null,
    statusChangedAt: null,
    plan: { code: plan, name: plan[0]?.toUpperCase() + plan.slice(1) },
    dataRegion: 'eu-west-1',
    deploymentMode: 'saas',
    deployments: [],
    deletion: null,
    createdAt: created,
    updatedAt: created,
  };
}

export const PLATFORM_ORG = organization(
  'platform',
  'Gateway Platform Operations',
  'platform',
  'enterprise',
);
export const CUSTOMER_ORGS: Organization[] = [
  organization('alpha', 'Alpha Industries (example)', 'customer', 'business'),
  organization('bravo', 'Bravo Logistics (example)', 'customer', 'starter'),
  organization('charlie', 'Charlie Health (example)', 'customer', 'enterprise'),
  ...Array.from({ length: 27 }, (_, i) =>
    organization(
      `tenant-${String(i + 1).padStart(2, '0')}`,
      `Synthetic Tenant ${i + 1}`,
      'customer',
      'business',
    ),
  ),
];
const ALL_ORGS = [PLATFORM_ORG, ...CUSTOMER_ORGS];

/**
 * Fixture state lives on globalThis: `next dev` compiles each route handler into its own bundle,
 * so module-level maps would differ between the login route and the proxy route.
 */
interface FixtureState {
  sessions: Map<string, FixtureSession>;
  accessTokens: Map<string, string>;
  refreshTokens: Map<string, string>;
  challenges: Map<string, FixtureUser>;
  enrolled: Map<string, boolean>;
}
const globalState = globalThis as typeof globalThis & { __egDevFixtureSessionState?: FixtureState };
const state: FixtureState = (globalState.__egDevFixtureSessionState ??= {
  sessions: new Map(),
  accessTokens: new Map(),
  refreshTokens: new Map(),
  challenges: new Map(),
  enrolled: new Map(),
});
const { sessions, accessTokens, refreshTokens, challenges, enrolled } = state;
const random = new SeededRandom('session-fixtures');

function token(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, '')}`;
}

function parseHint(email: string): FixtureUser | null {
  const match = /^(?:(mfa|enroll)\.)?([a-z_]+)@example\.com$/.exec(email.trim().toLowerCase());
  if (!match) return null;
  const role = match[2] as SystemRoleKey;
  if (!SYSTEM_ROLE_KEYS.includes(role)) return null;
  const mode = match[1];
  const userId = stableUuid(`user:${email.toLowerCase()}`);
  const mfaEnabled = enrolled.get(userId) ?? mode === 'mfa';
  return {
    id: userId,
    email: email.toLowerCase(),
    displayName: role
      .split('_')
      .map((part) => part[0]?.toUpperCase() + part.slice(1))
      .join(' '),
    role,
    mfaEnabled,
    mfaEnrollmentRequired: mode === 'enroll' && !mfaEnabled,
  };
}

function homeOrg(user: FixtureUser): Organization {
  return PLATFORM_ROLE_KEYS.includes(user.role) ? PLATFORM_ORG : (CUSTOMER_ORGS[0] as Organization);
}

function issueTokens(user: FixtureUser, mfaAuthenticated: boolean, sessionId?: string) {
  const id = sessionId ?? random.uuid();
  const existing = sessions.get(id);
  sessions.set(id, {
    id,
    user,
    mfaAuthenticated,
    createdAt: existing?.createdAt ?? new Date().toISOString(),
    override: existing?.override ?? null,
  });
  const at = token('devat');
  const rt = token('devrt');
  accessTokens.set(at, id);
  refreshTokens.set(rt, id);
  const org = homeOrg(user);
  return ok('AuthController_login_v1', {
    accessToken: at,
    tokenType: 'Bearer',
    expiresIn: 600,
    refreshToken: rt,
    refreshTokenExpiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
    sessionId: id,
    mfaEnrollmentRequired: user.mfaEnrollmentRequired,
    user: { id: user.id, email: user.email, displayName: user.displayName },
    organization: { id: org.id, slug: org.slug, name: org.name, kind: org.kind },
  });
}

function sessionOf(request: FixtureRequest): FixtureSession | null {
  if (!request.token) return null;
  const id = accessTokens.get(request.token);
  return id ? (sessions.get(id) ?? null) : null;
}

function withSession(
  request: FixtureRequest,
  fn: (session: FixtureSession) => FixtureResponse,
): FixtureResponse {
  const session = sessionOf(request);
  if (!session) return apiError(401, 'unauthorized', 'Unauthorized');
  return fn(session);
}

function body(request: FixtureRequest): Record<string, unknown> {
  return request.body && typeof request.body === 'object'
    ? (request.body as Record<string, unknown>)
    : {};
}

function text(request: FixtureRequest, key: string): string {
  const value = body(request)[key];
  return typeof value === 'string' ? value : '';
}

const SIX_DIGITS = /^\d{6}$/;

function recoveryCodes(): string[] {
  const r = new SeededRandom(Date.now());
  const chars = 'abcdefghijkmnpqrstuvwxyz23456789';
  return Array.from({ length: 10 }, () =>
    Array.from({ length: 11 }, (_, i) => (i === 5 ? '-' : chars[r.int(0, chars.length - 1)])).join(
      '',
    ),
  );
}

export const fixtures: FixtureHandlers = {
  MetaController_get_v1: () =>
    ok('MetaController_get_v1', {
      service: 'email-gateway-api',
      version: '0.0.0-dev-fixtures',
      apiVersion: 'v1',
      environment: 'dev-fixtures',
    }),

  AuthController_login_v1: (request) => {
    const user = parseHint(text(request, 'email'));
    if (!user || !body(request).password)
      return apiError(401, 'unauthorized', 'Invalid credentials');
    if (user.mfaEnabled) {
      const mfaToken = token('devmfa');
      challenges.set(mfaToken, user);
      return ok('AuthController_login_v1', { mfaRequired: true, mfaToken, expiresIn: 300 });
    }
    return issueTokens(user, false);
  },

  AuthController_verifyMfa_v1: (request) => {
    const input = body(request);
    const user = challenges.get(text(request, 'mfaToken'));
    if (!user) return apiError(401, 'unauthorized', 'Invalid credentials');
    const valid =
      (typeof input.code === 'string' && SIX_DIGITS.test(input.code)) ||
      (typeof input.recoveryCode === 'string' && input.recoveryCode.length >= 10);
    if (!valid) return apiError(401, 'unauthorized', 'Invalid credentials');
    challenges.delete(String(input.mfaToken));
    const result = issueTokens(user, true);
    return { ...result, body: result.body };
  },

  AuthController_refresh_v1: (request) => {
    const rt = text(request, 'refreshToken');
    const id = refreshTokens.get(rt);
    const session = id ? sessions.get(id) : undefined;
    if (!session) return apiError(401, 'unauthorized', 'Unauthorized');
    refreshTokens.delete(rt);
    const user = parseHint(session.user.email) ?? session.user;
    return issueTokens(user, session.mfaAuthenticated || user.mfaEnabled, session.id);
  },

  AuthController_logout_v1: (request) => {
    const session = sessionOf(request);
    if (session) sessions.delete(session.id);
    return noContent();
  },

  AuthController_logoutAll_v1: (request) => {
    const session = sessionOf(request);
    if (!session) return apiError(401, 'unauthorized', 'Unauthorized');
    for (const [id, s] of sessions) if (s.user.id === session.user.id) sessions.delete(id);
    return noContent();
  },

  AuthController_me_v1: (request) => {
    if (request.token?.startsWith('devovr_')) {
      const [, sessionId] = request.token.split('_');
      const session = sessionId ? sessions.get(sessionId) : undefined;
      if (!session?.override) return apiError(401, 'unauthorized', 'Unauthorized');
      const target =
        ALL_ORGS.find((o) => o.id === session.override?.organizationId) ?? PLATFORM_ORG;
      return ok('AuthController_me_v1', {
        user: {
          id: session.user.id,
          email: session.user.email,
          displayName: session.user.displayName,
          status: 'active',
        },
        organization: { id: target.id, slug: target.slug, name: target.name, kind: target.kind },
        roles: [session.user.role],
        permissions: ROLE_PERMISSIONS[session.user.role].filter((p) => !p.startsWith('platform:')),
        mfaEnabled: true,
        emailVerified: true,
        mfaEnrollmentRequired: false,
        session: { id: session.id, mfaAuthenticated: true },
        override: session.override,
      });
    }
    return withSession(request, (session) => {
      const user = parseHint(session.user.email) ?? session.user;
      const org = homeOrg(user);
      return ok('AuthController_me_v1', {
        user: { id: user.id, email: user.email, displayName: user.displayName, status: 'active' },
        organization: { id: org.id, slug: org.slug, name: org.name, kind: org.kind },
        roles: [user.role],
        permissions: [...ROLE_PERMISSIONS[user.role]],
        mfaEnabled: user.mfaEnabled,
        emailVerified: true,
        mfaEnrollmentRequired: user.mfaEnrollmentRequired,
        session: { id: session.id, mfaAuthenticated: session.mfaAuthenticated },
        override: null,
      });
    });
  },

  SessionsController_list_v1: (request) =>
    withSession(request, (current) =>
      ok('SessionsController_list_v1', {
        data: [...sessions.values()]
          .filter((s) => s.user.id === current.user.id)
          .map((s) => ({
            id: s.id,
            current: s.id === current.id,
            authenticatedAt: s.createdAt,
            lastUsedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
            ipAddress: '192.0.2.10',
            userAgent: 'Mozilla/5.0 (dev fixtures)',
            mfaAuthenticated: s.mfaAuthenticated,
          })),
      }),
    ),

  SessionsController_revoke_v1: (request) =>
    withSession(request, (current) => {
      const target = sessions.get(request.params.sessionId ?? '');
      if (!target || target.user.id !== current.user.id)
        return apiError(404, 'not_found', 'Not found');
      sessions.delete(target.id);
      return noContent();
    }),

  MfaController_setup_v1: (request) =>
    withSession(request, (session) =>
      session.user.mfaEnabled
        ? apiError(409, 'conflict', 'MFA is already enabled')
        : ok('MfaController_setup_v1', {
            secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
            otpauthUri: `otpauth://totp/Email%20Gateway%20(dev):${encodeURIComponent(session.user.email)}?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Email%20Gateway%20(dev)&algorithm=SHA1&digits=6&period=30`,
          }),
    ),

  MfaController_enable_v1: (request) =>
    withSession(request, (session) => {
      if (!SIX_DIGITS.test(text(request, 'code'))) {
        return apiError(403, 'forbidden', 'Invalid code');
      }
      enrolled.set(session.user.id, true);
      session.user = { ...session.user, mfaEnabled: true, mfaEnrollmentRequired: false };
      session.mfaAuthenticated = true;
      return ok('MfaController_enable_v1', { recoveryCodes: recoveryCodes() });
    }),

  MfaController_disable_v1: (request) =>
    withSession(request, (session) => {
      if (!SIX_DIGITS.test(text(request, 'code')))
        return apiError(403, 'forbidden', 'Invalid code');
      enrolled.set(session.user.id, false);
      session.user = { ...session.user, mfaEnabled: false };
      return noContent();
    }),

  MfaController_regenerate_v1: (request) =>
    withSession(request, () =>
      SIX_DIGITS.test(text(request, 'code'))
        ? ok('MfaController_regenerate_v1', { recoveryCodes: recoveryCodes() })
        : apiError(403, 'forbidden', 'Invalid code'),
    ),

  AuthController_changePassword_v1: (request) =>
    withSession(request, () => {
      const next = text(request, 'newPassword');
      if (next.length < 12 || next.length > 128) {
        return apiError(400, 'validation_failed', ['newPassword: must be 12-128 characters']);
      }
      return noContent();
    }),

  AuthController_sendVerification_v1: (request) => withSession(request, () => ({ status: 202 })),

  AuthController_forgotPassword_v1: () => ({ status: 202 }),

  AuthController_resetPassword_v1: (request) =>
    text(request, 'token').startsWith('egt_')
      ? noContent()
      : apiError(400, 'validation_failed', 'Invalid or expired token'),

  AuthController_verifyEmail_v1: (request) =>
    text(request, 'token').startsWith('egt_')
      ? noContent()
      : apiError(400, 'validation_failed', 'Invalid or expired token'),

  AuthController_inspectInvitation_v1: (request) =>
    text(request, 'token').startsWith('egt_')
      ? ok('AuthController_inspectInvitation_v1', {
          email: 'invited.user@example.com',
          organizationName: CUSTOMER_ORGS[0]?.name ?? 'Alpha',
          expiresAt: new Date(anchor + 6 * 86_400_000).toISOString(),
        })
      : apiError(400, 'validation_failed', 'Invalid or expired token'),

  AuthController_acceptInvitation_v1: (request) =>
    text(request, 'token').startsWith('egt_')
      ? noContent()
      : apiError(400, 'validation_failed', 'Invalid or expired token'),

  PlatformOverrideController_start_v1: (request) =>
    withSession(request, (session) => {
      if (!ROLE_PERMISSIONS[session.user.role].includes('platform:tenant_override')) {
        return apiError(403, 'forbidden', 'Forbidden');
      }
      if (!session.mfaAuthenticated) return apiError(403, 'mfa_required', 'MFA required');
      const input = body(request);
      const target = CUSTOMER_ORGS.find((o) => o.id === input.organizationId);
      if (!target) return apiError(404, 'organization_not_found', 'Organization not found');
      const minutes = typeof input.durationMinutes === 'number' ? input.durationMinutes : 30;
      session.override = {
        id: random.uuid(),
        organizationId: target.id,
        reason: text(request, 'reason'),
        expiresAt: new Date(Date.now() + minutes * 60_000).toISOString(),
      };
      return ok(
        'PlatformOverrideController_start_v1',
        {
          overrideId: session.override.id,
          accessToken: `devovr_${session.id}_${crypto.randomUUID().replace(/-/g, '')}`,
          tokenType: 'Bearer',
          expiresAt: session.override.expiresAt,
          organization: { id: target.id, slug: target.slug, name: target.name },
        },
        201,
      );
    }),

  PlatformOverrideController_end_v1: (request) =>
    withSession(request, (session) => {
      if (!session.override || session.override.id !== request.params.overrideId) {
        return apiError(404, 'not_found', 'Not found');
      }
      session.override = null;
      return noContent();
    }),

  OrganizationsController_get_v1: (request) =>
    withSession(request, () => {
      const org = ALL_ORGS.find((o) => o.id === request.params.id);
      return org
        ? ok('OrganizationsController_get_v1', org)
        : apiError(404, 'not_found', 'Not found');
    }),

  OrganizationsController_list_v1: (request) =>
    withSession(request, (session) => {
      const user = session.user;
      const visible = ROLE_PERMISSIONS[user.role].includes('platform:organizations')
        ? ALL_ORGS
        : [homeOrg(user)];
      const q = request.query.get('q')?.toLowerCase();
      const kind = request.query.get('kind');
      const filtered = visible.filter(
        (o) =>
          (!q || o.name.toLowerCase().includes(q) || o.slug.includes(q)) &&
          (!kind || o.kind === kind),
      );
      return { status: 200, body: paginate(filtered, request.query) };
    }),
};

/** The principal behind a fixture token (for feature fixtures that filter by role or tenant). */
export function resolveFixturePrincipal(
  accessToken: string | null,
): { role: SystemRoleKey; permissions: readonly string[]; organizationId: string } | null {
  if (!accessToken) return null;
  if (accessToken.startsWith('devovr_')) {
    const session = sessions.get(accessToken.split('_')[1] ?? '');
    if (!session?.override) return null;
    return {
      role: session.user.role,
      permissions: ROLE_PERMISSIONS[session.user.role].filter((p) => !p.startsWith('platform:')),
      organizationId: session.override.organizationId,
    };
  }
  const id = accessTokens.get(accessToken);
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  return {
    role: session.user.role,
    permissions: ROLE_PERMISSIONS[session.user.role],
    organizationId: homeOrg(session.user).id,
  };
}
