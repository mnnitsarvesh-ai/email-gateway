import 'server-only';
import { z } from 'zod';
import type { ServerConfig } from '@/server/config';
import { MFA_AAD, SESSION_AAD, randomToken, seal, unseal } from './seal';

/** Sealed session cookie budget (design P2); browsers cap a cookie at 4096 bytes. */
export const SESSION_COOKIE_MAX_BYTES = 3_800;
/** MFA challenges live at most this long (the api's challenge TTL is 300 s). */
export const MFA_CHALLENGE_MAX_SECONDS = 300;

const overrideSchema = z
  .object({
    id: z.string().min(1),
    at: z.string().min(1),
    exp: z.number().int(),
    organizationId: z.string().min(1),
    organizationName: z.string(),
  })
  .strict();

const sessionSchema = z
  .object({
    v: z.literal(1),
    at: z.string().min(1),
    atExp: z.number().int(),
    rt: z.string().min(1),
    rtExp: z.number().int(),
    sid: z.string().min(1),
    csrf: z.string().min(16),
    mfaEnroll: z.boolean(),
    ovr: overrideSchema.optional(),
  })
  .strict();

const mfaSchema = z
  .object({
    v: z.literal(1),
    mfaToken: z.string().min(1),
    exp: z.number().int(),
    next: z.string().optional(),
  })
  .strict();

export type PortalSession = z.infer<typeof sessionSchema>;
export type SessionOverride = z.infer<typeof overrideSchema>;
export type MfaChallenge = z.infer<typeof mfaSchema>;

export interface CookieNames {
  readonly session: string;
  readonly mfa: string;
  readonly csrf: string;
}

/** `__Host-` names on https; plain `eg_*` names when the public origin is http (local/ci only). */
export function cookieNames(secure: boolean): CookieNames {
  return secure
    ? { session: '__Host-eg_session', mfa: '__Host-eg_mfa', csrf: '__Host-eg_csrf' }
    : { session: 'eg_session', mfa: 'eg_mfa', csrf: 'eg_csrf' };
}

export function parseCookies(header: string | null | undefined): Map<string, string> {
  const map = new Map<string, string>();
  if (!header) return map;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!map.has(name)) map.set(name, value);
  }
  return map;
}

interface CookieOptions {
  httpOnly: boolean;
  maxAgeSeconds: number;
}

/** Attributes exactly as P2: `HttpOnly` (except CSRF); `Secure; SameSite=Strict; Path=/`. */
export function serializeCookie(name: string, value: string, options: CookieOptions): string {
  const parts = [`${name}=${value}`, 'Path=/', 'Secure', 'SameSite=Strict'];
  if (options.httpOnly) parts.push('HttpOnly');
  parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAgeSeconds))}`);
  return parts.join('; ');
}

function keys(config: ServerConfig): string[] {
  return [config.PORTAL_SESSION_KEY, config.PORTAL_SESSION_KEY_PREVIOUS].filter(
    (key): key is string => Boolean(key),
  );
}

export async function readSession(
  cookieHeader: string | null | undefined,
  config: ServerConfig,
): Promise<PortalSession | null> {
  const sealed = parseCookies(cookieHeader).get(cookieNames(config.secure).session);
  const value = await unseal(sealed, keys(config), SESSION_AAD);
  const parsed = sessionSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

export async function readMfaChallenge(
  cookieHeader: string | null | undefined,
  config: ServerConfig,
  now = Date.now(),
): Promise<MfaChallenge | null> {
  const sealed = parseCookies(cookieHeader).get(cookieNames(config.secure).mfa);
  const parsed = mfaSchema.safeParse(await unseal(sealed, keys(config), MFA_AAD));
  if (!parsed.success || parsed.data.exp <= now) return null;
  return parsed.data;
}

export class CookieTooLargeError extends Error {
  constructor(readonly bytes: number) {
    super(`Sealed session cookie of ${bytes} bytes exceeds ${SESSION_COOKIE_MAX_BYTES}`);
    this.name = 'CookieTooLargeError';
  }
}

export async function sealSession(session: PortalSession, config: ServerConfig): Promise<string> {
  const sealed = await seal(sessionSchema.parse(session), config.PORTAL_SESSION_KEY, SESSION_AAD);
  if (sealed.length > SESSION_COOKIE_MAX_BYTES) throw new CookieTooLargeError(sealed.length);
  return sealed;
}

/** Session and CSRF cookies for a (re)sealed session; Max-Age runs until the refresh expiry. */
export async function sessionCookies(
  session: PortalSession,
  config: ServerConfig,
  now = Date.now(),
): Promise<string[]> {
  const names = cookieNames(config.secure);
  const maxAge = Math.max(1, Math.floor((session.rtExp - now) / 1000));
  const sealed = await sealSession(session, config);
  return [
    serializeCookie(names.session, sealed, { httpOnly: true, maxAgeSeconds: maxAge }),
    serializeCookie(names.csrf, session.csrf, { httpOnly: false, maxAgeSeconds: maxAge }),
  ];
}

export async function mfaChallengeCookie(
  challenge: MfaChallenge,
  config: ServerConfig,
  now = Date.now(),
): Promise<string> {
  const maxAge = Math.min(MFA_CHALLENGE_MAX_SECONDS, Math.floor((challenge.exp - now) / 1000));
  const sealed = await seal(mfaSchema.parse(challenge), config.PORTAL_SESSION_KEY, MFA_AAD);
  return serializeCookie(cookieNames(config.secure).mfa, sealed, {
    httpOnly: true,
    maxAgeSeconds: maxAge,
  });
}

export function clearMfaCookie(config: ServerConfig): string {
  return serializeCookie(cookieNames(config.secure).mfa, '', { httpOnly: true, maxAgeSeconds: 0 });
}

/** Expires all three cookies (logout, refresh failure, tampering). */
export function clearSessionCookies(config: ServerConfig): string[] {
  const names = cookieNames(config.secure);
  return [
    serializeCookie(names.session, '', { httpOnly: true, maxAgeSeconds: 0 }),
    serializeCookie(names.csrf, '', { httpOnly: false, maxAgeSeconds: 0 }),
    clearMfaCookie(config),
  ];
}

/** The api's token response (login, MFA verify, refresh). */
export interface TokenResponse {
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  refreshTokenExpiresAt: string;
  sessionId: string;
  mfaEnrollmentRequired: boolean;
}

const tokenResponseSchema = z.object({
  accessToken: z.string().min(1),
  expiresIn: z.number().int().positive(),
  refreshToken: z.string().min(1),
  refreshTokenExpiresAt: z.string().min(1),
  sessionId: z.string().min(1),
  mfaEnrollmentRequired: z.boolean(),
});

export function isTokenResponse(value: unknown): value is TokenResponse {
  return tokenResponseSchema.safeParse(value).success;
}

/** A new session from a token response; the CSRF token rotates with every seal of new tokens. */
export function sessionFromTokens(
  tokens: TokenResponse,
  now = Date.now(),
  previous?: PortalSession | null,
): PortalSession {
  const rtExp = Date.parse(tokens.refreshTokenExpiresAt);
  return {
    v: 1,
    at: tokens.accessToken,
    atExp: now + tokens.expiresIn * 1000,
    rt: tokens.refreshToken,
    rtExp: Number.isFinite(rtExp) ? rtExp : now + tokens.expiresIn * 1000,
    sid: tokens.sessionId,
    csrf: randomToken(32),
    mfaEnroll: tokens.mfaEnrollmentRequired,
    ...(previous?.ovr && previous.ovr.exp > now ? { ovr: previous.ovr } : {}),
  };
}

/** Public, token-free view of the session (`GET /bff/session`). */
export interface SessionView {
  authenticated: boolean;
  accessExpiresAt: string | null;
  refreshExpiresAt: string | null;
  mfaEnrollmentRequired: boolean;
  override: {
    id: string;
    organizationId: string;
    organizationName: string;
    expiresAt: string;
  } | null;
}

export function sessionView(session: PortalSession | null, now = Date.now()): SessionView {
  if (!session || session.rtExp <= now) {
    return {
      authenticated: false,
      accessExpiresAt: null,
      refreshExpiresAt: null,
      mfaEnrollmentRequired: false,
      override: null,
    };
  }
  const ovr = session.ovr && session.ovr.exp > now ? session.ovr : null;
  return {
    authenticated: true,
    accessExpiresAt: new Date(session.atExp).toISOString(),
    refreshExpiresAt: new Date(session.rtExp).toISOString(),
    mfaEnrollmentRequired: session.mfaEnroll,
    override: ovr
      ? {
          id: ovr.id,
          organizationId: ovr.organizationId,
          organizationName: ovr.organizationName,
          expiresAt: new Date(ovr.exp).toISOString(),
        }
      : null,
  };
}
