import { hash } from 'argon2';
import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import { apiBaseUrl } from './api-client';
import { secretBoxEncrypt } from './smtp-fixtures';
import { base32Encode, totp } from './totp';

/**
 * A platform administrator with TOTP MFA, logged in to the RUNNING api (API_HOST_PORT: the `api`
 * container or a host process), for the stack suites that call platform endpoints (step 3.2
 * dead-letter replay: `platform:dead_letter_replay`, `@RequireMfa`, user sessions only).
 *
 * The user is created in the seeded platform organization (`platform`) with the system role
 * `platform_admin`, an Argon2id password hash with the api's parameters (AUTH_ARGON2_*) and a
 * TOTP secret encrypted exactly as the api's SecretBox stores it (AES-256-GCM with
 * DATA_ENCRYPTION_KEY, AAD `mfa:user:<id>`). It logs in with password, then the TOTP code
 * (RFC 6238, SHA-1, 6 digits, 30 s), like a person would. Neither the password nor the secret
 * is ever printed. `remove()` deletes the user (roles and sessions cascade) and its login audit
 * rows; `audit_logs` rows stay, as in the api suites.
 */
export interface PlatformAdminSession {
  userId: bigint;
  /** `users.public_id` (the audit actor id). */
  userPublicId: string;
  /**
   * `headers` are extra request headers, e.g. the `Idempotency-Key` of a step 6.1 §3.5
   * sensitive mutation (`idempotencyKey()` of ./api-client).
   */
  call(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body?: unknown,
    headers?: Record<string, string>,
  ): Promise<{ status: number; body: Record<string, unknown> }>;
  remove(): Promise<void>;
}

export { totp } from './totp';

export async function platformAdminSession(prisma: PrismaClient): Promise<PlatformAdminSession> {
  const platform = await prisma.organization.findUniqueOrThrow({
    where: { slug: 'platform' },
    select: { id: true, slug: true },
  });
  const role = await prisma.role.findFirstOrThrow({
    where: { key: 'platform_admin', organizationId: null },
    select: { id: true },
  });
  const email = `it-${randomBytes(6).toString('hex')}@messaging.integration.test`;
  const password = `It-${randomBytes(18).toString('base64url')}!9a`;
  const passwordHash = await hash(password.normalize('NFKC'), {
    type: 2, // argon2id
    memoryCost: Number(process.env.AUTH_ARGON2_MEMORY_KIB ?? 19_456),
    timeCost: Number(process.env.AUTH_ARGON2_TIME_COST ?? 2),
    parallelism: Number(process.env.AUTH_ARGON2_PARALLELISM ?? 1),
  });
  const user = await prisma.user.create({
    data: {
      organizationId: platform.id,
      email,
      displayName: 'Messaging stack test',
      status: 'active',
      passwordHash,
      emailVerifiedAt: new Date(),
    },
    select: { id: true, publicId: true },
  });
  const remove = async () => {
    await prisma.loginAuditLog.deleteMany({
      where: { OR: [{ userId: user.id }, { emailAttempted: email }] },
    });
    await prisma.user.deleteMany({ where: { id: user.id } });
  };
  try {
    await prisma.userRole.create({
      data: { userId: user.id, roleId: role.id, organizationId: platform.id },
    });
    const key = randomBytes(20);
    await prisma.user.update({
      where: { id: user.id },
      data: {
        mfaEnabled: true,
        mfaSecretCiphertext: secretBoxEncrypt(base32Encode(key), `mfa:user:${user.id}`),
      },
    });

    const post = async (
      path: string,
      body: unknown,
      token?: string,
      headers: Record<string, string> = {},
    ) => {
      const res = await fetch(`${apiBaseUrl()}/api/v1${path}`, {
        method: 'POST',
        headers: {
          ...headers,
          'content-type': 'application/json',
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60_000),
      });
      const text = await res.text();
      return {
        status: res.status,
        body: (text ? JSON.parse(text) : {}) as Record<string, unknown>,
      };
    };
    const first = await post('/auth/login', { email, password, organization: platform.slug });
    if (first.status !== 200) throw new Error(`platform login failed with ${first.status}`);
    let accessToken = first.body.accessToken as string | undefined;
    if (first.body.mfaRequired) {
      const step = Math.floor(Date.now() / 30_000);
      const second = await post('/auth/mfa/verify', {
        mfaToken: first.body.mfaToken,
        code: totp(key, step),
      });
      if (second.status !== 200) throw new Error(`MFA verification failed with ${second.status}`);
      accessToken = second.body.accessToken as string;
    }
    if (!accessToken) throw new Error('platform login returned no access token');
    const token = accessToken;

    return {
      userId: user.id,
      userPublicId: user.publicId,
      call: async (method, path, body, headers = {}) => {
        if (method === 'POST') return post(path, body ?? {}, token, headers);
        const res = await fetch(`${apiBaseUrl()}/api/v1${path}`, {
          method,
          headers: { ...headers, authorization: `Bearer ${token}` },
          signal: AbortSignal.timeout(60_000),
        });
        const text = await res.text();
        return {
          status: res.status,
          body: (text ? JSON.parse(text) : {}) as Record<string, unknown>,
        };
      },
      remove,
    };
  } catch (err) {
    await remove();
    throw err;
  }
}
