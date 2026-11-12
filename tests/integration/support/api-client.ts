import { hash } from 'argon2';
import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import { stack } from './env';
import { secretBoxEncrypt } from './smtp-fixtures';
import { base32Encode, totp } from './totp';

/**
 * A tenant user of a fixture organization, logged in to the RUNNING api (API_HOST_PORT; the
 * `api` container of the apps profile or `pnpm --filter @email-gateway/api dev` on the host).
 * The password is stored as an Argon2id hash with the api's parameters (AUTH_ARGON2_*), exactly
 * as the api's PasswordHasher stores it, and never printed. Removed by `remove()`.
 *
 * With `{ mfa: true }` (step 4.5: the DLP evidence endpoint is `@RequireMfa`) the user gets a
 * TOTP secret stored exactly as the api's SecretBox stores it (AES-256-GCM with
 * DATA_ENCRYPTION_KEY, AAD `mfa:user:<id>`) and logs in with password, then the TOTP code, like
 * a person would; neither the password nor the secret is ever printed.
 */
export interface ApiResponse {
  status: number;
  body: unknown;
  headers: Headers;
}

export interface ApiSession {
  userId: bigint;
  /** The user's e-mail address (verified). */
  email: string;
  /** Public id of the user (the operator id in lifecycle history and audit rows). */
  userPublicId: string;
  get(path: string): Promise<ApiResponse>;
  /** A GET whose body is returned as bytes (downloads, step 5.3 Q12); never parsed or printed. */
  getRaw(path: string): Promise<{ status: number; bytes: Buffer; headers: Headers }>;
  put(path: string, body: unknown): Promise<ApiResponse>;
  post(path: string, body: unknown, headers?: Record<string, string>): Promise<ApiResponse>;
  patch(path: string, body: unknown): Promise<ApiResponse>;
  delete(path: string): Promise<ApiResponse>;
  /**
   * Fresh re-authentication material (step 5.3 Q12 download grants): the password and, for an
   * MFA user, a TOTP code of a 30-second step not used before by this session (the api's TOTP
   * verification is replay-protected, so this waits for the next step when needed). Never print.
   */
  reauth(): Promise<{ password: string; totpCode?: string }>;
  remove(): Promise<void>;
}

export const apiBaseUrl = () => `http://${stack.host}:${stack.ports.services.api}`;

export async function apiRunning(): Promise<boolean> {
  try {
    const res = await fetch(`${apiBaseUrl()}/health/ready`, { signal: AbortSignal.timeout(2_000) });
    return res.ok;
  } catch {
    return false;
  }
}

export async function apiSession(
  prisma: PrismaClient,
  organization: { id: bigint; slug: string },
  roleKey: string,
  options: { mfa?: boolean; email?: string } = {},
): Promise<ApiSession> {
  const email = options.email ?? `it-${randomBytes(6).toString('hex')}@routing.integration.test`;
  const password = `It-${randomBytes(18).toString('base64url')}!9a`;
  const passwordHash = await hash(password.normalize('NFKC'), {
    type: 2, // argon2id
    memoryCost: Number(process.env.AUTH_ARGON2_MEMORY_KIB ?? 19_456),
    timeCost: Number(process.env.AUTH_ARGON2_TIME_COST ?? 2),
    parallelism: Number(process.env.AUTH_ARGON2_PARALLELISM ?? 1),
  });
  const existingSettings = await prisma.organizationSetting.findUnique({
    where: { organizationId: organization.id },
  });
  if (!existingSettings) {
    await prisma.organizationSetting.create({
      data: { organizationId: organization.id, mfaRequired: false },
    });
  }
  const user = await prisma.user.create({
    data: {
      organizationId: organization.id,
      email,
      displayName: 'Routing stack test',
      status: 'active',
      passwordHash,
      emailVerifiedAt: new Date(),
    },
    select: { id: true, publicId: true },
  });
  const role = await prisma.role.findFirstOrThrow({
    where: { key: roleKey, organizationId: null },
    select: { id: true },
  });
  await prisma.userRole.create({
    data: { userId: user.id, roleId: role.id, organizationId: organization.id },
  });
  const mfaKey = options.mfa ? randomBytes(20) : undefined;
  if (mfaKey) {
    await prisma.user.update({
      where: { id: user.id },
      data: {
        mfaEnabled: true,
        mfaSecretCiphertext: secretBoxEncrypt(base32Encode(mfaKey), `mfa:user:${user.id}`),
      },
    });
  }

  const login = await fetch(`${apiBaseUrl()}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password, organization: organization.slug }),
  });
  if (login.status !== 200) throw new Error(`api login failed with ${login.status}`);
  const first = (await login.json()) as {
    accessToken?: string;
    mfaRequired?: boolean;
    mfaToken?: string;
  };
  let accessToken = first.accessToken;
  let lastStep = -1;
  const nextTotp = async (key: Buffer): Promise<string> => {
    let step = Math.floor(Date.now() / 30_000);
    while (step <= lastStep) {
      await new Promise((r) => setTimeout(r, 1_000));
      step = Math.floor(Date.now() / 30_000);
    }
    lastStep = step;
    return totp(key, step);
  };
  if (first.mfaRequired) {
    if (!mfaKey) throw new Error('the api asked for MFA, but the user has no TOTP secret');
    const verify = await fetch(`${apiBaseUrl()}/api/v1/auth/mfa/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ mfaToken: first.mfaToken, code: await nextTotp(mfaKey) }),
    });
    if (verify.status !== 200) throw new Error(`MFA verification failed with ${verify.status}`);
    accessToken = ((await verify.json()) as { accessToken: string }).accessToken;
  }
  if (!accessToken) throw new Error('api login returned no access token');
  const call = async (
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ): Promise<ApiResponse> => {
    const res = await fetch(`${apiBaseUrl()}/api/v1${path}`, {
      method,
      headers: {
        ...headers,
        authorization: `Bearer ${accessToken}`,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    return {
      status: res.status,
      body: text ? (JSON.parse(text) as unknown) : null,
      headers: res.headers,
    };
  };
  return {
    userId: user.id,
    email,
    userPublicId: user.publicId,
    get: (path) => call('GET', path),
    getRaw: async (path) => {
      const res = await fetch(`${apiBaseUrl()}/api/v1${path}`, {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      return {
        status: res.status,
        bytes: Buffer.from(await res.arrayBuffer()),
        headers: res.headers,
      };
    },
    put: (path, body) => call('PUT', path, body),
    post: (path, body, headers) => call('POST', path, body, headers),
    patch: (path, body) => call('PATCH', path, body),
    delete: (path) => call('DELETE', path),
    reauth: async () => ({
      password,
      ...(mfaKey ? { totpCode: await nextTotp(mfaKey) } : {}),
    }),
    remove: async () => {
      // Roles, sessions and tokens cascade with the user; login audit rows reference the
      // organization (fixture data, removed like the api suites remove theirs).
      await prisma.loginAuditLog.deleteMany({ where: { organizationId: organization.id } });
      await prisma.user.deleteMany({ where: { id: user.id } });
      if (!existingSettings) {
        await prisma.organizationSetting.deleteMany({ where: { organizationId: organization.id } });
      }
    },
  };
}
