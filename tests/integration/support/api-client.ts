import { hash } from 'argon2';
import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import { stack } from './env';

/**
 * A tenant user of a fixture organization, logged in to the RUNNING api (API_HOST_PORT; the
 * `api` container of the apps profile or `pnpm --filter @email-gateway/api dev` on the host).
 * The password is stored as an Argon2id hash with the api's parameters (AUTH_ARGON2_*), exactly
 * as the api's PasswordHasher stores it, and never printed. Removed by `remove()`.
 */
export interface ApiResponse {
  status: number;
  body: unknown;
  headers: Headers;
}

export interface ApiSession {
  userId: bigint;
  /** Public id of the user (the operator id in lifecycle history and audit rows). */
  userPublicId: string;
  get(path: string): Promise<ApiResponse>;
  put(path: string, body: unknown): Promise<ApiResponse>;
  post(path: string, body: unknown, headers?: Record<string, string>): Promise<ApiResponse>;
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
): Promise<ApiSession> {
  const email = `it-${randomBytes(6).toString('hex')}@routing.integration.test`;
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

  const login = await fetch(`${apiBaseUrl()}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password, organization: organization.slug }),
  });
  if (login.status !== 200) throw new Error(`api login failed with ${login.status}`);
  const { accessToken } = (await login.json()) as { accessToken: string };
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
    userPublicId: user.publicId,
    get: (path) => call('GET', path),
    put: (path, body) => call('PUT', path, body),
    post: (path, body, headers) => call('POST', path, body, headers),
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
