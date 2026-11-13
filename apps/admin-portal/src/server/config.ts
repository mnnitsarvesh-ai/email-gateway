import 'server-only';
import { readFileSync } from 'node:fs';
import { z } from 'zod';

/**
 * Portal server configuration (design §3.5). Loaded once, validated with zod, never sent to the
 * browser (no `NEXT_PUBLIC_*` keys exist). Errors name the key, never its value.
 */

const FILE_KEYS = [
  'PORTAL_SESSION_KEY',
  'PORTAL_SESSION_KEY_PREVIOUS',
  'API_TRUSTED_FORWARDER_TOKEN',
] as const;

const origin = (key: string) =>
  z
    .string()
    .url(`${key} must be an http(s) origin`)
    .transform((value, ctx) => {
      let url: URL;
      try {
        url = new URL(value);
      } catch {
        ctx.addIssue({ code: 'custom', message: `${key} must be an http(s) origin` });
        return z.NEVER;
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        ctx.addIssue({ code: 'custom', message: `${key} must use http or https` });
        return z.NEVER;
      }
      if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) {
        ctx.addIssue({ code: 'custom', message: `${key} must be an origin without a path` });
        return z.NEVER;
      }
      return url.origin;
    });

const hexKey = (key: string) =>
  z.string().regex(/^[0-9a-fA-F]{64}$/, `${key} must be 64 hexadecimal characters (32 bytes)`);

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    APP_ENV: z.enum(['local', 'ci', 'staging', 'production']).default('local'),
    API_INTERNAL_URL: origin('API_INTERNAL_URL'),
    PORTAL_PUBLIC_URL: origin('PORTAL_PUBLIC_URL'),
    PORTAL_SESSION_KEY: hexKey('PORTAL_SESSION_KEY'),
    PORTAL_SESSION_KEY_PREVIOUS: hexKey('PORTAL_SESSION_KEY_PREVIOUS').optional(),
    API_TRUSTED_FORWARDER_TOKEN: z
      .string()
      .min(32, 'API_TRUSTED_FORWARDER_TOKEN must be 32-256 characters')
      .max(256, 'API_TRUSTED_FORWARDER_TOKEN must be 32-256 characters')
      .optional(),
    PORTAL_TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(5).default(0),
    PORTAL_API_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(60_000).default(15_000),
    PORTAL_DEV_MOCKS: z.enum(['disabled', 'enabled']).default('disabled'),
  })
  .superRefine((cfg, ctx) => {
    const localLike = cfg.APP_ENV === 'local' || cfg.APP_ENV === 'ci';
    if (cfg.PORTAL_PUBLIC_URL.startsWith('http:') && !localLike) {
      ctx.addIssue({
        code: 'custom',
        path: ['PORTAL_PUBLIC_URL'],
        message: 'must be an https:// origin unless APP_ENV is local or ci',
      });
    }
    if (cfg.PORTAL_TRUST_PROXY_HOPS === 0 && !localLike) {
      ctx.addIssue({
        code: 'custom',
        path: ['PORTAL_TRUST_PROXY_HOPS'],
        message:
          'must be at least 1 unless APP_ENV is local or ci (with 0 a client-sent X-Forwarded-For chooses the forwarded IP)',
      });
    }
    if (cfg.NODE_ENV === 'production' && !cfg.API_TRUSTED_FORWARDER_TOKEN) {
      ctx.addIssue({
        code: 'custom',
        path: ['API_TRUSTED_FORWARDER_TOKEN'],
        message: 'is required when NODE_ENV=production (ADR-0060)',
      });
    }
    if (cfg.PORTAL_DEV_MOCKS === 'enabled' && cfg.NODE_ENV !== 'development') {
      ctx.addIssue({
        code: 'custom',
        path: ['PORTAL_DEV_MOCKS'],
        message: 'enabled is allowed only with NODE_ENV=development (design P9)',
      });
    }
    if (
      cfg.PORTAL_SESSION_KEY_PREVIOUS &&
      cfg.PORTAL_SESSION_KEY_PREVIOUS.toLowerCase() === cfg.PORTAL_SESSION_KEY.toLowerCase()
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['PORTAL_SESSION_KEY_PREVIOUS'],
        message: 'must differ from PORTAL_SESSION_KEY',
      });
    }
  });

export type ServerConfig = Readonly<z.infer<typeof schema>> & {
  /** `https:` public origin: `__Host-` cookie names, HSTS, `upgrade-insecure-requests`. */
  readonly secure: boolean;
};

export class PortalConfigError extends Error {
  constructor(readonly issues: string[]) {
    super(`Invalid admin-portal configuration:\n  ${issues.join('\n  ')}`);
    this.name = 'PortalConfigError';
  }
}

/** Reads `<KEY>_FILE` into `<KEY>` when `<KEY>` is unset or empty (Kubernetes Secret files). */
export function resolveFileSecrets(
  env: Record<string, string | undefined>,
  readFile: (path: string) => string = (path) => readFileSync(path, 'utf8'),
): Record<string, string | undefined> {
  const resolved = { ...env };
  for (const key of FILE_KEYS) {
    const path = env[`${key}_FILE`];
    if (!path || (resolved[key] !== undefined && resolved[key] !== '')) continue;
    try {
      resolved[key] = readFile(path).trim();
    } catch {
      throw new PortalConfigError([`${key}_FILE: the file cannot be read`]);
    }
  }
  return resolved;
}

/** Validates an environment (pure; `getServerConfig` caches the result for `process.env`). */
export function loadServerConfig(
  env: Record<string, string | undefined>,
  readFile?: (path: string) => string,
): ServerConfig {
  const withFiles = resolveFileSecrets(env, readFile);
  const nonEmpty = Object.fromEntries(
    Object.entries(withFiles).filter(([, value]) => value !== undefined && value !== ''),
  );
  const result = schema.safeParse(nonEmpty);
  if (!result.success) {
    throw new PortalConfigError(
      result.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`),
    );
  }
  return Object.freeze({
    ...result.data,
    secure: result.data.PORTAL_PUBLIC_URL.startsWith('https:'),
  });
}

let cached: ServerConfig | undefined;

export function getServerConfig(): ServerConfig {
  cached ??= loadServerConfig(process.env);
  return cached;
}

/** Tests only: forget the cached configuration. */
export function resetServerConfigForTests(): void {
  cached = undefined;
}
