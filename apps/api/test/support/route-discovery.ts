/**
 * Route discovery for the route-level suites (route security, the step 6.1 conventions and the
 * WP5 inventory): every controller route of the running app (Nest discovery) with its
 * authorization, rate-limit, rate-class, idempotency, secret and cursor metadata, and the routes
 * Express actually serves.
 */
import { type INestApplication, RequestMethod, VERSION_NEUTRAL } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA, VERSION_METADATA } from '@nestjs/common/constants';
import { DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core';
import {
  AUTHZ_KEY,
  CURSOR_LIST_KEY,
  type CursorEncoding,
  IS_PUBLIC_KEY,
  REQUIRE_MFA_KEY,
  USER_ONLY_KEY,
} from '../../src/auth-contracts/decorators';
import { API_GLOBAL_PREFIX } from '../../src/http/configure-api-app';
import type { IdempotentOptions } from '../../src/http/idempotency/idempotency.interceptor';
import { QUARANTINE_RATE_LIMIT_KEY } from '../../src/modules/quarantine/quarantine-rate-limit';
import {
  IDEMPOTENT_KEY,
  RATE_CLASS_KEY,
  type RateClass,
  RETURNS_SECRET_KEY,
} from '../../src/rate-limit/rate-class.decorator';
import { RATE_LIMIT_KEY, type RateLimitOptions } from '../../src/rate-limit/rate-limit.options';

/** Probes and the Prometheus scrape stay outside the `/api` prefix (configureApiApp). */
export const PREFIX_EXCLUDED = new Set(['health/live', 'health/ready', 'metrics']);
const DEFAULT_VERSION = '1';

export interface DiscoveredRoute {
  method: string;
  path: string;
  name: string;
  isPublic: boolean;
  hasRequirement: boolean;
  requirement: unknown;
  requireMfa: boolean;
  userOnly: boolean;
  rateLimits: RateLimitOptions[];
  /** Config-driven quarantine rate limit kind (step 5.3), if any. */
  quarantineRate: string | null;
  /** `@RateClass()` of the route (step 6.1 D8), if any. */
  rateClass: RateClass | null;
  /** `@Idempotent()` options (step 6.1 D9), if any. */
  idempotency: IdempotentOptions | null;
  /** `@ReturnsSecret()` (step 6.1 D9). */
  returnsSecret: boolean;
  /** `@CursorList()` encoding (step 6.1 D3), if declared. */
  cursor: CursorEncoding | null;
}

const asArray = (value: unknown): string[] =>
  Array.isArray(value) ? (value as string[]) : [typeof value === 'string' ? value : ''];
const join = (...parts: string[]) =>
  `/${parts
    .flatMap((p) => p.split('/'))
    .filter(Boolean)
    .join('/')}`;

/** Needs `DiscoveryModule` among the testing module's imports. */
export function discoverRoutes(app: INestApplication): DiscoveredRoute[] {
  const discovery = app.get(DiscoveryService);
  const scanner = app.get(MetadataScanner);
  const reflector = app.get(Reflector);
  const routes: DiscoveredRoute[] = [];
  for (const wrapper of discovery.getControllers()) {
    const controller = wrapper.metatype as (new (...args: never[]) => object) | null;
    if (!controller || !wrapper.instance) continue;
    const prototype = Object.getPrototypeOf(wrapper.instance) as Record<string, unknown>;
    for (const name of scanner.getAllMethodNames(prototype)) {
      const handler = prototype[name] as (...args: unknown[]) => unknown;
      const methodPath = Reflect.getMetadata(PATH_METADATA, handler) as unknown;
      if (methodPath === undefined) continue;
      const verb = RequestMethod[Reflect.getMetadata(METHOD_METADATA, handler) as number];
      const version =
        (Reflect.getMetadata(VERSION_METADATA, handler) as string | symbol | undefined) ??
        (Reflect.getMetadata(VERSION_METADATA, controller) as string | symbol | undefined) ??
        DEFAULT_VERSION;
      const targets = [handler, controller];
      for (const base of asArray(Reflect.getMetadata(PATH_METADATA, controller))) {
        for (const sub of asArray(methodPath)) {
          const relative = join(base, sub).slice(1);
          const prefix = PREFIX_EXCLUDED.has(relative) ? '' : API_GLOBAL_PREFIX;
          const versionSegment = version === VERSION_NEUTRAL ? '' : `v${String(version)}`;
          routes.push({
            method: verb!.toLowerCase(),
            path: join(prefix, versionSegment, relative),
            name: `${controller.name}.${name}`,
            isPublic: !!reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, targets),
            hasRequirement: reflector.getAllAndOverride<unknown>(AUTHZ_KEY, targets) !== undefined,
            requirement: reflector.getAllAndOverride<unknown>(AUTHZ_KEY, targets),
            requireMfa: !!reflector.getAllAndOverride<boolean>(REQUIRE_MFA_KEY, targets),
            userOnly: !!reflector.getAllAndOverride<boolean>(USER_ONLY_KEY, targets),
            rateLimits: (Reflect.getMetadata(RATE_LIMIT_KEY, handler) as RateLimitOptions[]) ?? [],
            quarantineRate:
              (Reflect.getMetadata(QUARANTINE_RATE_LIMIT_KEY, handler) as string | undefined) ??
              null,
            rateClass:
              reflector.getAllAndOverride<RateClass | undefined>(RATE_CLASS_KEY, targets) ?? null,
            idempotency:
              (Reflect.getMetadata(IDEMPOTENT_KEY, handler) as IdempotentOptions | undefined) ??
              null,
            returnsSecret: Reflect.getMetadata(RETURNS_SECRET_KEY, handler) === true,
            cursor:
              (Reflect.getMetadata(CURSOR_LIST_KEY, handler) as CursorEncoding | undefined) ?? null,
          });
        }
      }
    }
  }
  return routes;
}

/**
 * Controller routes registered on the Express router. Middleware applied with `forRoutes()` (the
 * correlation-id, request-id and metrics middleware) is mounted for every HTTP verb; such
 * catch-all layers are not controller routes and are skipped.
 */
export function expressRoutes(app: INestApplication): string[] {
  const instance = app.getHttpAdapter().getInstance() as {
    router: { stack: Array<{ route?: { path: string; methods: Record<string, boolean> } }> };
  };
  return instance.router.stack.flatMap((layer) => {
    const route = layer.route;
    if (!route) return [];
    const methods = Object.keys(route.methods).filter((m) => m !== '_all');
    if (route.methods._all || methods.length > 5) return [];
    return methods.map((m) => `${m} ${route.path}`);
  });
}
