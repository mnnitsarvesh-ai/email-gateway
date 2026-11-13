/**
 * Route inventory of step 6.1 (docs/plan/steps/18-rest-api.md §9 "Route inventory", D3, D7, D9,
 * D13, D14, §3.5, §3.8): every route the running api serves (Nest discovery on the stubbed
 * AppModule) is checked against the conventions, so a route added later without its
 * authorization, documentation, tests, cursor encoding, strict schemas or idempotency metadata
 * fails here. The checks:
 *
 * 1. boundary — under `/api/v1`, or one of the three internal endpoints (D13);
 * 2. authorization — a documented `@Public()` route, a permission requirement, or an explicit
 *    `@AuthenticatedOnly()` self-service route (D7);
 * 3. OpenAPI — an operation with a tag, a summary, a security requirement (non-public), the
 *    standard error responses, a request body schema when the handler takes a body, a 2xx schema
 *    unless 204, and explicit examples on the routes new in 6.1 (D14);
 * 4. coverage — an entry in test/route-coverage (§3.8) whose e2e, integration and cross-tenant
 *    files exist and carry `@covers <method> <path>`; the manifests name no route that does not
 *    exist;
 * 5. lists — a route whose 2xx body has `nextCursor` declares `@CursorList`, the manifest agrees,
 *    and every list new in 6.1 is `v1` (D3);
 * 6. strict request schemas — every body and query schema rejects unknown fields (D1);
 * 7. sensitive mutations — every §3.5 route has idempotency metadata and the `sensitive` class;
 *    no route is both `@Idempotent()` and `@ReturnsSecret()` (D9, D10); a `@ReturnsSecret()`
 *    route takes an Idempotency-Key only when it is one of the two step 6.2 webhook secret
 *    routes and declares the redacted replay (ADR-0057).
 *
 * Step 6.2 (docs/plan/steps/19-webhooks-notifications.md §6.2) adds the 17 webhook and
 * notification routes (`NEW_IN_6_2`, examples required, lists v1), five transactional keyed
 * routes and the `SECRET_BEARING_REDACTED_REPLAY` allow-list. Step 7.1
 * (docs/plan/steps/20-admin-portal.md §3.3) adds three expensive report routes (`NEW_IN_7_1`).
 */
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants';
import { RouteParamtypes } from '@nestjs/common/enums/route-paramtypes.enum';
import { DiscoveryService } from '@nestjs/core';
import type { OpenAPIObject } from '@nestjs/swagger';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { z } from 'zod';
import { buildOpenApiDocument } from '../src/http/openapi';
import { TRANSACTIONAL_IDEMPOTENCY_KEY } from '../src/modules/messages/api-docs';
import { LifecycleOperationBodySchema } from '../src/modules/messages/dto/messages.schemas';
import { BulkBodySchema } from '../src/modules/quarantine/dto/quarantine.schemas';
import { SettingsUpdateBodySchema } from '../src/modules/notifications/notifications.schemas';
import { CreateSuppressionBodySchema } from '../src/modules/recipients/recipient-suppressions.schemas';
import {
  CreateReplayBodySchema,
  CreateWebhookBodySchema,
  RotateSecretBodySchema,
} from '../src/modules/webhooks/webhooks.schemas';
import { isStrictRequestSchema } from '../src/validation/strict-schema';
import { ZodValidationPipe } from '../src/validation/zod-validation.pipe';
import { COVERAGE, COVERAGE_BY_AREA, type RouteCoverage } from './route-coverage';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';
import { type DiscoveredRoute, discoverRoutes } from './support/route-discovery';

const REPO_ROOT = resolve(__dirname, '../../..');

/** D13: the only routes outside `/api/v1` (internal port; never in an Ingress or the document). */
const INTERNAL_ROUTES = ['get /health/live', 'get /health/ready', 'get /metrics'];

/** D7: the documented `@Public()` routes (unchanged by 6.1) and the internal endpoints. */
const PUBLIC_ROUTES = [
  ...INTERNAL_ROUTES,
  'get /api/v1/meta',
  'post /api/v1/auth/login',
  'post /api/v1/auth/mfa/verify',
  'post /api/v1/auth/refresh',
  'post /api/v1/auth/password/forgot',
  'post /api/v1/auth/password/reset',
  'post /api/v1/auth/email/verify',
  'post /api/v1/auth/invitations/inspect',
  'post /api/v1/auth/invitations/accept',
];

/**
 * D7: the self-service routes that need a principal but no permission (`@AuthenticatedOnly()`),
 * read from the code: the caller's own profile, sessions, password, email verification, MFA
 * enrollment and the end of the caller's own platform override. Everything else names a
 * permission.
 */
const AUTHENTICATED_ONLY_ROUTES = [
  'get /api/v1/auth/me',
  'post /api/v1/auth/logout',
  'post /api/v1/auth/logout-all',
  'post /api/v1/auth/password/change',
  'post /api/v1/auth/email/verification',
  'get /api/v1/auth/sessions',
  'delete /api/v1/auth/sessions/:sessionId',
  'post /api/v1/auth/mfa/totp/setup',
  'post /api/v1/auth/mfa/totp/enable',
  'post /api/v1/auth/mfa/totp/disable',
  'post /api/v1/auth/mfa/recovery-codes',
  'delete /api/v1/platform/overrides/:overrideId',
  // Step 6.2 N3: the caller's own notification preferences (users only).
  'get /api/v1/notifications/preferences',
  'put /api/v1/notifications/preferences',
];

/** §3.3: the 20 routes new in step 6.1 (examples required, lists must be v1). */
const NEW_IN_6_1 = [
  'get /api/v1/messages',
  'get /api/v1/messages/:messageId',
  'get /api/v1/messages/:messageId/recipients',
  'get /api/v1/messages/:messageId/attachments',
  'get /api/v1/attachments',
  'get /api/v1/messages/:messageId/urls',
  'get /api/v1/url-protection/clicks',
  'get /api/v1/recipients/suppressions',
  'get /api/v1/recipients/suppressions/:suppressionId',
  'post /api/v1/recipients/suppressions',
  'delete /api/v1/recipients/suppressions/:suppressionId',
  'get /api/v1/audit/logs',
  'get /api/v1/platform/audit/logs',
  'get /api/v1/reports/traffic',
  'get /api/v1/reports/threats',
  'get /api/v1/reports/url-clicks',
  'get /api/v1/usage',
  'get /api/v1/billing/plan',
  'get /api/v1/billing/usage',
  'get /api/v1/threat-intelligence/lookup',
];

/** Step 6.2 §6.1: the 17 webhook and notification routes (examples required, lists v1). */
const NEW_IN_6_2 = [
  'get /api/v1/webhooks',
  'post /api/v1/webhooks',
  'get /api/v1/webhooks/event-types',
  'get /api/v1/webhooks/:webhookId',
  'patch /api/v1/webhooks/:webhookId',
  'delete /api/v1/webhooks/:webhookId',
  'post /api/v1/webhooks/:webhookId/rotate-secret',
  'post /api/v1/webhooks/:webhookId/test',
  'get /api/v1/webhooks/:webhookId/deliveries',
  'get /api/v1/webhooks/:webhookId/deliveries/:deliveryId',
  'post /api/v1/webhooks/:webhookId/deliveries/:deliveryId/replay',
  'post /api/v1/webhooks/:webhookId/replays',
  'get /api/v1/webhooks/:webhookId/replays/:replayId',
  'get /api/v1/notifications/settings',
  'put /api/v1/notifications/settings',
  'get /api/v1/notifications/preferences',
  'put /api/v1/notifications/preferences',
];

/**
 * ADR-0057: the only routes allowed to combine `@ReturnsSecret()` with an Idempotency-Key, and
 * only as `@ReturnsSecret({ redactedReplay: true })` with the transactional mechanism (the
 * stored response carries `secret: null`).
 */
const SECRET_BEARING_REDACTED_REPLAY = [
  'post /api/v1/webhooks',
  'post /api/v1/webhooks/:webhookId/rotate-secret',
];

/** §3.5: sensitive mutations keyed transactionally (IdempotencyService.execute). */
const SENSITIVE_TRANSACTIONAL = [
  'post /api/v1/messages/:messageId/rescan',
  'post /api/v1/messages/:messageId/release',
  'post /api/v1/quarantine/bulk',
  'post /api/v1/quarantine/entries',
  'post /api/v1/quarantine/entries/:entryId/release',
  'post /api/v1/quarantine/entries/:entryId/request-release',
  'post /api/v1/quarantine/entries/:entryId/reject',
  'post /api/v1/quarantine/entries/:entryId/delete',
  'post /api/v1/quarantine/approvals/:approvalId/approve',
  'post /api/v1/quarantine/approvals/:approvalId/deny',
  'post /api/v1/quarantine/approvals/:approvalId/cancel',
  'post /api/v1/quarantine/me/entries/:entryId/release',
  'post /api/v1/quarantine/me/entries/:entryId/request-release',
  'post /api/v1/recipients/suppressions',
  'delete /api/v1/recipients/suppressions/:suppressionId',
  // Step 6.2 §6.1 (ADR-0057 for the first and third).
  'post /api/v1/webhooks',
  'delete /api/v1/webhooks/:webhookId',
  'post /api/v1/webhooks/:webhookId/rotate-secret',
  'post /api/v1/webhooks/:webhookId/deliveries/:deliveryId/replay',
  'post /api/v1/webhooks/:webhookId/replays',
];

/** §3.5: the legacy sensitive mutations keyed by the reservation interceptor (`@Idempotent`). */
const SENSITIVE_LEGACY = [
  'post /api/v1/domains/:id/dkim/rotate',
  'patch /api/v1/organizations/:id/status',
  'post /api/v1/organizations/:id/deletion',
  'post /api/v1/organizations/:id/deletion/confirm',
  'post /api/v1/users/invitations',
  'post /api/v1/users/:id/invitation',
  'post /api/v1/users/:id/mfa/reset',
  'post /api/v1/policies/:policyId/versions/:versionNo/publish',
  'post /api/v1/policies/:policyId/versions/:versionNo/activate',
  'post /api/v1/risk-scoring/profile/versions/:versionId/publish',
  'post /api/v1/risk-scoring/profile/versions/:versionId/activate',
  'post /api/v1/risk-scoring/profile/reset',
  'delete /api/v1/bec/history',
  'delete /api/v1/dlp/evidence',
  'delete /api/v1/messages/:messageId/scans/:scanId/dlp-evidence',
  'put /api/v1/dlp/compliance/aadhaar',
  'delete /api/v1/dlp/compliance/aadhaar',
  'post /api/v1/platform/dead-letters/replay',
  'post /api/v1/platform/attachment-rescans',
  'post /api/v1/platform/organizations/:organizationId/messages/:messageId/scan-training',
  'post /api/v1/platform/threat-hashes',
  'post /api/v1/platform/threat-indicators',
];

/**
 * Step 7.1 §3.3 (docs/plan/steps/20-admin-portal.md): the three reports of the admin dashboard
 * (examples required, class `expensive`, in the insights manifest).
 */
const NEW_IN_7_1 = [
  'get /api/v1/reports/delivery',
  'get /api/v1/reports/processing',
  'get /api/v1/reports/top-domains',
];

/** D9: secret-bearing responses (sensitive class, never idempotency-stored). */
const SECRET_BEARING = [
  'post /api/v1/api-keys',
  'post /api/v1/smtp-connectors',
  'post /api/v1/smtp-connectors/:id/rotate-secret',
  'post /api/v1/platform/overrides',
  'post /api/v1/auth/mfa/totp/setup',
  'post /api/v1/auth/mfa/recovery-codes',
];

/** §3.5: the `expensive` class (no key). */
const EXPENSIVE = [
  'get /api/v1/reports/traffic',
  'get /api/v1/reports/threats',
  'get /api/v1/reports/url-clicks',
  ...NEW_IN_7_1,
  'get /api/v1/billing/usage',
  'get /api/v1/threat-intelligence/lookup',
  'get /api/v1/attachments',
  'post /api/v1/policies/test',
  'post /api/v1/messages/:messageId/scans/:scanId/policy/dry-run',
  'post /api/v1/messages/:messageId/scans/:scanId/risk/dry-run',
];

/**
 * 2xx responses that deliberately have no body although they are not 204: `202 Accepted` of the
 * enumeration-safe self-service mails (the same empty answer whether or not an account matched).
 */
const EMPTY_ACCEPTED = [
  'post /api/v1/auth/password/forgot',
  'post /api/v1/auth/email/verification',
];

/**
 * `@Body() body: unknown` handlers whose service parses the body (after the Idempotency-Key
 * checks of the transactional mechanism), with the schema the service applies.
 */
const BODY_PARSED_IN_SERVICE = new Map<string, z.ZodType>([
  ['QuarantineToolsController.bulk', BulkBodySchema],
  ['MessageLifecycleController.rescan', LifecycleOperationBodySchema],
  ['MessageLifecycleController.release', LifecycleOperationBodySchema],
  ['RecipientSuppressionsController.create', CreateSuppressionBodySchema],
  // Step 6.2: keyed routes parse after the key checks; settings map to their coded 400.
  ['WebhooksController.create', CreateWebhookBodySchema],
  ['WebhooksController.rotate', RotateSecretBodySchema],
  ['WebhookDeliveriesController.createReplay', CreateReplayBodySchema],
  ['NotificationsController.putSettings', SettingsUpdateBodySchema],
]);

const BODY: number = RouteParamtypes.BODY;
const QUERY: number = RouteParamtypes.QUERY;

type Json = Record<string, unknown>;
interface Operation {
  tags?: string[];
  summary?: string;
  security?: unknown[];
  parameters?: Array<{ name: string; in: string; required?: boolean }>;
  requestBody?: { content?: Record<string, Json> };
  responses: Record<string, { content?: Record<string, Json> } | undefined>;
  [extension: `x-${string}`]: unknown;
}

interface RouteFacts {
  route: DiscoveredRoute;
  key: string;
  takesBody: boolean;
  schemas: Array<{ kind: 'body' | 'query'; schema: z.ZodType }>;
  transactional: { operation: string } | null;
}

const keyOf = (r: Pick<DiscoveredRoute, 'method' | 'path'>) => `${r.method} ${r.path}`;
const openApiPath = (path: string) => path.replace(/:([A-Za-z0-9_]+)/g, '{$1}');

/** Matches `@covers <route>` exactly (not as a prefix of a longer route). */
function hasMarker(text: string, route: string): boolean {
  const escaped = route.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`@covers ${escaped}(?=\\s|$)`, 'm').test(text);
}

const fileCache = new Map<string, string | null>();
function readRepoFile(file: string): string | null {
  if (!fileCache.has(file)) {
    const absolute = resolve(REPO_ROOT, file);
    fileCache.set(file, existsSync(absolute) ? readFileSync(absolute, 'utf8') : null);
  }
  return fileCache.get(file)!;
}

function resolveRef(doc: OpenAPIObject, schema: unknown): Json | undefined {
  let current = schema as Json | undefined;
  for (let i = 0; i < 5 && current && typeof current.$ref === 'string'; i += 1) {
    const name = current.$ref.split('/').pop()!;
    current = doc.components?.schemas?.[name] as Json | undefined;
  }
  return current;
}

/** `nextCursor` among the properties of a 2xx JSON body (directly or in an `allOf` member). */
function isCursorPage(doc: OpenAPIObject, op: Operation): boolean {
  return Object.entries(op.responses).some(([status, response]) => {
    if (!/^2\d\d$/.test(status)) return false;
    const schema = resolveRef(doc, response?.content?.['application/json']?.schema);
    const members = [
      schema,
      ...((schema?.allOf as unknown[]) ?? []).map((s) => resolveRef(doc, s)),
    ];
    return members.some(
      (m) => m?.properties !== undefined && 'nextCursor' in (m.properties as Json),
    );
  });
}

function hasExample(media: Json | undefined): boolean {
  if (!media) return false;
  const schema = media.schema as Json | undefined;
  return (
    media.example !== undefined || media.examples !== undefined || schema?.example !== undefined
  );
}

describe('route inventory (step 6.1, e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  let doc: OpenAPIObject;
  let facts: RouteFacts[];
  const byKey = new Map<string, RouteFacts>();

  const operation = (key: string): Operation | undefined => {
    const [method, path] = key.split(' ') as [string, string];
    return (doc.paths[openApiPath(path)] as Record<string, Operation> | undefined)?.[method];
  };
  const isInternal = (key: string) => INTERNAL_ROUTES.includes(key);

  beforeAll(async () => {
    api = await createStubbedApiApp({}, { discovery: true, principals: false });
    doc = buildOpenApiDocument(api.app);
    const routes = discoverRoutes(api.app);
    facts = [];
    for (const wrapper of api.app.get(DiscoveryService).getControllers()) {
      const controller = wrapper.metatype as (new (...args: never[]) => object) | null;
      if (!controller || !wrapper.instance) continue;
      const prototype = controller.prototype as Record<string, unknown>;
      for (const route of routes.filter((r) => r.name.startsWith(`${controller.name}.`))) {
        const handlerName = route.name.slice(controller.name.length + 1);
        const args = (Reflect.getMetadata(ROUTE_ARGS_METADATA, controller, handlerName) ??
          {}) as Record<string, { pipes?: unknown[] }>;
        const schemas: RouteFacts['schemas'] = [];
        let takesBody = false;
        for (const [argKey, arg] of Object.entries(args)) {
          const type = Number(argKey.split(':')[0]);
          if (type !== BODY && type !== QUERY) continue;
          if (type === BODY) takesBody = true;
          for (const pipe of arg.pipes ?? []) {
            if (pipe instanceof ZodValidationPipe) {
              schemas.push({
                kind: type === BODY ? 'body' : 'query',
                schema: (pipe as unknown as { schema: z.ZodType }).schema,
              });
            }
          }
          const parsedInService = BODY_PARSED_IN_SERVICE.get(route.name);
          if (parsedInService && type === BODY) {
            schemas.push({ kind: 'body', schema: parsedInService });
          }
        }
        const transactional =
          (Reflect.getMetadata(TRANSACTIONAL_IDEMPOTENCY_KEY, prototype[handlerName] as object) as
            { operation: string } | undefined) ?? null;
        const fact: RouteFacts = { route, key: keyOf(route), takesBody, schemas, transactional };
        facts.push(fact);
        byKey.set(fact.key, fact);
      }
    }
  });

  afterAll(async () => {
    await api?.close();
  });

  it('discovers every route once (269 operations under /api/v1 plus the 3 internal endpoints)', () => {
    expect(facts.length).toBe(byKey.size);
    // 249 after step 6.1, plus the 17 routes of step 6.2, plus the 3 reports of step 7.1.
    expect(facts.filter((f) => f.key.includes(' /api/v1/')).length).toBe(269);
    expect(
      facts
        .filter((f) => isInternal(f.key))
        .map((f) => f.key)
        .sort(),
    ).toEqual([...INTERNAL_ROUTES].sort());
  });

  it('serves nothing outside /api/v1 except the internal allow-list (D13)', () => {
    const outside = facts
      .filter((f) => !f.route.path.startsWith('/api/v1/') && !isInternal(f.key))
      .map((f) => f.key);
    expect(outside).toEqual([]);
  });

  it('every route is a documented public route, names a permission, or is allow-listed self-service (D7)', () => {
    const failures: string[] = [];
    for (const { key, route } of facts) {
      const requirement = route.requirement as
        { mode?: string; permissions?: string[] } | undefined;
      if (route.isPublic) {
        if (!PUBLIC_ROUTES.includes(key)) failures.push(`${key}: @Public() but not documented`);
        if (requirement !== undefined) failures.push(`${key}: @Public() with a requirement`);
        continue;
      }
      if (requirement?.mode === 'authenticated') {
        if (!AUTHENTICATED_ONLY_ROUTES.includes(key)) {
          failures.push(`${key}: @AuthenticatedOnly() but not in the self-service allow-list`);
        }
        continue;
      }
      if (
        (requirement?.mode !== 'all' && requirement?.mode !== 'any') ||
        (requirement.permissions ?? []).length === 0
      ) {
        failures.push(`${key}: no permission requirement`);
      }
    }
    expect(failures).toEqual([]);
    // The allow-lists name only routes that exist and carry exactly that kind of authorization.
    for (const key of PUBLIC_ROUTES) expect(byKey.get(key)?.route.isPublic, key).toBe(true);
    for (const key of AUTHENTICATED_ONLY_ROUTES) {
      expect(byKey.get(key)?.route.requirement, key).toEqual({ mode: 'authenticated' });
    }
  });

  it('documents every /api/v1 route as an operation with tag, summary, security, errors, body and 2xx schema (D14)', () => {
    const failures: string[] = [];
    for (const { key, route, takesBody } of facts) {
      if (isInternal(key)) {
        if (operation(key)) failures.push(`${key}: internal endpoint in the public document`);
        continue;
      }
      const op = operation(key);
      if (!op) {
        failures.push(`${key}: no OpenAPI operation`);
        continue;
      }
      if ((op.tags ?? []).length === 0) failures.push(`${key}: no tag`);
      if (!op.summary?.trim()) failures.push(`${key}: no summary`);
      const secured = (op.security ?? []).length > 0;
      if (route.isPublic === secured) {
        failures.push(
          `${key}: security ${secured ? 'on a public' : 'missing on a protected'} route`,
        );
      }
      const hasInput = (op.parameters ?? []).length > 0 || op.requestBody !== undefined;
      const standard = ['429', '500', '503'];
      if (hasInput) standard.push('400');
      if (secured) standard.push('401', '403');
      if (route.path.includes('/:')) standard.push('404');
      for (const status of standard) {
        if (!op.responses[status]) failures.push(`${key}: no ${status} response`);
      }
      if (takesBody) {
        const media = Object.values(op.requestBody?.content ?? {});
        if (!media.some((m) => m.schema !== undefined))
          failures.push(`${key}: no requestBody schema`);
      }
      const ok = Object.entries(op.responses).filter(([s]) => /^2\d\d$/.test(s));
      if (ok.length === 0) failures.push(`${key}: no 2xx response`);
      for (const [status, response] of ok) {
        if (status === '204' || EMPTY_ACCEPTED.includes(key)) continue;
        const media = Object.values(response?.content ?? {});
        if (!media.some((m) => m.schema !== undefined))
          failures.push(`${key}: ${status} without schema`);
      }
    }
    expect(failures).toEqual([]);
    for (const key of EMPTY_ACCEPTED) {
      expect(Object.keys(operation(key)!.responses), key).toContain('202');
    }
  });

  it('gives every route new in 6.1, 6.2 and 7.1 explicit response examples (D14)', () => {
    const failures: string[] = [];
    for (const key of [...NEW_IN_6_1, ...NEW_IN_6_2, ...NEW_IN_7_1]) {
      const op = operation(key);
      if (!op) {
        failures.push(`${key}: missing`);
        continue;
      }
      for (const [status, response] of Object.entries(op.responses)) {
        if (!/^2\d\d$/.test(status) || status === '204') continue;
        if (!hasExample(response?.content?.['application/json'])) {
          failures.push(`${key}: ${status} without an example`);
        }
      }
      if (op.requestBody && !Object.values(op.requestBody.content ?? {}).some(hasExample)) {
        failures.push(`${key}: requestBody without an example`);
      }
    }
    expect(failures).toEqual([]);
    // NEW_IN_6_1 is exactly the 6.1 part of the WP2/WP3 manifests (the rest of messages.ts is
    // the pre-6.1 messages module).
    const preSixOneMessages = COVERAGE_BY_AREA.messages
      .map((c) => c.route)
      .filter((r) => !NEW_IN_6_1.includes(r));
    expect(preSixOneMessages.sort()).toEqual(
      [
        'get /api/v1/messages/:messageId/lifecycle',
        'get /api/v1/messages/:messageId/lifecycle/history',
        'post /api/v1/messages/:messageId/rescan',
        'post /api/v1/messages/:messageId/release',
        'get /api/v1/messages/:messageId/scans',
      ].sort(),
    );
    expect(
      COVERAGE_BY_AREA.insights.every(
        (c) => NEW_IN_6_1.includes(c.route) || NEW_IN_7_1.includes(c.route),
      ),
    ).toBe(true);
    expect(NEW_IN_6_1).toHaveLength(20);
    expect(NEW_IN_7_1.every((r) => COVERAGE_BY_AREA.insights.some((c) => c.route === r))).toBe(
      true,
    );
    // NEW_IN_6_2 is exactly the step 6.2 manifest.
    expect(COVERAGE_BY_AREA.webhooks.map((c) => c.route).sort()).toEqual([...NEW_IN_6_2].sort());
    expect(NEW_IN_6_2).toHaveLength(17);
  });

  it('has one coverage entry per served route and none for a route that does not exist (§3.8)', () => {
    const entries = COVERAGE.map((c) => c.route);
    const duplicates = entries.filter((r, i) => entries.indexOf(r) !== i);
    expect(duplicates).toEqual([]);
    const served = new Set(byKey.keys());
    expect(entries.filter((r) => !served.has(r))).toEqual([]);
    expect([...served].filter((r) => !entries.includes(r)).sort()).toEqual([]);
    // Each area holds its own routes: pre-6.1 in legacy.ts (except the messages module).
    for (const route of COVERAGE_BY_AREA.legacy.map((c) => c.route)) {
      expect(NEW_IN_6_1.includes(route), route).toBe(false);
      expect(NEW_IN_6_2.includes(route), route).toBe(false);
      expect(NEW_IN_7_1.includes(route), route).toBe(false);
    }
  });

  it('every coverage file exists and carries the @covers marker of its route (§3.8)', () => {
    const failures: string[] = [];
    const check = (entry: RouteCoverage, column: string, file: string) => {
      const text = readRepoFile(file);
      if (text === null) failures.push(`${entry.route}: ${column} file ${file} does not exist`);
      else if (!hasMarker(text, entry.route)) {
        failures.push(`${entry.route}: ${column} file ${file} has no "@covers ${entry.route}"`);
      }
    };
    for (const entry of COVERAGE) {
      check(entry, 'e2e', entry.e2e);
      check(entry, 'integration', entry.integration);
      if (typeof entry.crossTenant === 'string') {
        check(entry, 'crossTenant', entry.crossTenant);
      } else {
        if (!entry.crossTenant.why.trim())
          failures.push(`${entry.route}: crossTenant n/a without why`);
        const key = entry.route;
        const route = byKey.get(key)?.route;
        // `public` only for public routes; `self-only` only for self-service routes.
        if (entry.crossTenant.na === 'public' && route && !route.isPublic) {
          failures.push(`${key}: crossTenant "public" on a protected route`);
        }
      }
    }
    expect(failures).toEqual([]);
  });

  it('every list declares its cursor encoding; the manifest agrees; 6.1 lists are v1 (D3)', () => {
    const failures: string[] = [];
    const coverage = new Map(COVERAGE.map((c) => [c.route, c]));
    for (const { key, route } of facts) {
      if (isInternal(key)) continue;
      const list = isCursorPage(doc, operation(key)!);
      if (list && route.cursor === null) failures.push(`${key}: list without @CursorList`);
      if (!list && route.cursor !== null) failures.push(`${key}: @CursorList on a non-list`);
      if ((coverage.get(key)?.cursor ?? null) !== route.cursor) {
        failures.push(`${key}: manifest cursor ${coverage.get(key)?.cursor} ≠ ${route.cursor}`);
      }
      if (
        (NEW_IN_6_1.includes(key) || NEW_IN_6_2.includes(key) || NEW_IN_7_1.includes(key)) &&
        route.cursor === 'v0'
      )
        failures.push(`${key}: 6.1/6.2/7.1 list on v0`);
      if (route.cursor !== null && operation(key)!['x-eg-cursor'] !== route.cursor) {
        failures.push(`${key}: x-eg-cursor not documented`);
      }
    }
    expect(failures).toEqual([]);
    const counts = { v0: 0, v1: 0 };
    for (const { route } of facts) if (route.cursor) counts[route.cursor] += 1;
    // 33 pre-6.1 lists keep the unsigned v0 cursors; the 9 lists of 6.1 and the 2 of 6.2
    // (webhooks, deliveries) are signed v1.
    expect(counts).toEqual({ v0: 33, v1: 11 });
  });

  it('every body and query schema of every route is strict at every object node (D1)', () => {
    const offenders: string[] = [];
    let checked = 0;
    for (const { key, takesBody, schemas } of facts) {
      if (takesBody && !schemas.some((s) => s.kind === 'body')) {
        offenders.push(`${key}: body without a zod schema`);
      }
      for (const { kind, schema } of schemas) {
        checked += 1;
        for (const path of isStrictRequestSchema(schema)) offenders.push(`${key} ${kind} ${path}`);
      }
    }
    expect(offenders).toEqual([]);
    expect(checked).toBeGreaterThan(150);
  });

  it('every §3.5 sensitive mutation has idempotency metadata and the sensitive class (D9, D10)', () => {
    const failures: string[] = [];
    for (const key of [...SENSITIVE_TRANSACTIONAL, ...SENSITIVE_LEGACY]) {
      const fact = byKey.get(key);
      const op = operation(key);
      if (!fact || !op) {
        failures.push(`${key}: missing`);
        continue;
      }
      const legacy = SENSITIVE_LEGACY.includes(key);
      if (legacy && fact.route.idempotency?.legacy !== true) {
        failures.push(`${key}: no @Idempotent({ legacy: true })`);
      }
      if (!legacy && fact.transactional === null) failures.push(`${key}: no transactional marker`);
      if (fact.route.rateClass !== 'sensitive') failures.push(`${key}: not in the sensitive class`);
      if (op['x-eg-idempotency'] !== (legacy ? 'legacy' : 'required')) {
        failures.push(`${key}: x-eg-idempotency ${String(op['x-eg-idempotency'])}`);
      }
      const header = (op.parameters ?? []).find(
        (p) => p.in === 'header' && p.name.toLowerCase() === 'idempotency-key',
      );
      if (!header?.required) failures.push(`${key}: Idempotency-Key header not documented`);
    }
    expect(failures).toEqual([]);
    // Nothing else is keyed, and every operation name is unique (one key space per tenant).
    const keyed = facts
      .filter((f) => f.route.idempotency !== null || f.transactional !== null)
      .map((f) => f.key)
      .sort();
    expect(keyed).toEqual([...SENSITIVE_TRANSACTIONAL, ...SENSITIVE_LEGACY].sort());
    const operations = facts.flatMap((f) =>
      [f.route.idempotency?.operation, f.transactional?.operation].filter(Boolean),
    );
    expect(new Set(operations).size).toBe(operations.length);
    expect(operations).toHaveLength(42);
  });

  it('no route is both @Idempotent() and @ReturnsSecret(); secret-bearing and expensive routes carry their class (D8, D9, ADR-0057)', () => {
    expect(
      facts.filter((f) => f.route.returnsSecret && f.route.idempotency !== null).map((f) => f.key),
    ).toEqual([]);
    // ADR-0057: @ReturnsSecret + idempotency only on the allow-list, only transactional and
    // only with the redacted replay; the allow-list routes are exactly that.
    expect(
      facts
        .filter((f) => f.route.returnsSecret && f.transactional)
        .filter(
          (f) => !SECRET_BEARING_REDACTED_REPLAY.includes(f.key) || !f.route.secretRedactedReplay,
        )
        .map((f) => f.key),
    ).toEqual([]);
    for (const key of SECRET_BEARING_REDACTED_REPLAY) {
      const fact = byKey.get(key);
      expect(fact?.route.returnsSecret, key).toBe(true);
      expect(fact?.route.secretRedactedReplay, key).toBe(true);
      expect(fact?.transactional, key).not.toBeNull();
      expect(operation(key)?.['x-eg-secret-replay'], key).toBe('redacted');
    }
    expect(
      facts
        .filter((f) => f.route.secretRedactedReplay)
        .map((f) => f.key)
        .sort(),
    ).toEqual([...SECRET_BEARING_REDACTED_REPLAY].sort());
    expect(
      facts
        .filter((f) => f.route.returnsSecret && !f.route.secretRedactedReplay)
        .map((f) => f.key)
        .sort(),
    ).toEqual([...SECRET_BEARING].sort());
    const byClass = (rateClass: string) =>
      facts
        .filter((f) => f.route.rateClass === rateClass)
        .map((f) => f.key)
        .sort();
    expect(byClass('expensive')).toEqual([...EXPENSIVE].sort());
    expect(byClass('sensitive')).toEqual(
      [
        ...new Set([
          ...SENSITIVE_TRANSACTIONAL,
          ...SENSITIVE_LEGACY,
          ...SECRET_BEARING,
          ...SECRET_BEARING_REDACTED_REPLAY,
        ]),
      ].sort(),
    );
    for (const { key, route } of facts) {
      if (route.rateClass && operation(key)?.['x-eg-rate-class'] !== route.rateClass) {
        throw new Error(`${key}: x-eg-rate-class not documented`);
      }
    }
  });
});
