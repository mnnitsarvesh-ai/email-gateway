import type { INestApplication } from '@nestjs/common';
import { DocumentBuilder, type OpenAPIObject, SwaggerModule } from '@nestjs/swagger';
import type {
  HeaderObject,
  OperationObject,
  ParameterObject,
  PathItemObject,
  ReferenceObject,
  ResponseObject,
  SchemaObject,
} from '@nestjs/swagger/dist/interfaces/open-api-spec.interface';

/** Security scheme names used by `@ApiBearerAuth(...)` and `@ApiSecurity(...)`. */
export const ACCESS_TOKEN_SCHEME = 'access-token';
export const API_KEY_SCHEME = 'api-key';

/** Path of the Swagger UI (served outside production only). */
export const OPENAPI_PATH = 'docs';

/**
 * Internal endpoints served by the api that are not part of the public contract (step 6.1
 * D13): the Prometheus scrape and the probes (documented in contracts §9, never routed publicly).
 */
export const INTERNAL_PATHS: readonly string[] = ['/metrics', '/health/live', '/health/ready'];

const METHODS = ['get', 'put', 'post', 'delete', 'patch', 'options', 'head', 'trace'] as const;

const ref = (kind: 'schemas' | 'headers', name: string): ReferenceObject => ({
  $ref: `#/components/${kind}/${name}`,
});

/** Shared error schemas (D1, §3.2). */
export const ERROR_SCHEMAS: Record<string, SchemaObject> = {
  ErrorBody: {
    type: 'object',
    description:
      'Every error of the API (step 6.1 D1). `code` is a stable snake_case machine code; ' +
      '`message` is a string, or a list of `"<path>: <issue>"` strings for validation errors. ' +
      'Coded errors may add detail fields (ids, states, versions, codes; never content).',
    properties: {
      statusCode: { type: 'integer', example: 404 },
      error: { type: 'string', example: 'NOT_FOUND' },
      code: { type: 'string', example: 'not_found' },
      message: {
        oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }],
        example: 'Not found',
      },
      correlationId: { type: 'string', description: 'The x-correlation-id of the request' },
      requestId: {
        type: 'string',
        format: 'uuid',
        description: 'The X-Request-Id of the response',
      },
    },
    required: ['statusCode', 'error', 'code', 'message', 'requestId'],
    additionalProperties: true,
  },
  ValidationErrorBody: {
    allOf: [
      ref('schemas', 'ErrorBody'),
      {
        type: 'object',
        properties: {
          statusCode: { type: 'integer', enum: [400] },
          code: {
            type: 'string',
            example: 'validation_failed',
            description:
              '`validation_failed` (unknown fields included), or a specific code such as ' +
              '`cursor_invalid`, `idempotency_key_required`, `idempotency_key_invalid`',
          },
          message: {
            oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }],
            example: ['name: Required'],
          },
        },
      },
    ],
  },
  RateLimitedErrorBody: {
    allOf: [
      ref('schemas', 'ErrorBody'),
      {
        type: 'object',
        properties: {
          statusCode: { type: 'integer', enum: [429] },
          code: { type: 'string', enum: ['rate_limited'] },
          message: { type: 'string', example: 'Too many requests' },
          scope: {
            type: 'string',
            enum: ['principal', 'tenant', 'sensitive', 'expensive', 'route'],
            description: 'Which limit was exceeded (step 6.1 D8)',
          },
        },
        required: ['scope'],
      },
    ],
  },
};

const integerHeader = (description: string): HeaderObject => ({
  description,
  schema: { type: 'integer', minimum: 0 },
});

/** Shared response headers (D1, D8, D9, §3.4). */
export const STANDARD_HEADERS: Record<string, HeaderObject> = {
  'X-Request-Id': {
    description: 'Server-minted id of this request (UUID); quote it when reporting a problem',
    schema: { type: 'string', format: 'uuid' },
  },
  'X-Correlation-Id': {
    description: 'The caller-supplied x-correlation-id if well formed, otherwise a new one',
    schema: { type: 'string' },
  },
  'RateLimit-Limit': integerHeader(
    'Requests allowed in the current 60 s window of the most restrictive limit',
  ),
  'RateLimit-Remaining': integerHeader('Requests left in that window'),
  'RateLimit-Reset': integerHeader('Seconds until that window ends'),
  'Retry-After': integerHeader('Seconds to wait before retrying'),
  'Idempotency-Replayed': {
    description:
      '`true` when the stored response of an earlier request with the same key is returned',
    schema: { type: 'string', enum: ['true'] },
  },
};

interface StandardResponse {
  status: string;
  description: string;
  schema: string;
  applies: (op: OperationFacts) => boolean;
}

interface OperationFacts {
  secured: boolean;
  hasInput: boolean;
  hasPathParams: boolean;
}

const STANDARD_RESPONSES: readonly StandardResponse[] = [
  {
    status: '400',
    description: 'Invalid request (validation_failed or a specific code)',
    schema: 'ValidationErrorBody',
    applies: (op) => op.hasInput,
  },
  {
    status: '401',
    description: 'Missing or invalid credentials (unauthorized)',
    schema: 'ErrorBody',
    applies: (op) => op.secured,
  },
  {
    status: '403',
    description: 'Not allowed (forbidden, mfa_required, mfa_enrollment_required, user_required)',
    schema: 'ErrorBody',
    applies: (op) => op.secured,
  },
  {
    status: '404',
    description: 'Not found, or not visible to the caller (another tenant’s resource)',
    schema: 'ErrorBody',
    applies: (op) => op.hasPathParams,
  },
  {
    status: '429',
    description: 'Too many requests (rate_limited, with scope and Retry-After)',
    schema: 'RateLimitedErrorBody',
    applies: () => true,
  },
  {
    status: '500',
    description: 'Unexpected error (internal_error; no details are disclosed)',
    schema: 'ErrorBody',
    applies: () => true,
  },
  {
    status: '503',
    description: 'A dependency is unavailable (service_unavailable or a specific code)',
    schema: 'ErrorBody',
    applies: () => true,
  },
];

function isReference(value: unknown): value is ReferenceObject {
  return typeof value === 'object' && value !== null && '$ref' in value;
}

function addHeaders(response: ResponseObject, names: readonly string[]): void {
  const headers = (response.headers ??= {});
  for (const name of names) {
    const present = Object.keys(headers).some((h) => h.toLowerCase() === name.toLowerCase());
    if (!present) headers[name] = ref('headers', name);
  }
}

/**
 * Step 6.1 D13, D14: removes the internal endpoints, adds the shared error schemas and headers,
 * and gives every operation the standard error responses it does not document itself (`400`
 * with parameters or a body, `401`/`403` when secured, `404` with path parameters, `429`, `500`,
 * `503`) and the standard response headers (`X-Request-Id`, `X-Correlation-Id` everywhere,
 * `RateLimit-*` on secured operations, `Retry-After` on `429`, `Idempotency-Replayed` on the 2xx
 * responses of `x-eg-idempotency` operations). Responses and headers an operation documents are
 * never overwritten; operationIds are left as generated.
 */
export function postProcessOpenApiDocument(document: OpenAPIObject): OpenAPIObject {
  for (const path of INTERNAL_PATHS) delete document.paths[path];
  const components = (document.components ??= {});
  components.schemas = { ...(components.schemas ?? {}), ...ERROR_SCHEMAS };
  components.headers = { ...(components.headers ?? {}), ...STANDARD_HEADERS };

  for (const [path, item] of Object.entries<PathItemObject>(document.paths)) {
    const shared = (item.parameters ?? []).filter((p): p is ParameterObject => !isReference(p));
    for (const method of METHODS) {
      const op = item[method] as (OperationObject & Record<string, unknown>) | undefined;
      if (!op) continue;
      const parameters = [
        ...shared,
        ...(op.parameters ?? []).filter((p): p is ParameterObject => !isReference(p)),
      ];
      const facts: OperationFacts = {
        secured: (op.security ?? document.security ?? []).length > 0,
        hasInput: parameters.length > 0 || op.requestBody !== undefined,
        hasPathParams: parameters.some((p) => p.in === 'path') || path.includes('{'),
      };
      const responses = (op.responses ??= {});
      for (const standard of STANDARD_RESPONSES) {
        if (!standard.applies(facts) || responses[standard.status] !== undefined) continue;
        responses[standard.status] = {
          description: standard.description,
          content: { 'application/json': { schema: ref('schemas', standard.schema) } },
        };
      }
      const idempotent = op['x-eg-idempotency'] !== undefined;
      for (const [status, response] of Object.entries(responses)) {
        if (!response || isReference(response)) continue;
        const names = ['X-Request-Id', 'X-Correlation-Id'];
        if (facts.secured) names.push('RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset');
        if (status === '429') names.push('Retry-After');
        if (idempotent && /^2\d\d$/.test(status)) names.push('Idempotency-Replayed');
        addHeaders(response, names);
      }
    }
  }
  return document;
}

/**
 * The description of the public document (step 6.1 D14): base path, authentication, the
 * conventions in one paragraph each, what is deliberately not offered, and the deferrals. The
 * full contract is docs/api/README.md and ADR-0050..0053.
 */
export const OPENAPI_DESCRIPTION = [
  'Control-plane API of the Email Security Gateway. Every business route is under `/api/v1` ' +
    '(ADR-0015, ADR-0053); nothing else is public. Probes (`/health/live`, `/health/ready`) and ' +
    'the Prometheus scrape (`/metrics`) are internal endpoints of the api port, never routed by ' +
    'the Ingress and not part of this document; this document itself (`/docs`, `/docs-json`) ' +
    'is served outside production only.',
  '**Authentication.** A bearer access token (`Authorization: Bearer <JWT>`, from `POST ' +
    '/api/v1/auth/login`) or, where an operation lists the `api-key` scheme, an organization ' +
    'API key (`X-API-Key`). The organization is always the caller’s (the token or key), never ' +
    'a header or a body field; another tenant’s resource answers `404`. `x-eg-permissions` ' +
    'names the permission(s) each operation requires.',
  '**Conventions (ADR-0050).** Resources are plural kebab-case nouns; a single resource is ' +
    'returned bare, a collection as `{ "data": [...], "nextCursor": string | null }` (the ' +
    'quarantine lists of step 5.3 keep `items`). Every error is `{ statusCode, error, code, ' +
    'message, correlationId, requestId, ... }` with a stable snake_case `code`; every response ' +
    'carries `X-Request-Id` (server-minted) and `x-correlation-id`. Request bodies and query ' +
    'strings are strict: an unknown field is `400 validation_failed`.',
  '**Lists (ADR-0051).** `limit` (1-100, default 25) and `cursor`; keyset order, no totals, no ' +
    'offsets. Lists added in 6.1 (`x-eg-cursor: v1`) use signed cursors bound to the ' +
    'organization, the filters and the sort (`400 cursor_invalid` otherwise); earlier lists keep ' +
    'their unsigned `v0` cursors. A page may be short, even empty, while `nextCursor` is not ' +
    'null (scan budget): follow `nextCursor` until it is null. Filters are `field=value`, ' +
    '`field=a,b` and `field.gte=` / `.lte=` / `.gt=` / `.lt=`; `sort=-receivedAt` style.',
  '**Rate limits and idempotency (ADR-0052).** Authenticated requests are limited per user or ' +
    'API key and per organization (60 s windows; `RateLimit-Limit`, `RateLimit-Remaining`, ' +
    '`RateLimit-Reset`); `x-eg-rate-class: sensitive | expensive` operations have their own ' +
    'tighter bucket. `429 rate_limited` carries `scope` and `Retry-After`; when the limiter ' +
    'store is down the API answers `503` (fail closed). Operations with `x-eg-idempotency` ' +
    'require an `Idempotency-Key` header (`required`: exactly once with the effect; `legacy`: ' +
    'the reservation interceptor, at most once per key); replays carry `Idempotency-Replayed: ' +
    'true`. Responses that contain a secret (`x-eg-returns-secret`) are never stored and take ' +
    'no key, except the two webhook secret routes (`x-eg-secret-replay: redacted`, ADR-0057): ' +
    'they require a key, store the response with `secret: null` and return the secret only in ' +
    'the original response.',
  '**Integration surfaces today.** Organization API keys (`/api/v1/api-keys`, scoped to ' +
    'tenant permissions) for this API, SMTP connectors (`/api/v1/smtp-connectors`) for ' +
    'outbound relay from customer systems, and signed webhooks (`/api/v1/webhooks`, step 6.2) ' +
    'for mail, threat, quarantine and domain events.',
  '**Not offered, by design.** `delivery_routes` management: no service reads that table ' +
    '(inbound destinations are `/domains/{id}/destinations`, outbound relay is SMTP connectors), ' +
    'so a management API would change nothing. Tenant-managed threat indicators and ' +
    'IP/domain/URL reputation: no engine reads tenant rows; tenants can look up the platform ' +
    'data the engines use (`GET /threat-intelligence/lookup`) and keep their own allow-lists ' +
    'as BEC trusted senders, DLP exceptions and policy conditions. Prices, invoices and ' +
    'payments: no such data exists (`GET /billing/plan` says `pricing: null`).',
  '**Deferred to later steps.** Archive, journal search, retention policies, legal holds and ' +
    'export: step 8.1. Microsoft 365 and Google Workspace connectors: step 8.2. Deployment ' +
    'manager: step 8.3. Admin-portal screens (webhooks, delivery history, preferences): ' +
    'steps 7.x.',
].join('\n\n');

/**
 * Tag descriptions (D14): the step that built each module and its scope or deferrals. Every
 * tag an operation uses must be listed here (test/openapi.test.ts).
 */
export const OPENAPI_TAGS: ReadonlyArray<{ name: string; description: string }> = [
  { name: 'meta', description: 'Public build and version information (step 0.1).' },
  {
    name: 'auth',
    description:
      'Steps 1.2-1.3: login, MFA verification, token refresh and logout, password and email ' +
      'self-service, invitation acceptance. Public routes are limited per IP and per account.',
  },
  { name: 'mfa', description: 'Step 1.3: TOTP enrollment, disable and recovery codes (self).' },
  { name: 'sessions', description: 'Step 1.3: the caller’s own sessions and their revocation.' },
  {
    name: 'users',
    description: 'Step 1.3: users of the organization, invitations, roles and MFA reset.',
  },
  {
    name: 'roles',
    description: 'Step 1.3: system and custom roles and the permission catalog (`/permissions`).',
  },
  {
    name: 'api-keys',
    description:
      'Step 1.3: organization API keys (an integration surface of today); the secret is shown ' +
      'once at creation and never stored in an idempotency record.',
  },
  {
    name: 'audit',
    description:
      'Step 1.3: login events. Step 6.1: the organization’s audit log (`GET /audit/logs`, ' +
      '`audit:read`, signed cursors, bounded range, the search itself audited).',
  },
  {
    name: 'organizations',
    description:
      'Step 1.2: organizations, settings, features, limits (incl. the per-tenant API rate ' +
      'limit `api_requests_per_minute`), usage and the deletion workflow.',
  },
  {
    name: 'domains',
    description:
      'Steps 2.1-2.3: domains, DNS verification and records, DKIM rotation, the inbound ' +
      'recipient registry and the inbound destination servers.',
  },
  {
    name: 'smtp-connectors',
    description:
      'Step 2.2: outbound SMTP relay connectors (an integration surface of today); secrets ' +
      'shown once.',
  },
  {
    name: 'deliveries',
    description: 'Step 2.3: per-message delivery status, delivery events and the delivery list.',
  },
  {
    name: 'messages',
    description:
      'Step 3.3: lifecycle, history, rescan, release. Step 4.1: scan results. Step 6.1: the ' +
      'message list (replica, signed cursors, scan budget), detail and recipients. Message ' +
      'content and S3 keys are never returned.',
  },
  {
    name: 'scan-settings',
    description: 'Step 4.1: per-organization engine settings (including URL protection).',
  },
  {
    name: 'attachments',
    description:
      'Step 6.1: attachment metadata and verdicts of a message and the SHA-256 search; never ' +
      'content (downloads only through quarantine download grants, step 5.3).',
  },
  {
    name: 'url-protection',
    description:
      'Step 6.1: the URLs of a message with their verdicts and rewrite status, and the ' +
      'time-of-click events (step 4.3 click-service data). Settings are `/scan-settings/url`.',
  },
  {
    name: 'recipients',
    description:
      'Step 6.1: the recipient suppression list the outbound path enforces (bounces, ' +
      'complaints, manual and unsubscribe entries); create and delete need an Idempotency-Key.',
  },
  { name: 'bec', description: 'Step 4.4: BEC executives, vendors, trusted senders, feedback.' },
  {
    name: 'dlp',
    description:
      'Step 4.5: DLP policies, rules, exceptions, patterns, dictionaries, compliance packs, ' +
      'incidents and the audited evidence routes.',
  },
  {
    name: 'risk-scoring',
    description: 'Step 5.1: versioned risk profiles, publish, activate, reset and dry-runs.',
  },
  {
    name: 'policies',
    description:
      'Step 5.2: policies, versions, publish and activation, tests and dry-runs, settings and ' +
      'execution history.',
  },
  { name: 'departments', description: 'Step 5.2: departments and members used by policies.' },
  {
    name: 'quarantine',
    description:
      'Step 5.3: quarantine search, preview, download grants, release with re-validation, ' +
      'approvals, end-user self-service and settings.',
  },
  {
    name: 'reports',
    description:
      'Step 6.1: traffic, threat and URL-click aggregates computed on the replica over bounded ' +
      'ranges, cached per organization (`503 report_timeout` instead of an overloaded replica).',
  },
  {
    name: 'usage',
    description: 'Step 6.1: the caller’s organization usage (same data as step 1.2’s route).',
  },
  {
    name: 'billing',
    description:
      'Step 6.1: the plan, effective entitlements and monthly metered quantities from recorded ' +
      'data. No prices, invoices or payments exist (`pricing: null`).',
  },
  {
    name: 'threat-intelligence',
    description:
      'Step 6.1: look up a hash, URL, domain or IP in the platform threat data the engines ' +
      'use (audited, expensive class). Tenant-managed indicators are not offered.',
  },
  {
    name: 'webhooks',
    description:
      'Step 6.2: signed webhook subscriptions (HMAC-SHA256 `EG-Signature`, secret shown once, ' +
      'rotation with overlap), the event catalogue, delivery history with attempts, single and ' +
      'time-range replay, test pings. `webhook:read` / `webhook:manage`; needs the plan ' +
      'feature `webhooks`. Not offered: events for SMTP-time refusals, per-recipient ' +
      'deliveries, URL clicks, DLP incidents and archive (8.1), connector events (8.2), ' +
      'payload version 2, custom headers or mTLS, back-fill of past events; portal screens: 7.x.',
  },
  {
    name: 'notifications',
    description:
      'Step 6.2: tenant security-alert settings (threat detected, DNS record failures, ' +
      'webhook disabled: enabled, severity, throttle windows) and the caller’s own notification ' +
      'preferences (opt-outs, quarantine digest). E-mail only; SMS, chat and push channels are ' +
      'not offered; portal screens: 7.x.',
  },
  {
    name: 'platform',
    description:
      'Platform staff only: overrides (1.3), dead letters (3.2), scan training (4.1), threat ' +
      'hashes and attachment rescans (4.2), threat indicators (4.3), cross-tenant audit log ' +
      '(6.1, users with MFA, audited).',
  },
];

/** Builds the OpenAPI 3 document of the running app (paths include the `/api` prefix). */
export function buildOpenApiDocument(app: INestApplication): OpenAPIObject {
  const builder = new DocumentBuilder()
    .setTitle('Email Security Gateway API')
    .setDescription(OPENAPI_DESCRIPTION)
    .setVersion('v1')
    .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, ACCESS_TOKEN_SCHEME)
    .addApiKey({ type: 'apiKey', in: 'header', name: 'X-API-Key' }, API_KEY_SCHEME);
  for (const tag of OPENAPI_TAGS) builder.addTag(tag.name, tag.description);
  return postProcessOpenApiDocument(SwaggerModule.createDocument(app, builder.build()));
}

/** Serves Swagger UI at `/docs` (and the JSON at `/docs-json`). Callers skip it in production. */
export function setupOpenApi(app: INestApplication): void {
  SwaggerModule.setup(OPENAPI_PATH, app, () => buildOpenApiDocument(app));
}

/**
 * Step 6.1 D13: the document is served outside production only (`/docs`, `/docs-json` are
 * internal tooling, never public). Returns whether it was mounted. Used by main.ts.
 */
export function setupOpenApiOutsideProduction(
  app: INestApplication,
  config: { NODE_ENV: string },
): boolean {
  if (config.NODE_ENV === 'production') return false;
  setupOpenApi(app);
  return true;
}
