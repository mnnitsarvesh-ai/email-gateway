/**
 * Public / internal boundary of step 6.1 (D13, ADR-0053; docs/plan/steps/18-rest-api.md §9):
 *
 * - the public OpenAPI document lists only `/api/v1/*`;
 * - the internal endpoints are not reachable under the public prefixes (`/api/metrics`,
 *   `/api/health/live`, `/api/docs`, `/api/v1/metrics` are `404 route_not_found` with an
 *   `X-Request-Id`), while they keep working at their internal paths;
 * - with `NODE_ENV=production` the api does not serve `/docs` or `/docs-json` (the guard main.ts
 *   uses, applied to the configured app), outside production it does;
 * - every Ingress of the rendered Kubernetes base (every YAML document of
 *   infrastructure/kubernetes/base/*.yaml) routes only the click-service's documented public
 *   paths or the api's `Prefix /api/v1/`, and nothing routes `/metrics`, `/health`, `/docs` or a
 *   worker Service.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseAllDocuments } from 'yaml';
import { buildOpenApiDocument, setupOpenApiOutsideProduction } from '../src/http/openapi';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';

const K8S_BASE = resolve(__dirname, '../../../infrastructure/kubernetes/base');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The only Ingress paths allowed (service → path → pathType). */
const ALLOWED_INGRESS_PATHS: Record<string, Record<string, string>> = {
  // Step 4.3 U14, ADR-0031: the time-of-click redirect and its stylesheet.
  'click-service': { '/c/': 'Prefix', '/static/click.css': 'Exact' },
  // Step 6.1 D13, ADR-0053: the business API only.
  api: { '/api/v1/': 'Prefix' },
};

interface K8sObject {
  apiVersion?: string;
  kind?: string;
  metadata?: { name?: string };
  spec?: Record<string, unknown>;
}

interface IngressPath {
  ingress: string;
  host: string | undefined;
  path: string;
  pathType: string | undefined;
  service: string | undefined;
  port: unknown;
}

function baseObjects(): Array<K8sObject & { file: string }> {
  const files = readdirSync(K8S_BASE).filter((f) => /\.ya?ml$/.test(f));
  return files.flatMap((file) =>
    parseAllDocuments(readFileSync(resolve(K8S_BASE, file), 'utf8')).flatMap((document) => {
      if (document.errors.length > 0) {
        throw new Error(`${file}: ${document.errors.map((e) => e.message).join('; ')}`);
      }
      const value = document.toJS() as K8sObject | null;
      return value ? [{ ...value, file }] : [];
    }),
  );
}

function ingressPaths(objects: K8sObject[]): IngressPath[] {
  type Backend = { service?: { name?: string; port?: unknown } };
  type Rule = { host?: string; http?: { paths?: Array<Record<string, unknown>> } };
  return objects
    .filter((o) => o.kind === 'Ingress')
    .flatMap((ingress) => {
      const spec = ingress.spec as { rules?: Rule[]; defaultBackend?: Backend };
      if (spec.defaultBackend) {
        throw new Error(`Ingress ${ingress.metadata?.name}: a defaultBackend routes every path`);
      }
      return (spec.rules ?? []).flatMap((rule) =>
        (rule.http?.paths ?? []).map((p) => ({
          ingress: ingress.metadata?.name ?? '?',
          host: rule.host,
          path: typeof p.path === 'string' ? p.path : '',
          pathType: p.pathType as string | undefined,
          service: (p.backend as Backend | undefined)?.service?.name,
          port: (p.backend as Backend | undefined)?.service?.port,
        })),
      );
    });
}

describe('public / internal boundary (step 6.1 D13, e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;

  beforeAll(async () => {
    api = await createStubbedApiApp({}, { principals: false });
  });

  afterAll(async () => {
    await api?.close();
  });

  it('the public OpenAPI document lists only /api/v1/* paths', () => {
    const paths = Object.keys(buildOpenApiDocument(api.app).paths);
    expect(paths.length).toBeGreaterThan(100);
    expect(paths.filter((p) => !p.startsWith('/api/v1/'))).toEqual([]);
  });

  it.each([
    '/api/metrics',
    '/api/health/live',
    '/api/health/ready',
    '/api/docs',
    '/api/v1/metrics',
  ])('GET %s is 404 route_not_found with an X-Request-Id', async (path) => {
    const res = await api.http().get(path).expect(404);
    expect(res.headers['x-request-id']).toMatch(UUID);
    expect(res.body).toMatchObject({ statusCode: 404, code: 'route_not_found' });
    expect(res.body.requestId).toBe(res.headers['x-request-id']);
    // Nothing of the scrape leaks into the error body.
    expect(JSON.stringify(res.body)).not.toContain('# HELP');
  });

  it('the internal endpoints keep answering at their internal paths', async () => {
    await api.http().get('/health/live').expect(200);
    const metrics = await api.http().get('/metrics').expect(200);
    expect(metrics.text).toContain('api_http_requests_total');
  });

  it('NODE_ENV=production serves neither /docs nor /docs-json (the guard of main.ts)', async () => {
    let mounted: boolean | undefined;
    const production = await createStubbedApiApp(
      { NODE_ENV: 'production' },
      {
        principals: false,
        beforeInit: (app, config) => {
          mounted = setupOpenApiOutsideProduction(app, config);
        },
      },
    );
    try {
      expect(production.config.NODE_ENV).toBe('production');
      expect(mounted).toBe(false);
      for (const path of ['/docs', '/docs-json', '/api/docs', '/api/docs-json']) {
        const res = await production.http().get(path);
        expect(res.status, path).toBe(404);
        expect(res.headers['x-request-id'], path).toMatch(UUID);
      }
    } finally {
      await production.close();
    }
  });

  it('outside production the same guard serves /docs-json with the public document', async () => {
    let mounted: boolean | undefined;
    const development = await createStubbedApiApp(
      {},
      {
        principals: false,
        beforeInit: (app, config) => {
          mounted = setupOpenApiOutsideProduction(app, config);
        },
      },
    );
    try {
      expect(mounted).toBe(true);
      const res = await development.http().get('/docs-json').expect(200);
      const paths = Object.keys((res.body as { paths: Record<string, unknown> }).paths);
      expect(paths.length).toBeGreaterThan(100);
      expect(paths.filter((p) => !p.startsWith('/api/v1/'))).toEqual([]);
    } finally {
      await development.close();
    }
  });

  describe('Kubernetes base manifests', () => {
    const objects = baseObjects();
    const paths = ingressPaths(objects);
    const services = new Map(
      objects.filter((o) => o.kind === 'Service').map((o) => [o.metadata?.name, o]),
    );
    const workerServices = [...services.keys()].filter(
      (name) => name !== 'api' && name !== 'click-service' && name !== 'admin-portal',
    );

    it('parses every YAML document of the base and finds the api and click-service Ingresses', () => {
      expect(objects.length).toBeGreaterThan(50);
      const ingresses = objects.filter((o) => o.kind === 'Ingress').map((o) => o.metadata?.name);
      expect(ingresses.sort()).toEqual(['api', 'click-service']);
    });

    it('routes only the documented paths: click-service /c/ and /static/click.css, api Prefix /api/v1/', () => {
      const failures: string[] = [];
      for (const p of paths) {
        const allowed = p.service ? ALLOWED_INGRESS_PATHS[p.service] : undefined;
        if (!allowed) {
          failures.push(`${p.ingress}: ${p.path} → ${p.service ?? '?'} (service not allowed)`);
        } else if (allowed[p.path] !== p.pathType) {
          failures.push(`${p.ingress}: ${p.path} (${p.pathType}) → ${p.service}`);
        }
        if (!p.host) failures.push(`${p.ingress}: ${p.path} without a host`);
        if (p.service && !services.has(p.service)) {
          failures.push(`${p.ingress}: backend ${p.service} is not a Service of the base`);
        }
      }
      expect(failures).toEqual([]);
      expect(paths.filter((p) => p.service === 'api')).toEqual([
        expect.objectContaining({ path: '/api/v1/', pathType: 'Prefix', port: { name: 'http' } }),
      ]);
    });

    it('no Ingress routes /metrics, /health, /docs or a worker Service', () => {
      const internal = /^\/(api\/)?(metrics|health|docs)(\/|-|$)|^\/$/;
      expect(paths.filter((p) => internal.test(p.path)).map((p) => p.path)).toEqual([]);
      expect(paths.filter((p) => workerServices.includes(p.service ?? ''))).toEqual([]);
      // The api Ingress cannot match an internal path: /api/v1/ never prefixes one.
      for (const internalPath of [
        '/metrics',
        '/health/live',
        '/health/ready',
        '/docs',
        '/docs-json',
      ]) {
        expect(internalPath.startsWith('/api/v1/')).toBe(false);
      }
    });

    it('the api Deployment mounts the cursor key as a secret file and sets the 6.1 keys', () => {
      const deployment = objects.find(
        (o) => o.kind === 'Deployment' && o.metadata?.name === 'api',
      ) as { spec: { template: { spec: Record<string, unknown> } } } | undefined;
      const pod = deployment!.spec.template.spec as {
        containers: Array<{ env: Array<{ name: string; value?: string; valueFrom?: unknown }> }>;
        volumes: Array<{ name: string; secret?: { secretName: string } }>;
      };
      const env = new Map(pod.containers[0]!.env.map((e) => [e.name, e]));
      expect(env.get('API_CURSOR_KEY_FILE')?.value).toBe('/var/run/secrets/api-cursor/key');
      // Never the secret value itself in the manifest.
      expect(env.has('API_CURSOR_KEY')).toBe(false);
      expect(env.get('API_CURSOR_KEY_PREVIOUS')?.valueFrom).toBeDefined();
      expect(pod.volumes.find((v) => v.name === 'api-cursor-key')?.secret?.secretName).toBe(
        'email-gateway-api-cursor-key',
      );
      for (const key of [
        'API_CURSOR_TTL_SECONDS',
        'API_RATE_PRINCIPAL_PER_MINUTE',
        'API_RATE_TENANT_DEFAULT_PER_MINUTE',
        'API_RATE_TENANT_MIN_PER_MINUTE',
        'API_RATE_TENANT_MAX_PER_MINUTE',
        'API_RATE_SENSITIVE_PER_MINUTE',
        'API_RATE_EXPENSIVE_PER_MINUTE',
        'API_RATE_LIMIT_CACHE_SECONDS',
        'API_IDEMPOTENCY_LEGACY_MODE',
        'API_IDEMPOTENCY_PENDING_TTL_SECONDS',
        'API_LIST_SCAN_BUDGET_ROWS',
        'API_MESSAGES_MAX_RANGE_DAYS',
        'API_AUDIT_MAX_RANGE_DAYS',
        'REPORTS_MAX_RANGE_DAYS',
        'REPORTS_CACHE_TTL_SECONDS',
        'REPORTS_QUERY_TIMEOUT_MS',
        'RECIPIENT_SUPPRESSIONS_MAX_MANUAL',
      ]) {
        expect(env.get(key)?.value, key).toMatch(/\S/);
      }
      expect(env.get('API_IDEMPOTENCY_LEGACY_MODE')?.value).toBe('enforce');
    });
  });
});
