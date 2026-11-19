// @vitest-environment node
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { operations } from '@/lib/api/operations.gen';
import type { OperationId } from '@/lib/api/types';
import { createMockFetch, mergedFixtures } from '@/server/dev-mocks';
import { toJsonSchema } from '@/test/contract';
import { PROVIDER_OPERATIONS, resetProviderFixtures } from './provider-connections';

/**
 * Dev fixtures of the provider connection pages (step 8.2 WP6): every one of the 24 operations
 * answers with a body matching its OpenAPI response, and the rules the pages rely on hold
 * (single-use consent state, preview → impact token → apply with `impact_changed`, redacted
 * replay of the consent URL and the probe address, tenant isolation, no credential kept).
 */

const API = 'http://api.test:3000';
const fetchImpl = createMockFetch(mergedFixtures());
const REPO = join(__dirname, '../../../../../..');
const spec = JSON.parse(readFileSync(join(REPO, 'docs/api/openapi.json'), 'utf8')) as {
  paths: Record<
    string,
    Record<string, { responses: Record<string, { content?: Record<string, { schema: unknown }> }> }>
  >;
};
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);

function responseErrors(operationId: OperationId, status: number, body: unknown): string[] {
  const op = operations[operationId];
  const schema =
    spec.paths[op.path]?.[op.method.toLowerCase()]?.responses[String(status)]?.content?.[
      'application/json'
    ]?.schema;
  if (!schema) return [`no ${status} schema for ${operationId}`];
  const validate = ajv.compile(toJsonSchema(schema) as object);
  return validate(body)
    ? []
    : (validate.errors ?? []).map((e) => `${e.instancePath || '(root)'} ${e.message ?? ''}`);
}

async function login(email: string): Promise<string> {
  const response = await fetchImpl(`${API}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'any' }),
  });
  const first = (await response.json()) as { accessToken?: string; mfaToken?: string };
  if (first.accessToken) return first.accessToken;
  const verified = await fetchImpl(`${API}/api/v1/auth/mfa/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ mfaToken: first.mfaToken, code: '000000' }),
  });
  return ((await verified.json()) as { accessToken: string }).accessToken;
}

let keyCounter = 0;
const k = () => `key-${(keyCounter += 1)}`;

async function call(token: string, method: string, path: string, body?: unknown, key?: string) {
  const response = await fetchImpl(`${API}/api/v1${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...(key ? { 'idempotency-key': key } : {}),
    },
    body: body === undefined ? null : JSON.stringify(body),
  });
  const text = await response.text();
  let parsed: unknown = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  return {
    status: response.status,
    headers: response.headers,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in a test
    body: parsed as Record<string, any>,
  };
}

beforeEach(() => resetProviderFixtures());

describe('provider connection dev fixtures (step 8.2 WP6)', () => {
  it('cover exactly the 24 provider operations of §5.2', () => {
    const handlers = mergedFixtures();
    expect(PROVIDER_OPERATIONS).toHaveLength(24);
    for (const op of PROVIDER_OPERATIONS) expect(handlers[op], op).toBeDefined();
    const fromSpec = Object.keys(operations).filter((id) =>
      /^Provider(Catalog|Connections|Grants|Domains|MailFlow|Attestations|Validations|Health|Guide)Controller/.test(
        id,
      ),
    );
    expect([...fromSpec].sort()).toEqual([...PROVIDER_OPERATIONS].sort());
  });

  it('answer every operation with an OpenAPI-valid body and keep the wizard rules', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const admin = await login('organization_admin@example.com');
    const check = (op: OperationId, res: { status: number; body: unknown }) => {
      expect(res.status, `${op}: ${JSON.stringify(res.body)}`).toBeLessThan(300);
      expect(responseErrors(op, res.status, res.body), op).toEqual([]);
    };
    check(
      'ProviderCatalogController_get_v1',
      await call(admin, 'GET', '/provider-integrations/catalog'),
    );
    const list = await call(admin, 'GET', '/provider-connections');
    check('ProviderConnectionsController_list_v1', list);
    expect(list.body.data).toHaveLength(2);
    const seeded = list.body.data[0].id as string;
    for (const [op, path] of [
      ['ProviderConnectionsController_get_v1', ''],
      ['ProviderConnectionsController_wizard_v1', '/wizard'],
      ['ProviderDomainsController_list_v1', '/domains'],
      ['ProviderMailFlowController_get_v1', '/mail-flow'],
      ['ProviderValidationsController_list_v1', '/validations'],
      ['ProviderHealthController_get_v1', '/health'],
      ['ProviderGuideController_get_v1', '/setup-guide'],
    ] as const) {
      check(op, await call(admin, 'GET', `/provider-connections/${seeded}${path}`));
    }
    const markdown = await call(
      admin,
      'GET',
      `/provider-connections/${seeded}/setup-guide?format=markdown`,
    );
    expect(markdown.status).toBe(200);
    expect(markdown.headers.get('content-type')).toContain('text/markdown');
    expect(markdown.headers.get('content-disposition')).toContain('setup-microsoft-365-');
    expect(markdown.body as unknown as string).toContain('<a id="inbound-mx"></a>');

    // A new Microsoft 365 connection through admin consent.
    const created = await call(
      admin,
      'POST',
      '/provider-connections',
      { provider: 'microsoft_365', displayName: 'Fixture tenant' },
      k(),
    );
    check('ProviderConnectionsController_create_v1', created);
    const id = created.body.id as string;
    const grantKey = k();
    const grant = await call(
      admin,
      'POST',
      `/provider-connections/${id}/grants`,
      { profile: 'm365.mail_flow', authMethod: 'platform_app' },
      grantKey,
    );
    check('ProviderGrantsController_create_v1', grant);
    const consentUrl = new URL(grant.body.consent.consentUrl as string, 'http://portal.test');
    expect(consentUrl.pathname).toBe('/integrations/providers/consent-callback');
    const replay = await call(
      admin,
      'POST',
      `/provider-connections/${id}/grants`,
      { profile: 'm365.mail_flow', authMethod: 'platform_app' },
      grantKey,
    );
    expect(replay.headers.get('idempotency-replayed')).toBe('true');
    expect(replay.body.consent.consentUrl).toBeNull();
    const state = consentUrl.searchParams.get('state');
    const consent = { state, tenant: consentUrl.searchParams.get('tenant'), adminConsent: true };
    const completed = await call(
      admin,
      'POST',
      '/provider-connections/consent/complete',
      consent,
      k(),
    );
    check('ProviderGrantsController_completeConsent_v1', completed);
    expect(completed.body).toMatchObject({ connectionId: id, status: 'verifying' });
    expect(
      (await call(admin, 'POST', '/provider-connections/consent/complete', consent, k())).body.code,
    ).toBe('consent_state_invalid');
    vi.advanceTimersByTime(4000);
    const bound = await call(admin, 'GET', `/provider-connections/${id}`);
    expect(bound.body.grants[0].status).toBe('active');

    // Domains, then the I10 binding.
    const domains = await call(admin, 'GET', '/domains?status=active&limit=100');
    const free = (domains.body.data as { id: string }[]).slice(2, 3).map((d) => d.id);
    const linked = await call(
      admin,
      'PUT',
      `/provider-connections/${id}/domains`,
      { domainIds: free },
      k(),
    );
    check('ProviderDomainsController_replace_v1', linked);
    const taken = (domains.body.data as { id: string }[])[0]!.id;
    expect(
      (await call(admin, 'PUT', `/provider-connections/${id}/domains`, { domainIds: [taken] }, k()))
        .body.code,
    ).toBe('domain_linked_elsewhere');
    expect((await call(admin, 'GET', `/provider-connections/${id}`)).body.status).toBe('active');

    // Preview → apply; a stale token is impact_changed.
    const change = { kind: 'inbound', domainIds: free };
    const preview = await call(admin, 'POST', `/provider-connections/${id}/mail-flow/preview`, {
      change,
    });
    check('ProviderMailFlowController_preview_v1', preview);
    expect(preview.body.changeSet.domains[0].changed).toBe(true);
    const applied = await call(
      admin,
      'POST',
      `/provider-connections/${id}/mail-flow/apply`,
      { change, impactToken: preview.body.impactToken, confirm: true },
      k(),
    );
    check('ProviderMailFlowController_apply_v1', applied);
    expect(
      (
        await call(
          admin,
          'POST',
          `/provider-connections/${id}/mail-flow/apply`,
          { change, impactToken: preview.body.impactToken, confirm: true },
          k(),
        )
      ).body.code,
    ).toBe('impact_changed');

    check(
      'ProviderAttestationsController_record_v1',
      await call(
        admin,
        'POST',
        `/provider-connections/${id}/attestations`,
        { code: 'm365.inbound_connector_created', attested: true },
        k(),
      ),
    );
    const outbound = await call(admin, 'POST', `/provider-connections/${id}/mail-flow/preview`, {
      change: { kind: 'outbound', mode: 'probe_only' },
    });
    await call(
      admin,
      'POST',
      `/provider-connections/${id}/mail-flow/apply`,
      {
        change: { kind: 'outbound', mode: 'probe_only' },
        impactToken: outbound.body.impactToken,
        confirm: true,
      },
      k(),
    );
    const runKey = k();
    const run = await call(
      admin,
      'POST',
      `/provider-connections/${id}/validations`,
      { kind: 'full' },
      runKey,
    );
    check('ProviderValidationsController_create_v1', run);
    expect(run.body.probeAddress).toMatch(/^eg-probe-[a-z2-7]{26}@/);
    const runReplay = await call(
      admin,
      'POST',
      `/provider-connections/${id}/validations`,
      { kind: 'full' },
      runKey,
    );
    expect(runReplay.body.probeAddress).toBeNull();
    vi.advanceTimersByTime(7000);
    const finished = await call(
      admin,
      'GET',
      `/provider-connections/${id}/validations/${run.body.id}`,
    );
    check('ProviderValidationsController_get_v1', finished);
    expect(['passed', 'warning']).toContain(finished.body.status);
    expect(finished.body.probeObservations).toHaveLength(1);

    check(
      'ProviderHealthController_checkNow_v1',
      await call(admin, 'POST', `/provider-connections/${id}/health/check`, undefined, k()),
    );
    const current = await call(admin, 'GET', `/provider-connections/${id}`);
    check(
      'ProviderConnectionsController_update_v1',
      await call(admin, 'PATCH', `/provider-connections/${id}`, {
        displayName: 'Fixture tenant renamed',
        rowVersion: current.body.rowVersion,
      }),
    );
    check(
      'ProviderGrantsController_verify_v1',
      await call(
        admin,
        'POST',
        `/provider-connections/${id}/grants/m365.mail_flow/verify`,
        {},
        k(),
      ),
    );
    const disable = await call(admin, 'POST', `/provider-connections/${id}/mail-flow/preview`, {
      change: { kind: 'disable' },
    });
    const disconnected = await call(
      admin,
      'DELETE',
      `/provider-connections/${id}`,
      { impactToken: disable.body.impactToken, confirm: true },
      k(),
    );
    check('ProviderConnectionsController_disconnect_v1', disconnected);
    expect(disconnected.body.connection.status).toBe('disabled');

    // Customer-owned Google key: credentials accepted, never stored (only a fingerprint).
    const google = await call(
      admin,
      'POST',
      '/provider-connections',
      { provider: 'google_workspace', displayName: 'Fixture Google' },
      k(),
    );
    const gid = google.body.id as string;
    await call(
      admin,
      'POST',
      `/provider-connections/${gid}/grants`,
      { profile: 'google.mail_flow', authMethod: 'customer_service_account' },
      k(),
    );
    const marker = ['fixture', 'key', 'material'].join('-');
    const uploaded = await call(
      admin,
      'PUT',
      `/provider-connections/${gid}/grants/google.mail_flow/credentials`,
      {
        serviceAccountKey: { type: 'service_account', private_key: marker },
        subjectEmail: 'admin@example.test',
      },
      k(),
    );
    check('ProviderGrantsController_setCredentials_v1', uploaded);
    expect(
      JSON.stringify((await call(admin, 'GET', `/provider-connections/${gid}`)).body),
    ).not.toContain(marker);
    check(
      'ProviderGrantsController_revoke_v1',
      await call(
        admin,
        'DELETE',
        `/provider-connections/${gid}/grants/google.mail_flow`,
        undefined,
        k(),
      ),
    );
    vi.useRealTimers();
  });

  it('keeps organizations apart and enforces the permissions', async () => {
    const admin = await login('organization_admin@example.com');
    const reader = await login('read_only_user@example.com');
    const id = (await call(admin, 'GET', '/provider-connections')).body.data[0].id as string;
    expect((await call(reader, 'GET', `/provider-connections/${id}`)).status).toBe(200);
    expect(
      (
        await call(
          reader,
          'POST',
          '/provider-connections',
          { provider: 'microsoft_365', displayName: 'x' },
          k(),
        )
      ).status,
    ).toBe(403);
    expect(
      (await call(admin, 'GET', '/provider-connections/0193f400-0000-7000-8000-00000000ffff')).body
        .code,
    ).toBe('connection_not_found');
    const mailFlow = await call(reader, 'GET', `/provider-connections/${id}/mail-flow`);
    expect(mailFlow.body.routeToken.value).toBeNull();
    expect(mailFlow.body.routeToken.masked).toMatch(/^••••/);
  });
});
