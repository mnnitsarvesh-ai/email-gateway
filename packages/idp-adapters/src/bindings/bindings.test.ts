/**
 * The 8.2 bindings (design note §0.3, §0.4, §11.2; merge note M4) against step 8.2's library and
 * its test doubles: `FakeProviderServer` (in-process, 127.0.0.1), `StaticGrantSource` and the real
 * `ProviderTokenService` with the R1 options. No real provider endpoint is contacted.
 */
import {
  ATO_PROFILES,
  ProviderRequestError,
  ProviderTokenService,
  resolveProviderEndpoints,
  testing,
  type ProviderConnectionView as Connection82View,
  type ProviderEndpoints,
} from '@email-gateway/provider-integrations';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { ConnectionAccessError } from '../port/connection-port';
import { PERMISSION_REQUIREMENTS } from '../requirements';
import { ConnectionDirectory, eligibilityOf, toDirectoryConnection } from './connection-directory';
import {
  atoPermissionProfiles,
  ProviderConnectionBinding,
  toConnectionAccessError,
  toPortConnection,
  type ConnectionReads,
} from './provider-connections';

const { FakeProviderServer, StaticGrantSource, testClientSecret, testGuid, testServiceAccountKey } =
  testing;

const ORG = 4242n;
const signal = () => AbortSignal.timeout(10_000);

const fake = new FakeProviderServer();
let endpoints: ProviderEndpoints;

beforeAll(async () => {
  await fake.start();
  endpoints = resolveProviderEndpoints(fake.endpoints());
});
afterAll(() => fake.stop());

/** An 8.2 reader double holding connection views. */
class Reads implements ConnectionReads {
  readonly views: Connection82View[] = [];
  get(organizationId: bigint, publicId: string): Promise<Connection82View | null> {
    return Promise.resolve(
      this.views.find(
        (v) => v.publicId === publicId && v.organizationId === organizationId.toString(),
      ) ?? null,
    );
  }
  listForOrganization(organizationId: bigint): Promise<Connection82View[]> {
    return Promise.resolve(
      this.views.filter((v) => v.organizationId === organizationId.toString()),
    );
  }
}

function microsoftView(overrides: Partial<Connection82View> = {}): Connection82View {
  return {
    publicId: testGuid(),
    organizationId: ORG.toString(),
    provider: 'microsoft_365',
    displayName: 'Contoso IT (example)',
    status: 'active',
    externalTenantId: testGuid(),
    linkedDomains: [
      { name: 'contoso-it.example', providerVerified: true },
      { name: 'alias.contoso-it.example', providerVerified: false },
    ],
    grants: [
      {
        publicId: testGuid(),
        profile: 'm365.mail_flow',
        status: 'active',
        observedPermissions: ['Domain.Read.All', 'Organization.Read.All'],
        subjectEmail: null,
      },
      {
        publicId: testGuid(),
        profile: 'm365.ato_telemetry',
        status: 'active',
        observedPermissions: [
          'AuditLog.Read.All',
          'Directory.Read.All',
          'IdentityRiskEvent.Read.All',
          'User.Read.All',
        ],
        subjectEmail: null,
      },
      {
        publicId: testGuid(),
        profile: 'm365.ato_response',
        status: 'verifying',
        observedPermissions: [],
        subjectEmail: null,
      },
    ],
    updatedAt: new Date('2026-11-19T10:00:00.000Z'),
    ...overrides,
  };
}

describe('mapping of 8.2 views (§0.4)', () => {
  it('maps statuses, grants, observed permissions and dates', () => {
    const view = microsoftView({ status: 'connecting' });
    const port = toPortConnection(view);
    expect(port.status).toBe('configuring');
    expect(toPortConnection({ ...view, status: 'draft' }).status).toBe('configuring');
    expect(toPortConnection({ ...view, status: 'disabled' }).status).toBe('disabled');
    expect(port.grants.map((g) => [g.profile, g.status])).toEqual([
      ['m365.mail_flow', 'active'],
      ['m365.ato_telemetry', 'active'],
      ['m365.ato_response', 'pending'],
    ]);
    // 8.2's reader returns [] for a never-verified grant: the port says null.
    expect(port.grants[2]!.observedPermissions).toBeNull();
    expect(port.updatedAt).toBe('2026-11-19T10:00:00.000Z');
    expect(port.linkedDomains).toEqual(view.linkedDomains);
  });

  it('maps every 8.2 token error code onto the port vocabulary', () => {
    const cases: [ProviderRequestError['code'], string][] = [
      ['invalid_client', 'credentials_invalid'],
      ['unauthorized_client', 'credentials_invalid'],
      ['credential_unavailable', 'credentials_invalid'],
      ['consent_missing', 'consent_missing'],
      ['tenant_not_found', 'connection_inactive'],
      ['forbidden', 'scope_not_granted'],
      ['throttled', 'throttled'],
      ['unavailable', 'provider_unavailable'],
      ['timeout', 'provider_unavailable'],
      ['bad_response', 'provider_unavailable'],
    ];
    for (const [from, to] of cases) {
      expect(toConnectionAccessError(new ProviderRequestError(from)).code).toBe(to);
    }
    expect(
      toConnectionAccessError(new ProviderRequestError('throttled', { retryAfterMs: 4_000 })),
    ).toMatchObject({ code: 'throttled', retryAfterMs: 4_000 });
    expect(toConnectionAccessError(new Error('boom')).code).toBe('provider_unavailable');
  });
});

describe('ProviderConnectionBinding over 8.2’s token service (worker)', () => {
  let reads: Reads;
  let grants: InstanceType<typeof StaticGrantSource>;
  let binding: ProviderConnectionBinding;

  beforeEach(() => {
    fake.reset();
    reads = new Reads();
    grants = new StaticGrantSource();
    binding = new ProviderConnectionBinding({
      connections: reads,
      tokens: new ProviderTokenService({ grants, endpoints }),
    });
  });

  it('echo-checks the organization on get and list', async () => {
    const view = microsoftView();
    reads.views.push(view, microsoftView({ organizationId: '7' }));
    expect((await binding.get(ORG.toString(), view.publicId, signal()))?.publicId).toBe(
      view.publicId,
    );
    expect(await binding.get('7', view.publicId, signal())).toBeNull();
    expect(await binding.get('not-a-number', view.publicId, signal())).toBeNull();
    expect((await binding.list(ORG.toString(), signal())).map((c) => c.publicId)).toEqual([
      view.publicId,
    ]);
  });

  it('acquires Graph and Office 365 Management tokens (R1 resource) for the telemetry grant', async () => {
    const view = microsoftView();
    reads.views.push(view);
    const tenantId = view.externalTenantId!;
    const clientId = testGuid();
    const secret = testClientSecret();
    fake.addMicrosoftTenant({ tenantId, displayName: 'Contoso IT (example)', domains: [] });
    fake.addMicrosoftApp({ clientId, secret });
    fake.consent(tenantId, clientId, ['AuditLog.Read.All', 'User.Read.All']);
    fake.consent(tenantId, clientId, ['ActivityFeed.Read'], 'https://manage.office.com');
    grants.set(
      { organizationId: ORG, connectionPublicId: view.publicId, profile: 'm365.ato_telemetry' },
      {
        grantPublicId: view.grants[1]!.publicId,
        profile: 'm365.ato_telemetry',
        authMethod: 'customer_app_secret',
        status: 'active',
        credentialVersion: 1,
        tenantId,
        clientId,
        subjectEmail: null,
        credential: { method: 'customer_app_secret', clientSecret: secret },
      },
    );
    const connection = (await binding.get(ORG.toString(), view.publicId, signal()))!;
    const graph = await binding.acquireToken(
      connection,
      { profile: 'm365.ato_telemetry', resource: 'graph' },
      signal(),
    );
    const o365 = await binding.acquireToken(
      connection,
      { profile: 'm365.ato_telemetry', resource: 'o365_management' },
      signal(),
    );
    expect(graph.accessToken.length).toBeGreaterThan(16);
    expect(o365.accessToken).not.toBe(graph.accessToken);
    expect(graph.expiresAt).toBeGreaterThan(Date.now());
    expect(fake.requests.filter((r) => r.endpoint === 'm365.token').map((r) => r.scope)).toEqual([
      'https://graph.microsoft.com/.default',
      'https://manage.office.com/.default',
    ]);
    expect(JSON.stringify(fake.requests)).not.toContain(secret);
  });

  it('refuses missing or inactive grants before any provider call, and maps refusals', async () => {
    const view = microsoftView();
    reads.views.push(view);
    const connection = (await binding.get(ORG.toString(), view.publicId, signal()))!;
    await expect(
      binding.acquireToken(
        connection,
        { profile: 'm365.ato_response_extended', resource: 'graph' },
        signal(),
      ),
    ).rejects.toMatchObject({ code: 'grant_missing' });
    await expect(
      binding.acquireToken(
        connection,
        { profile: 'm365.ato_response', resource: 'graph' },
        signal(),
      ),
    ).rejects.toMatchObject({ code: 'consent_missing' });
    expect(fake.requests).toHaveLength(0);
    // The grant row exists for the connection but its credential is gone (8.2: credential_unavailable).
    const error = await binding
      .acquireToken(connection, { profile: 'm365.ato_telemetry', resource: 'graph' }, signal())
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConnectionAccessError);
    expect(error).toMatchObject({ code: 'credentials_invalid' });
  });

  it('R4: impersonates any user of a linked domain for Gmail (subject), not only the admin', async () => {
    const customerId = 'Cexample01';
    const view: Connection82View = {
      ...microsoftView(),
      provider: 'google_workspace',
      externalTenantId: customerId,
      linkedDomains: [{ name: 'fabrikam-it.example', providerVerified: true }],
      grants: [
        {
          publicId: testGuid(),
          profile: 'google.ato_telemetry',
          status: 'active',
          observedPermissions: [...ATO_PROFILES[3]!.permissions],
          subjectEmail: 'admin@fabrikam-it.example',
        },
      ],
    };
    reads.views.push(view);
    const sa = testServiceAccountKey(
      'ato@proj.iam.gserviceaccount.test',
      endpoints.googleToken.href,
    );
    fake.addGoogleServiceAccount(sa.account);
    fake.addGoogleCustomer({
      customerId,
      primaryDomain: 'fabrikam-it.example',
      domains: [{ domainName: 'fabrikam-it.example', verified: true, isPrimary: true }],
      admins: ['admin@fabrikam-it.example'],
    });
    fake.delegate(customerId, sa.account.clientId, [...ATO_PROFILES[3]!.permissions]);
    grants.set(
      { organizationId: ORG, connectionPublicId: view.publicId, profile: 'google.ato_telemetry' },
      {
        grantPublicId: view.grants[0]!.publicId,
        profile: 'google.ato_telemetry',
        authMethod: 'customer_service_account',
        status: 'active',
        credentialVersion: 1,
        tenantId: null,
        clientId: null,
        subjectEmail: 'admin@fabrikam-it.example',
        credential: { method: 'customer_service_account', key: sa.document },
      },
    );
    const connection = (await binding.get(ORG.toString(), view.publicId, signal()))!;
    await binding.acquireToken(
      connection,
      { profile: 'google.ato_telemetry', resource: 'google' },
      signal(),
    );
    await binding.acquireToken(
      connection,
      { profile: 'google.ato_telemetry', resource: 'google', subject: 'alex@fabrikam-it.example' },
      signal(),
    );
    expect(fake.assertions.google.map((c) => c.sub)).toEqual([
      'admin@fabrikam-it.example',
      'alex@fabrikam-it.example',
    ]);
  });
});

describe('ConnectionDirectory (api, read-only)', () => {
  it('lists connections with ATO profiles, required/missing permissions and eligibility', async () => {
    const reads = new Reads();
    const active = microsoftView();
    const inactive = microsoftView({ status: 'configuring' });
    reads.views.push(active, inactive, microsoftView({ organizationId: '9' }));
    const directory = new ConnectionDirectory(reads);
    const entries = await directory.list(ORG);
    expect(entries.map((e) => e.connection.publicId)).toEqual([active.publicId, inactive.publicId]);
    const entry = entries[0]!;
    expect(entry.kind).toBe('microsoft_entra');
    expect(entry.providerVerifiedDomains).toEqual(['contoso-it.example']);
    expect(entry.profiles.map((p) => p.profile)).toEqual([
      'm365.ato_telemetry',
      'm365.ato_response',
      'm365.ato_response_extended',
    ]);
    const telemetry = entry.profiles[0]!;
    expect(telemetry.notObservable).toEqual(['ActivityFeed.Read']);
    expect(telemetry.grant).toMatchObject({ status: 'active', missing: ['MailboxSettings.Read'] });
    expect(entry.profiles[1]!.grant).toMatchObject({ status: 'pending', observed: null });
    expect(entry.profiles[2]!.grant).toBeNull();

    expect(eligibilityOf(entry, new Set())).toEqual({ eligibility: 'eligible', reasons: [] });
    expect(eligibilityOf(entry, new Set([active.publicId])).eligibility).toBe('already_bound');
    expect(eligibilityOf(entries[1]!, new Set())).toEqual({
      eligibility: 'inactive',
      reasons: ['connection_inactive'],
    });
    const noTelemetry = toDirectoryConnection(toPortConnection(microsoftView({ grants: [] })));
    expect(eligibilityOf(noTelemetry, new Set()).reasons).toEqual(['telemetry_grant_missing']);
    expect(await directory.get(9n, active.publicId)).toBeNull();
    expect((await directory.get(ORG, active.publicId))?.connection.status).toBe('active');
  });
});

describe('8.2 registry ↔ PERMISSION_REQUIREMENTS', () => {
  it('the six registered ATO profiles carry exactly the catalogue’s permissions', () => {
    const catalogue = Object.values(PERMISSION_REQUIREMENTS).flatMap((r) => r.profiles);
    expect(
      atoPermissionProfiles()
        .map((p) => p.key)
        .sort(),
    ).toEqual(catalogue.map((p) => p.key).sort());
    for (const profile of catalogue) {
      const registered = atoPermissionProfiles().find((p) => p.key === profile.key)!;
      expect([...registered.permissions].sort()).toEqual(
        profile.permissions.map((p) => p.name).sort(),
      );
      expect(registered).toMatchObject({
        version: profile.version,
        purpose: profile.purpose,
        readOnly: profile.readOnly,
      });
    }
  });
});
