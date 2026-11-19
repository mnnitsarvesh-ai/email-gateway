import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import type { ServiceAccountKey } from '../crypto/credential-cipher';
import { ProviderRequestError } from '../errors';
import type { GrantTokenRecord, GrantTokenSource } from '../tokens/token-service';
import type { GrantRef } from '../types';
import type {
  FakeFailure,
  FakeGoogleCustomer,
  FakeGoogleServiceAccount,
  FakeMicrosoftApp,
  FakeMicrosoftTenant,
  FakeRequestLogEntry,
} from './fake-provider-server';

/** An RSA key pair generated at test runtime (never committed, §10.1). */
export interface TestRsaKey {
  privateKeyPem: string;
  publicKeyPem: string;
  /** Hex SHA-1 of the SPKI DER: stands in for a certificate thumbprint in tests. */
  thumbprint: string;
  /** 40 hex characters, like a Google `private_key_id`. */
  keyId: string;
}

export function generateTestRsaKey(bits = 2048): TestRsaKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    thumbprint: createHash('sha1').update(der).digest('hex').toUpperCase(),
    keyId: randomBytes(20).toString('hex'),
  };
}

/** A service-account key document for `clientEmail` with a runtime key (for uploads and tokens). */
export function testServiceAccountKey(
  clientEmail: string,
  tokenUrl: string,
  key: TestRsaKey = generateTestRsaKey(),
  clientId = String(100_000_000_000_000_000_000n + BigInt(randomBytes(4).readUInt32BE())),
): { document: ServiceAccountKey; account: FakeGoogleServiceAccount; key: TestRsaKey } {
  return {
    document: {
      type: 'service_account',
      client_email: clientEmail.toLowerCase(),
      private_key: key.privateKeyPem,
      private_key_id: key.keyId,
      token_uri: tokenUrl,
      client_id: clientId,
    },
    account: {
      clientEmail: clientEmail.toLowerCase(),
      clientId,
      keyId: key.keyId,
      publicKeyPem: key.publicKeyPem,
    },
    key,
  };
}

/** A random client secret for fake apps (runtime only; not secret-shaped). */
export const testClientSecret = (): string => `fake${randomBytes(24).toString('base64url')}`;

/** A random lower-case GUID. */
export function testGuid(): string {
  const hex = randomBytes(16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** An in-memory `GrantTokenSource` (unit tests, contract suite, 8.5 adapter tests). */
export class StaticGrantSource implements GrantTokenSource {
  private readonly records = new Map<string, GrantTokenRecord>();
  loads = 0;

  private key(ref: GrantRef): string {
    return `${ref.organizationId}|${ref.connectionPublicId}|${ref.profile}`;
  }

  set(ref: GrantRef, record: GrantTokenRecord): void {
    this.records.set(this.key(ref), record);
  }

  loadForToken(ref: GrantRef): Promise<GrantTokenRecord> {
    this.loads += 1;
    const record = this.records.get(this.key(ref));
    if (!record) return Promise.reject(new ProviderRequestError('credential_unavailable'));
    return Promise.resolve({ ...record });
  }
}

/**
 * HTTP client of the fake's admin API (`/_fake/*`), for the in-process fake and the Compose
 * `provider-fake` alike.
 */
export class FakeProviderAdminClient {
  constructor(
    private readonly baseUrl: string,
    private readonly adminToken: string,
  ) {}

  private async post(path: string, body: unknown = {}): Promise<void> {
    const response = await fetch(`${this.baseUrl.replace(/\/+$/, '')}${path}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${this.adminToken}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (response.status !== 204) throw new Error(`fake admin ${path} answered ${response.status}`);
  }

  reset = () => this.post('/_fake/reset');
  addMicrosoftTenant = (tenant: FakeMicrosoftTenant) => this.post('/_fake/m365/tenants', tenant);
  addMicrosoftApp = (app: FakeMicrosoftApp) => this.post('/_fake/m365/apps', app);
  consent = (tenantId: string, clientId: string, roles: string[], resource?: string) =>
    this.post('/_fake/m365/consents', {
      tenantId,
      clientId,
      roles,
      ...(resource ? { resource } : {}),
    });
  revokeConsent = (tenantId: string, clientId: string) =>
    this.post('/_fake/m365/consents/revoke', { tenantId, clientId });
  setConsentTenant = (tenantId: string | null, decline = false) =>
    this.post('/_fake/m365/consent-tenant', { tenantId, decline });
  addGoogleCustomer = (customer: FakeGoogleCustomer) =>
    this.post('/_fake/google/customers', customer);
  addGoogleServiceAccount = (account: FakeGoogleServiceAccount) =>
    this.post('/_fake/google/service-accounts', account);
  delegate = (customerId: string, clientId: string, scopes: string[]) =>
    this.post('/_fake/google/delegations', { customerId, clientId, scopes });
  failNext = (failure: FakeFailure) => this.post('/_fake/failures', failure);
  setPaging = (options: {
    graphPageSize?: number;
    googlePageSize?: number;
    foreignNextLink?: boolean;
  }) => this.post('/_fake/paging', options);

  async requests(): Promise<FakeRequestLogEntry[]> {
    const response = await fetch(`${this.baseUrl.replace(/\/+$/, '')}/_fake/requests`, {
      headers: { authorization: `Bearer ${this.adminToken}` },
    });
    return ((await response.json()) as { requests: FakeRequestLogEntry[] }).requests;
  }
}
