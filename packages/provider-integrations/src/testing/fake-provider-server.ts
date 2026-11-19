import {
  createPublicKey,
  createSecretKey,
  randomBytes,
  randomUUID,
  timingSafeEqual,
  type KeyObject,
} from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { SignJWT, decodeJwt, decodeProtectedHeader, jwtVerify, type JWTPayload } from 'jose';
import type { ProviderEndpointsConfig } from '../endpoints';

/**
 * In-process HTTP fake of the four provider endpoints (D6 `testing`, §10.1): the Microsoft
 * identity platform token endpoint and admin-consent redirect, Microsoft Graph `organization` and
 * `domains`, the Google OAuth token endpoint (JWT bearer) and the Admin SDK `customers` and
 * `domains`. It verifies client secrets, certificate assertions and service-account JWTs the way
 * the providers do, issues tokens carrying the granted permissions, and serves scripted
 * failures. It never contacts the Internet. An optional admin API (`/_fake/*`, bearer
 * `adminToken`) configures it over HTTP, so the same contract suite runs against the in-process
 * fake and the Compose `provider-fake`.
 *
 * Path layout (matches the local `.env`): `/m365/login`, `/m365/graph`, `/google/token`,
 * `/google/admin`.
 */

export type FakeEndpoint =
  'm365.token' | 'm365.consent' | 'm365.graph' | 'google.token' | 'google.admin';

export interface FakeMicrosoftDomain {
  name: string;
  isVerified: boolean;
  isDefault?: boolean;
  /** Default `['Email']`. */
  supportedServices?: string[];
  /** The Exchange MX target (`<domain>.mail.protection.outlook.com`), or null for none. */
  mxHost?: string | null;
}

export interface FakeMicrosoftTenant {
  tenantId: string;
  displayName: string;
  domains: FakeMicrosoftDomain[];
}

export interface FakeMicrosoftApp {
  clientId: string;
  /** Client secret (customer apps, or the platform app in local/ci). */
  secret?: string;
  /** Certificate credential: the public key and the SHA-1 thumbprint (hex) the assertion names. */
  certificate?: { publicKeyPem: string; thumbprint: string };
  /** Single-tenant app: only this tenant may issue tokens. */
  homeTenantId?: string;
  /** Application permissions an admin consent grants (Graph). */
  requiredRoles?: string[];
}

export interface FakeGoogleDomain {
  domainName: string;
  verified: boolean;
  isPrimary?: boolean;
  aliases?: { name: string; verified: boolean }[];
}

export interface FakeGoogleCustomer {
  customerId: string;
  primaryDomain: string;
  organizationName?: string;
  domains: FakeGoogleDomain[];
  /** Administrators (may read the directory). */
  admins: string[];
  /**
   * Further users that may be impersonated (8.5 R4). Omitted = any address of the customer's
   * domains may be impersonated (admin rights still required for the directory).
   */
  users?: string[];
}

export interface FakeGoogleServiceAccount {
  clientEmail: string;
  /** Numeric OAuth client id (the domain-wide delegation entry). */
  clientId: string;
  /** `private_key_id` (the assertion's `kid`). */
  keyId: string;
  publicKeyPem: string;
}

export interface FakeFailure {
  endpoint: FakeEndpoint | 'any';
  status?: number;
  body?: unknown;
  /** Raw body (overrides `body`). */
  rawBody?: string;
  contentType?: string;
  headers?: Record<string, string>;
  /** How many requests fail (default 1). */
  times?: number;
  /** Delay before answering (timeout tests). */
  delayMs?: number;
  /** Answer with a redirect to this URL. */
  redirectTo?: string;
  /** Answer with this many filler bytes of JSON (byte-cap tests). */
  bodyBytes?: number;
}

export interface FakeRequestLogEntry {
  endpoint: FakeEndpoint | 'admin' | 'unknown';
  method: string;
  /** Path without the query string. */
  path: string;
  status: number;
  tenantId?: string;
  clientId?: string;
  subject?: string;
  scope?: string;
}

export interface FakeProviderServerOptions {
  host?: string;
  port?: number;
  /** Enables the `/_fake/*` admin API with this bearer token. */
  adminToken?: string;
  /** Graph `serviceConfigurationRecords` page size (paging tests). */
  graphPageSize?: number;
  /** Admin SDK `domains` page size. */
  googlePageSize?: number;
  /** Access-token lifetime (default 3600 s). */
  tokenLifetimeSeconds?: number;
}

interface IssuedClaims extends JWTPayload {
  kind: 'm365' | 'google';
  tid?: string;
  appid?: string;
  roles?: string[];
  scp?: string[];
  customerId?: string;
  resource?: string;
}

const GRAPH_RESOURCE = 'https://graph.microsoft.com';
const JSON_TYPE = 'application/json; charset=utf-8';

const lower = (v: string) => v.trim().toLowerCase();

export class FakeProviderServer {
  private server: Server | null = null;
  private readonly signingKey: KeyObject = createSecretKey(randomBytes(32));
  private readonly options: Required<Omit<FakeProviderServerOptions, 'adminToken'>> & {
    adminToken?: string;
  };

  private readonly m365Tenants = new Map<string, FakeMicrosoftTenant>();
  private readonly m365Apps = new Map<string, FakeMicrosoftApp>();
  /** tenant|client|resource → roles */
  private readonly m365Consents = new Map<string, Set<string>>();
  private readonly googleCustomers = new Map<string, FakeGoogleCustomer>();
  private readonly googleAccounts = new Map<string, FakeGoogleServiceAccount>();
  /** customer|clientId → scopes */
  private readonly googleDelegations = new Map<string, Set<string>>();
  private failures: (FakeFailure & { remaining: number })[] = [];
  private consentTenant: { tenantId: string; decline: boolean } | null = null;
  private foreignNextLink = false;

  /** Every request served (no secrets, no tokens). */
  readonly requests: FakeRequestLogEntry[] = [];
  /** Decoded (verified) client assertions and JWT bearer assertions, for claim assertions. */
  readonly assertions: { microsoft: JWTPayload[]; google: (JWTPayload & { kid?: string })[] } = {
    microsoft: [],
    google: [],
  };

  constructor(options: FakeProviderServerOptions = {}) {
    this.options = {
      host: options.host ?? '127.0.0.1',
      port: options.port ?? 0,
      graphPageSize: options.graphPageSize ?? 100,
      googlePageSize: options.googlePageSize ?? 100,
      tokenLifetimeSeconds: options.tokenLifetimeSeconds ?? 3600,
      ...(options.adminToken ? { adminToken: options.adminToken } : {}),
    };
  }

  async start(): Promise<this> {
    if (this.server) return this;
    const server = createServer((req, res) => {
      this.handle(req, res).catch(() => {
        if (!res.headersSent) this.json(res, 500, { error: 'server_error' });
        else res.end();
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.options.port, this.options.host, () => resolve());
    });
    this.server = server;
    return this;
  }

  async stop(): Promise<void> {
    const server = this.server;
    this.server = null;
    if (!server) return;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  get baseUrl(): string {
    if (!this.server) throw new Error('FakeProviderServer is not started');
    const address = this.server.address() as AddressInfo;
    const host = address.family === 'IPv6' ? `[${address.address}]` : address.address;
    return `http://${host}:${address.port}`;
  }

  /** Endpoint configuration pointing at this fake (`allowHttp`). */
  endpoints(): ProviderEndpointsConfig {
    return fakeEndpointsFor(this.baseUrl);
  }

  // ---- state ---------------------------------------------------------------------------------

  reset(): void {
    this.m365Tenants.clear();
    this.m365Apps.clear();
    this.m365Consents.clear();
    this.googleCustomers.clear();
    this.googleAccounts.clear();
    this.googleDelegations.clear();
    this.failures = [];
    this.consentTenant = null;
    this.foreignNextLink = false;
    this.requests.length = 0;
    this.assertions.microsoft.length = 0;
    this.assertions.google.length = 0;
  }

  addMicrosoftTenant(tenant: FakeMicrosoftTenant): void {
    this.m365Tenants.set(lower(tenant.tenantId), {
      ...tenant,
      tenantId: lower(tenant.tenantId),
      domains: tenant.domains.map((d) => ({ ...d, name: lower(d.name) })),
    });
  }

  addMicrosoftApp(app: FakeMicrosoftApp): void {
    this.m365Apps.set(lower(app.clientId), { ...app, clientId: lower(app.clientId) });
  }

  /** Grants application permissions of `clientId` in `tenantId` for a resource (default Graph). */
  consent(tenantId: string, clientId: string, roles: string[], resource = GRAPH_RESOURCE): void {
    this.m365Consents.set(`${lower(tenantId)}|${lower(clientId)}|${resource}`, new Set(roles));
  }

  revokeConsent(tenantId: string, clientId: string, resource = GRAPH_RESOURCE): void {
    this.m365Consents.delete(`${lower(tenantId)}|${lower(clientId)}|${resource}`);
  }

  /** The tenant the admin-consent endpoint simulates (and whether the admin declines). */
  setConsentTenant(tenantId: string | null, decline = false): void {
    this.consentTenant = tenantId ? { tenantId: lower(tenantId), decline } : null;
  }

  addGoogleCustomer(customer: FakeGoogleCustomer): void {
    this.googleCustomers.set(customer.customerId, {
      ...customer,
      primaryDomain: lower(customer.primaryDomain),
      admins: customer.admins.map(lower),
      ...(customer.users ? { users: customer.users.map(lower) } : {}),
      domains: customer.domains.map((d) => ({
        ...d,
        domainName: lower(d.domainName),
        ...(d.aliases ? { aliases: d.aliases.map((a) => ({ ...a, name: lower(a.name) })) } : {}),
      })),
    });
  }

  addGoogleServiceAccount(account: FakeGoogleServiceAccount): void {
    this.googleAccounts.set(lower(account.clientEmail), {
      ...account,
      clientEmail: lower(account.clientEmail),
    });
  }

  /** Domain-wide delegation of `scopes` to `clientId` in a customer. */
  delegate(customerId: string, clientId: string, scopes: string[]): void {
    this.googleDelegations.set(`${customerId}|${clientId}`, new Set(scopes));
  }

  revokeDelegation(customerId: string, clientId: string): void {
    this.googleDelegations.delete(`${customerId}|${clientId}`);
  }

  failNext(failure: FakeFailure): void {
    this.failures.push({ ...failure, remaining: failure.times ?? 1 });
  }

  setPaging(options: {
    graphPageSize?: number;
    googlePageSize?: number;
    foreignNextLink?: boolean;
  }): void {
    if (options.graphPageSize !== undefined)
      this.options.graphPageSize = Math.max(1, options.graphPageSize);
    if (options.googlePageSize !== undefined)
      this.options.googlePageSize = Math.max(1, options.googlePageSize);
    if (options.foreignNextLink !== undefined) this.foreignNextLink = options.foreignNextLink;
  }

  // ---- HTTP ----------------------------------------------------------------------------------

  private json(
    res: ServerResponse,
    status: number,
    body: unknown,
    headers: Record<string, string> = {},
  ): void {
    const text = JSON.stringify(body);
    res.writeHead(status, {
      'content-type': JSON_TYPE,
      'content-length': Buffer.byteLength(text),
      ...headers,
    });
    res.end(text);
  }

  private log(entry: FakeRequestLogEntry): void {
    this.requests.push(entry);
    if (this.requests.length > 1000) this.requests.splice(0, this.requests.length - 1000);
  }

  private async readBody(req: IncomingMessage, max = 262_144): Promise<string> {
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of req) {
      total += (chunk as Buffer).length;
      if (total > max) throw new Error('body too large');
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks).toString('utf8');
  }

  private endpointOf(path: string): FakeEndpoint | 'admin' | 'unknown' {
    if (path.startsWith('/_fake/')) return 'admin';
    if (path.startsWith('/m365/login/organizations/v2.0/adminconsent')) return 'm365.consent';
    if (path.startsWith('/m365/login/')) return 'm365.token';
    if (path.startsWith('/m365/graph/')) return 'm365.graph';
    if (path === '/google/token') return 'google.token';
    if (path.startsWith('/google/admin/')) return 'google.admin';
    return 'unknown';
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://fake.invalid');
    const path = url.pathname;
    const endpoint = this.endpointOf(path);
    const method = req.method ?? 'GET';

    if (endpoint === 'admin') return this.handleAdmin(req, res, path, method);
    if (endpoint === 'unknown') {
      this.log({ endpoint, method, path, status: 404 });
      return this.json(res, 404, { error: 'not_found' });
    }
    const failure = this.failures.find((f) => f.endpoint === endpoint || f.endpoint === 'any');
    if (failure) {
      failure.remaining -= 1;
      if (failure.remaining <= 0) this.failures.splice(this.failures.indexOf(failure), 1);
      if (failure.delayMs) await new Promise((r) => setTimeout(r, failure.delayMs));
      if (res.destroyed) return;
      const status = failure.redirectTo ? 302 : (failure.status ?? 500);
      this.log({ endpoint, method, path, status });
      if (failure.redirectTo) {
        res.writeHead(302, { location: failure.redirectTo });
        return void res.end();
      }
      const raw =
        failure.rawBody ??
        (failure.bodyBytes !== undefined
          ? JSON.stringify({ filler: 'x'.repeat(failure.bodyBytes) })
          : JSON.stringify(failure.body ?? {}));
      res.writeHead(status, {
        'content-type': failure.contentType ?? JSON_TYPE,
        ...failure.headers,
      });
      return void res.end(raw);
    }

    switch (endpoint) {
      case 'm365.token':
        return this.microsoftToken(req, res, path, method);
      case 'm365.consent':
        return this.microsoftConsent(res, url, method);
      case 'm365.graph':
        return this.graph(req, res, url, method);
      case 'google.token':
        return this.googleToken(req, res, method);
      case 'google.admin':
        return this.googleAdmin(req, res, url, method);
    }
  }

  // ---- Microsoft identity platform ----------------------------------------------------------

  private async microsoftToken(
    req: IncomingMessage,
    res: ServerResponse,
    path: string,
    method: string,
  ): Promise<void> {
    const match = /^\/m365\/login\/([^/]+)\/oauth2\/v2\.0\/token$/.exec(path);
    const fail = (
      status: number,
      error: string,
      codes: number[],
      extra: Partial<FakeRequestLogEntry> = {},
    ) => {
      this.log({ endpoint: 'm365.token', method, path, status, ...extra });
      this.json(res, status, {
        error,
        error_description: `AADSTS${codes[0] ?? 0}: fake error`,
        error_codes: codes,
        trace_id: randomUUID(),
      });
    };
    if (!match || method !== 'POST') return fail(404, 'invalid_request', [900561]);
    const form = new URLSearchParams(await this.readBody(req));
    const tenantId = lower(match[1]!);
    const clientId = lower(form.get('client_id') ?? '');
    const scope = form.get('scope') ?? '';
    const log = { tenantId, clientId, scope };
    if (form.get('grant_type') !== 'client_credentials')
      return fail(400, 'unsupported_grant_type', [70003], log);
    const tenant = this.m365Tenants.get(tenantId);
    if (!tenant) return fail(400, 'invalid_request', [90002], log);
    const app = this.m365Apps.get(clientId);
    if (!app) return fail(400, 'unauthorized_client', [700016], log);
    if (app.homeTenantId && lower(app.homeTenantId) !== tenantId)
      return fail(400, 'unauthorized_client', [700016], log);

    if (form.has('client_secret')) {
      const secret = form.get('client_secret') ?? '';
      if (!app.secret || !safeEqual(secret, app.secret))
        return fail(401, 'invalid_client', [7000215], log);
    } else if (
      form.get('client_assertion_type') === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    ) {
      if (!app.certificate) return fail(401, 'invalid_client', [700027], log);
      const assertion = form.get('client_assertion') ?? '';
      try {
        const header = decodeProtectedHeader(assertion);
        const expectedX5t = Buffer.from(app.certificate.thumbprint, 'hex').toString('base64url');
        if (header.alg !== 'RS256' || header.x5t !== expectedX5t) throw new Error('x5t');
        const { payload } = await jwtVerify(
          assertion,
          createPublicKey(app.certificate.publicKeyPem),
          {
            algorithms: ['RS256'],
            audience: `${requestOrigin(req)}${path}`,
            issuer: clientId,
            subject: clientId,
            maxTokenAge: '15m',
          },
        );
        if (!payload.jti || !payload.exp || payload.exp - (payload.iat ?? 0) > 3600)
          throw new Error('claims');
        this.assertions.microsoft.push(payload);
      } catch {
        return fail(401, 'invalid_client', [700027], log);
      }
    } else {
      return fail(401, 'invalid_client', [7000216], log);
    }

    const resourceMatch = /^(.+)\/\.default$/.exec(scope);
    if (!resourceMatch) return fail(400, 'invalid_scope', [1002012], log);
    const resource = resourceMatch[1]!;
    const roles = this.m365Consents.get(`${tenantId}|${clientId}|${resource}`);
    if (!roles) return fail(400, 'invalid_grant', [65001], log);
    const token = await this.issue({
      kind: 'm365',
      tid: tenantId,
      appid: clientId,
      roles: [...roles].sort(),
      resource,
    });
    this.log({ endpoint: 'm365.token', method, path, status: 200, ...log });
    this.json(res, 200, {
      token_type: 'Bearer',
      expires_in: this.options.tokenLifetimeSeconds,
      ext_expires_in: this.options.tokenLifetimeSeconds,
      access_token: token,
    });
  }

  private microsoftConsent(res: ServerResponse, url: URL, method: string): void {
    const path = url.pathname;
    const clientId = lower(url.searchParams.get('client_id') ?? '');
    const redirect = url.searchParams.get('redirect_uri') ?? '';
    const state = url.searchParams.get('state') ?? '';
    const app = this.m365Apps.get(clientId);
    let target: URL;
    try {
      target = new URL(redirect);
    } catch {
      this.log({ endpoint: 'm365.consent', method, path, status: 400, clientId });
      return this.json(res, 400, { error: 'invalid_request' });
    }
    const consent = this.consentTenant;
    if (!app || !consent || consent.decline) {
      target.searchParams.set('error', consent?.decline ? 'access_denied' : 'invalid_client');
      target.searchParams.set(
        'error_description',
        'The administrator declined or the application is unknown.',
      );
    } else {
      this.consent(consent.tenantId, clientId, app.requiredRoles ?? []);
      target.searchParams.set('tenant', consent.tenantId);
      target.searchParams.set('admin_consent', 'True');
    }
    target.searchParams.set('state', state);
    this.log({ endpoint: 'm365.consent', method, path, status: 302, clientId });
    res.writeHead(302, { location: target.href });
    res.end();
  }

  private async bearer(
    req: IncomingMessage,
    kind: 'm365' | 'google',
  ): Promise<IssuedClaims | null> {
    const header = req.headers.authorization ?? '';
    const match = /^Bearer ([A-Za-z0-9._-]+)$/.exec(header);
    if (!match) return null;
    try {
      const { payload } = await jwtVerify(match[1]!, this.signingKey, { algorithms: ['HS256'] });
      const claims = payload as IssuedClaims;
      return claims.kind === kind ? claims : null;
    } catch {
      return null;
    }
  }

  private async issue(claims: Omit<IssuedClaims, 'iat' | 'exp'>): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ ...claims })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuedAt(now)
      .setExpirationTime(now + this.options.tokenLifetimeSeconds)
      .setJti(randomUUID())
      .sign(this.signingKey);
  }

  // ---- Microsoft Graph -----------------------------------------------------------------------

  private async graph(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    method: string,
  ): Promise<void> {
    const path = url.pathname;
    const graphError = (status: number, code: string) => {
      this.log({ endpoint: 'm365.graph', method, path, status });
      this.json(res, status, {
        error: { code, message: 'fake graph error', innerError: { 'request-id': randomUUID() } },
      });
    };
    if (method !== 'GET') return graphError(405, 'Request_BadRequest');
    const claims = await this.bearer(req, 'm365');
    if (!claims || claims.resource !== GRAPH_RESOURCE)
      return graphError(401, 'InvalidAuthenticationToken');
    const tenant = this.m365Tenants.get(claims.tid ?? '');
    if (!tenant) return graphError(401, 'InvalidAuthenticationToken');
    const roles = new Set(claims.roles ?? []);
    const rest = path.slice('/m365/graph/v1.0'.length);
    const ok = (body: unknown) => {
      this.log({ endpoint: 'm365.graph', method, path, status: 200, tenantId: tenant.tenantId });
      this.json(res, 200, body);
    };

    if (rest === '/organization') {
      if (!roles.has('Organization.Read.All') && !roles.has('Directory.Read.All')) {
        return graphError(403, 'Authorization_RequestDenied');
      }
      return ok({
        '@odata.context': `${requestOrigin(req)}/m365/graph/v1.0/$metadata#organization`,
        value: [
          {
            id: tenant.tenantId,
            displayName: tenant.displayName,
            verifiedDomains: tenant.domains
              .filter((d) => d.isVerified)
              .map((d) => ({
                name: d.name,
                isDefault: d.isDefault === true,
                isInitial: d.name.endsWith('.onmicrosoft.com'),
                type: 'Managed',
                capabilities: 'Email, OfficeCommunicationsOnline',
              })),
          },
        ],
      });
    }
    const domainMatch = /^\/domains\/([^/]+)(\/serviceConfigurationRecords)?$/.exec(rest);
    if (domainMatch) {
      if (!roles.has('Domain.Read.All') && !roles.has('Directory.Read.All')) {
        return graphError(403, 'Authorization_RequestDenied');
      }
      const domain = tenant.domains.find(
        (d) => d.name === lower(decodeURIComponent(domainMatch[1]!)),
      );
      if (!domain) return graphError(404, 'Request_ResourceNotFound');
      if (!domainMatch[2]) {
        return ok({
          id: domain.name,
          isVerified: domain.isVerified,
          isDefault: domain.isDefault === true,
          authenticationType: 'Managed',
          supportedServices: domain.supportedServices ?? ['Email'],
        });
      }
      const records: unknown[] = [
        ...(domain.mxHost
          ? [
              {
                id: randomUUID(),
                recordType: 'Mx',
                label: domain.name,
                supportedService: 'Email',
                ttl: 3600,
                isOptional: false,
                mailExchange: domain.mxHost,
                preference: 0,
              },
            ]
          : []),
        {
          id: randomUUID(),
          recordType: 'Txt',
          label: domain.name,
          supportedService: 'Email',
          ttl: 3600,
          isOptional: false,
          text: 'v=spf1 include:spf.protection.outlook.com -all',
        },
        {
          id: randomUUID(),
          recordType: 'CName',
          label: `autodiscover.${domain.name}`,
          supportedService: 'Email',
          ttl: 3600,
          isOptional: false,
          canonicalName: 'autodiscover.outlook.com',
        },
      ];
      const size = this.options.graphPageSize;
      const skip = Number(url.searchParams.get('$skiptoken') ?? '0') || 0;
      const page = records.slice(skip, skip + size);
      const more = skip + size < records.length;
      const next = more
        ? this.foreignNextLink
          ? `https://graph.attacker.example/v1.0${rest}?$skiptoken=${skip + size}`
          : `${requestOrigin(req)}/m365/graph/v1.0${rest}?$skiptoken=${skip + size}`
        : undefined;
      return ok({ value: page, ...(next ? { '@odata.nextLink': next } : {}) });
    }
    return graphError(400, 'Request_BadRequest');
  }

  // ---- Google OAuth --------------------------------------------------------------------------

  private async googleToken(
    req: IncomingMessage,
    res: ServerResponse,
    method: string,
  ): Promise<void> {
    const path = '/google/token';
    const fail = (
      status: number,
      error: string,
      description: string,
      extra: Partial<FakeRequestLogEntry> = {},
    ) => {
      this.log({ endpoint: 'google.token', method, path, status, ...extra });
      this.json(res, status, { error, error_description: description });
    };
    if (method !== 'POST') return fail(405, 'invalid_request', 'Method not allowed');
    const form = new URLSearchParams(await this.readBody(req));
    if (form.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
      return fail(400, 'unsupported_grant_type', 'Invalid grant_type');
    }
    const assertion = form.get('assertion') ?? '';
    let iss: string;
    let kid: string | undefined;
    try {
      iss = lower(String(decodeJwt(assertion).iss ?? ''));
      kid = decodeProtectedHeader(assertion).kid;
    } catch {
      return fail(400, 'invalid_grant', 'Invalid JWT');
    }
    const account = this.googleAccounts.get(iss);
    if (!account) return fail(400, 'invalid_grant', 'Invalid JWT Signature.');
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(assertion, createPublicKey(account.publicKeyPem), {
        algorithms: ['RS256'],
        audience: `${requestOrigin(req)}${path}`,
        issuer: account.clientEmail,
      }));
    } catch {
      return fail(400, 'invalid_grant', 'Invalid JWT Signature.', { clientId: account.clientId });
    }
    if (kid !== account.keyId)
      return fail(400, 'invalid_grant', 'Invalid JWT Signature.', { clientId: account.clientId });
    const iat = payload.iat ?? 0;
    const exp = payload.exp ?? 0;
    const now = Math.floor(Date.now() / 1000);
    if (exp - iat > 3600 || iat > now + 300) {
      return fail(
        400,
        'invalid_grant',
        'Invalid JWT: Token must be a short-lived token (60 minutes) and in a reasonable timeframe.',
      );
    }
    this.assertions.google.push({ ...payload, ...(kid ? { kid } : {}) });
    const subject = lower(String(payload.sub ?? ''));
    const rawScope = (payload as { scope?: unknown }).scope;
    const scopes = (typeof rawScope === 'string' ? rawScope : '').split(/\s+/).filter(Boolean);
    const log = { clientId: account.clientId, subject, scope: scopes.join(' ') };
    const customer = this.customerOfAddress(subject);
    if (!customer || !this.mayImpersonate(customer, subject)) {
      return fail(400, 'invalid_grant', 'Invalid email or User ID', log);
    }
    const delegated = this.googleDelegations.get(`${customer.customerId}|${account.clientId}`);
    if (scopes.length === 0 || !delegated || scopes.some((s) => !delegated.has(s))) {
      return fail(
        401,
        'unauthorized_client',
        'Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested.',
        log,
      );
    }
    const token = await this.issue({
      kind: 'google',
      sub: subject,
      scp: scopes,
      customerId: customer.customerId,
    });
    this.log({ endpoint: 'google.token', method, path, status: 200, ...log });
    this.json(res, 200, {
      access_token: token,
      expires_in: this.options.tokenLifetimeSeconds - 1,
      token_type: 'Bearer',
    });
  }

  private customerOfAddress(address: string): FakeGoogleCustomer | undefined {
    const domain = address.split('@')[1] ?? '';
    for (const customer of this.googleCustomers.values()) {
      const names = customer.domains.flatMap((d) => [
        d.domainName,
        ...(d.aliases ?? []).map((a) => a.name),
      ]);
      if (names.includes(domain)) return customer;
    }
    return undefined;
  }

  private mayImpersonate(customer: FakeGoogleCustomer, subject: string): boolean {
    if (customer.admins.includes(subject)) return true;
    return customer.users ? customer.users.includes(subject) : true;
  }

  // ---- Google Admin SDK ----------------------------------------------------------------------

  private async googleAdmin(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    method: string,
  ): Promise<void> {
    const path = url.pathname;
    const apiError = (status: number, reason: string, statusText: string) => {
      this.log({ endpoint: 'google.admin', method, path, status });
      this.json(res, status, {
        error: {
          code: status,
          message: 'fake admin error',
          status: statusText,
          errors: [{ reason, domain: 'global', message: 'fake' }],
        },
      });
    };
    if (method !== 'GET') return apiError(405, 'badRequest', 'INVALID_ARGUMENT');
    const claims = await this.bearer(req, 'google');
    if (!claims) return apiError(401, 'authError', 'UNAUTHENTICATED');
    const customer = this.googleCustomers.get(claims.customerId ?? '');
    if (!customer) return apiError(401, 'authError', 'UNAUTHENTICATED');
    const scopes = new Set(claims.scp ?? []);
    const isAdmin = customer.admins.includes(lower(String(claims.sub ?? '')));
    const rest = path.slice('/google/admin'.length);
    const ok = (body: unknown) => {
      this.log({
        endpoint: 'google.admin',
        method,
        path,
        status: 200,
        tenantId: customer.customerId,
      });
      this.json(res, 200, body);
    };
    const has = (scope: string) =>
      scopes.has(`https://www.googleapis.com/auth/${scope}.readonly`) ||
      scopes.has(`https://www.googleapis.com/auth/${scope}`);

    if (rest === '/admin/directory/v1/customers/my_customer') {
      if (!has('admin.directory.customer') || !isAdmin)
        return apiError(403, 'forbidden', 'PERMISSION_DENIED');
      return ok({
        kind: 'admin#directory#customer',
        id: customer.customerId,
        customerDomain: customer.primaryDomain,
        ...(customer.organizationName
          ? { postalAddress: { organizationName: customer.organizationName } }
          : {}),
      });
    }
    if (rest === '/admin/directory/v1/customer/my_customer/domains') {
      if (!has('admin.directory.domain') || !isAdmin)
        return apiError(403, 'forbidden', 'PERMISSION_DENIED');
      const all = customer.domains.map((d) => ({
        kind: 'admin#directory#domain',
        domainName: d.domainName,
        verified: d.verified,
        isPrimary: d.isPrimary === true,
        domainAliases: (d.aliases ?? []).map((a) => ({
          kind: 'admin#directory#domainAlias',
          domainAliasName: a.name,
          parentDomainName: d.domainName,
          verified: a.verified,
        })),
      }));
      const size = this.options.googlePageSize;
      const start = Number(url.searchParams.get('pageToken')?.replace(/^p/, '') ?? '0') || 0;
      const page = all.slice(start, start + size);
      return ok({
        kind: 'admin#directory#domains',
        domains: page,
        ...(start + size < all.length ? { nextPageToken: `p${start + size}` } : {}),
      });
    }
    return apiError(404, 'notFound', 'NOT_FOUND');
  }

  // ---- admin API -----------------------------------------------------------------------------

  private async handleAdmin(
    req: IncomingMessage,
    res: ServerResponse,
    path: string,
    method: string,
  ): Promise<void> {
    const token = this.options.adminToken;
    const given = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1] ?? '';
    if (!token || !safeEqual(given, token)) {
      this.log({ endpoint: 'admin', method, path, status: 401 });
      return this.json(res, 401, { error: 'unauthorized' });
    }
    const done = (status = 204, body?: unknown) => {
      this.log({ endpoint: 'admin', method, path, status });
      if (body === undefined) {
        res.writeHead(status);
        return void res.end();
      }
      this.json(res, status, body);
    };
    if (method === 'GET' && path === '/_fake/requests')
      return done(200, { requests: this.requests });
    if (method === 'GET' && path === '/_fake/assertions') return done(200, this.assertions);
    if (method !== 'POST') return done(405, { error: 'method_not_allowed' });
    let body: Record<string, unknown> = {};
    try {
      const text = await this.readBody(req);
      body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
    } catch {
      return done(400, { error: 'invalid_json' });
    }
    try {
      switch (path) {
        case '/_fake/reset':
          this.reset();
          return done();
        case '/_fake/m365/tenants':
          this.addMicrosoftTenant(body as unknown as FakeMicrosoftTenant);
          return done();
        case '/_fake/m365/apps':
          this.addMicrosoftApp(body as unknown as FakeMicrosoftApp);
          return done();
        case '/_fake/m365/consents':
          this.consent(
            String(body.tenantId),
            String(body.clientId),
            (body.roles as string[]) ?? [],
            (body.resource as string) ?? GRAPH_RESOURCE,
          );
          return done();
        case '/_fake/m365/consents/revoke':
          this.revokeConsent(
            String(body.tenantId),
            String(body.clientId),
            (body.resource as string) ?? GRAPH_RESOURCE,
          );
          return done();
        case '/_fake/m365/consent-tenant':
          this.setConsentTenant((body.tenantId as string | null) ?? null, body.decline === true);
          return done();
        case '/_fake/google/customers':
          this.addGoogleCustomer(body as unknown as FakeGoogleCustomer);
          return done();
        case '/_fake/google/service-accounts':
          this.addGoogleServiceAccount(body as unknown as FakeGoogleServiceAccount);
          return done();
        case '/_fake/google/delegations':
          this.delegate(
            String(body.customerId),
            String(body.clientId),
            (body.scopes as string[]) ?? [],
          );
          return done();
        case '/_fake/google/delegations/revoke':
          this.revokeDelegation(String(body.customerId), String(body.clientId));
          return done();
        case '/_fake/failures':
          this.failNext(body as unknown as FakeFailure);
          return done();
        case '/_fake/paging':
          this.setPaging(body);
          return done();
        default:
          return done(404, { error: 'not_found' });
      }
    } catch {
      return done(400, { error: 'invalid_state' });
    }
  }
}

/** The origin the client used (Host header), so audiences and paging links work behind any name. */
function requestOrigin(req: IncomingMessage): string {
  const host = req.headers.host ?? 'localhost';
  return `http://${/^[A-Za-z0-9.:[\]-]{1,300}$/.test(host) ? host : 'localhost'}`;
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Endpoint configuration for a fake at `baseUrl` (in-process or the Compose `provider-fake`). */
export function fakeEndpointsFor(baseUrl: string): ProviderEndpointsConfig {
  const base = baseUrl.replace(/\/+$/, '');
  return {
    m365LoginUrl: `${base}/m365/login`,
    m365GraphUrl: `${base}/m365/graph`,
    m365ManagementUrl: 'https://manage.office.com',
    googleTokenUrl: `${base}/google/token`,
    googleAdminUrl: `${base}/google/admin`,
    allowHttp: true,
  };
}
