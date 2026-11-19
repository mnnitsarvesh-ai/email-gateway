import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { dkimSign } from 'mailauth/lib/dkim/sign';
import type { PrismaClient } from '@email-gateway/database';
import type { ApiResponse, ApiSession } from './api-client';
import { idempotencyKey } from './api-client';
import { composeExec, runningServices, waitFor } from './compose';
import { stack } from './env';
import type { SmtpStackGate } from './smtp-stack';
import { webhooksStackGate } from './webhooks';

/**
 * Shared pieces of the step 8.2 stack suite (docs/plan/steps/25-m365-google-connectors.md §10.5):
 * the Compose `provider-fake` admin API (tenants, apps, consents, Google customers, service
 * accounts, delegations, DNS TXT records of `relay-proof.test`), runtime-generated keys (never
 * committed), DKIM signing as Exchange Online / Gmail would, and the api's provider routes.
 * Nothing here reaches a real Microsoft or Google endpoint.
 */

export const RELAY_PROOF_ZONE = 'relay-proof.test';
export const M365_SENDER = 'provider-sender-m365';
export const GOOGLE_SENDER = 'provider-sender-google';
export const M365_PERMISSIONS = ['Organization.Read.All', 'Domain.Read.All'];
export const GOOGLE_SCOPES = [
  'https://www.googleapis.com/auth/admin.directory.customer.readonly',
  'https://www.googleapis.com/auth/admin.directory.domain.readonly',
];

const fakePort = () => Number(process.env.PROVIDER_FAKE_HOST_PORT || 18093);
export const fakeBaseUrl = () => `http://${stack.host}:${fakePort()}`;
const integrationWorkerPort = () => Number(process.env.INTEGRATION_WORKER_HOST_PORT || 3086);

async function ok(url: string): Promise<boolean> {
  try {
    return (await fetch(url, { signal: AbortSignal.timeout(3_000) })).ok;
  } catch {
    return false;
  }
}

let cached: Promise<SmtpStackGate> | undefined;

/**
 * Gate of the provider suite: the webhook stack gate (Postfix, adapter, engines, relay, api,
 * webhook-worker, receiver) plus a ready integration-worker, the provider-fake (with its admin
 * token in `.env`) and both provider-relay test clients.
 */
export function providerStackGate(): Promise<SmtpStackGate> {
  cached ??= (async () => {
    const base = await webhooksStackGate();
    if (base.skip) return base;
    const problems: string[] = base.problem ? [base.problem] : [];
    if (!(await ok(`http://${stack.host}:${integrationWorkerPort()}/health/ready`))) {
      problems.push(
        `integration-worker is not ready on ${stack.host}:${integrationWorkerPort()} ` +
          '(docker compose --profile apps up -d --wait integration-worker)',
      );
    }
    if (!process.env.PROVIDER_FAKE_ADMIN_TOKEN) {
      problems.push('PROVIDER_FAKE_ADMIN_TOKEN is not set in .env (append the 8.2 keys)');
    }
    if (!(await ok(`${fakeBaseUrl()}/health`))) {
      problems.push(
        'provider-fake is not running (docker compose --profile smtp-test up -d --wait provider-fake)',
      );
    }
    const services = await runningServices();
    for (const service of [M365_SENDER, GOOGLE_SENDER]) {
      if (!services.has(service)) {
        problems.push(
          `${service} is not running (docker compose --profile smtp-test up -d ${service})`,
        );
      }
    }
    return { ...base, problem: problems.length > 0 ? problems.join('\n') : undefined };
  })();
  return cached;
}

// --- provider-fake admin API ---------------------------------------------------------------------

async function fakePost(path: string, body: unknown): Promise<void> {
  const response = await fetch(`${fakeBaseUrl()}${path}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${process.env.PROVIDER_FAKE_ADMIN_TOKEN ?? ''}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (response.status !== 204) throw new Error(`provider-fake ${path} answered ${response.status}`);
}

export const fake = {
  addMicrosoftTenant: (tenant: {
    tenantId: string;
    displayName: string;
    domains: { name: string; isVerified: boolean; isDefault?: boolean; mxHost?: string | null }[];
  }) => fakePost('/_fake/m365/tenants', tenant),
  addMicrosoftApp: (app: {
    clientId: string;
    secret?: string;
    homeTenantId?: string;
    requiredRoles?: string[];
  }) => fakePost('/_fake/m365/apps', app),
  consent: (tenantId: string, clientId: string, roles: string[]) =>
    fakePost('/_fake/m365/consents', { tenantId, clientId, roles }),
  revokeConsent: (tenantId: string, clientId: string) =>
    fakePost('/_fake/m365/consents/revoke', { tenantId, clientId }),
  setConsentTenant: (tenantId: string | null, decline = false) =>
    fakePost('/_fake/m365/consent-tenant', { tenantId, decline }),
  addGoogleCustomer: (customer: {
    customerId: string;
    primaryDomain: string;
    organizationName?: string;
    domains: { domainName: string; verified: boolean; isPrimary?: boolean }[];
    admins: string[];
  }) => fakePost('/_fake/google/customers', customer),
  addGoogleServiceAccount: (account: {
    clientEmail: string;
    clientId: string;
    keyId: string;
    publicKeyPem: string;
  }) => fakePost('/_fake/google/service-accounts', account),
  delegate: (customerId: string, clientId: string, scopes: string[]) =>
    fakePost('/_fake/google/delegations', { customerId, clientId, scopes }),
  /** A TXT record under relay-proof.test (served to dns-sink, so to the smtp-adapter). */
  publishTxt: (name: string, values: string[]) => fakePost('/_fake/dns/txt', { name, values }),
  deleteTxt: (name: string) => fakePost('/_fake/dns/txt/delete', { name }),
};

// --- runtime keys --------------------------------------------------------------------------------

/** A random lower-case GUID (Microsoft tenant / app ids). */
export const guid = (): string => randomUUID();

/** A test client secret generated at run time (never a literal; never secret-shaped). */
export const runtimeSecret = (): string => randomBytes(24).toString('base64url');

export interface ServiceAccount {
  clientEmail: string;
  clientId: string;
  keyId: string;
  publicKeyPem: string;
  /** The JSON key document the customer uploads (`token_uri` = the api's configured URL). */
  key(tokenUri: string): Record<string, string>;
}

/** A Google service account with an RSA key generated at run time. */
export function serviceAccount(label: string): ServiceAccount {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const clientId = String(BigInt(`0x${randomBytes(8).toString('hex')}`)).padStart(21, '1');
  const keyId = randomBytes(20).toString('hex');
  const clientEmail = `${label}@it-provider.iam.example.test`;
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  return {
    clientEmail,
    clientId,
    keyId,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    key: (tokenUri) => ({
      type: 'service_account',
      client_email: clientEmail,
      client_id: clientId,
      private_key_id: keyId,
      private_key: privatePem,
      token_uri: tokenUri,
    }),
  };
}

export interface ProviderDkimKey {
  domain: string;
  selector: string;
  privateKeyPem: string;
}

/** The provider's DKIM key of a domain (RSA 2048), published under relay-proof.test. */
export async function providerDkimKey(
  domain: string,
  selector = 'prov1',
): Promise<ProviderDkimKey> {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const der = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  await fake.publishTxt(`${selector}._domainkey.${domain}`, [`v=DKIM1; k=rsa; p=${der}`]);
  return {
    domain,
    selector,
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

/** Signs a message as the provider would (relaxed/relaxed, `h=` covering From). */
export async function dkimSignAs(message: string, key: ProviderDkimKey): Promise<string> {
  const result = (await dkimSign(message, {
    canonicalization: 'relaxed/relaxed',
    signatureData: [
      {
        signingDomain: key.domain,
        selector: key.selector,
        privateKey: key.privateKeyPem,
        algorithm: 'rsa-sha256',
      },
    ],
  })) as { signatures: string; errors: unknown[] };
  if (result.errors.length > 0) throw new Error('test DKIM signing failed');
  return result.signatures + message;
}

/** A plain message (CRLF) with optional extra headers, ready to sign. */
export function providerMessage(options: {
  from: string;
  to: readonly string[];
  subject: string;
  headers?: readonly string[];
  body?: string;
}): string {
  return [
    ...(options.headers ?? []),
    `From: ${options.from}`,
    `To: ${options.to.join(', ')}`,
    `Subject: ${options.subject}`,
    `Message-ID: <${randomUUID()}@provider.example.test>`,
    `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    options.body ?? `Body of ${options.subject}.`,
    '',
  ].join('\r\n');
}

/** An environment value of a running Compose service (non-secret keys only). */
export async function serviceEnv(service: string, key: string): Promise<string> {
  if (
    !/^(PROVIDER|INTEGRATION|GATEWAY)_[A-Z0-9_]+$/.test(key) ||
    /KEY|SECRET|TOKEN(?!_URL$)/.test(key)
  ) {
    throw new Error(`refusing to read ${key}`);
  }
  const result = await composeExec(service, ['printenv', key], { timeoutMs: 20_000 });
  return result.stdout.trim();
}

// --- api helpers ---------------------------------------------------------------------------------

export function expectStatus(res: ApiResponse, status: number, what: string): void {
  if (res.status !== status) {
    throw new Error(
      `${what} answered ${res.status} (expected ${status}): ${JSON.stringify(res.body)}`,
    );
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON of the api in tests
export type Json = any;

/** Preview → apply of one mail-flow change (D13); returns the apply response. */
export async function previewAndApply(
  session: ApiSession,
  connectionId: string,
  change: Record<string, unknown>,
): Promise<{ preview: Json; apply: ApiResponse }> {
  const preview = await session.post(`/provider-connections/${connectionId}/mail-flow/preview`, {
    change,
  });
  expectStatus(preview, 200, `preview ${String(change.kind)}`);
  const body = preview.body as Json;
  const apply = await session.post(
    `/provider-connections/${connectionId}/mail-flow/apply`,
    { change, impactToken: body.impactToken, confirm: true },
    idempotencyKey(),
  );
  return { preview: body, apply };
}

/** Waits until GET /provider-connections/{id} satisfies `predicate`. */
export function waitForConnection(
  session: ApiSession,
  connectionId: string,
  what: string,
  predicate: (connection: Json) => boolean,
  timeoutMs = 120_000,
): Promise<Json> {
  return waitFor(
    `connection ${connectionId}: ${what}`,
    async () => {
      const res = await session.get(`/provider-connections/${connectionId}`);
      return res.status === 200 && predicate(res.body) ? res.body : undefined;
    },
    { timeoutMs, intervalMs: 2_000 },
  );
}

/** Waits until a validation run is finished (passed, warning, failed or expired). */
export function waitForRun(
  session: ApiSession,
  connectionId: string,
  runId: string,
  timeoutMs = 180_000,
): Promise<Json> {
  return waitFor(
    `validation run ${runId}`,
    async () => {
      const res = await session.get(`/provider-connections/${connectionId}/validations/${runId}`);
      const run = res.body as Json;
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- loose JSON of the api
      return res.status === 200 && ['passed', 'warning', 'failed', 'expired'].includes(run.status)
        ? run
        : undefined;
    },
    { timeoutMs, intervalMs: 2_000 },
  );
}

/**
 * Removes every step 8.2 row of the fixture organizations in the order of the tenant purge
 * (design §3.3): counters, observations, health, runs, consent states, domain links, grants, the
 * relay connectors' link, then the connections. The organizations themselves are removed by
 * SmtpFixtures.cleanup afterwards.
 */
export async function purgeProviderRows(
  prisma: PrismaClient,
  organizationIds: readonly bigint[],
): Promise<void> {
  if (organizationIds.length === 0) return;
  const where = { organizationId: { in: [...organizationIds] } };
  await prisma.providerRelayCounter.deleteMany({ where });
  await prisma.providerProbeObservation.deleteMany({ where });
  await prisma.providerHealthEvent.deleteMany({ where });
  await prisma.providerHealthCheck.deleteMany({ where });
  await prisma.providerValidationRun.deleteMany({ where });
  await prisma.providerConsentState.deleteMany({ where });
  await prisma.providerConnectionDomain.deleteMany({ where });
  await prisma.providerConnectionGrant.deleteMany({ where });
  await prisma.smtpConnector.updateMany({
    where: { ...where, providerConnectionId: { not: null } },
    data: { providerConnectionId: null },
  });
  await prisma.providerConnection.deleteMany({ where });
}

/** Rows of the provider tables still referencing the organizations (all zero after cleanup). */
export async function providerRowCounts(
  prisma: PrismaClient,
  organizationIds: readonly bigint[],
): Promise<Record<string, number>> {
  const where = { organizationId: { in: [...organizationIds] } };
  return {
    connections: await prisma.providerConnection.count({ where }),
    grants: await prisma.providerConnectionGrant.count({ where }),
    domains: await prisma.providerConnectionDomain.count({ where }),
    runs: await prisma.providerValidationRun.count({ where }),
    observations: await prisma.providerProbeObservation.count({ where }),
    healthChecks: await prisma.providerHealthCheck.count({ where }),
    healthEvents: await prisma.providerHealthEvent.count({ where }),
    counters: await prisma.providerRelayCounter.count({ where }),
  };
}
