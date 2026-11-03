/**
 * Helpers for the step 2.2 API integration suites (WP5): SMTP connectors, recipient validation
 * and the DKIM signing publisher. Networks are random so suites can run against a shared
 * database (and alongside other packages' fixtures) without colliding with the global
 * non-overlap rule; domains are unique `.test` names inserted directly when a suite needs a
 * state the API cannot reach without DNS (an active, outbound-enabled domain).
 */
import { randomInt } from 'node:crypto';
import type { DomainStatus } from '@email-gateway/database';
import type { Test } from 'supertest';
import { SecretBox } from '../../src/crypto/secret-box';
import { generateDkimKeyPair } from '../../src/modules/domains/engine/dkim';
import { dkimKeyAad } from '../../src/modules/domains/services/domain-configuration.service';
import type { IntegrationApp } from './app';
import { type FixtureOrganization, uniqueSuffix } from './fixtures';

/**
 * A random /24 in 45.0.0.0/8. Connector networks must be publicly routable (step 2.2 §12.7:
 * private, shared and documentation ranges are refused), so the suites use a public block; the
 * test database never routes mail, so who holds the block in reality does not matter.
 */
export function randomV4Network(prefix = 24): string {
  return `45.${randomInt(256)}.${randomInt(256)}.0/${prefix}`;
}

/** A random /64 in 2a10::/12 (a public RIR block; same reasoning as `randomV4Network`). */
export function randomV6Network(): string {
  const group = () => randomInt(1, 0xffff).toString(16);
  return `2a10:${group()}:${group()}:${group()}::/64`;
}

/** A random SHA-256 fingerprint as `openssl x509 -fingerprint -sha256` prints it. */
export function randomFingerprint(): { colon: string; hex: string } {
  const bytes = Array.from({ length: 32 }, () => randomInt(256).toString(16).padStart(2, '0'));
  return { colon: bytes.join(':').toUpperCase(), hex: bytes.join('') };
}

export interface ConnectorBody {
  id: string;
  name: string;
  authType: 'sasl' | 'source_ip' | 'client_certificate';
  status: 'active' | 'disabled';
  saslUsername: string | null;
  certificateFingerprintSha256: string | null;
  networks: Array<{ cidr: string; ipVersion: 4 | 6 }>;
  requireTls: boolean;
  secretSetAt: string | null;
  createdAt: string;
  updatedAt: string;
  credentials?: { username: string; password: string };
}

/** The `/smtp-connectors` routes as one caller. */
export class ConnectorApi {
  constructor(
    private readonly ctx: IntegrationApp,
    readonly headers: Record<string, string>,
  ) {}

  private url(id?: string, suffix = ''): string {
    return id === undefined ? '/api/v1/smtp-connectors' : `/api/v1/smtp-connectors/${id}${suffix}`;
  }

  create(body: Record<string, unknown>): Test {
    return this.ctx.http.post(this.url()).set(this.headers).send(body);
  }
  list(query = ''): Test {
    return this.ctx.http.get(`${this.url()}${query}`).set(this.headers);
  }
  get(id: string): Test {
    return this.ctx.http.get(this.url(id)).set(this.headers);
  }
  update(id: string, body: Record<string, unknown>): Test {
    return this.ctx.http.patch(this.url(id)).set(this.headers).send(body);
  }
  rotate(id: string): Test {
    return this.ctx.http.post(this.url(id, '/rotate-secret')).set(this.headers);
  }
  remove(id: string): Test {
    return this.ctx.http.delete(this.url(id)).set(this.headers);
  }

  async okCreate(body: Record<string, unknown>): Promise<ConnectorBody> {
    const res = await this.create({ name: `c-${uniqueSuffix()}`, ...body });
    if (res.status !== 201) {
      throw new Error(`connector create failed: ${res.status} ${JSON.stringify(res.body)}`);
    }
    return res.body as ConnectorBody;
  }
}

/** The recipient-validation routes of one domain as one caller. */
export class RecipientApi {
  constructor(
    private readonly ctx: IntegrationApp,
    readonly headers: Record<string, string>,
  ) {}

  private url(id: string, suffix: string): string {
    return `/api/v1/domains/${id}${suffix}`;
  }

  getValidation(id: string): Test {
    return this.ctx.http.get(this.url(id, '/recipient-validation')).set(this.headers);
  }
  setValidation(id: string, body: Record<string, unknown>): Test {
    return this.ctx.http.put(this.url(id, '/recipient-validation')).set(this.headers).send(body);
  }
  list(id: string, query = ''): Test {
    return this.ctx.http.get(`${this.url(id, '/recipients')}${query}`).set(this.headers);
  }
  add(id: string, localParts: unknown[]): Test {
    return this.ctx.http.post(this.url(id, '/recipients')).set(this.headers).send({ localParts });
  }
  remove(id: string, localParts: unknown[]): Test {
    return this.ctx.http
      .post(this.url(id, '/recipients/remove'))
      .set(this.headers)
      .send({ localParts });
  }
}

export interface InsertedDomain {
  id: bigint;
  publicId: string;
  name: string;
}

/** A domain row inserted directly (with its settings row), e.g. `active` + outbound. */
export async function insertDomain(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  options: { status?: DomainStatus; outboundEnabled?: boolean; label?: string } = {},
): Promise<InsertedDomain> {
  const status = options.status ?? 'active';
  const now = new Date();
  return ctx.prisma.domain.create({
    data: {
      organizationId: org.id,
      name: `${options.label ?? 'smtp'}-${uniqueSuffix()}.smtp-it.test`,
      status,
      statusChangedAt: now,
      inboundEnabled: true,
      outboundEnabled: options.outboundEnabled ?? true,
      ...(status !== 'pending_verification' && { verifiedAt: now }),
      ...(status === 'active' && { activatedAt: now }),
      settings: { create: { organizationId: org.id } },
    },
    select: { id: true, publicId: true, name: true },
  });
}

/**
 * A DKIM key of the domain, encrypted exactly as the api stores it (SecretBox, AAD
 * `dkim:<domain public id>:<selector>`). Returns the selector and the PEM (test assertions only).
 */
export async function insertDkimKey(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  domain: InsertedDomain,
  options: { status?: 'pending' | 'active' | 'rotating'; selector?: string } = {},
): Promise<{ id: bigint; selector: string; pem: string }> {
  const pair = await generateDkimKeyPair('rsa_2048');
  const selector = options.selector ?? `it${uniqueSuffix()}`.slice(0, 15);
  const row = await ctx.prisma.domainDkimKey.create({
    data: {
      organizationId: org.id,
      domainId: domain.id,
      selector,
      algorithm: 'rsa_2048',
      publicKey: pair.publicKeyDns,
      privateKeyCiphertext: ctx
        .get(SecretBox)
        .encrypt(pair.privateKeyPem, dkimKeyAad(domain.publicId, selector)),
      status: options.status ?? 'active',
      ...(options.status !== 'pending' && { activatedAt: new Date() }),
    },
    select: { id: true },
  });
  return { id: row.id, selector, pem: pair.privateKeyPem };
}
