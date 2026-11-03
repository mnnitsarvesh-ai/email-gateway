import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { SmtpConnectorAuthType } from '@email-gateway/database';
import { z } from 'zod';
import { cacheKeys } from '../tenancy/cache-keys';
import { RedisJsonCache } from '../tenancy/redis-json-cache';
import { ipInRange, type IpKey, normalizeFingerprint } from './addresses';

/** Connector cache TTL (D11). Status changes take effect within this bound. */
export const CONNECTOR_CACHE_TTL_SECONDS = 30;

/** An active connector of an active organization (never carries the secret hash). */
export interface ConnectorView {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  authType: SmtpConnectorAuthType;
  requireTls: boolean;
  /** Networks of a `client_certificate` connector (restrict its client IPs); empty otherwise. */
  networks: { version: 4 | 6; start: Buffer; end: Buffer }[];
}

const decimal = z.string().regex(/^\d{1,20}$/);
const hex = z.string().regex(/^(?:[0-9a-f]{2}){4,16}$/);
const connectorDto = z.object({
  id: decimal,
  publicId: z.string(),
  organizationId: decimal,
  authType: z.enum(['sasl', 'source_ip', 'client_certificate']),
  requireTls: z.boolean(),
  networks: z.array(
    z.object({ version: z.union([z.literal(4), z.literal(6)]), start: hex, end: hex }),
  ),
});
type ConnectorDto = z.infer<typeof connectorDto>;

/** SASL usernames are generated (`egc-` + base32) and stored in VARCHAR(64). */
const SASL_USERNAME = /^[\x21-\x7e]{1,64}$/;

interface ConnectorRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  authType: SmtpConnectorAuthType;
  status: string;
  requireTls: boolean;
  organization: { status: string };
  networks?: { ipVersion: number; rangeStart: Uint8Array; rangeEnd: Uint8Array }[];
}

interface NetworkMatchRow {
  rangeEnd: Uint8Array;
  id: bigint;
  publicId: string;
  organizationId: bigint;
  authType: SmtpConnectorAuthType;
  status: string;
  requireTls: number | boolean;
  organizationStatus: string;
}

/**
 * Resolves the outbound connector of a session (step 2.2 D10, D11) from the writer:
 *
 * - SASL username → active `sasl` connector;
 * - certificate (or public-key) SHA-256 fingerprint → active `client_certificate` connector,
 *   with its networks (an optional client IP restriction);
 * - client IP → active `source_ip` connector whose network contains it, through the range query
 *   of §3 (`ip_version = ? AND range_start <= ? ORDER BY range_start DESC LIMIT 1`, then
 *   `range_end >= ip`; correct because networks never overlap across all connectors).
 *
 * Only active connectors of active organizations resolve; everything else is null. Results
 * (including null) are cached for 30 s under `sa:conn:*`. Database errors propagate.
 */
@Injectable()
export class ConnectorResolver {
  constructor(
    private readonly prisma: PrismaService,
    private readonly cache: RedisJsonCache,
  ) {}

  async bySaslUsername(username: string): Promise<ConnectorView | null> {
    if (!SASL_USERNAME.test(username)) return null;
    return this.cached(cacheKeys.connectorBySasl(username), async () => {
      const row = await this.prisma.smtpConnector.findUnique({
        where: { saslUsername: username },
        select: connectorSelect(false),
      });
      return usable(row, 'sasl');
    });
  }

  async byCertificateFingerprint(raw: string | undefined): Promise<ConnectorView | null> {
    const fingerprint = normalizeFingerprint(raw);
    if (fingerprint === null) return null;
    return this.cached(cacheKeys.connectorByFingerprint(fingerprint), async () => {
      const row = await this.prisma.smtpConnector.findUnique({
        where: { certFingerprintSha256: fingerprint },
        select: connectorSelect(true),
      });
      return usable(row, 'client_certificate');
    });
  }

  async byClientAddress(ip: IpKey): Promise<ConnectorView | null> {
    return this.cached(cacheKeys.connectorByIp(ip.text), async () => {
      const [row] = await this.prisma.$queryRaw<NetworkMatchRow[]>`
        SELECT n.range_end AS rangeEnd, c.id, c.public_id AS publicId,
               c.organization_id AS organizationId, c.auth_type AS authType, c.status,
               c.require_tls AS requireTls, o.status AS organizationStatus
        FROM smtp_connector_networks n
        JOIN smtp_connectors c ON c.id = n.connector_id
        JOIN organizations o ON o.id = c.organization_id
        WHERE n.ip_version = ${ip.version} AND n.range_start <= ${ip.bytes}
        ORDER BY n.range_start DESC
        LIMIT 1`;
      if (!row || Buffer.compare(Buffer.from(row.rangeEnd), ip.bytes) < 0) return null;
      return usable(
        {
          id: BigInt(row.id),
          publicId: row.publicId,
          organizationId: BigInt(row.organizationId),
          authType: row.authType,
          status: row.status,
          requireTls: row.requireTls === true || row.requireTls === 1,
          organization: { status: row.organizationStatus },
        },
        'source_ip',
      );
    });
  }

  private async cached(
    key: string,
    load: () => Promise<ConnectorDto | null>,
  ): Promise<ConnectorView | null> {
    const dto = await this.cache.getOrLoad({
      cache: 'connector',
      key,
      ttlSeconds: CONNECTOR_CACHE_TTL_SECONDS,
      negativeTtlSeconds: CONNECTOR_CACHE_TTL_SECONDS,
      schema: connectorDto,
      load,
    });
    return dto === null ? null : fromDto(dto);
  }
}

/** True when the client IP is allowed by a connector's optional network restriction. */
export function connectorAllowsIp(connector: ConnectorView, ip: IpKey | null): boolean {
  if (connector.networks.length === 0) return true;
  if (ip === null) return false;
  return connector.networks.some(
    (network) => network.version === ip.version && ipInRange(ip.bytes, network.start, network.end),
  );
}

function connectorSelect(withNetworks: boolean) {
  return {
    id: true,
    publicId: true,
    organizationId: true,
    authType: true,
    status: true,
    requireTls: true,
    organization: { select: { status: true } },
    ...(withNetworks && {
      networks: { select: { ipVersion: true, rangeStart: true, rangeEnd: true } },
    }),
  } as const;
}

function usable(row: ConnectorRow | null, authType: SmtpConnectorAuthType): ConnectorDto | null {
  if (
    !row ||
    row.authType !== authType ||
    row.status !== 'active' ||
    row.organization.status !== 'active'
  ) {
    return null;
  }
  return {
    id: row.id.toString(),
    publicId: row.publicId,
    organizationId: row.organizationId.toString(),
    authType: row.authType,
    requireTls: row.requireTls,
    networks: (row.networks ?? []).flatMap((network) =>
      network.ipVersion === 4 || network.ipVersion === 6
        ? [
            {
              version: network.ipVersion,
              start: Buffer.from(network.rangeStart).toString('hex'),
              end: Buffer.from(network.rangeEnd).toString('hex'),
            },
          ]
        : [],
    ),
  };
}

function fromDto(dto: ConnectorDto): ConnectorView {
  return {
    id: BigInt(dto.id),
    publicId: dto.publicId,
    organizationId: BigInt(dto.organizationId),
    authType: dto.authType,
    requireTls: dto.requireTls,
    networks: dto.networks.map((network) => ({
      version: network.version,
      start: Buffer.from(network.start, 'hex'),
      end: Buffer.from(network.end, 'hex'),
    })),
  };
}
