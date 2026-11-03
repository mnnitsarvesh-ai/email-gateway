import type { ConnectorView } from './dto/smtp-connectors.schemas';
import type { ConnectorRow } from './repositories/smtp-connectors.repository';

/** Response shape of a connector (§4.1). The row never carries the secret hash. */
export function toConnectorView(row: ConnectorRow): ConnectorView {
  return {
    id: row.publicId,
    name: row.name,
    authType: row.authType,
    status: row.status,
    saslUsername: row.saslUsername,
    certificateFingerprintSha256: row.certFingerprintSha256,
    networks: row.networks.map((n) => ({ cidr: n.cidr, ipVersion: n.ipVersion === 6 ? 6 : 4 })),
    requireTls: row.requireTls,
    secretSetAt: row.secretSetAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}
