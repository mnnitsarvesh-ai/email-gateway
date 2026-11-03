import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';

/** The active RSA signing key of a domain that may sign outbound mail (step 2.2 D12). */
export interface SignableKey {
  keyId: bigint;
  domainPublicId: string;
  /** ASCII (punycode) domain name: the `dkim_selectors` field. */
  domainName: string;
  selector: string;
  /** `SecretBox` ciphertext of the PKCS#8 PEM (AAD `dkim:<domain public id>:<selector>`). */
  ciphertext: string;
}

/**
 * **System-level** query of the DKIM signing publisher (D12, ADR-0020). It scans every
 * organization by design (redis-dkim serves all tenants) and returns only what the signer
 * needs. Writer only: a replica lagging behind a suspension must never keep a key published.
 */
@Injectable()
export class DkimSigningRepository {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Keys that may sign: key `active`, `rsa_2048`, ciphertext present; domain `active` and
   * outbound-enabled; organization `active`. Ordered by key id, so the newest key of a domain
   * comes last.
   */
  async findSignableKeys(): Promise<SignableKey[]> {
    const rows = await this.prisma.domainDkimKey.findMany({
      where: {
        status: 'active',
        algorithm: 'rsa_2048',
        privateKeyCiphertext: { not: null },
        domain: {
          status: 'active',
          outboundEnabled: true,
          organization: { status: 'active' },
        },
      },
      select: {
        id: true,
        selector: true,
        privateKeyCiphertext: true,
        domain: { select: { publicId: true, name: true } },
      },
      orderBy: { id: 'asc' },
    });
    return rows.flatMap((row) =>
      row.privateKeyCiphertext === null
        ? []
        : [
            {
              keyId: row.id,
              domainPublicId: row.domain.publicId,
              domainName: row.domain.name,
              selector: row.selector,
              ciphertext: row.privateKeyCiphertext,
            },
          ],
    );
  }
}
