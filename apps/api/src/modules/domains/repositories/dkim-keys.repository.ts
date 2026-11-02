import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { DkimAlgorithm, DkimKeyStatus, Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Client = Prisma.TransactionClient;

/** Never selects the private key material (ADR-0018): it is only ever written here. */
const keySelect = {
  id: true,
  domainId: true,
  selector: true,
  algorithm: true,
  publicKey: true,
  status: true,
  activatedAt: true,
  retireAfter: true,
  retiredAt: true,
  createdAt: true,
} satisfies Prisma.DomainDkimKeySelect;

export type DkimKeyRow = Prisma.DomainDkimKeyGetPayload<{ select: typeof keySelect }>;

/**
 * `domain_dkim_keys` of the scope's domains (D9, ADR-0018). The encrypted private key is
 * written once on insert and cleared (crypto-shredding) when a key is retired or revoked; no
 * method returns it.
 */
@Injectable()
export class DkimKeysRepository {
  constructor(private readonly prisma: PrismaService) {}

  listForDomain(
    scope: TenantScope,
    domainId: bigint,
    client: Client = this.prisma,
  ): Promise<DkimKeyRow[]> {
    return client.domainDkimKey.findMany({
      where: tenantWhere(scope, { domainId }),
      select: keySelect,
      orderBy: { id: 'asc' },
    });
  }

  create(
    tx: Client,
    scope: TenantScope,
    data: {
      domainId: bigint;
      selector: string;
      algorithm: DkimAlgorithm;
      publicKey: string;
      /** `SecretBox` ciphertext of the PKCS#8 PEM (AAD `dkim:<domain public id>:<selector>`). */
      privateKeyCiphertext: string;
    },
  ): Promise<DkimKeyRow> {
    return tx.domainDkimKey.create({
      data: {
        organizationId: scope.organizationId,
        domainId: data.domainId,
        selector: data.selector,
        algorithm: data.algorithm,
        publicKey: data.publicKey,
        privateKeyCiphertext: data.privateKeyCiphertext,
        privateKeyRef: null,
        status: 'pending',
      },
      select: keySelect,
    });
  }

  async activate(tx: Client, scope: TenantScope, id: bigint, now: Date): Promise<void> {
    await tx.domainDkimKey.updateMany({
      where: tenantWhere(scope, { id, status: 'pending' as DkimKeyStatus }),
      data: { status: 'active', activatedAt: now },
    });
  }

  async startRotating(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    retireAfter: Date,
  ): Promise<void> {
    await tx.domainDkimKey.updateMany({
      where: tenantWhere(scope, { id, status: 'active' as DkimKeyStatus }),
      data: { status: 'rotating', retireAfter },
    });
  }

  /** Revokes the keys (status `revoked`, ciphertext cleared); returns how many changed. */
  async revoke(tx: Client, scope: TenantScope, ids: readonly bigint[]): Promise<number> {
    if (ids.length === 0) return 0;
    const { count } = await tx.domainDkimKey.updateMany({
      where: tenantWhere(scope, {
        id: { in: [...ids] },
        status: { notIn: ['retired', 'revoked'] as DkimKeyStatus[] },
      }),
      data: { status: 'revoked', privateKeyCiphertext: null },
    });
    return count;
  }

  /**
   * Retires a rotating key whose overlap ended (conditional: still `rotating`, `retire_after`
   * passed); clears the ciphertext. True when this call retired it.
   */
  async retire(tx: Client, scope: TenantScope, id: bigint, now: Date): Promise<boolean> {
    const { count } = await tx.domainDkimKey.updateMany({
      where: tenantWhere(scope, {
        id,
        status: 'rotating' as DkimKeyStatus,
        retireAfter: { lte: now },
      }),
      data: { status: 'retired', retiredAt: now, privateKeyCiphertext: null },
    });
    return count === 1;
  }
}
