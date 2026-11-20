import { Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { createConnectionDirectory, type DirectoryConnection } from '@email-gateway/idp-adapters';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { AtoProvidersRepository } from '../repositories/ato-providers.repository';

type Db = Prisma.TransactionClient;

/**
 * The api's read-only view of the organization's step 8.2 connections (design note §0.3, §6 route
 * 3, merge note M4): wraps the `connection-directory` binding of `@email-gateway/idp-adapters`,
 * the only code that knows 8.2's names. Never a token, credential or provider call. The
 * organization always comes from the caller's `TenantScope`; the binding echo-checks every
 * returned connection against it. Reads run on the replica, or on the writer transaction when a
 * mutation passes it (D4 eligibility is decided inside the binding transaction).
 */
@Injectable()
export class AtoConnectionDirectory {
  constructor(private readonly clients: AtoProvidersRepository) {}

  /** Every connection of the organization (disabled ones included), oldest first. */
  list(scope: TenantScope, db?: Db): Promise<DirectoryConnection[]> {
    return createConnectionDirectory(this.clients.readClient(db)).list(scope.organizationId);
  }

  /** One connection of the organization, or null (another organization's id answers null). */
  get(
    scope: TenantScope,
    connectionPublicId: string,
    db?: Db,
  ): Promise<DirectoryConnection | null> {
    return createConnectionDirectory(this.clients.readClient(db)).get(
      scope.organizationId,
      connectionPublicId,
    );
  }
}
