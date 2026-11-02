import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { OrganizationKind, OrganizationStatus, Prisma } from '@email-gateway/database';

export interface OrganizationAuthRecord {
  id: bigint;
  publicId: string;
  slug: string;
  name: string;
  kind: OrganizationKind;
  status: OrganizationStatus;
  deletedAt: Date | null;
}

const orgSelect = {
  id: true,
  publicId: true,
  slug: true,
  name: true,
  kind: true,
  status: true,
  deletedAt: true,
} satisfies Prisma.OrganizationSelect;

/** Organization lookups of the authentication paths (writer). */
@Injectable()
export class OrganizationsAuthRepository {
  constructor(private readonly prisma: PrismaService) {}

  findBySlug(slug: string): Promise<OrganizationAuthRecord | null> {
    return this.prisma.organization.findUnique({ where: { slug }, select: orgSelect });
  }

  findById(id: bigint): Promise<OrganizationAuthRecord | null> {
    return this.prisma.organization.findUnique({ where: { id }, select: orgSelect });
  }

  findByPublicId(publicId: string): Promise<OrganizationAuthRecord | null> {
    return this.prisma.organization.findUnique({ where: { publicId }, select: orgSelect });
  }
}
