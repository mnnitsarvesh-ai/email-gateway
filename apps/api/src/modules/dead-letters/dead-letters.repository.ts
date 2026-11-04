import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';

/**
 * Organization id translation for the dead-letter replay (Q9) on the writer: the filter arrives
 * as a public id, dead letters carry the internal decimal id (`x-eg-organization-id`), and the
 * response shows public ids only.
 */
@Injectable()
export class DeadLettersRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** Internal id (decimal string) of an organization public id, or null when unknown. */
  async organizationIdOf(publicId: string): Promise<string | null> {
    const row = await this.prisma.organization.findUnique({
      where: { publicId },
      select: { id: true },
    });
    return row ? row.id.toString() : null;
  }

  /** Public ids of internal organization ids (decimal strings); unknown ids are absent. */
  async publicIdsOf(ids: readonly string[]): Promise<Map<string, string>> {
    const unique = [...new Set(ids)].filter((id) => /^[1-9][0-9]{0,19}$/.test(id));
    if (unique.length === 0) return new Map();
    const rows = await this.prisma.organization.findMany({
      where: { id: { in: unique.map((id) => BigInt(id)) } },
      select: { id: true, publicId: true },
    });
    return new Map(rows.map((r) => [r.id.toString(), r.publicId]));
  }
}
