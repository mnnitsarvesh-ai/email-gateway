import type { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import { OrganizationFeaturesService } from './organization-features.service';

function client(row: { enabled: boolean } | null) {
  return { organizationFeature: { findUnique: vi.fn().mockResolvedValue(row) } };
}

describe('OrganizationFeaturesService', () => {
  it('reads the feature flag on the writer', async () => {
    const prisma = client({ enabled: true });
    const features = new OrganizationFeaturesService(prisma as unknown as PrismaService);
    expect(await features.isEnabled(7n, 'api_access')).toBe(true);
    expect(prisma.organizationFeature.findUnique).toHaveBeenCalledWith({
      where: { organizationId_featureKey: { organizationId: 7n, featureKey: 'api_access' } },
      select: { enabled: true },
    });
  });

  it('is false for a disabled or missing feature', async () => {
    expect(
      await new OrganizationFeaturesService(
        client({ enabled: false }) as unknown as PrismaService,
      ).isEnabled(1n, 'sso'),
    ).toBe(false);
    expect(
      await new OrganizationFeaturesService(client(null) as unknown as PrismaService).isEnabled(
        1n,
        'sso',
      ),
    ).toBe(false);
  });

  it('uses the given transaction client', async () => {
    const prisma = client({ enabled: false });
    const tx = client({ enabled: true });
    const features = new OrganizationFeaturesService(prisma as unknown as PrismaService);
    expect(
      await features.isEnabled(1n, 'api_access', tx as unknown as Prisma.TransactionClient),
    ).toBe(true);
    expect(prisma.organizationFeature.findUnique).not.toHaveBeenCalled();
  });
});
