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

describe('OrganizationFeaturesService: plan fallback and service profile (step 8.6)', () => {
  function planClient(
    rows: Array<{ featureKey: string; enabled: boolean }>,
    defaults: Record<string, boolean> | null,
  ) {
    return {
      organizationFeature: { findMany: vi.fn().mockResolvedValue(rows) },
      organization: {
        findUnique: vi
          .fn()
          .mockResolvedValue(defaults === null ? null : { plan: { defaultFeatures: defaults } }),
      },
    };
  }

  it('uses the row when it exists and the plan default when it is missing', async () => {
    const prisma = planClient([{ featureKey: 'archiving', enabled: false }], {
      archiving: true,
      journal_intake: true,
    });
    const features = new OrganizationFeaturesService(prisma as unknown as PrismaService);
    expect(await features.effective(3n, ['archiving', 'journal_intake', 'sso'])).toEqual({
      archiving: false,
      journal_intake: true,
      sso: false,
    });
    expect(await features.isEffectivelyEnabled(3n, 'journal_intake')).toBe(true);
  });

  it('is false without a plan', async () => {
    const prisma = planClient([], null);
    const features = new OrganizationFeaturesService(prisma as unknown as PrismaService);
    expect(await features.isEffectivelyEnabled(3n, 'journal_intake')).toBe(false);
  });

  it.each([
    [{ inbound_filtering: false, outbound_filtering: false, archiving: true }, 'archive_only'],
    [{ inbound_filtering: true, outbound_filtering: false, archiving: true }, 'gateway'],
    [{ inbound_filtering: false, outbound_filtering: true, archiving: true }, 'gateway'],
    [{ inbound_filtering: false, outbound_filtering: false, archiving: false }, 'gateway'],
  ])('derives the service profile from %j', async (defaults, profile) => {
    const prisma = planClient([], defaults);
    const features = new OrganizationFeaturesService(prisma as unknown as PrismaService);
    expect(await features.serviceProfile(9n)).toBe(profile);
  });
});
