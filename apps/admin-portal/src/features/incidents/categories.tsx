'use client';

import { usePermissions } from '@/lib/auth/me';
import { ATO_INCIDENT_CATEGORY } from '@/features/ato/incident-panels';
import type { IncidentCategoryUi } from './model';

/**
 * The registered incident categories (step 8.4 D24). Order is the display order. ATP-4 appends
 * its categories here; the generic pages need no other change.
 */
export const INCIDENT_CATEGORIES: readonly IncidentCategoryUi[] = [ATO_INCIDENT_CATEGORY];

export function categoryUi(id: string): IncidentCategoryUi | null {
  return INCIDENT_CATEGORIES.find((c) => c.id === id) ?? null;
}

export function categoryLabel(id: string): string {
  return categoryUi(id)?.label ?? id.replace(/_/g, ' ');
}

/** Categories whose read permission the user holds (the api filters the same way). */
export function useReadableCategories(): IncidentCategoryUi[] {
  const permissions = usePermissions();
  return INCIDENT_CATEGORIES.filter((c) => permissions.has(c.readPermission));
}

/** Categories whose manage permission the user holds (manual incidents, triage). */
export function useManageableCategories(): IncidentCategoryUi[] {
  const permissions = usePermissions();
  return INCIDENT_CATEGORIES.filter((c) => permissions.has(c.managePermission));
}
