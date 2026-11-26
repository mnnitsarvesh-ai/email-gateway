import 'server-only';
import type { SuccessBody } from '@/lib/api/types';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixture state of the protection modes (step API-1 D1, D2), shared by the domains,
 * organizations and api-mode fixtures without import cycles: the organization modes live here,
 * the domains fixture registers a reader of its domains (configured mode, MX observation), and
 * the views compute the effective mode on every read (a getter, so a changed organization mode
 * moves every inheriting domain at once, as the api does). Synthetic only.
 */

export type ProtectionMode = 'inline' | 'api' | 'hybrid';
type OrganizationView = SuccessBody<'OrganizationsController_get_v1'>;
type DomainModeView = SuccessBody<'DomainsController_get_v1'>['protectionMode'];

export interface DomainModeSource {
  readonly id: string;
  readonly name: string;
  readonly configured: ProtectionMode | null;
  readonly mxPointsToGateway: boolean;
  readonly deleted: boolean;
}

interface ModeState {
  orgs: Map<string, { mode: ProtectionMode; changedAt: string | null }>;
  domainSource: ((organizationId: string) => readonly DomainModeSource[]) | null;
  planSource: ((organizationId: string) => string | null) | null;
}

const store = globalThis as typeof globalThis & { __egDevFixtureProtectionModes?: ModeState };
const state: ModeState = (store.__egDevFixtureProtectionModes ??= {
  orgs: new Map(),
  domainSource: null,
  planSource: null,
});

/** Forgets every organization mode (tests). */
export function resetProtectionModes(): void {
  state.orgs.clear();
}

/** The organizations fixture registers how to read an organization's plan code. */
export function registerPlanSource(source: (organizationId: string) => string | null): void {
  state.planSource = source;
}

/** Plan code of an organization (`business` when unknown: the first customer's plan). */
export function planOf(organizationId: string): string {
  return state.planSource?.(organizationId) ?? 'business';
}

/** The domains fixture registers how to read an organization's domains (once per bundle). */
export function registerDomainModeSource(
  source: (organizationId: string) => readonly DomainModeSource[],
): void {
  state.domainSource = source;
}

export function organizationMode(organizationId: string): {
  mode: ProtectionMode;
  changedAt: string | null;
} {
  return state.orgs.get(organizationId) ?? { mode: 'inline', changedAt: null };
}

export function setOrganizationMode(organizationId: string, mode: ProtectionMode): void {
  state.orgs.set(organizationId, { mode, changedAt: new Date().toISOString() });
}

/**
 * Plans with the `api_mode_protection` feature in the fixtures: the synthetic plans `business`
 * and `enterprise` (the real catalog: enterprise and dedicated); never `starter` or
 * `archive_only`.
 */
export function entitledPlan(planCode: string): boolean {
  return planCode !== 'starter' && planCode !== 'archive_only' && planCode !== 'trial';
}

export function liveDomains(organizationId: string): readonly DomainModeSource[] {
  return (state.domainSource?.(organizationId) ?? []).filter((d) => !d.deleted);
}

export function effectiveMode(
  organizationId: string,
  configured: ProtectionMode | null,
): ProtectionMode {
  return configured ?? organizationMode(organizationId).mode;
}

export function domainModeView(
  organizationId: string,
  configured: ProtectionMode | null,
  changedAt: string | null,
): DomainModeView {
  return {
    configured,
    effective: effectiveMode(organizationId, configured),
    inherited: configured === null,
    changedAt,
  };
}

export function domainsByEffectiveMode(organizationId: string): Record<ProtectionMode, number> {
  const counts: Record<ProtectionMode, number> = { inline: 0, api: 0, hybrid: 0 };
  for (const domain of liveDomains(organizationId))
    counts[effectiveMode(organizationId, domain.configured)] += 1;
  return counts;
}

/** The `protectionMode` block of the organization view and `GET …/protection-mode` (D2). */
export function organizationModeView(
  organizationId: string,
  planCode: string,
): OrganizationView['protectionMode'] {
  const { mode, changedAt } = organizationMode(organizationId);
  const counts = domainsByEffectiveMode(organizationId);
  const entitled = entitledPlan(planCode);
  return {
    mode,
    changedAt,
    entitled,
    active: entitled && counts.api + counts.hybrid > 0,
    domainsByEffectiveMode: counts,
  };
}

/** Makes an organization view's `protectionMode` live (enumerable getter: JSON includes it). */
export function attachOrganizationMode<T extends OrganizationView>(org: T): T {
  Object.defineProperty(org, 'protectionMode', {
    enumerable: true,
    configurable: true,
    get: () => organizationModeView(org.id, org.plan.code),
  });
  return org;
}
