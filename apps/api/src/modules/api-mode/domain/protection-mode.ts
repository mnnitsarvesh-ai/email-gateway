import type { ProtectionModeValue } from '../../../tenancy/api-mode-status.service';

/**
 * Protection-mode rules (step API-1 D1, D2; ADR-0098), pure so every combination is
 * table-tested. The mode controls the API side only: no rule here ever touches inline mail flow
 * (`inbound_enabled`, `outbound_enabled`, destinations, connectors; N2).
 *
 * - Effective mode = the domain's own mode ?? the organization's.
 * - `api`/`hybrid` (as the resulting EFFECTIVE mode) need the feature `api_mode_protection`;
 *   `inline` is always allowed (also to leave API mode after a plan downgrade).
 * - A change that makes a domain's effective mode `api` (from `inline`/`hybrid`) is refused while
 *   its latest definitive MX observation points to the gateway (N2).
 */

export type ConfiguredDomainMode = ProtectionModeValue | null;
export type RequestedDomainMode = ProtectionModeValue | 'inherit';

/** At most this many domain names in `details.domains` of an MX conflict (D2). */
export const MX_CONFLICT_DETAIL_LIMIT = 20;

export const effectiveModeOf = (
  configured: ConfiguredDomainMode,
  organizationMode: ProtectionModeValue,
): ProtectionModeValue => configured ?? organizationMode;

/** `api` or `hybrid`: the modes that need the feature. */
export const isApiSide = (mode: ProtectionModeValue): boolean =>
  mode === 'api' || mode === 'hybrid';

/** A refusal of a mode change (the service maps it to the coded error). */
export type ModeRefusal =
  | { code: 'api_mode_not_enabled' }
  | { code: 'protection_mode_mx_points_to_gateway'; domains: Array<{ id: string; name: string }> };

export interface DomainModeFacts {
  publicId: string;
  name: string;
  configured: ConfiguredDomainMode;
  /** The latest definitive MX observation has a host pointing to the gateway. */
  mxPointsToGateway: boolean;
}

export type DomainModeDecision =
  | { kind: 'unchanged'; effective: ProtectionModeValue }
  | {
      kind: 'change';
      fromConfigured: ConfiguredDomainMode;
      toConfigured: ConfiguredDomainMode;
      fromEffective: ProtectionModeValue;
      toEffective: ProtectionModeValue;
    }
  | { kind: 'refused'; refusal: ModeRefusal };

/** `PUT /domains/{domainId}/protection-mode` (D2; `inherit` = NULL). */
export function decideDomainModeChange(input: {
  domain: DomainModeFacts;
  organizationMode: ProtectionModeValue;
  requested: RequestedDomainMode;
  entitled: boolean;
}): DomainModeDecision {
  const { domain, organizationMode } = input;
  const toConfigured: ConfiguredDomainMode = input.requested === 'inherit' ? null : input.requested;
  const fromEffective = effectiveModeOf(domain.configured, organizationMode);
  if (toConfigured === domain.configured) return { kind: 'unchanged', effective: fromEffective };
  const toEffective = effectiveModeOf(toConfigured, organizationMode);
  if (isApiSide(toEffective) && !input.entitled) {
    return { kind: 'refused', refusal: { code: 'api_mode_not_enabled' } };
  }
  if (toEffective === 'api' && fromEffective !== 'api' && domain.mxPointsToGateway) {
    return {
      kind: 'refused',
      refusal: {
        code: 'protection_mode_mx_points_to_gateway',
        domains: [{ id: domain.publicId, name: domain.name }],
      },
    };
  }
  return {
    kind: 'change',
    fromConfigured: domain.configured,
    toConfigured,
    fromEffective,
    toEffective,
  };
}

export type OrganizationModeDecision =
  | { kind: 'unchanged' }
  | {
      kind: 'change';
      from: ProtectionModeValue;
      to: ProtectionModeValue;
      /** Domains without their own mode (their effective mode follows the organization). */
      inheritingDomains: number;
      /** Domains whose effective mode is `api` after the change. */
      effectiveApiDomains: number;
    }
  | { kind: 'refused'; refusal: ModeRefusal };

/**
 * `PUT /organizations/{id}/protection-mode` (D2): the MX check runs over every inheriting domain
 * that would become effective `api`; any conflict refuses the whole change (at most
 * MX_CONFLICT_DETAIL_LIMIT names, sorted by name).
 */
export function decideOrganizationModeChange(input: {
  from: ProtectionModeValue;
  to: ProtectionModeValue;
  entitled: boolean;
  domains: readonly DomainModeFacts[];
}): OrganizationModeDecision {
  if (input.from === input.to) return { kind: 'unchanged' };
  if (isApiSide(input.to) && !input.entitled) {
    return { kind: 'refused', refusal: { code: 'api_mode_not_enabled' } };
  }
  const inheriting = input.domains.filter((d) => d.configured === null);
  if (input.to === 'api' && input.from !== 'api') {
    const conflicts = inheriting
      .filter((d) => d.mxPointsToGateway)
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
      .slice(0, MX_CONFLICT_DETAIL_LIMIT)
      .map((d) => ({ id: d.publicId, name: d.name }));
    if (conflicts.length > 0) {
      return {
        kind: 'refused',
        refusal: { code: 'protection_mode_mx_points_to_gateway', domains: conflicts },
      };
    }
  }
  return {
    kind: 'change',
    from: input.from,
    to: input.to,
    inheritingDomains: inheriting.length,
    effectiveApiDomains: input.domains.filter(
      (d) => effectiveModeOf(d.configured, input.to) === 'api',
    ).length,
  };
}

export type CreateModeDecision =
  | { kind: 'ok'; configured: ConfiguredDomainMode; inboundEnabled: boolean }
  | { kind: 'refused'; code: 'api_mode_not_enabled' | 'protection_mode_inbound_conflict' };

/**
 * `POST /domains` with the optional `protectionMode` (D2): absent = inherit. `api` needs inbound
 * mail flow off (`422 protection_mode_inbound_conflict` when `inboundEnabled: true` is sent); a
 * domain whose effective mode is `api` is created with inbound off when `inboundEnabled` is
 * omitted (ADR-0098: API-mode domains are created with inbound off). An `api`/`hybrid` effective
 * mode needs the feature.
 */
export function decideCreateMode(input: {
  requested: ProtectionModeValue | undefined;
  inboundEnabled: boolean | undefined;
  organizationMode: ProtectionModeValue;
  entitled: boolean;
}): CreateModeDecision {
  const configured: ConfiguredDomainMode = input.requested ?? null;
  const effective = effectiveModeOf(configured, input.organizationMode);
  if (configured === 'api' && input.inboundEnabled === true) {
    return { kind: 'refused', code: 'protection_mode_inbound_conflict' };
  }
  if (configured !== null && isApiSide(configured) && !input.entitled) {
    return { kind: 'refused', code: 'api_mode_not_enabled' };
  }
  return {
    kind: 'ok',
    configured,
    inboundEnabled: input.inboundEnabled ?? effective !== 'api',
  };
}
