/**
 * The service profile of an organization (step 8.6 D13, ADR-0090): derived from its effective
 * features, never stored. `archive_only` when it has `archiving` but neither inbound nor
 * outbound filtering (the archive-only plan: journal intake, journaling and archive without mail
 * filtering); `gateway` otherwise. The portal hides gateway-only pages for `archive_only`, and
 * domains of an archive-only organization cannot enable mail flow.
 */
export const SERVICE_PROFILES = ['gateway', 'archive_only'] as const;
export type ServiceProfile = (typeof SERVICE_PROFILES)[number];

export function serviceProfileOf(features: {
  inboundFiltering: boolean;
  outboundFiltering: boolean;
  archiving: boolean;
}): ServiceProfile {
  return !features.inboundFiltering && !features.outboundFiltering && features.archiving
    ? 'archive_only'
    : 'gateway';
}
