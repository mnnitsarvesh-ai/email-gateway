import { domainOf, normalizeAddress } from '../capture/eligibility';
import type { MessageDirection } from '../vocabulary';

/**
 * Directions of a journal intake message (step 8.6 D3). Intake mail never passes the gateway's
 * listeners, so its directions come from the organization's own domains:
 *
 * - **org-side domains**: the organization's domains in `verified` / `active` / `suspended`
 *   (exact, case-insensitive match; the caller passes the names);
 * - **sender**: the envelope `Sender:` (or MAIL FROM, merged by the caller into `sender`), else
 *   the header From;
 * - **message direction**: org-side sender → `internal` when every recipient (at least one) is
 *   org-side, else `outbound`; external (or no) sender → `inbound`;
 * - **recipient direction**: org-side recipient → `internal` (org-side sender) or `inbound`;
 *   external recipient with an org-side sender → `outbound`; external recipient with an external
 *   sender → `null` (unknown: only addressed, not org-side);
 * - **org-side domain** (`email_messages.domain_id`): the sender's domain for outbound and
 *   internal, the first org-side recipient's domain for inbound; null when there is none (the
 *   caller then uses the organization's lowest-id verified domain).
 */

export interface ClassifyIntakePartiesInput {
  /** Envelope `Sender:` of the report, else MAIL FROM; null/empty = unknown. */
  sender: string | null;
  /** The header From of the stored message (display name allowed). */
  headerFrom: string | null;
  recipients: readonly { address: string }[];
  /** Names of the organization's org-side domains. */
  orgDomains: readonly string[];
}

export interface ClassifiedIntakeRecipient {
  address: string;
  orgSide: boolean;
  direction: MessageDirection | null;
}

export interface ClassifiedIntakeParties {
  direction: MessageDirection;
  /** The normalized address the direction was decided on (null when none was usable). */
  senderAddress: string | null;
  senderOrgSide: boolean;
  recipients: ClassifiedIntakeRecipient[];
  /** The org-side domain name for `domain_id`, or null (caller falls back). */
  orgSideDomain: string | null;
}

const normalizeDomain = (d: string) => d.trim().toLowerCase().replace(/\.$/, '');

export function classifyIntakeParties(input: ClassifyIntakePartiesInput): ClassifiedIntakeParties {
  const org = new Set(input.orgDomains.map(normalizeDomain).filter((d) => d !== ''));
  const isOrg = (address: string | null) => {
    const d = domainOf(address);
    return d !== null && org.has(normalizeDomain(d));
  };
  const senderAddress =
    [input.sender, input.headerFrom]
      .map((a) => normalizeAddress(a))
      .find((a): a is string => a !== null && a !== '<>' && domainOf(a) !== null) ?? null;
  const senderOrgSide = isOrg(senderAddress);
  const recipients: ClassifiedIntakeRecipient[] = input.recipients.map((r) => {
    const orgSide = isOrg(r.address);
    const direction: MessageDirection | null = orgSide
      ? senderOrgSide
        ? 'internal'
        : 'inbound'
      : senderOrgSide
        ? 'outbound'
        : null;
    return { address: r.address, orgSide, direction };
  });
  const direction: MessageDirection = senderOrgSide
    ? recipients.length > 0 && recipients.every((r) => r.orgSide)
      ? 'internal'
      : 'outbound'
    : 'inbound';
  const firstOrgRecipient = recipients.find((r) => r.orgSide);
  const orgSideDomain = senderOrgSide
    ? normalizeDomain(domainOf(senderAddress)!)
    : firstOrgRecipient
      ? normalizeDomain(domainOf(firstOrgRecipient.address)!)
      : null;
  return { direction, senderAddress, senderOrgSide, recipients, orgSideDomain };
}
