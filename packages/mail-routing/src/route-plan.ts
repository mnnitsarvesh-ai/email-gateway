import { domainToASCII } from 'node:url';
import {
  classifyRecipient,
  deliveryPathFor,
  type DsnNotify,
  type ListenerDirection,
  type ReinjectionListenerName,
  type RoutedDirection,
  type TraceDirection,
} from './direction';
import { recipientSetSha256 } from './reinjection-key';

/**
 * Route planning and the per-recipient split (step 2.3 R1, R4, R7). Pure: the planner loads the
 * domain views and suppressions with the repository of this package (writer) and passes them in.
 */

/** postfix-outbound `smtpd_recipient_limit`: one group is one SMTP transaction. */
export const MAX_RECIPIENTS_PER_GROUP = 100;

/** Ownership of a recipient domain (resolveDomainOwner semantics; see loadDomainViews). */
export interface DomainView {
  /** `domains.id` of the verified owner's row, null without an owner. */
  domainId: bigint | null;
  /** Owning organization, null without an owner. */
  ownerOrganizationId: bigint | null;
  /**
   * `active`: active domain of an active organization (resolveActiveDomain would return it);
   * `suspended`: domain or organization suspended; `none`: no verified owner (pending, failed,
   * deleted, unknown name, organization pending deletion).
   */
  ownerStatus: 'active' | 'suspended' | 'none';
}

export interface PlanRecipient {
  recipientId: bigint;
  rcptSeq: number;
  address: string;
  /** `email_recipients.direction` (classified at ingestion), null for pre-2.3 rows. */
  storedDirection: RoutedDirection | null;
}

export interface PlanRecipientRoutesInput {
  listenerDirection: ListenerDirection;
  messageOrganizationId: bigint;
  recipients: readonly PlanRecipient[];
  /** Keyed by recipientDomain(address). A missing entry counts as `ownerStatus: 'none'`. */
  domains: ReadonlyMap<string, DomainView>;
  /** Active suppressions of the message's organization, lower-cased addresses. */
  suppressedAddresses: ReadonlySet<string>;
  /** `DELIVERY_BATCH_MAX_RECIPIENTS`, 1..100. */
  maxRecipientsPerGroup: number;
}

export type RecipientRefusalReason = 'direction_changed' | 'recipient_domain_inactive';

interface DecisionBase {
  recipientId: bigint;
  rcptSeq: number;
  /** Lower-cased address. */
  address: string;
  /** The direction classified now (what the delivery row records). */
  direction: RoutedDirection;
}

/** A recipient that is reinjected (or held, for a suspended inbound domain). */
export interface RecipientRoute extends DecisionBase {
  kind: 'route';
  listener: ReinjectionListenerName;
  /** `tenant:<domainId>` (inbound, internal) | `mx:<recipient domain>` (outbound). */
  destinationKey: string;
  notify: DsnNotify;
  traceDirection: TraceDirection;
  /** `gateway_hold`: the domain or its organization is suspended; retried, never delivered now. */
  hold: 'gateway_hold' | null;
}

/** A recipient that is not delivered; its delivery row starts in this status. */
export interface RecipientRefusal extends DecisionBase {
  kind: 'refusal';
  status: 'failed' | 'suppressed';
  reason: RecipientRefusalReason | 'suppressed';
}

export type RecipientDecision = RecipientRoute | RecipientRefusal;

/** One `delivery_reinjections` row: one SMTP transaction into postfix-outbound. */
export interface RouteGroup {
  listener: ReinjectionListenerName;
  direction: RoutedDirection;
  destinationKey: string;
  notify: DsnNotify;
  traceDirection: TraceDirection;
  hold: 'gateway_hold' | null;
  /** Sorted ascending. */
  recipientIds: bigint[];
  /** Lower-cased, de-duplicated, sorted addresses of the group. */
  addresses: string[];
  recipientSetSha256: string;
}

export interface RoutePlan {
  /** One decision per input recipient, in input order. */
  decisions: RecipientDecision[];
  /** Groups ordered by (listener, direction, destinationKey), then chunk. */
  groups: RouteGroup[];
}

/**
 * The domain part of an address, lower case, one trailing dot stripped; null when the address
 * has no usable domain. The key of `PlanRecipientRoutesInput.domains`.
 */
export function recipientDomain(address: string): string | null {
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return null;
  const domain = address.slice(at + 1).toLowerCase();
  const stripped = domain.endsWith('.') ? domain.slice(0, -1) : domain;
  return stripped.length > 0 && !stripped.includes('@') ? stripped : null;
}

/** ASCII (punycode) form for `mx:<domain>` keys; the input when IDNA conversion fails. */
function asciiDomain(domain: string): string {
  const ascii = domainToASCII(domain);
  return ascii.length > 0 ? ascii.toLowerCase() : domain;
}

function decide(recipient: PlanRecipient, input: PlanRecipientRoutesInput): RecipientDecision {
  const address = recipient.address.toLowerCase();
  const domain = recipientDomain(address);
  const view: DomainView = (domain !== null ? input.domains.get(domain) : undefined) ?? {
    domainId: null,
    ownerOrganizationId: null,
    ownerStatus: 'none',
  };
  const owner =
    view.ownerStatus === 'active' && view.ownerOrganizationId !== null
      ? { organizationId: view.ownerOrganizationId }
      : null;
  const direction = classifyRecipient({
    listenerDirection: input.listenerDirection,
    messageOrganizationId: input.messageOrganizationId,
    recipientDomainOwner: owner,
  });
  const base = {
    recipientId: recipient.recipientId,
    rcptSeq: recipient.rcptSeq,
    address,
    direction,
  };
  const refuse = (reason: RecipientRefusalReason): RecipientRefusal => ({
    ...base,
    kind: 'refusal',
    status: 'failed',
    reason,
  });

  // Mail approved under one direction's policy never leaves under another (R1).
  if (recipient.storedDirection !== null && recipient.storedDirection !== direction) {
    return refuse('direction_changed');
  }
  if (domain === null) return refuse('recipient_domain_inactive');
  const path = deliveryPathFor(direction);

  if (direction === 'inbound') {
    // The recipient domain must still belong to the message's organization.
    if (view.ownerOrganizationId !== input.messageOrganizationId || view.domainId === null) {
      return refuse('recipient_domain_inactive');
    }
    if (view.ownerStatus === 'none') return refuse('recipient_domain_inactive');
    return {
      ...base,
      kind: 'route',
      ...path,
      destinationKey: `tenant:${view.domainId.toString()}`,
      hold: view.ownerStatus === 'suspended' ? 'gateway_hold' : null,
    };
  }
  if (direction === 'internal') {
    if (view.domainId === null) return refuse('recipient_domain_inactive');
    return {
      ...base,
      kind: 'route',
      ...path,
      destinationKey: `tenant:${view.domainId.toString()}`,
      hold: null,
    };
  }
  if (input.suppressedAddresses.has(address)) {
    return { ...base, kind: 'refusal', status: 'suppressed', reason: 'suppressed' };
  }
  return {
    ...base,
    kind: 'route',
    ...path,
    destinationKey: `mx:${asciiDomain(domain)}`,
    hold: null,
  };
}

const compareBigint = (a: bigint, b: bigint): number => (a < b ? -1 : a > b ? 1 : 0);
const compareText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * One decision per recipient (R1, R4, R7):
 *
 * - direction = classifyRecipient now; a stored direction that differs → `failed`
 *   `direction_changed` (never delivered under another direction's policy);
 * - inbound: the domain must still be owned by the message's organization → route
 *   `tenant:<domainId>` via 10026, `NOTIFY=NEVER`, trace `in`; suspended domain or organization
 *   → the same route with `hold = gateway_hold`; no owner or another owner → `failed`
 *   `recipient_domain_inactive`;
 * - internal: `tenant:<domainId>` via 10026, `NOTIFY=FAILURE,DELAY`, trace `in`;
 * - outbound: an active suppression of the organization → `suppressed`; otherwise
 *   `mx:<domain>` via 10027, `NOTIFY=FAILURE,DELAY`, trace `out`.
 *
 * Routes are grouped by (listener, direction, destinationKey) and chunked to
 * `maxRecipientsPerGroup` in ascending recipient id order; each group carries its sorted
 * recipient ids and its recipientSetSha256.
 */
export function planRecipientRoutes(input: PlanRecipientRoutesInput): RoutePlan {
  const max = input.maxRecipientsPerGroup;
  if (!Number.isInteger(max) || max < 1 || max > MAX_RECIPIENTS_PER_GROUP) {
    throw new Error(`maxRecipientsPerGroup must be an integer 1-${MAX_RECIPIENTS_PER_GROUP}`);
  }
  const seen = new Set<bigint>();
  for (const recipient of input.recipients) {
    if (seen.has(recipient.recipientId)) {
      throw new Error(`Duplicate recipient id ${recipient.recipientId.toString()}`);
    }
    seen.add(recipient.recipientId);
  }

  const decisions = input.recipients.map((recipient) => decide(recipient, input));
  const buckets = new Map<string, RecipientRoute[]>();
  for (const decision of decisions) {
    if (decision.kind !== 'route') continue;
    const key = `${decision.listener}|${decision.direction}|${decision.destinationKey}`;
    const bucket = buckets.get(key);
    if (bucket) bucket.push(decision);
    else buckets.set(key, [decision]);
  }

  const groups: RouteGroup[] = [];
  for (const key of [...buckets.keys()].sort(compareText)) {
    const routes = buckets.get(key)!.sort((a, b) => compareBigint(a.recipientId, b.recipientId));
    for (let i = 0; i < routes.length; i += max) {
      const chunk = routes.slice(i, i + max);
      const first = chunk[0]!;
      const addresses = [...new Set(chunk.map((route) => route.address))].sort(compareText);
      groups.push({
        listener: first.listener,
        direction: first.direction,
        destinationKey: first.destinationKey,
        notify: first.notify,
        traceDirection: first.traceDirection,
        hold: first.hold,
        recipientIds: chunk.map((route) => route.recipientId),
        addresses,
        recipientSetSha256: recipientSetSha256(addresses),
      });
    }
  }
  return { decisions, groups };
}
