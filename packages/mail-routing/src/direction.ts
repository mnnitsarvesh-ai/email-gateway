/**
 * Direction resolution (step 2.3 R1). Direction is never derived from headers: it comes from the
 * ingestion listener (authenticated connector or inbound MX) and the organizations' verified
 * domains.
 */

/** Ingestion listener: LMTP `:10050` (inbound MX) or `:10051` (authenticated outbound). */
export type ListenerDirection = 'inbound' | 'outbound';
/** Routed direction of a recipient (`email_recipients.direction`, `email_deliveries.direction`). */
export type RoutedDirection = 'inbound' | 'outbound' | 'internal';

export interface ClassifyRecipientInput {
  listenerDirection: ListenerDirection;
  /** The message's organization, set by ingestion (trusted context). */
  messageOrganizationId: bigint;
  /**
   * Owner of the recipient domain with `resolveActiveDomain` semantics (verified, `active`
   * domain of an `active` organization; `inbound_enabled` not required), or null.
   */
  recipientDomainOwner: { organizationId: bigint } | null;
}

/**
 * - `inbound` listener → `inbound`, always: ingestion already proved the recipient domain is the
 *   organization's, and a same-organization sender on the unauthenticated MX is a spoofing
 *   candidate, never internal.
 * - `outbound` listener, recipient domain actively owned by the message's organization →
 *   `internal`.
 * - `outbound` listener, anything else (no owner, inactive, or **another organization of this
 *   gateway**) → `outbound`: other tenants are reached through their public MX.
 */
export function classifyRecipient(input: ClassifyRecipientInput): RoutedDirection {
  if (input.listenerDirection === 'inbound') return 'inbound';
  const owner = input.recipientDomainOwner;
  if (owner !== null && owner.organizationId === input.messageOrganizationId) return 'internal';
  return 'outbound';
}

/**
 * `email_messages.direction`: `internal` only when the listener is outbound and every recipient
 * (at least one) is internal; otherwise the listener direction (mixed messages stay
 * `outbound`; the per-recipient directions live on recipients and deliveries).
 */
export function messageDirection(
  listenerDirection: ListenerDirection,
  recipientDirections: readonly RoutedDirection[],
): RoutedDirection {
  if (
    listenerDirection === 'outbound' &&
    recipientDirections.length > 0 &&
    recipientDirections.every((direction) => direction === 'internal')
  ) {
    return 'internal';
  }
  return listenerDirection;
}

/** postfix-outbound reinjection listener per routed direction (R4). */
export type ReinjectionListenerName = 'reinject_inbound' | 'reinject_outbound';
/** RCPT TO `NOTIFY=` per routed direction (R4): no DSN backscatter for inbound mail. */
export type DsnNotify = 'NEVER' | 'FAILURE,DELAY';
/** `X-Gateway-Trace` direction prepended by the worker (R4). */
export type TraceDirection = 'in' | 'out';

export interface DeliveryPath {
  listener: ReinjectionListenerName;
  notify: DsnNotify;
  traceDirection: TraceDirection;
}

/** R4: inbound → 10026/NEVER/in; internal → 10026/FAILURE,DELAY/in; outbound → 10027/FAILURE,DELAY/out. */
export function deliveryPathFor(direction: RoutedDirection): DeliveryPath {
  switch (direction) {
    case 'inbound':
      return { listener: 'reinject_inbound', notify: 'NEVER', traceDirection: 'in' };
    case 'internal':
      return { listener: 'reinject_inbound', notify: 'FAILURE,DELAY', traceDirection: 'in' };
    case 'outbound':
      return { listener: 'reinject_outbound', notify: 'FAILURE,DELAY', traceDirection: 'out' };
  }
}
