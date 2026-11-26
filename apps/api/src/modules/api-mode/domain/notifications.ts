import {
  clientStateMatches,
  type GraphNotificationItem,
  isGraphLifecycleEvent,
} from '@email-gateway/mailbox-api';

/**
 * Handling of one Graph change or lifecycle notification item (step API-1 D10.4, D12.4; N3), pure
 * so every case is table-tested. A notification is only a HINT to run the mailbox's delta query:
 * it selects a mailbox solely through a stored subscription id plus a constant-time match of the
 * client state against its stored SHA-256, the item's `tenantId` (when present) must be the
 * connection's bound tenant, and the result is at most "request a sync" (plus, for lifecycle
 * events, "renew the subscription" or "forget it"). Nothing of the payload (resource, content,
 * tenant) is trusted or stored.
 */

/** `kind` label of `api_mode_notifications_total` (the route that received the item). */
export type NotificationKind = 'change' | 'lifecycle';

/** `result` label of `api_mode_notifications_total`. */
export const NOTIFICATION_RESULTS = [
  'accepted',
  'unknown_subscription',
  'client_state_mismatch',
  'tenant_mismatch',
  'feed_inactive',
  'invalid',
  'rate_limited',
  'validation',
] as const;
export type NotificationResult = (typeof NOTIFICATION_RESULTS)[number];

/** The stored facts of the mailbox a subscription id selects (writer). */
export interface SubscribedMailbox {
  id: bigint;
  feedStatus: 'off' | 'pending' | 'active' | 'error' | 'throttled' | 'revoked';
  clientStateHash: string | null;
  /** The bound tenant of the provider connection (`external_tenant_id`), or null. */
  boundTenantId: string | null;
}

/** What one accepted item does to its mailbox row. */
export interface NotificationEffect {
  /** `sync_requested_at = COALESCE(sync_requested_at, NOW(3))`. */
  requestSync: boolean;
  /** `reauthorizationRequired`: `subscription_expires_at = NOW(3)` (forces the renewal). */
  expireSubscription: boolean;
  /** `subscriptionRemoved`: `subscription_id = NULL` (re-created by the worker). */
  clearSubscription: boolean;
}

export type NotificationDecision =
  | { result: 'accepted'; mailboxId: bigint; effect: NotificationEffect }
  | { result: Exclude<NotificationResult, 'accepted' | 'rate_limited' | 'validation'> };

const NO_EFFECT: NotificationEffect = {
  requestSync: false,
  expireSubscription: false,
  clearSubscription: false,
};

/** Graph tenant ids compare case-insensitively (GUIDs). */
const sameTenant = (a: string, b: string): boolean =>
  a.trim().toLowerCase() === b.trim().toLowerCase();

/** The decision for one parsed item and the mailbox its subscription id selected (or null). */
export function decideNotification(
  kind: NotificationKind,
  item: GraphNotificationItem,
  mailbox: SubscribedMailbox | null,
): NotificationDecision {
  if (mailbox === null) return { result: 'unknown_subscription' };
  if (
    item.clientState === undefined ||
    mailbox.clientStateHash === null ||
    !clientStateMatches(item.clientState, mailbox.clientStateHash)
  ) {
    return { result: 'client_state_mismatch' };
  }
  if (
    item.tenantId !== undefined &&
    (mailbox.boundTenantId === null || !sameTenant(item.tenantId, mailbox.boundTenantId))
  ) {
    return { result: 'tenant_mismatch' };
  }
  if (mailbox.feedStatus === 'off' || mailbox.feedStatus === 'revoked') {
    return { result: 'feed_inactive' };
  }
  const event = item.lifecycleEvent;
  if (event !== undefined) {
    if (!isGraphLifecycleEvent(event)) return { result: 'invalid' };
    switch (event) {
      case 'reauthorizationRequired':
        return {
          result: 'accepted',
          mailboxId: mailbox.id,
          effect: { ...NO_EFFECT, requestSync: true, expireSubscription: true },
        };
      case 'subscriptionRemoved':
        return {
          result: 'accepted',
          mailboxId: mailbox.id,
          effect: { ...NO_EFFECT, requestSync: true, clearSubscription: true },
        };
      case 'missed':
        return {
          result: 'accepted',
          mailboxId: mailbox.id,
          effect: { ...NO_EFFECT, requestSync: true },
        };
    }
  }
  // A change notification on the lifecycle route (or without a change type) is still only a hint.
  if (kind === 'lifecycle' && item.changeType === undefined) return { result: 'invalid' };
  return { result: 'accepted', mailboxId: mailbox.id, effect: { ...NO_EFFECT, requestSync: true } };
}

/**
 * Merges the effects of several accepted items of one mailbox (a batch may repeat a mailbox): one
 * coalescing UPDATE per mailbox.
 */
export function mergeEffects(
  decisions: readonly NotificationDecision[],
): Map<bigint, NotificationEffect> {
  const out = new Map<bigint, NotificationEffect>();
  for (const d of decisions) {
    if (d.result !== 'accepted') continue;
    const prev = out.get(d.mailboxId) ?? NO_EFFECT;
    out.set(d.mailboxId, {
      requestSync: prev.requestSync || d.effect.requestSync,
      expireSubscription: prev.expireSubscription || d.effect.expireSubscription,
      clearSubscription: prev.clearSubscription || d.effect.clearSubscription,
    });
  }
  return out;
}
