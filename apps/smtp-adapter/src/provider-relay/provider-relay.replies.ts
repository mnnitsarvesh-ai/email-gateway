import { UNKNOWN_USER } from '../shared/replies';

/**
 * Policy answers of the provider relay (step 8.2 D7.4, D7.5, D10). Kept beside the step 2.2
 * actions of `shared/replies.ts` (whose catalogue test pins exactly the step 2.2 set). Same
 * rules: generic texts, never data.
 */

/** A probe-domain recipient outside a provider-relay session (same text as an unknown user). */
export const PROBE_RECIPIENT_REFUSED = UNKNOWN_USER;

/**
 * `outbound_mode = probe_only` and a non-probe recipient: `451 4.7.1`, so the provider queues and
 * retries while the wizard is incomplete (Postfix accepts a numeric 4xx access action).
 */
export const PROVIDER_RELAY_NOT_ACTIVE =
  '451 4.7.1 Outbound routing through the gateway is not active yet for this organization';

/** `outbound_mode = suspended` (an administrator action, §15 Q7). */
export const PROVIDER_RELAY_SUSPENDED =
  '451 4.7.1 Outbound routing through the gateway is suspended';

/**
 * END-OF-MESSAGE of a provider-egress client whose session no longer resolves to any connector
 * (the connection, connector or domain link changed after RCPT accepted the recipients): the
 * message is deferred, never relayed without the provider relay marker (review finding; I7).
 */
export const PROVIDER_RELAY_STATE_CHANGED =
  'DEFER_IF_PERMIT 4.7.1 Provider relay authorization changed, try again later';

/** `MAIL FROM:<>` from provider egress ranges: no attribution is possible at RCPT (§1.4.2). */
export const NULL_SENDER_REFUSED =
  'REJECT 5.7.1 Null-sender mail is not accepted on the provider relay';
