import {
  MESSAGE_STATES,
  type MessageState,
  RECIPIENT_STATES,
  type RecipientState,
} from '@email-gateway/quarantine';

/**
 * Step 8.6 D3/D5: the registry's `MessageStatus` / `RecipientStatus` gained `journaled`, which only
 * journal intake messages can reach. Intake messages are never quarantined (I1), so a quarantine
 * entry's message can never be `journaled`; these guards narrow the registry values to the
 * quarantine library's vocabulary and fail loudly (500, logged) if that invariant is ever broken
 * rather than letting an unknown state reach a release or disposal decision.
 */
export function gatewayMessageState(state: string): MessageState {
  if (!(MESSAGE_STATES as readonly string[]).includes(state)) {
    throw new Error(`quarantine: message state ${state} is not a gateway state`);
  }
  return state as MessageState;
}

export function gatewayRecipientState(status: string): RecipientState {
  if (!(RECIPIENT_STATES as readonly string[]).includes(status)) {
    throw new Error(`quarantine: recipient status ${status} is not a gateway status`);
  }
  return status as RecipientState;
}
