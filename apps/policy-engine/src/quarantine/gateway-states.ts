import {
  MESSAGE_STATES,
  type MessageState,
  RECIPIENT_STATES,
  type RecipientState,
} from '@email-gateway/quarantine';

/**
 * Step 8.6 D3/D4: the registry's `MessageStatus` / `RecipientStatus` gained `journaled`, which only
 * journal intake messages reach. Intake messages never reach the policy engine or quarantine (I1),
 * so a quarantined message can never be `journaled`; these guards narrow the registry values to
 * the quarantine library's vocabulary and fail loudly if that invariant is ever broken (the same
 * guards as the api's `modules/quarantine/domain/gateway-states.ts`).
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
