import type { MessageDirection } from '@email-gateway/database';
import type { MessageStateChangedV1 } from '@email-gateway/event-contracts';
import type { ActorRole, MessageState } from './states';

export interface StateChangedInput {
  messageId: bigint;
  receivedAt: Date;
  direction: MessageDirection;
  previousState: MessageState | null;
  state: MessageState;
  version: number;
  round: number;
  reasonCode: string;
  actor: { role: ActorRole; type: 'system' | 'user' | 'api_key'; service: string };
  causationEventId: string | null;
  changedAt: Date;
}

/**
 * The `mail.message.state_changed.v1` payload of an applied transition (L7). Not validated
 * here: the service parses it with `messageStateChangedV1` before the outbox insert. No actor
 * id (public id) in the event.
 */
export function toStateChangedPayload(input: StateChangedInput): MessageStateChangedV1 {
  return {
    messageId: input.messageId.toString(),
    receivedAt: input.receivedAt.toISOString(),
    direction: input.direction,
    previousState: input.previousState,
    state: input.state,
    version: input.version,
    lifecycleRound: input.round,
    reasonCode: input.reasonCode,
    actorRole: input.actor.role,
    actorType: input.actor.type,
    actorService: input.actor.service,
    causationEventId: input.causationEventId,
    changedAt: input.changedAt.toISOString(),
  };
}
