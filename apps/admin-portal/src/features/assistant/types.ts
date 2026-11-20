import type { SuccessBody } from '@/lib/api/types';

/**
 * Local mirror of the assistant contracts (docs/architecture/contracts.md §35, step AI-1 §4.2 and
 * D8). The portal never imports `@email-gateway/assistant` (only apps/api may depend on it); the
 * REST shapes come from the generated client, the stream events and the card are typed here and
 * validated at runtime by `parseStreamEvent` before the UI uses them.
 */

export const STREAM_VERSION = 'assistant-stream/1';
export const CARD_VERSION = 'assistant-card/1';

export type CardKind = 'table' | 'kv' | 'series' | 'message' | 'error';
export type CardValue = string | number | boolean | null;

export interface CardColumn {
  readonly key: string;
  readonly label: string;
}

export interface CardLink {
  readonly label: string;
  readonly href: string;
  /** Row ref the link belongs to (table rows). */
  readonly ref?: string;
}

/** `assistant-card/1`: built by the api from the real API response, never from model text. */
export interface AssistantCard {
  readonly version: typeof CARD_VERSION;
  readonly executionId: string;
  readonly tool: string;
  readonly title: string;
  readonly status: 'ok' | 'error';
  readonly kind: CardKind;
  readonly columns?: readonly CardColumn[];
  readonly rows?: ReadonlyArray<Readonly<Record<string, CardValue>>>;
  readonly fields?: ReadonlyArray<{
    readonly key: string;
    readonly label: string;
    readonly value: CardValue;
  }>;
  readonly series?: {
    readonly x: readonly string[];
    readonly series: ReadonlyArray<{
      readonly name: string;
      readonly values: ReadonlyArray<number | null>;
    }>;
  };
  readonly total?: number;
  /** A next page exists (`POST /assistant/executions/{id}/more`). */
  readonly nextCursor?: boolean;
  readonly portalLinks: readonly CardLink[];
  readonly refs: readonly string[];
  readonly truncated?: boolean;
  readonly message?: string;
  readonly error?: { readonly httpStatus: number; readonly code: string; readonly message: string };
}

export type ExecutionDecision =
  | 'allowed'
  | 'denied_permission'
  | 'denied_unknown_tool'
  | 'denied_disabled'
  | 'denied_not_applicable'
  | 'denied_schema'
  | 'denied_ref'
  | 'denied_budget';

export type ExecutionStatus = 'succeeded' | 'failed' | 'refused' | 'timeout';

/** `assistant-stream/1` events (contracts §35): `event: <type>` + `data: <JSON of the rest>`. */
export type AssistantStreamEvent =
  | { type: 'turn.started'; turnId: string; conversationId: string; seq: number }
  | { type: 'text.delta'; text: string }
  | { type: 'tool.started'; executionId: string; tool: string; title: string }
  | {
      type: 'tool.completed';
      executionId: string;
      status: ExecutionStatus;
      decision: ExecutionDecision;
      card: AssistantCard;
    }
  | {
      type: 'tool.denied';
      executionId: string;
      tool: string;
      decision: Exclude<ExecutionDecision, 'allowed'>;
      message: string;
    }
  | {
      type: 'turn.completed';
      turnId: string;
      status: 'completed' | 'cancelled';
      usage: { inputTokens: number; outputTokens: number };
      messageId: string;
    }
  | { type: 'turn.failed'; turnId: string; code: string; message: string };

export type AssistantStreamEventType = AssistantStreamEvent['type'];

/** REST documents from the generated client. */
export type AssistantStatus = SuccessBody<'AssistantStatusController_get_v1'>;
export type AssistantUnavailableReason = NonNullable<AssistantStatus['reason']>;
export type AssistantSettings = SuccessBody<'AssistantSettingsController_get_v1'>;
export type AssistantUsage = SuccessBody<'AssistantUsageController_get_v1'>;
export type AssistantTools = SuccessBody<'AssistantToolsController_list_v1'>;
export type Conversation = SuccessBody<'AssistantConversationsController_get_v1'>;
export type StoredMessage = SuccessBody<'AssistantMessagesController_list_v1'>['data'][number];
export type Execution = SuccessBody<'AssistantExecutionsController_get_v1'>;
export type TurnResult = SuccessBody<'AssistantTurnsController_create_v1'>;
