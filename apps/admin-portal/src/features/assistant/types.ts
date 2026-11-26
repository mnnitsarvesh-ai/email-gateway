import type { SuccessBody } from '@/lib/api/types';

/**
 * Local mirror of the assistant contracts (docs/architecture/contracts.md §35, step AI-1 §4.2 and
 * D8). The portal never imports `@email-gateway/assistant` (only apps/api may depend on it); the
 * REST shapes come from the generated client, the stream events and the card are typed here and
 * validated at runtime by `parseStreamEvent` before the UI uses them.
 */

export const STREAM_VERSION = 'assistant-stream/1';
export const CARD_VERSION = 'assistant-card/1';
export const CONFIRMATION_SUMMARY_VERSION = 'assistant-confirmation/1';

export type CardKind = 'table' | 'kv' | 'series' | 'message' | 'error' | 'report';
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

/** Card statuses of a report (packages/assistant `REPORT_CARD_STATUSES`, step AI-6). */
export const REPORT_CARD_STATUSES = ['queued', 'running', 'available', 'failed'] as const;
export type ReportCardStatus = (typeof REPORT_CARD_STATUSES)[number];

/** Why a requested report section is not in the report (step AI-R D3). */
export type ReportOmissionReason =
  'permission' | 'not_enabled' | 'unavailable' | 'unexpected_response';

/**
 * The `report` object of a card of kind `report` (step AI-R D2 step 10, `CardSchema.report`):
 * server figures only; the HTML itself is fetched with `GET /assistant/reports/{reportId}`.
 */
export interface ReportCardData {
  readonly reportId: string;
  /**
   * Step AI-6 (D5): `queued` when the report is generated in the background (no figures yet;
   * the card polls `GET /assistant/reports/{id}`). Absent on cards stored before AI-6 =
   * `available`.
   */
  readonly status?: ReportCardStatus;
  readonly title: string;
  readonly period: {
    readonly from: string;
    readonly to: string;
    readonly granularity: string;
    readonly atoRange: string | null;
    /** `Last 7 days`, or the explicit window in UTC. */
    readonly label: string;
  };
  readonly generatedAt: string;
  readonly sizeBytes: number;
  readonly sections: readonly string[];
  readonly omitted: ReadonlyArray<{
    readonly section: string;
    readonly reason: ReportOmissionReason;
    /** The missing permission (`quarantine:read`) or the source error code. */
    readonly code?: string | null;
  }>;
  readonly figures: ReadonlyArray<{ readonly label: string; readonly value: string }>;
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
  /** Kind `report` only (step AI-R). */
  readonly report?: ReportCardData;
}

export type ExecutionDecision =
  | 'allowed'
  | 'denied_permission'
  | 'denied_unknown_tool'
  | 'denied_disabled'
  | 'denied_not_applicable'
  | 'denied_schema'
  | 'denied_ref'
  | 'denied_budget'
  /** A proposal guard refused the call; nothing was sent to the api (step AI-3 D3). */
  | 'denied_guard';

export type ExecutionStatus =
  | 'succeeded'
  | 'failed'
  | 'refused'
  | 'timeout'
  /** A write proposal waiting for the user's confirmation (step AI-2). */
  | 'pending_confirmation';

export type ConfirmationStatus =
  'pending' | 'executing' | 'executed' | 'failed' | 'expired' | 'cancelled';

/** Risk of a confirmable write (`critical` actions are portal only, never a tool). */
export type ConfirmationRisk = 'low' | 'medium' | 'high';

/** One "what it applies to" line; `untrusted` marks values that come from mail. */
export interface ConfirmationTarget {
  readonly label: string;
  readonly value: string;
  readonly untrusted?: boolean;
}

export interface ConfirmationChange {
  readonly label: string;
  readonly before?: string | null;
  readonly after: string;
}

/**
 * `assistant-confirmation/1` (step AI-2 D5): the impact summary the confirmation card renders.
 * Server-authored from the stored request and the target's current state, never model text.
 */
export interface ConfirmationSummary {
  readonly version: typeof CONFIRMATION_SUMMARY_VERSION;
  readonly title: string;
  /** One sentence: what will happen. */
  readonly action: string;
  readonly target: readonly ConfirmationTarget[];
  readonly changes: readonly ConfirmationChange[];
  /** Policy definitions, rule by rule. */
  readonly definition?: {
    readonly direction: string;
    readonly priority: number;
    readonly rules: ReadonlyArray<{
      readonly id: string;
      readonly when: string;
      readonly actions: string;
    }>;
  };
  readonly impact: readonly string[];
  readonly warnings: readonly string[];
  readonly reversible: boolean;
  /** The portal page that shows the target. */
  readonly portalRoute: string | null;
  /** Shown in a "Technical details" disclosure. */
  readonly request: { readonly method: string; readonly path: string };
}

/**
 * A write the assistant proposed (contracts §35.1, step AI-2 §4.2). Never contains the token:
 * the single-use token arrives once, in `confirmation.required`, and lives only in the memory of
 * the browser tab that received it.
 */
export interface ConfirmationView {
  readonly id: string;
  /** The proposal execution (status `pending_confirmation`). */
  readonly executionId: string;
  /** The confirmed write's execution (after confirm). */
  readonly resultExecutionId: string | null;
  readonly conversationId: string;
  readonly tool: string;
  readonly operationId: string;
  readonly risk: ConfirmationRisk;
  readonly requiresReauth: boolean;
  /** The session re-authenticated within the window: no password fields. */
  readonly reauthFresh: boolean;
  readonly status: ConfirmationStatus;
  /** Null once the conversation's content was purged. */
  readonly summary: ConfirmationSummary | null;
  /** Sent back unchanged by the confirm request. */
  readonly actionDigest: string;
  readonly expiresAt: string;
  readonly createdAt: string;
  readonly decidedAt: string | null;
  readonly executedAt: string | null;
  readonly result: { readonly httpStatus: number | null; readonly error: string | null } | null;
}

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
  | {
      /**
       * Right after the `tool.completed` (status `pending_confirmation`) of a write proposal.
       * `token` is null only for a JSON replay of a stored turn (the api never repeats a token).
       */
      type: 'confirmation.required';
      confirmation: ConfirmationView;
      token: string | null;
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
export type ConfirmResult = SuccessBody<'AssistantConfirmationsController_confirm_v1'>;
export type CancelResult = SuccessBody<'AssistantConfirmationsController_cancel_v1'>;
/** `GET /assistant/reports/{reportId}` (step AI-R §4.1): `{ report: ReportView, html }`. */
export type ReportDocument = SuccessBody<'AssistantReportsController_get_v1'>;
export type ReportView = ReportDocument['report'];
export type ReportDelivery = ReportView['deliveries'][number];
export type ReportJob = NonNullable<ReportView['job']>;

/** Step AI-6 (D2): the rating of an assistant message (owner view of `GET …/messages`). */
export type MessageFeedback = NonNullable<StoredMessage['feedback']>;
export type FeedbackRating = MessageFeedback['rating'];
export type FeedbackReason = NonNullable<MessageFeedback['reason']>;
export type FeedbackView = SuccessBody<'AssistantFeedbackController_set_v1'>;
/** Step AI-6 (D4): one hit of the owner's content search. */
export type SearchHit = SuccessBody<'AssistantSearchController_search_v1'>['data'][number];
export type TenantKeyView = SuccessBody<'AssistantProviderKeyController_set_v1'>;
export type EffectiveLimits = AssistantSettings['effectiveLimits'];
export type DataSharing = AssistantSettings['dataSharing'];
