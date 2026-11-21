/**
 * Confirmation contracts of step AI-2 (design `docs/plan/steps/29-ai-chat-confirmations-mail-writes.md`
 * §4.2, D3, D5; ADR-0093 amended): the server-authored summary the confirmation card renders
 * (`assistant-confirmation/1`), the confirmation view of the api routes and the stream event.
 * The portal mirrors these types (it may not import the package).
 */

export const CONFIRMATION_SUMMARY_VERSION = 'assistant-confirmation/1';
export const ACTION_DIGEST_VERSION = 'assistant-action/1';

export const CONFIRMATION_STATUSES = [
  'pending',
  'executing',
  'executed',
  'failed',
  'expired',
  'cancelled',
] as const;
export type ConfirmationStatus = (typeof CONFIRMATION_STATUSES)[number];

/** Risks a confirmable write can have (`critical` is portal only, never a tool). */
export const CONFIRMATION_RISKS = ['low', 'medium', 'high'] as const;
export type ConfirmationRisk = (typeof CONFIRMATION_RISKS)[number];

/** One "what it applies to" line; `untrusted` marks values that come from mail. */
export interface ConfirmationTarget {
  label: string;
  value: string;
  untrusted?: boolean;
}

export interface ConfirmationChange {
  label: string;
  before?: string | null;
  after: string;
}

export interface ConfirmationRuleSummary {
  id: string;
  /** The rule's `when` (and `unless`) flattened to readable text (≤ 300 characters). */
  when: string;
  /** Action types with their parameters, e.g. `QUARANTINE; TAG (label=external)`. */
  actions: string;
}

export interface ConfirmationDefinitionSummary {
  direction: string;
  priority: number;
  rules: ConfirmationRuleSummary[];
}

/** `assistant-confirmation/1` (design D5): server-authored, never model text. */
export interface ConfirmationSummary {
  version: typeof CONFIRMATION_SUMMARY_VERSION;
  /** "Create policy", "Release quarantined message". */
  title: string;
  /** One sentence: what will happen. */
  action: string;
  target: ConfirmationTarget[];
  changes: ConfirmationChange[];
  /** Policy definitions only. */
  definition?: ConfirmationDefinitionSummary;
  /** Consequences (medium and high risk have at least one). */
  impact: string[];
  /** E.g. "Deleting cannot be undone" (high risk has at least one). */
  warnings: string[];
  reversible: boolean;
  /** The portal page that shows the target. */
  portalRoute: string | null;
  /** Shown in a "Technical details" disclosure. */
  request: { method: string; path: string };
}

/** The confirmation as the api returns it (§4.2). Never contains the token. */
export interface ConfirmationView {
  id: string;
  /** The proposal execution. */
  executionId: string;
  /** The confirmed write's execution (after confirm). */
  resultExecutionId: string | null;
  conversationId: string;
  tool: string;
  operationId: string;
  risk: ConfirmationRisk;
  requiresReauth: boolean;
  /** The session re-authenticated within the window (the card skips the password fields). */
  reauthFresh: boolean;
  status: ConfirmationStatus;
  /** Null once the conversation's content was purged. */
  summary: ConfirmationSummary | null;
  /** The digest the card shows and the confirm request sends back. */
  actionDigest: string;
  expiresAt: string;
  createdAt: string;
  decidedAt: string | null;
  executedAt: string | null;
  result: { httpStatus: number | null; error: string | null } | null;
}
