import type {
  AssistantCard,
  AssistantStreamEvent,
  ConfirmationStatus,
  ConfirmationView,
  ExecutionDecision,
  ExecutionStatus,
} from './types';

/**
 * The browser-side state of one turn while it streams (step AI-1 D14): the user's text, the
 * assistant text so far, one chip per tool execution and the outcome. Pure reducer, so the order
 * rules of `assistant-stream/1` are unit-tested without React.
 */

export type ToolChipState =
  | 'running'
  | 'succeeded'
  | 'denied'
  | 'failed'
  /** A write proposal waiting for confirmation (step AI-2). */
  | 'pending'
  | 'cancelled'
  | 'expired';

export interface ToolEntry {
  readonly executionId: string;
  readonly tool: string;
  readonly title: string;
  readonly state: ToolChipState;
  readonly decision: ExecutionDecision | null;
  readonly card: AssistantCard | null;
  readonly message: string | null;
  /** A write proposal's confirmation (step AI-2); never its token. */
  readonly confirmation: ConfirmationView | null;
  /** The card of the confirmed write's execution (history). */
  readonly resultCard: AssistantCard | null;
}

export interface TurnError {
  readonly code: string;
  readonly message: string;
  readonly requestId?: string | null;
}

export interface PendingTurn {
  readonly clientTurnId: string;
  readonly conversationId: string;
  readonly message: string;
  readonly turnId: string | null;
  readonly text: string;
  readonly tools: readonly ToolEntry[];
  readonly status: 'running' | 'completed' | 'cancelled' | 'failed';
  readonly error: TurnError | null;
}

/** The api caps assistant text at 16 000 characters; the browser never holds more than this. */
export const MAX_STREAM_TEXT = 20_000;

export function newPendingTurn(input: {
  clientTurnId: string;
  conversationId: string;
  message: string;
}): PendingTurn {
  return {
    ...input,
    turnId: null,
    text: '',
    tools: [],
    status: 'running',
    error: null,
  };
}

export function chipState(status: ExecutionStatus, decision: ExecutionDecision): ToolChipState {
  if (decision !== 'allowed' || status === 'refused') return 'denied';
  if (status === 'pending_confirmation') return 'pending';
  return status === 'succeeded' ? 'succeeded' : 'failed';
}

function upsertTool(
  tools: readonly ToolEntry[],
  executionId: string,
  update: (current: ToolEntry | null) => ToolEntry,
): ToolEntry[] {
  const index = tools.findIndex((tool) => tool.executionId === executionId);
  if (index < 0) return [...tools, update(null)];
  return tools.map((tool, i) => (i === index ? update(tool) : tool));
}

export function reduceTurn(turn: PendingTurn, event: AssistantStreamEvent): PendingTurn {
  if (turn.status !== 'running') return turn;
  switch (event.type) {
    case 'turn.started':
      // Also the start of a JSON replay after a broken stream: rebuild from scratch.
      return { ...turn, turnId: event.turnId, text: '', tools: [] };
    case 'text.delta':
      return { ...turn, text: (turn.text + event.text).slice(0, MAX_STREAM_TEXT) };
    case 'tool.started':
      return {
        ...turn,
        tools: upsertTool(turn.tools, event.executionId, (current) => ({
          executionId: event.executionId,
          tool: event.tool,
          title: event.title || current?.title || event.tool,
          state: 'running',
          decision: null,
          card: null,
          message: null,
          confirmation: null,
          resultCard: null,
        })),
      };
    case 'tool.completed':
      return {
        ...turn,
        tools: upsertTool(turn.tools, event.executionId, (current) => ({
          executionId: event.executionId,
          tool: current?.tool ?? event.card.tool,
          title: current?.title ?? event.card.title,
          state: chipState(event.status, event.decision),
          decision: event.decision,
          card: event.card,
          message: event.card.error?.message ?? null,
          confirmation: current?.confirmation ?? null,
          resultCard: null,
        })),
      };
    case 'confirmation.required': {
      // The token stays out of the turn state (the confirmation store keeps it, D10).
      const { confirmation } = event;
      return {
        ...turn,
        tools: upsertTool(turn.tools, confirmation.executionId, (current) => ({
          executionId: confirmation.executionId,
          tool: current?.tool ?? confirmation.tool,
          title: current?.title ?? confirmation.summary?.title ?? confirmation.tool,
          state: 'pending',
          decision: 'allowed',
          card: current?.card ?? null,
          message: current?.message ?? null,
          confirmation,
          resultCard: null,
        })),
      };
    }
    case 'tool.denied':
      return {
        ...turn,
        tools: upsertTool(turn.tools, event.executionId, (current) => ({
          executionId: event.executionId,
          tool: event.tool,
          title: current?.title ?? event.tool,
          state: 'denied',
          decision: event.decision,
          card: null,
          message: event.message,
          confirmation: null,
          resultCard: null,
        })),
      };
    case 'turn.completed':
      return {
        ...turn,
        turnId: event.turnId,
        status: event.status === 'cancelled' ? 'cancelled' : 'completed',
        tools: turn.tools.map((tool) =>
          tool.state === 'running' ? { ...tool, state: 'failed' } : tool,
        ),
      };
    case 'turn.failed':
      return {
        ...turn,
        turnId: event.turnId || turn.turnId,
        status: 'failed',
        error: { code: event.code, message: event.message },
        tools: turn.tools.map((tool) =>
          tool.state === 'running' ? { ...tool, state: 'failed' } : tool,
        ),
      };
    default:
      return turn;
  }
}

/** Ends a running turn locally (cancel before the api confirmed, or a client-side failure). */
export function endTurn(
  turn: PendingTurn,
  status: 'cancelled' | 'failed',
  error: TurnError | null = null,
): PendingTurn {
  if (turn.status !== 'running') return turn;
  return {
    ...turn,
    status,
    error,
    tools: turn.tools.map((tool) =>
      tool.state === 'running' ? { ...tool, state: 'failed' } : tool,
    ),
  };
}

/*
 * Confirmations (step AI-2 D10): per proposal execution, the latest view, the single-use token
 * and the phase of the card. The token is held in this in-memory state of the browser tab only:
 * never in localStorage or sessionStorage, never logged, never in the query cache; it is dropped
 * after confirm, cancel, expiry or a refusal that ends the confirmation. Without a token (reload,
 * other tab, JSON replay) the card can only cancel.
 */

export type ConfirmationPhase = 'idle' | 'confirming' | 'cancelling' | 'decided';

export interface LiveConfirmation {
  readonly view: ConfirmationView;
  readonly token: string | null;
  readonly phase: ConfirmationPhase;
  /** The confirmed write's result card (from the confirm response). */
  readonly resultCard: AssistantCard | null;
  /** Focus has not yet moved to the card (a new live proposal). */
  readonly focusPending: boolean;
}

/** Keyed by the proposal execution id. */
export type ConfirmationStore = ReadonlyMap<string, LiveConfirmation>;

export type ConfirmationAction =
  /** `confirmation.required` arrived (live stream or JSON fallback). */
  | { type: 'proposed'; view: ConfirmationView; token: string | null; now?: number }
  | { type: 'phase'; executionId: string; phase: Exclude<ConfirmationPhase, 'decided'> }
  /** A newer view (confirm, cancel, get); a non-pending view drops the token. */
  | {
      type: 'settled';
      view: ConfirmationView;
      resultCard?: AssistantCard | null;
    }
  /** The token can no longer be used (expiry seen locally, a refusal that ends it). */
  | { type: 'drop_token'; executionId: string }
  | { type: 'focused'; executionId: string };

export const EMPTY_CONFIRMATIONS: ConfirmationStore = new Map();

const STATUS_RANK: Record<ConfirmationStatus, number> = {
  pending: 0,
  executing: 1,
  executed: 2,
  failed: 2,
  expired: 2,
  cancelled: 2,
};

/** The more advanced of two views of the same confirmation (status, then decision time). */
export function newerView(a: ConfirmationView, b: ConfirmationView | null): ConfirmationView {
  if (!b) return a;
  const rank = STATUS_RANK[b.status] - STATUS_RANK[a.status];
  if (rank !== 0) return rank > 0 ? b : a;
  if (b.resultExecutionId && !a.resultExecutionId) return b;
  return a;
}

export function reduceConfirmations(
  store: ConfirmationStore,
  action: ConfirmationAction,
): ConfirmationStore {
  const next = new Map(store);
  switch (action.type) {
    case 'proposed': {
      const now = action.now ?? Date.now();
      // Tokens of proposals that expired are dropped whenever a new one arrives.
      for (const [key, entry] of next) {
        if (entry.token && Date.parse(entry.view.expiresAt) <= now) {
          next.set(key, { ...entry, token: null });
        }
      }
      const current = next.get(action.view.executionId);
      const view = newerView(action.view, current?.view ?? null);
      next.set(action.view.executionId, {
        view,
        token: view.status === 'pending' ? (action.token ?? current?.token ?? null) : null,
        phase: view.status === 'pending' ? 'idle' : 'decided',
        resultCard: current?.resultCard ?? null,
        focusPending: action.token !== null && !current,
      });
      return next;
    }
    case 'phase': {
      const current = next.get(action.executionId);
      if (!current || current.phase === 'decided') return store;
      next.set(action.executionId, { ...current, phase: action.phase });
      return next;
    }
    case 'settled': {
      const current = next.get(action.view.executionId);
      const view = newerView(action.view, current?.view ?? null);
      const pending = view.status === 'pending';
      next.set(action.view.executionId, {
        view,
        token: pending ? (current?.token ?? null) : null,
        phase: pending ? 'idle' : 'decided',
        resultCard: action.resultCard ?? current?.resultCard ?? null,
        focusPending: false,
      });
      return next;
    }
    case 'drop_token': {
      const current = next.get(action.executionId);
      if (!current || current.token === null) return store;
      next.set(action.executionId, {
        ...current,
        token: null,
        phase: current.phase === 'decided' ? 'decided' : 'idle',
      });
      return next;
    }
    case 'focused': {
      const current = next.get(action.executionId);
      if (!current?.focusPending) return store;
      next.set(action.executionId, { ...current, focusPending: false });
      return next;
    }
    default:
      return store;
  }
}

/** The chip of a proposal follows its confirmation (the proposal execution never changes). */
export function confirmationChipState(status: ConfirmationStatus): ToolChipState {
  switch (status) {
    case 'pending':
      return 'pending';
    case 'executing':
      return 'running';
    case 'executed':
      return 'succeeded';
    case 'failed':
      return 'failed';
    case 'cancelled':
      return 'cancelled';
    case 'expired':
    default:
      return 'expired';
  }
}

/** Tool entries with the tab's newer confirmation views and result cards merged in. */
export function withLiveConfirmations(
  tools: readonly ToolEntry[],
  store: ConfirmationStore,
): ToolEntry[] {
  return tools.map((tool) => {
    if (!tool.confirmation) return tool;
    const live = store.get(tool.executionId);
    const confirmation = newerView(tool.confirmation, live?.view ?? null);
    return {
      ...tool,
      confirmation,
      state: confirmationChipState(confirmation.status),
      resultCard: live?.resultCard ?? tool.resultCard,
    };
  });
}
