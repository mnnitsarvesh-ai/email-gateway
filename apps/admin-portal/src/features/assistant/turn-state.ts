import type {
  AssistantCard,
  AssistantStreamEvent,
  ExecutionDecision,
  ExecutionStatus,
} from './types';

/**
 * The browser-side state of one turn while it streams (step AI-1 D14): the user's text, the
 * assistant text so far, one chip per tool execution and the outcome. Pure reducer, so the order
 * rules of `assistant-stream/1` are unit-tested without React.
 */

export type ToolChipState = 'running' | 'succeeded' | 'denied' | 'failed';

export interface ToolEntry {
  readonly executionId: string;
  readonly tool: string;
  readonly title: string;
  readonly state: ToolChipState;
  readonly decision: ExecutionDecision | null;
  readonly card: AssistantCard | null;
  readonly message: string | null;
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

function chipState(status: ExecutionStatus, decision: ExecutionDecision): ToolChipState {
  if (decision !== 'allowed' || status === 'refused') return 'denied';
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
        })),
      };
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
