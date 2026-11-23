import {
  confirmationSpecOf,
  guardMessageOf,
  type ExecutionDecision,
} from '@email-gateway/assistant';

/**
 * Fixed server-authored messages of refused tool calls (decision ≠ `allowed`). The executor
 * sends the model and the stream these, sometimes with a detail (the schema issues, the unknown
 * reference); an execution view carries the fixed text only (`refusalMessageOf`).
 */
export const DENIAL_MESSAGES: Record<Exclude<ExecutionDecision, 'allowed'>, string> = {
  denied_budget: 'This turn already used its maximum number of tool calls.',
  denied_unknown_tool: 'There is no tool with this name. Use a name from the catalogue index.',
  denied_not_applicable: 'This operation is not available in chat; it stays in the portal.',
  denied_disabled: 'This tool is not enabled for chat yet; use the portal page.',
  denied_permission: 'You do not have the permission this tool needs.',
  denied_schema: 'The arguments do not match the tool’s input schema.',
  denied_ref: 'A reference (@r<seq>.<row>) does not name a result of this conversation.',
  // Step AI-3 D3: the refusal message is the guard's own (`GUARD_MESSAGES`); this is a fallback.
  denied_guard: 'This change is not allowed in chat.',
};

/**
 * The message of an execution view (step AI-3 D12): null for an allowed call; for a refused one
 * the fixed text of its decision, and for `denied_guard` the guard's own message, derived from
 * the confirmation spec of the stored operation (the row keeps the decision, not the message;
 * every spec's guards share one message, a registry consistency rule). Never an argument value,
 * so a stored conversation (reload, refetch) shows what the live stream showed.
 */
export function refusalMessageOf(decision: ExecutionDecision, operationId: string): string | null {
  if (decision === 'allowed') return null;
  if (decision === 'denied_guard')
    return guardMessageOf(confirmationSpecOf(operationId)) ?? DENIAL_MESSAGES.denied_guard;
  return DENIAL_MESSAGES[decision];
}
