import {
  ACTION_DIGEST_VERSION,
  canonicalJson,
  type ConfirmationRisk,
  type ConfirmationSnapshot,
  type DigestInput,
  type DigestPreconditions,
  type EachSnapshotItem,
  type HttpMethod,
  type OperationTool,
} from '@email-gateway/assistant';

/**
 * The stored halves of a confirmation's binding (step AI-2 D1 steps 5–8, D3): the request that
 * runs on confirm, the precondition state it was proposed against, and the `assistant-action/1`
 * digest input rebuilt from the stored columns. Pure functions; the confirm route recomputes
 * the digest from storage and refuses any difference (tampered storage) besides comparing the
 * digest the card showed.
 */

/**
 * The stored request (`ai_chat_action_confirmations.request`): the concrete method, path (with
 * the query) and JSON body, plus `params` = the final arguments without the body, so the
 * executor rebuilds exactly these from `params` + `body` and asserts the result is identical.
 */
export interface StoredRequest {
  method: HttpMethod;
  path: string;
  body: unknown;
  params: Record<string, unknown>;
}

/** The stored preconditions (`ai_chat_action_confirmations.preconditions`). */
export interface StoredPreconditions {
  rowVersion: number | null;
  definitionSha256: string | null;
  ruleCount: number | null;
  /** The single read's snapshot (state, row version and display fields), else null. */
  snapshot: ConfirmationSnapshot | null;
  /** `each` reads (bulk): the first 25 ids. */
  items?: EachSnapshotItem[];
  /** `each`: number of ids in the request. */
  total?: number;
  action?: string | null;
}

const METHODS: readonly string[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

/** The stored request JSON, or null when purged or malformed. */
export function parseStoredRequest(value: unknown): StoredRequest | null {
  if (!isRecord(value)) return null;
  const { method, path, body, params } = value;
  if (typeof method !== 'string' || !METHODS.includes(method)) return null;
  if (typeof path !== 'string' || !path.startsWith('/api/v1/')) return null;
  if (!isRecord(params)) return null;
  return { method: method as HttpMethod, path, body: body ?? null, params };
}

/** The stored preconditions JSON, or null when purged or malformed. */
export function parseStoredPreconditions(value: unknown): StoredPreconditions | null {
  if (!isRecord(value)) return null;
  const int = (v: unknown): number | null =>
    typeof v === 'number' && Number.isSafeInteger(v) ? v : null;
  const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
  const out: StoredPreconditions = {
    rowVersion: int(value.rowVersion),
    definitionSha256: str(value.definitionSha256),
    ruleCount: int(value.ruleCount),
    snapshot: isRecord(value.snapshot) ? (value.snapshot as ConfirmationSnapshot) : null,
  };
  if (Array.isArray(value.items)) {
    const items: EachSnapshotItem[] = [];
    for (const item of value.items) {
      if (!isRecord(item) || typeof item.id !== 'string' || typeof item.stateDigest !== 'string') {
        return null;
      }
      items.push({
        id: item.id,
        status: str(item.status),
        rowVersion: int(item.rowVersion),
        stateDigest: item.stateDigest,
      });
    }
    out.items = items;
    out.total = int(value.total) ?? items.length;
    out.action = str(value.action);
  }
  return out;
}

/** The final arguments of the stored request (`params` + `body`). */
export function argsOfStoredRequest(request: StoredRequest): Record<string, unknown> {
  return request.body === null ? { ...request.params } : { ...request.params, body: request.body };
}

/** The request half of the digest input. */
export function digestRequestOf(request: Pick<StoredRequest, 'method' | 'path' | 'body'>): {
  method: HttpMethod;
  path: string;
  body: unknown;
} {
  return { method: request.method, path: request.path, body: request.body ?? null };
}

/** True when two requests are identical (method, path with query, canonical body). */
export function sameRequest(
  a: { method: string; path: string; body?: unknown },
  b: { method: string; path: string; body?: unknown },
): boolean {
  return (
    a.method === b.method &&
    a.path === b.path &&
    canonicalJson(a.body ?? null) === canonicalJson(b.body ?? null)
  );
}

/** The preconditions half of the digest input (D3). */
export function digestPreconditionsOf(
  stateDigest: string | null,
  preconditions: StoredPreconditions,
): DigestPreconditions {
  return {
    stateDigest,
    rowVersion: preconditions.rowVersion,
    definitionSha256: preconditions.definitionSha256,
    ...(preconditions.items
      ? { items: preconditions.items.map(({ id, stateDigest: s }) => ({ id, stateDigest: s })) }
      : {}),
  };
}

export interface DigestFacts {
  confirmationId: string;
  organizationPublicId: string;
  userPublicId: string;
  sessionFamilyId: string;
  overrideId: string | null;
  conversationId: string;
  executionId: string;
  tool: string;
  operationId: string;
  risk: ConfirmationRisk;
  requiresReauth: boolean;
  request: Pick<StoredRequest, 'method' | 'path' | 'body'>;
  stateDigest: string | null;
  preconditions: StoredPreconditions;
  expiresAt: Date;
}

/** The `assistant-action/1` digest input (D3). */
export function digestInputOf(facts: DigestFacts): DigestInput {
  return {
    v: ACTION_DIGEST_VERSION,
    confirmationId: facts.confirmationId,
    organizationPublicId: facts.organizationPublicId,
    userPublicId: facts.userPublicId,
    sessionFamilyId: facts.sessionFamilyId,
    overrideId: facts.overrideId,
    conversationId: facts.conversationId,
    executionId: facts.executionId,
    tool: facts.tool,
    operationId: facts.operationId,
    risk: facts.risk,
    requiresReauth: facts.requiresReauth,
    request: digestRequestOf(facts.request),
    preconditions: digestPreconditionsOf(facts.stateDigest, facts.preconditions),
    expiresAt: facts.expiresAt.toISOString(),
  };
}

/** A write tool's risk as a confirmation risk (`critical` and read risks are never confirmable). */
export function confirmationRiskOf(tool: Pick<OperationTool, 'risk'>): ConfirmationRisk | null {
  return tool.risk === 'low' || tool.risk === 'medium' || tool.risk === 'high' ? tool.risk : null;
}
