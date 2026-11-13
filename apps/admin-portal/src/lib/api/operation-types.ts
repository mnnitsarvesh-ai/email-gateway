/** Shapes of the generated operation table (`operations.gen.ts`, design P7). */

export type HttpMethod = 'GET' | 'PUT' | 'POST' | 'DELETE' | 'PATCH';

/** One `x-eg-permissions` requirement: `all` needs every permission, `any` at least one. */
export interface PermissionRequirement {
  readonly mode: 'all' | 'any';
  readonly permissions: readonly string[];
}

export interface OperationMeta {
  readonly operationId: string;
  readonly method: HttpMethod;
  /** Full template path, e.g. `/api/v1/domains/{id}`. */
  readonly path: string;
  readonly tag: string | null;
  /** `null` = authenticated only (or public); otherwise every requirement must hold. */
  readonly permissions: readonly PermissionRequirement[] | null;
  /** No security requirement: sent without Authorization. */
  readonly public: boolean;
  readonly idempotency: 'required' | 'legacy' | null;
  readonly cursor: 'v0' | 'v1' | null;
  readonly rateClass: string | null;
  readonly returnsSecret: boolean;
  readonly secretReplay: string | null;
  /** Collection key of the 200 response (`items` for the 5.3 quarantine lists). */
  readonly listKey: 'data' | 'items' | null;
  /** Allowed `sort` values, `null` when the operation takes no `sort`. */
  readonly sort: readonly string[] | null;
  /** Token-bearing operation: only the BFF session routes may call it (P5). */
  readonly bffOnly: boolean;
}

export type RouteSegment = string | { readonly param: string };

export interface RouteMatcher<Id extends string = string> {
  readonly method: HttpMethod;
  /** Path segments after `/api/v1/`. */
  readonly segments: readonly RouteSegment[];
  readonly operationId: Id;
}
