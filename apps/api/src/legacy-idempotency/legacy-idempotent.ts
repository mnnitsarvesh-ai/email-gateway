import {
  applyDecorators,
  type CallHandler,
  type ExecutionContext,
  type NestInterceptor,
  UseInterceptors,
} from '@nestjs/common';
import { map, type Observable } from 'rxjs';
import { SAFE_METADATA_KEYS, SENSITIVE_METADATA_KEY } from '../audit/audit.service';
import { Idempotent, type IdempotentOptions } from '../http/idempotency/idempotency.interceptor';

/**
 * `@Idempotent()` for the few legacy sensitive mutations (step 6.1 §3.5, WP4) whose unchanged
 * response DTO carries a non-credential field whose name matches the audit credential pattern
 * (`SENSITIVE_METADATA_KEY`: `…key`, `…code`, …): the DKIM rotation (`key`, `dnsRecord.key`),
 * the organization status change (`plan.code`), the user invitation (`roles[].key`) and the
 * policy version publish/activate (`validation.violations[].code`). The `IdempotencyInterceptor`
 * refuses (500, by design, D9) to store any body with such a key, so these routes could not be
 * decorated with `@Idempotent()` alone without changing their responses.
 *
 * The route names the verified non-credential field names (`publicFields`). An inner
 * interceptor (closest to the handler) re-runs the credential-key scan with only those names
 * exempted (anything else matching still fails closed with a 500, nothing stored) and hands the
 * interceptor an opaque envelope `{ legacyResponseJson: "<the JSON body>" }`; an outer
 * interceptor unwraps it on the way out, for the first response, for a replay and for a keyless
 * `warn`-mode request alike. The client always sees the unchanged DTO; the stored row holds the
 * envelope. Everything else (key validation, reservation, replay, 422 on reuse, the `sensitive`
 * class, OpenAPI `x-eg-idempotency`) is the unchanged `@Idempotent()`.
 *
 * Caveat (documented): a replay whose stored status differs from the route's current status is
 * written by `IdempotencyInterceptor` itself and would bypass the unwrap; the routes using this
 * decorator have one fixed 2xx status each.
 *
 * Replaces itself once `@Idempotent()` accepts a per-route allow-list of public field names
 * (requested from the owner of `http/idempotency`).
 */
export interface LegacyIdempotentOptions extends IdempotentOptions {
  /** Response field names verified to be non-credentials although they match the pattern. */
  publicFields: readonly string[];
}

/** The envelope field; its name does not match the credential pattern. */
export const LEGACY_RESPONSE_ENVELOPE = 'legacyResponseJson';

/** Names that may never be exempted, whatever the route says. */
const NEVER_PUBLIC = /password|secret|token/i;

/** Object keys of `value` (at any depth) that look like credentials and are not exempted. */
export function credentialLikeKeys(
  value: unknown,
  publicFields: ReadonlySet<string>,
  path = '',
  seen = new Set<unknown>(),
): string[] {
  if (value === null || typeof value !== 'object' || seen.has(value)) return [];
  seen.add(value);
  if (Array.isArray(value)) {
    return value.flatMap((item) => credentialLikeKeys(item, publicFields, `${path}[]`, seen));
  }
  const found: string[] = [];
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const at = path ? `${path}.${key}` : key;
    if (
      SENSITIVE_METADATA_KEY.test(key) &&
      !SAFE_METADATA_KEYS.has(key) &&
      !publicFields.has(key)
    ) {
      found.push(at);
    }
    found.push(...credentialLikeKeys(item, publicFields, at, seen));
  }
  return found;
}

const isEnvelope = (body: unknown): body is Record<typeof LEGACY_RESPONSE_ENVELOPE, string> =>
  body !== null &&
  typeof body === 'object' &&
  !Array.isArray(body) &&
  Object.keys(body).length === 1 &&
  typeof (body as Record<string, unknown>)[LEGACY_RESPONSE_ENVELOPE] === 'string';

/** Inner: the handler's body → envelope (after the scan with the route's exemptions). */
export class LegacyResponseWrapInterceptor implements NestInterceptor {
  private readonly publicFields: ReadonlySet<string>;

  constructor(
    private readonly operation: string,
    publicFields: readonly string[],
  ) {
    this.publicFields = new Set(publicFields);
  }

  intercept(_context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next.handle().pipe(
      map((body: unknown) => {
        if (body === undefined || body === null) return body;
        const json = JSON.stringify(body);
        const offending = credentialLikeKeys(JSON.parse(json) as unknown, this.publicFields);
        if (offending.length > 0) {
          // A programming error (a new credential-like field): 500, nothing is stored.
          throw new Error(
            `@LegacyIdempotent(${this.operation}) refuses to store a response with credential-like keys`,
          );
        }
        return { [LEGACY_RESPONSE_ENVELOPE]: json };
      }),
    );
  }
}

/** Outer: envelope (first response or replay) → the unchanged response body. */
export class LegacyResponseUnwrapInterceptor implements NestInterceptor {
  intercept(_context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next
      .handle()
      .pipe(
        map((body: unknown) =>
          isEnvelope(body) ? (JSON.parse(body[LEGACY_RESPONSE_ENVELOPE]) as unknown) : body,
        ),
      );
  }
}

/** See the file comment. Interceptor order: unwrap → IdempotencyInterceptor → wrap → handler. */
export function LegacyIdempotent(options: LegacyIdempotentOptions): MethodDecorator {
  if (options.publicFields.length === 0) {
    throw new Error(`@LegacyIdempotent(${options.operation}): use @Idempotent() instead`);
  }
  for (const field of options.publicFields) {
    if (!SENSITIVE_METADATA_KEY.test(field) || NEVER_PUBLIC.test(field)) {
      throw new Error(`@LegacyIdempotent(${options.operation}): ${field} cannot be exempted`);
    }
  }
  return applyDecorators(
    UseInterceptors(new LegacyResponseUnwrapInterceptor()),
    Idempotent({ operation: options.operation, legacy: options.legacy }),
    UseInterceptors(new LegacyResponseWrapInterceptor(options.operation, options.publicFields)),
  );
}
