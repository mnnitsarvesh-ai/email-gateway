import {
  applyDecorators,
  type CallHandler,
  type ExecutionContext,
  Inject,
  Injectable,
  type NestInterceptor,
  SetMetadata,
  UnauthorizedException,
  UseInterceptors,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ApiExtension } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { from, lastValueFrom, mergeMap, type Observable, of } from 'rxjs';
import { API_CONFIG } from '../../api-config.token';
import { SAFE_METADATA_KEYS, SENSITIVE_METADATA_KEY } from '../../audit/audit.service';
import type { AuthenticatedRequest } from '../../auth-contracts/request';
import { scopeFromPrincipal } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import {
  IDEMPOTENT_KEY,
  RateClass,
  RETURNS_SECRET_KEY,
} from '../../rate-limit/rate-class.decorator';
import { ApiConventionMetrics } from '../api-metrics';
import {
  ApiIdempotencyKey,
  canonicalJson,
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
  IdempotencyInProgressException,
  idempotencyKeyRequired,
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from './idempotency-key';
import { IdempotencyReservationService } from './idempotency-reservation.service';
import type { IdempotentRequest } from './idempotency.service';

export { IDEMPOTENT_KEY } from '../../rate-limit/rate-class.decorator';

export interface IdempotentOptions {
  /** Stable operation name, e.g. `domain.dkim_rotate` (§3.5). */
  operation: string;
  /**
   * A legacy route newly placed on the sensitive list: a missing key is accepted while
   * `API_IDEMPOTENCY_LEGACY_MODE=warn` (deprecation switch), refused under `enforce`.
   */
  legacy?: boolean;
}

/** Where the `Link rel="deprecation"` of a keyless legacy request points (repo-relative doc). */
export const IDEMPOTENCY_DEPRECATION_DOC = '/docs/api/README.md#idempotency';
const OPERATION = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;
const RESOURCE_ID_MAX = 64;

/** True when `value` holds an object key the audit scrub treats as a credential, at any depth. */
export function containsSensitiveKey(value: unknown, seen = new Set<unknown>()): boolean {
  if (value === null || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) return value.some((item) => containsSensitiveKey(item, seen));
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_METADATA_KEY.test(key) && !SAFE_METADATA_KEYS.has(key)) return true;
    if (containsSensitiveKey(item, seen)) return true;
  }
  return false;
}

/**
 * Idempotency-Key reservation for a legacy sensitive mutation (step 6.1 D9, §3.5): metadata for
 * `IdempotencyInterceptor`, the interceptor itself, the documented header, `x-eg-idempotency`
 * (`required` | `legacy`) and the `sensitive` rate class. Refuses (when the class is decorated)
 * to be combined with `@ReturnsSecret()`: a secret-bearing response is never stored.
 */
export function Idempotent(options: IdempotentOptions): MethodDecorator {
  if (!OPERATION.test(options.operation) || options.operation.length > 64) {
    throw new Error(`@Idempotent: invalid operation name ${options.operation}`);
  }
  const frozen = Object.freeze({ operation: options.operation, legacy: options.legacy === true });
  const apply = applyDecorators(
    SetMetadata(IDEMPOTENT_KEY, frozen),
    UseInterceptors(IdempotencyInterceptor),
    ApiIdempotencyKey(),
    ApiExtension('x-eg-idempotency', frozen.legacy ? 'legacy' : 'required'),
    RateClass('sensitive'),
  );
  return (target: object, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    if (Reflect.getMetadata(RETURNS_SECRET_KEY, descriptor.value as object) === true) {
      throw new Error(
        `${String(propertyKey)}: @Idempotent() cannot be combined with @ReturnsSecret() (D9)`,
      );
    }
    apply(target, propertyKey, descriptor);
  };
}

type IdempotencyConfig = Pick<ApiConfig, 'API_IDEMPOTENCY_LEGACY_MODE'>;

/**
 * Runs an `@Idempotent()` route under the reservation flow of D9 (see
 * IdempotencyReservationService): validates the `Idempotency-Key` header (`400
 * idempotency_key_required` / `idempotency_key_invalid`; a keyless legacy route in `warn` mode is
 * processed as before with `Deprecation: true` and a deprecation `Link`), reserves the key, runs
 * the handler, stores its 2xx response (or releases the reservation on an error and rethrows).
 * A replay answers the stored status and body with `Idempotency-Replayed: true`.
 *
 * Fingerprint = requestFingerprint({ operation, resourceId: canonical JSON of the path params,
 * body }); `resource_id` stores the first path parameter's value (or `-`). Organization and
 * principal come from the authenticated principal only.
 */
@Injectable()
export class IdempotencyInterceptor implements NestInterceptor {
  constructor(
    private readonly reflector: Reflector,
    private readonly reservations: IdempotencyReservationService,
    private readonly metrics: ApiConventionMetrics,
    @Inject(API_CONFIG) private readonly config: IdempotencyConfig,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const options = this.reflector.get<IdempotentOptions | undefined>(
      IDEMPOTENT_KEY,
      context.getHandler(),
    );
    if (!options) throw new Error('IdempotencyInterceptor used without @Idempotent()');
    if (this.reflector.get<boolean | undefined>(RETURNS_SECRET_KEY, context.getHandler())) {
      throw new Error('IdempotencyInterceptor refuses a @ReturnsSecret() route (D9)');
    }
    const http = context.switchToHttp();
    const req = http.getRequest<Request & AuthenticatedRequest>();
    const res = http.getResponse<Response>();
    const principal = req.principal;
    if (!principal) throw new UnauthorizedException();

    const raw: unknown = req.headers[IDEMPOTENCY_KEY_HEADER];
    if (raw === undefined || raw === '') {
      if (options.legacy && this.config.API_IDEMPOTENCY_LEGACY_MODE === 'warn') {
        this.metrics.idempotency.inc({ outcome: 'missing_legacy' });
        res.setHeader('Deprecation', 'true');
        res.setHeader('Link', `<${IDEMPOTENCY_DEPRECATION_DOC}>; rel="deprecation"`);
        return next.handle();
      }
      throw idempotencyKeyRequired();
    }
    const key = parseIdempotencyKey(raw);
    const params = (req.params ?? {}) as Record<string, string>;
    const firstParam = Object.values(params)[0];
    const request: IdempotentRequest = {
      organizationId: scopeFromPrincipal(principal).organizationId,
      principal: principalKey(principal),
      operation: options.operation,
      key,
      resourceId:
        typeof firstParam === 'string' && firstParam !== ''
          ? firstParam.slice(0, RESOURCE_ID_MAX)
          : '-',
      fingerprint: requestFingerprint({
        operation: options.operation,
        resourceId: canonicalJson(params),
        body: (req.body as unknown) ?? null,
      }),
    };

    return from(this.reserveCounted(request)).pipe(
      mergeMap((outcome) => {
        if (outcome.kind === 'replay') {
          this.metrics.idempotency.inc({ outcome: 'replayed' });
          res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
          return this.replay(res, outcome.statusCode, outcome.body);
        }
        const { reservation } = outcome;
        return from(
          (async () => {
            let body: unknown;
            try {
              body = await lastValueFrom(next.handle(), { defaultValue: undefined });
            } catch (error) {
              await this.reservations.release(reservation);
              throw error;
            }
            // What goes on the wire: Dates as ISO strings, undefined dropped.
            const wire = body === undefined ? null : (JSON.parse(JSON.stringify(body)) as unknown);
            if (containsSensitiveKey(wire)) {
              await this.reservations.release(reservation);
              // A programming error (a secret-bearing response on an idempotent route): 500,
              // nothing is stored.
              throw new Error(
                `@Idempotent(${options.operation}) refuses to store a response with a credential-like key`,
              );
            }
            await this.reservations.complete(reservation, res.statusCode, wire);
            this.metrics.idempotency.inc({ outcome: 'stored' });
            return body;
          })(),
        );
      }),
    );
  }

  private async reserveCounted(request: IdempotentRequest) {
    try {
      return await this.reservations.reserve(request);
    } catch (error) {
      if (error instanceof IdempotencyInProgressException) {
        this.metrics.idempotency.inc({ outcome: 'in_progress' });
      } else if ((error as { code?: unknown }).code === 'idempotency_key_reused') {
        this.metrics.idempotency.inc({ outcome: 'reused' });
      }
      throw error;
    }
  }

  /**
   * The stored response. When its status is the route's own (the normal case) Nest replies as
   * usual. Otherwise (e.g. the route's status changed since it was stored) the stored status
   * is sent here directly and the response object ignores Nest's later default status.
   */
  private replay(res: Response, statusCode: number, body: unknown): Observable<unknown> {
    if (res.statusCode === statusCode) return of(body);
    res.status(statusCode);
    if (body === null || body === undefined) res.end();
    else res.json(body);
    const sent = res;
    // The reply that follows (status + empty send) must not rewrite the status already sent.
    sent.status = (() => sent) as Response['status'];
    return of(undefined);
  }
}
