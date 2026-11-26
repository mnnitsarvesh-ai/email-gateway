import {
  type CanActivate,
  type ExecutionContext,
  HttpException,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { type Counter, MetricsService } from '@email-gateway/common';
import { setContextTenant } from '@email-gateway/logger';
import type { Response } from 'express';
import { isAssistantJobRoute } from '../../../auth-contracts/assistant-job-routes';
import { IS_PUBLIC_KEY } from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { AuthenticatedRequest } from '../../../auth-contracts/request';
import { scopeFromPrincipal } from '../../../auth-contracts/tenant-scope';
import { AccessTokenPrincipalResolver } from '../services/access-token-principal-resolver.service';
import { ApiKeyAuthenticatorService } from '../services/api-key-authenticator.service';
import {
  OverrideRequestAuditor,
  routeTemplate,
} from '../services/override-request-auditor.service';

const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

/** The single credential of a request, or why there is none. */
type Credential = { kind: 'bearer'; token: string } | { kind: 'api_key'; key: string } | null;

function credentialOf(req: AuthenticatedRequest): Credential {
  const authorization = req.headers.authorization;
  const apiKey = req.headers['x-api-key'];
  const hasBearer = authorization !== undefined && authorization !== '';
  const hasApiKey = apiKey !== undefined && apiKey !== '';
  // Exactly one credential (D9): both, or neither, is a 401.
  if (hasBearer === hasApiKey) return null;
  if (hasBearer) {
    const match = BEARER.exec(authorization);
    return match?.[1] ? { kind: 'bearer', token: match[1] } : null;
  }
  return typeof apiKey === 'string' ? { kind: 'api_key', key: apiKey } : null;
}

/**
 * Global authentication (D9). `@Public()` routes pass. Otherwise exactly one credential: a
 * bearer access token (`AccessTokenPrincipalResolver`) or an `X-API-Key`. Sets `req.principal`,
 * `req.tenantScope` and the log context tenant. Every rejection is `401 Unauthorized`; an
 * unavailable key-value store or database is `503` (fail closed).
 *
 * Step AI-6 D5 (ADR-0096, I26): an access token with the claim `ajb` (an assistant report job's
 * token) is accepted only for `GET` on a matched route in `ASSISTANT_JOB_ROUTES`; anything else is
 * `401` (metric `api_assistant_job_token_refusals_total`, a warn log with the route template and
 * the job id only). Rate limits, permissions, tenant scope and override checks run unchanged.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);
  private readonly jobTokenRefusals: Counter;

  constructor(
    private readonly reflector: Reflector,
    private readonly resolver: AccessTokenPrincipalResolver,
    private readonly apiKeys: ApiKeyAuthenticatorService,
    private readonly overrideAuditor: OverrideRequestAuditor,
    metrics: MetricsService,
  ) {
    this.jobTokenRefusals = metrics.counter(
      'api_assistant_job_token_refusals_total',
      'Requests refused because an assistant report job token was used outside GET on the report ' +
        'source routes',
    );
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (context.getType() !== 'http') return false;
    const isPublic = this.reflector.getAllAndOverride<boolean | undefined>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const req = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const credential = credentialOf(req);
    if (!credential) throw new UnauthorizedException();

    let principal: Principal | null;
    try {
      principal =
        credential.kind === 'bearer'
          ? await this.resolver.resolve(credential.token)
          : await this.apiKeys.authenticate(credential.key);
    } catch (err) {
      if (err instanceof HttpException) throw err;
      this.logger.error({ message: 'Authentication dependency unavailable', err });
      throw new ServiceUnavailableException('Service temporarily unavailable');
    }
    if (!principal) throw new UnauthorizedException();
    if (principal.kind === 'user' && principal.assistantJobId !== undefined) {
      const route = routeTemplate(req);
      if (!isAssistantJobRoute(req.method, route)) {
        this.jobTokenRefusals.inc();
        this.logger.warn({
          message: 'Assistant job token refused outside its routes',
          route,
          jobId: principal.assistantJobId,
        });
        throw new UnauthorizedException();
      }
    }

    const scope = scopeFromPrincipal(principal);
    req.principal = principal;
    req.tenantScope = scope;
    setContextTenant(scope.organizationId.toString());
    if (principal.kind === 'user' && principal.override) {
      this.overrideAuditor.attach(req, context.switchToHttp().getResponse<Response>());
    }
    return true;
  }
}
