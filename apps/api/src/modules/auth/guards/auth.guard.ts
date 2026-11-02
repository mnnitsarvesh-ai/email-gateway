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
import { TENANT_PERMISSIONS } from '@email-gateway/database';
import { setContextTenant } from '@email-gateway/logger';
import type { Response } from 'express';
import { IS_PUBLIC_KEY } from '../../../auth-contracts/decorators';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { AuthenticatedRequest } from '../../../auth-contracts/request';
import { scopeFromPrincipal } from '../../../auth-contracts/tenant-scope';
import { ApiKeyAuthenticatorService } from '../services/api-key-authenticator.service';
import { OverrideRequestAuditor } from '../services/override-request-auditor.service';
import {
  OVERRIDE_PERMISSION,
  PlatformOverrideService,
} from '../services/platform-override.service';
import { PrincipalLoaderService } from '../services/principal-loader.service';
import { SessionService } from '../services/session.service';
import { TokenService } from '../services/token.service';

const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;
const TENANT = new Set<string>(TENANT_PERMISSIONS);

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
 * bearer access token or an `X-API-Key`. Sets `req.principal`, `req.tenantScope` and the log
 * context tenant. Every rejection is `401 Unauthorized`; an unavailable key-value store or
 * database is `503` (fail closed).
 */
@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly tokens: TokenService,
    private readonly sessions: SessionService,
    private readonly principals: PrincipalLoaderService,
    private readonly overrides: PlatformOverrideService,
    private readonly apiKeys: ApiKeyAuthenticatorService,
    private readonly overrideAuditor: OverrideRequestAuditor,
  ) {}

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
          ? await this.fromAccessToken(credential.token)
          : await this.apiKeys.authenticate(credential.key);
    } catch (err) {
      if (err instanceof HttpException) throw err;
      this.logger.error({ message: 'Authentication dependency unavailable', err });
      throw new ServiceUnavailableException('Service temporarily unavailable');
    }
    if (!principal) throw new UnauthorizedException();

    const scope = scopeFromPrincipal(principal);
    req.principal = principal;
    req.tenantScope = scope;
    setContextTenant(scope.organizationId.toString());
    if (principal.kind === 'user' && principal.override) {
      this.overrideAuditor.attach(req, context.switchToHttp().getResponse<Response>());
    }
    return true;
  }

  /** Bearer path: verify, deny-list, principal snapshot, optional override. Null = 401. */
  private async fromAccessToken(token: string): Promise<UserPrincipal | null> {
    const claims = await this.tokens.verify(token);
    if (!claims) return null;
    if (await this.sessions.isRevoked(claims.sid)) return null;
    const snapshot = await this.principals.load(claims.sub);
    if (!snapshot) return null;
    const { user, org } = snapshot;
    if (org.publicId !== claims.org) return null;
    if (user.status !== 'active' || user.deleted || org.status !== 'active' || org.deleted) {
      return null;
    }

    const principal: UserPrincipal = {
      kind: 'user',
      userId: BigInt(user.id),
      userPublicId: user.publicId,
      organizationId: BigInt(org.id),
      organizationPublicId: org.publicId,
      organizationKind: org.kind,
      sessionId: claims.sid,
      mfaAuthenticated: claims.amr.includes('otp'),
      // Current state, not the token claim: a newly required MFA restricts existing tokens.
      mfaEnrollmentRequired: org.mfaRequired && !user.mfaEnabled,
      permissions: new Set(snapshot.permissions),
    };
    if (claims.ovr === undefined) return principal;

    // Override token: still a platform user holding the override permission, same MFA session.
    if (
      org.kind !== 'platform' ||
      !principal.mfaAuthenticated ||
      !principal.permissions.has(OVERRIDE_PERMISSION)
    ) {
      return null;
    }
    const override = await this.overrides.resolve(claims.ovr, {
      userId: principal.userId,
      sessionId: principal.sessionId,
    });
    // Override tokens can outlive the deny-list entry, so the session itself must be live.
    if (!override || !(await this.sessions.isLive(principal.sessionId))) return null;
    return {
      ...principal,
      mfaEnrollmentRequired: false,
      permissions: new Set([...principal.permissions].filter((p) => TENANT.has(p))),
      override,
    };
  }
}
