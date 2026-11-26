import { Injectable } from '@nestjs/common';
import { TENANT_PERMISSIONS } from '@email-gateway/database';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { OVERRIDE_PERMISSION, PlatformOverrideService } from './platform-override.service';
import { PrincipalLoaderService } from './principal-loader.service';
import { SessionService } from './session.service';
import { TokenService } from './token.service';

const TENANT = new Set<string>(TENANT_PERMISSIONS);

/**
 * The bearer path of authentication (D9), shared by the `AuthGuard` and the assistant's report
 * job consumer (step AI-6 D5, ADR-0096: the job's principal is resolved exactly as a request with
 * its token would be): verify the access token, the session deny-list, the principal snapshot,
 * the home organization match, active user and organization, and an optional platform override
 * (platform user, MFA session, the override permission, a live session; permissions intersected
 * with the tenant permissions). A token with the claim `ajb` needs a live session family too and
 * yields `assistantJobId` (the guard restricts such tokens to `ASSISTANT_JOB_ROUTES`). Null = 401. Dependency failures propagate
 * (the guard answers 503).
 */
@Injectable()
export class AccessTokenPrincipalResolver {
  constructor(
    private readonly tokens: TokenService,
    private readonly sessions: SessionService,
    private readonly principals: PrincipalLoaderService,
    private readonly overrides: PlatformOverrideService,
  ) {}

  async resolve(token: string, now?: Date): Promise<UserPrincipal | null> {
    const claims = await this.tokens.verify(token, now);
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
      ...(claims.ajb !== undefined && { assistantJobId: claims.ajb }),
    };
    // A report job token (step AI-6 D5) acts only while its session family is live (not expired,
    // not revoked in the database), not merely absent from the deny-list.
    if (claims.ajb !== undefined && !(await this.sessions.isLive(principal.sessionId))) return null;
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
