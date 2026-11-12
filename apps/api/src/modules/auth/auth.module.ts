import { Module } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { AuthController } from './controllers/auth.controller';
import { MfaController } from './controllers/mfa.controller';
import { PlatformOverrideController } from './controllers/platform-override.controller';
import { SessionsController } from './controllers/sessions.controller';
import { AuthGuard } from './guards/auth.guard';
import { PermissionsGuard } from './guards/permissions.guard';
import { OverrideAuditInterceptor } from './interceptors/override-audit.interceptor';
import { ApiKeysAuthRepository } from './repositories/api-keys-auth.repository';
import { BootstrapRepository } from './repositories/bootstrap.repository';
import { LoginAuditRepository } from './repositories/login-audit.repository';
import { OrganizationsAuthRepository } from './repositories/organizations-auth.repository';
import { RecoveryCodesRepository } from './repositories/recovery-codes.repository';
import { SessionsRepository } from './repositories/sessions.repository';
import { UserTokensRepository } from './repositories/user-tokens.repository';
import { UsersAuthRepository } from './repositories/users-auth.repository';
import { ApiKeyAuthenticatorService } from './services/api-key-authenticator.service';
import { AuthenticationService } from './services/authentication.service';
import { BootstrapAdminService } from './services/bootstrap-admin.service';
import { EmailVerificationService } from './services/email-verification.service';
import { InvitationService } from './services/invitation.service';
import { LoginAuditService } from './services/login-audit.service';
import { LoginThrottleService } from './services/login-throttle.service';
import { MfaService } from './services/mfa.service';
import { OverrideRequestAuditor } from './services/override-request-auditor.service';
import { PasswordService } from './services/password.service';
import { PlatformOverrideService } from './services/platform-override.service';
import { PrincipalCacheService } from './services/principal-cache.service';
import { PrincipalLoaderService } from './services/principal-loader.service';
import { ReauthenticationService } from './services/reauthentication.service';
import { SessionPurgeService } from './services/session-purge.service';
import { SessionService } from './services/session.service';
import { TokenService } from './services/token.service';
import { UserTokenService } from './services/user-token.service';

/**
 * Authentication, sessions, MFA, password/email self-service, invitation acceptance, API-key
 * authentication, the platform override and the global guards (design §5, WP3). Relies on the
 * global ApiCommonModule building blocks and API_CONFIG.
 */
@Module({
  controllers: [AuthController, MfaController, SessionsController, PlatformOverrideController],
  providers: [
    // Repositories (the only Prisma users of this module).
    UsersAuthRepository,
    SessionsRepository,
    UserTokensRepository,
    RecoveryCodesRepository,
    LoginAuditRepository,
    ApiKeysAuthRepository,
    OrganizationsAuthRepository,
    BootstrapRepository,
    // Services.
    TokenService,
    LoginThrottleService,
    LoginAuditService,
    SessionService,
    UserTokenService,
    MfaService,
    AuthenticationService,
    PasswordService,
    EmailVerificationService,
    InvitationService,
    PrincipalCacheService,
    PrincipalLoaderService,
    ApiKeyAuthenticatorService,
    PlatformOverrideService,
    OverrideRequestAuditor,
    SessionPurgeService,
    BootstrapAdminService,
    ReauthenticationService,
    // Global guards in this order (D9), then the override audit interceptor.
    { provide: APP_GUARD, useClass: AuthGuard },
    { provide: APP_GUARD, useClass: PermissionsGuard },
    { provide: APP_INTERCEPTOR, useClass: OverrideAuditInterceptor },
  ],
  exports: [
    SessionService,
    InvitationService,
    EmailVerificationService,
    PrincipalCacheService,
    LoginThrottleService,
    ReauthenticationService,
  ],
})
export class AuthModule {}
