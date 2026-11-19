import { createHmac } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import {
  buildAdminConsentUrl,
  createConsentState,
  credentialFingerprint,
  hashConsentState,
  isEmailAddress,
  M365_INBOUND_CONNECTOR_NAME,
  M365_OUTBOUND_CONNECTOR_NAME,
  MICROSOFT_TENANT_ID,
  parseClientSecret,
  parseServiceAccountKey,
  profileByKey,
  ProviderCredentialCipher,
  ProviderCredentialInvalidError,
  sanitizeProviderErrorDescription,
} from '@email-gateway/provider-integrations';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import {
  CompleteConsentBodySchema,
  type ConsentCompletedView,
  CreateGrantBodySchema,
  type CreatedGrantView,
  GoogleCredentialsBodySchema,
  type GrantView,
  M365CredentialsBodySchema,
  type RevokedGrantView,
  SetCredentialsBodySchema,
  VerifyGrantBodySchema,
} from '../dto/provider-connections.schemas';
import { toGrantView } from '../provider-connections.mapper';
import {
  PROVIDER_AUDIT,
  PROVIDER_OPERATIONS,
  PROVIDER_TX_TIMEOUT_MS,
} from '../provider-connections.constants';
import {
  authMethodNotAllowed,
  authMethodUnavailable,
  connectionDisabled,
  connectionNotFound,
  connectionVersionConflict,
  consentStateInvalid,
  credentialInvalid,
  grantExists,
  grantNotFound,
  outboundActive,
  userPrincipalRequired,
} from '../provider-connections.errors';
import {
  type ConnectionAggregate,
  type GrantRow,
  ProviderConnectionsRepository,
} from '../repositories/provider-connections.repository';
import { ProviderGrantsRepository } from '../repositories/provider-grants.repository';
import { parseBody, parseProfileKey, parsePublicId } from './provider-common';
import { ProviderConnectionsService } from './provider-connections.service';

type Tx = Prisma.TransactionClient;

export type ProviderGrantsConfig = Pick<
  ApiConfig,
  | 'PROVIDER_CREDENTIAL_ENCRYPTION_KEY'
  | 'PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS'
  | 'PROVIDER_IMPACT_TOKEN_KEY'
  | 'PROVIDER_M365_LOGIN_URL'
  | 'PROVIDER_GOOGLE_TOKEN_URL'
  | 'PROVIDER_ALLOW_HTTP_ENDPOINTS'
  | 'PROVIDER_M365_MAILFLOW_APP_CLIENT_ID'
  | 'PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID'
  | 'PROVIDER_CONSENT_REDIRECT_URL'
  | 'PROVIDER_CONSENT_STATE_TTL_SECONDS'
  | 'PORTAL_PUBLIC_URL'
  | 'APP_ENV'
>;

/** The provider-side removal steps returned by a revocation (the gateway cannot revoke, I3). */
export function providerRemovalSteps(provider: string, authMethod: string): string[] {
  if (provider === 'microsoft_365') {
    return authMethod === 'platform_app'
      ? [
          'In the Microsoft Entra admin center → Enterprise applications, open the email ' +
            'security gateway application and delete it (this removes its admin consent).',
        ]
      : [
          'In the Microsoft Entra admin center → App registrations, delete the client secret ' +
            'you uploaded (or the whole app registration).',
        ];
  }
  return authMethod === 'platform_service_account'
    ? [
        'In the Google Admin console → Security → Access and data control → API controls → ' +
          'Domain-wide delegation, delete the entry of the gateway service account client id.',
      ]
    : [
        'In the Google Cloud console → IAM & Admin → Service accounts, delete the key you ' +
          'uploaded, and remove the service account from domain-wide delegation.',
      ];
}

/** Steps shown for Google domain-wide delegation (D3.5). */
export function delegationSteps(clientId: string, scopes: readonly string[]): string[] {
  return [
    'Sign in to the Google Admin console as a super administrator.',
    'Open Security → Access and data control → API controls → Manage domain-wide delegation.',
    `Add new: client ID ${clientId}, OAuth scopes ${scopes.join(',')}.`,
    'Choose a delegated administrator (ideally a dedicated admin with a custom read-only role) ' +
      'and confirm with POST …/grants/google.mail_flow/verify { subjectEmail }.',
  ];
}

/** The cleanup steps of a disconnection (D13). */
export function providerCleanupSteps(provider: string): string[] {
  if (provider === 'microsoft_365') {
    return [
      `In the Exchange admin center → Mail flow → Connectors, remove "${M365_OUTBOUND_CONNECTOR_NAME}" ` +
        `and "${M365_INBOUND_CONNECTOR_NAME}" (and the internal-routing connector and transport ` +
        'rules, if you created them) after pointing your MX records back to Microsoft 365.',
      ...providerRemovalSteps(provider, 'platform_app'),
    ];
  }
  return [
    'In the Google Admin console → Apps → Gmail, remove the gateway host, the outbound routing ' +
      'rule and the inbound gateway after pointing your MX records back to Google.',
    ...providerRemovalSteps(provider, 'platform_service_account'),
  ];
}

/**
 * Grants of a connection (step 8.2 §5.2 #8–12; D2, D3, D5; ADR-0076, ADR-0077): creation with the
 * single-use Microsoft admin-consent state (only its SHA-256 is stored) or the Google delegation
 * instructions, consent completion (single use, bound to organization, user and grant),
 * customer credential uploads (encrypted with the dedicated key; the api never decrypts),
 * re-verification and revocation. Every mutation is keyed, transactional and audited; no
 * secret, state or token ever reaches a stored response, a log line or an audit row.
 */
@Injectable()
export class ProviderGrantsService {
  private readonly cipher: ProviderCredentialCipher;

  constructor(
    @Inject(API_CONFIG) private readonly config: ProviderGrantsConfig,
    private readonly connections: ProviderConnectionsRepository,
    private readonly grants: ProviderGrantsRepository,
    private readonly idempotency: IdempotencyService,
    private readonly base: ProviderConnectionsService,
  ) {
    this.cipher = ProviderCredentialCipher.fromConfig(config);
  }

  now(): Date {
    return new Date();
  }

  private consentRedirect(): string {
    return (
      this.config.PROVIDER_CONSENT_REDIRECT_URL ??
      `${this.config.PORTAL_PUBLIC_URL}/integrations/providers/consent-callback`
    );
  }

  /**
   * `http:` in the consent URL: the login origin is already https unless
   * PROVIDER_ALLOW_HTTP_ENDPOINTS (configuration validation), and the redirect target is the
   * portal, which may be plain http only outside staging/production (configuration refuses it
   * there), as the local console is.
   */
  private allowHttpConsentUrl(): boolean {
    const env = this.config.APP_ENV;
    return this.config.PROVIDER_ALLOW_HTTP_ENDPOINTS || (env !== 'staging' && env !== 'production');
  }

  private async lockLive(
    tx: Tx,
    scope: TenantScope,
    publicId: string,
  ): Promise<ConnectionAggregate> {
    const aggregate = await this.connections.lock(tx, scope, publicId);
    if (!aggregate) throw connectionNotFound();
    if (aggregate.connection.status === 'disabled') throw connectionDisabled();
    return aggregate;
  }

  /** Moves a `draft` connection to `connecting` (a grant is in progress). */
  private async markConnecting(tx: Tx, scope: TenantScope, aggregate: ConnectionAggregate) {
    const c = aggregate.connection;
    if (c.status !== 'draft') return;
    if (!(await this.connections.update(tx, scope, c.id, c.rowVersion, { status: 'connecting' }))) {
      throw connectionVersionConflict(c.rowVersion);
    }
  }

  /**
   * `POST /provider-connections/{id}/grants` (#8): keyed; `{ profile, authMethod }` → a
   * `pending_consent` grant. `platform_app`: the admin-consent URL with a fresh single-use state
   * (user principals only), returned ONLY in the live response (the stored response carries
   * `consentUrl: null`, ADR-0057); `platform_service_account`: the delegation instructions;
   * customer methods: the credential upload is next. A revoked grant of the profile is reused.
   */
  async create(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<CreatedGrantView>> {
    const publicId = parsePublicId(input.id, 'id');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(CreateGrantBodySchema, input.body);
    const live: { consentUrl: string | null } = { consentUrl: null };
    const result = await this.idempotency.execute<CreatedGrantView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: PROVIDER_OPERATIONS.grantCreate,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({
          operation: PROVIDER_OPERATIONS.grantCreate,
          resourceId: publicId,
          body,
        }),
      },
      async (tx) => {
        live.consentUrl = null;
        const aggregate = await this.lockLive(tx, scope, publicId);
        const c = aggregate.connection;
        const profile = profileByKey(body.profile);
        if (
          !profile ||
          profile.provider !== c.provider ||
          !profile.authMethods.includes(body.authMethod)
        ) {
          throw authMethodNotAllowed(body.authMethod);
        }
        if (!this.base.availableAuthMethods().has(body.authMethod)) {
          throw authMethodUnavailable(body.authMethod);
        }
        if (body.authMethod === 'platform_app' && principal.kind !== 'user') {
          throw userPrincipalRequired();
        }
        const clientId =
          body.authMethod === 'platform_app'
            ? this.config.PROVIDER_M365_MAILFLOW_APP_CLIENT_ID!
            : body.authMethod === 'platform_service_account'
              ? this.config.PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID!
              : null;
        const existing = await this.grants.lockGrant(tx, scope, c.id, profile.key);
        if (existing && existing.status !== 'revoked') throw grantExists(existing.status);
        const fresh = {
          profileVersion: profile.version,
          authMethod: body.authMethod,
          clientId,
          requestedPermissions: [...profile.permissions],
        };
        const grant = existing
          ? await this.grants.update(tx, scope, existing, {
              ...fresh,
              status: 'pending_consent',
              subjectEmail: null,
              credentialCiphertext: null,
              credentialKeyId: null,
              credentialFingerprint: null,
              credentialSetAt: null,
              credentialExpiresAt: null,
              observedPermissions: null,
              missingPermissions: null,
              excessPermissions: null,
              claimedTenantId: null,
              consentedAt: null,
              consentedByUserId: null,
              verifyRequestedAt: null,
              verifiedAt: null,
              verifyClaimedUntil: null,
              lastErrorCode: null,
              consecutiveFailures: 0,
            })
          : await this.grants.create(tx, scope, {
              publicId: uuidv7(),
              connectionId: c.id,
              profile: profile.key,
              ...fresh,
            });
        if (!grant) throw grantExists('changed');
        await this.markConnecting(tx, scope, aggregate);
        let consent: CreatedGrantView['consent'] = null;
        if (body.authMethod === 'platform_app' && principal.kind === 'user') {
          const state = createConsentState();
          const expiresAt = new Date(
            this.now().getTime() + this.config.PROVIDER_CONSENT_STATE_TTL_SECONDS * 1000,
          );
          await this.grants.closeConsentStates(tx, scope, grant.id, this.now());
          await this.grants.insertConsentState(tx, scope, {
            connectionId: c.id,
            grantId: grant.id,
            userId: principal.userId,
            stateSha256: state.sha256,
            expiresAt,
          });
          live.consentUrl = buildAdminConsentUrl({
            loginUrl: this.config.PROVIDER_M365_LOGIN_URL,
            clientId: clientId!,
            redirectUri: this.consentRedirect(),
            state: state.state,
            allowHttp: this.allowHttpConsentUrl(),
          });
          consent = { consentUrl: null, expiresAt: expiresAt.toISOString() };
        }
        await this.base.record(tx, principal, scope, sourceIp, {
          action: PROVIDER_AUDIT.grantCreated,
          connectionPublicId: c.publicId,
          metadata: {
            grantId: grant.publicId,
            profile: profile.key,
            method: body.authMethod,
            reused: existing !== null,
          },
        });
        return {
          statusCode: 201,
          body: {
            grant: toGrantView(grant),
            next:
              body.authMethod === 'platform_app'
                ? 'consent'
                : body.authMethod === 'platform_service_account'
                  ? 'delegation'
                  : 'credentials',
            consent,
            delegation:
              body.authMethod === 'platform_service_account'
                ? {
                    clientId: clientId!,
                    scopes: [...profile.permissions],
                    adminConsoleSteps: delegationSteps(clientId!, profile.permissions),
                  }
                : null,
          },
        };
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
    if (result.replayed || live.consentUrl === null || result.body.consent === null) return result;
    return {
      ...result,
      body: { ...result.body, consent: { ...result.body.consent, consentUrl: live.consentUrl } },
    };
  }

  /**
   * `POST /provider-connections/consent/complete` (#9, D3.3): keyed; the state is looked up by
   * its SHA-256 for the caller's organization AND user; expired, used or foreign states are `404
   * consent_state_invalid`. Single use (marked used in the same transaction). A declined consent
   * sets the grant `error` (`consent_declined`); an accepted one records the CLAIMED tenant (the
   * worker verifies it before anything trusts it) and sets the grant `verifying`.
   */
  async completeConsent(
    principal: Principal,
    scope: TenantScope,
    input: { idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ConsentCompletedView>> {
    if (principal.kind !== 'user') throw userPrincipalRequired();
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(CompleteConsentBodySchema, input.body);
    const stateSha256 = hashConsentState(body.state);
    const declined = body.error !== undefined || body.adminConsent !== true;
    if (!declined && (body.tenant === undefined || !MICROSOFT_TENANT_ID.test(body.tenant))) {
      throw credentialInvalid('tenant');
    }
    return this.idempotency.execute<ConsentCompletedView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: PROVIDER_OPERATIONS.consentComplete,
        key,
        resourceId: stateSha256.slice(0, 32),
        fingerprint: requestFingerprint({
          operation: PROVIDER_OPERATIONS.consentComplete,
          resourceId: '-',
          body: { ...body, state: stateSha256 },
        }),
      },
      async (tx) => {
        const state = await this.grants.lockConsentState(tx, scope, stateSha256);
        const now = this.now();
        if (
          !state ||
          state.userId !== principal.userId ||
          state.usedAt !== null ||
          state.expiresAt.getTime() <= now.getTime()
        ) {
          throw consentStateInvalid();
        }
        const ref = await this.grants.connectionOf(tx, scope, state.connectionId);
        if (!ref) throw consentStateInvalid();
        const aggregate = await this.lockLive(tx, scope, ref.publicId);
        const grant = await this.grants.lockGrant(
          tx,
          scope,
          aggregate.connection.id,
          (await this.grants.findById(tx, scope, state.grantId))?.profile ?? '',
        );
        if (!grant || grant.id !== state.grantId || grant.status !== 'pending_consent') {
          throw consentStateInvalid();
        }
        if (!(await this.grants.markConsentUsed(tx, scope, state.id, now))) {
          throw consentStateInvalid();
        }
        const updated = declined
          ? await this.grants.update(tx, scope, grant, {
              status: 'error',
              lastErrorCode: 'consent_declined',
            })
          : await this.grants.update(tx, scope, grant, {
              status: 'verifying',
              claimedTenantId: body.tenant!,
              consentedAt: now,
              consentedByUserId: principal.userId,
              verifyRequestedAt: now,
              lastErrorCode: null,
              consecutiveFailures: 0,
            });
        if (!updated) throw consentStateInvalid();
        await this.base.record(tx, principal, scope, sourceIp, {
          action: PROVIDER_AUDIT.grantConsented,
          connectionPublicId: aggregate.connection.publicId,
          metadata: {
            grantId: grant.publicId,
            profile: grant.profile,
            outcome: declined ? 'declined' : 'consented',
            ...(declined && {
              providerError: sanitizeProviderErrorDescription(body.error) ?? null,
              providerErrorDescription: sanitizeProviderErrorDescription(body.errorDescription),
            }),
            ...(!declined && { claimedTenantId: body.tenant }),
          },
        });
        return {
          statusCode: 200,
          body: {
            connectionId: aggregate.connection.publicId,
            grantId: grant.publicId,
            status: updated.status,
          },
        };
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
  }

  /** HMAC of a secret under the impact-token key: request fingerprints never hash a secret raw. */
  private keyed(value: unknown): string {
    return (
      'hmac:' +
      createHmac('sha256', Buffer.from(this.config.PROVIDER_IMPACT_TOKEN_KEY, 'hex'))
        .update(JSON.stringify(value ?? null), 'utf8')
        .digest('hex')
    );
  }

  /**
   * `PUT /provider-connections/{id}/grants/{profile}/credentials` (#10, D5): customer methods
   * only (`422 auth_method_not_allowed`). The credential is validated (`422 credential_invalid`
   * naming the field, never the value), encrypted under PROVIDER_CREDENTIAL_ENCRYPTION_KEY with
   * the row-bound AAD (`credential_version + 1`) and the grant goes `verifying`. Keyed with the
   * redacted replay of ADR-0057: no response carries the credential, and the request fingerprint
   * is computed over an HMAC of the secret, never the secret.
   */
  async setCredentials(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; profile: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<GrantView>> {
    const publicId = parsePublicId(input.id, 'id');
    const profileKey = parseProfileKey(input.profile);
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(SetCredentialsBodySchema, input.body);
    const redacted =
      'clientSecret' in body
        ? { ...body, clientSecret: this.keyed(body.clientSecret) }
        : { ...body, serviceAccountKey: this.keyed(body.serviceAccountKey) };
    return this.idempotency.execute<GrantView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: PROVIDER_OPERATIONS.credentialsSet,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({
          operation: PROVIDER_OPERATIONS.credentialsSet,
          resourceId: `${publicId}:${profileKey}`,
          body: redacted,
        }),
      },
      async (tx) => {
        const aggregate = await this.lockLive(tx, scope, publicId);
        const c = aggregate.connection;
        const grant = await this.grants.lockGrant(tx, scope, c.id, profileKey);
        if (!grant || grant.status === 'revoked') throw grantNotFound();
        const now = this.now();
        const version = grant.credentialVersion + 1;
        const aad = {
          organizationId: scope.organizationId,
          connectionPublicId: c.publicId,
          grantPublicId: grant.publicId,
          credentialVersion: version,
        };
        let write: Parameters<ProviderGrantsRepository['update']>[3];
        try {
          if (grant.authMethod === 'customer_app_secret') {
            const m365 = M365CredentialsBodySchema.safeParse(body);
            if (!m365.success) throw credentialInvalid('body');
            const expiresAt = m365.data.expiresAt ? new Date(m365.data.expiresAt) : null;
            if (expiresAt !== null && expiresAt.getTime() <= now.getTime()) {
              throw credentialInvalid('expiresAt');
            }
            const encrypted = this.cipher.encryptCredential(
              parseClientSecret(m365.data.clientSecret),
              aad,
            );
            write = {
              clientId: m365.data.clientId,
              claimedTenantId: m365.data.tenantId,
              credentialCiphertext: encrypted.ciphertext,
              credentialKeyId: encrypted.keyId,
              credentialFingerprint: credentialFingerprint({
                clientId: m365.data.clientId,
                credentialVersion: version,
              }),
              credentialExpiresAt: expiresAt,
            };
          } else if (grant.authMethod === 'customer_service_account') {
            const google = GoogleCredentialsBodySchema.safeParse(body);
            if (!google.success) throw credentialInvalid('body');
            const subject = google.data.subjectEmail.trim().toLowerCase();
            if (!isEmailAddress(subject)) throw credentialInvalid('subjectEmail');
            const saKey = parseServiceAccountKey(google.data.serviceAccountKey, {
              tokenUrl: this.config.PROVIDER_GOOGLE_TOKEN_URL,
            });
            const encrypted = this.cipher.encryptCredential(
              { method: 'customer_service_account', key: saKey },
              aad,
            );
            write = {
              clientId: saKey.client_id ?? null,
              subjectEmail: subject,
              credentialCiphertext: encrypted.ciphertext,
              credentialKeyId: encrypted.keyId,
              credentialFingerprint: credentialFingerprint({
                clientId: saKey.client_id ?? saKey.client_email,
                privateKeyId: saKey.private_key_id,
                credentialVersion: version,
              }),
              credentialExpiresAt: null,
            };
          } else {
            throw authMethodNotAllowed(grant.authMethod);
          }
        } catch (error) {
          if (error instanceof ProviderCredentialInvalidError) throw credentialInvalid(error.field);
          throw error;
        }
        const updated = await this.grants.update(tx, scope, grant, {
          ...write,
          credentialVersion: version,
          credentialSetAt: now,
          status: 'verifying',
          verifyRequestedAt: now,
          verifiedAt: null,
          lastErrorCode: null,
          consecutiveFailures: 0,
          observedPermissions: null,
          missingPermissions: null,
          excessPermissions: null,
        });
        if (!updated) throw grantExists('changed');
        await this.markConnecting(tx, scope, aggregate);
        await this.base.record(tx, principal, scope, sourceIp, {
          action: PROVIDER_AUDIT.grantCredentialsSet,
          connectionPublicId: c.publicId,
          metadata: {
            grantId: grant.publicId,
            profile: grant.profile,
            method: grant.authMethod,
            credentialVersion: version,
            fingerprint: toGrantView(updated).credentialFingerprint,
            expiresAt: updated.credentialExpiresAt?.toISOString() ?? null,
          },
        });
        return { statusCode: 200, body: toGrantView(updated) };
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
  }

  /**
   * `POST /provider-connections/{id}/grants/{profile}/verify` (#11): keyed; re-verification by the
   * integration-worker (`verifying`). Google platform service account: `subjectEmail` the first
   * time (the delegation is confirmed: audited as `integration.grant_consented`). A customer grant
   * needs its credential, a Microsoft platform grant its consent (`422 credential_invalid`).
   */
  async verify(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; profile: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<GrantView>> {
    const publicId = parsePublicId(input.id, 'id');
    const profileKey = parseProfileKey(input.profile);
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(VerifyGrantBodySchema, input.body);
    return this.idempotency.execute<GrantView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: PROVIDER_OPERATIONS.grantVerify,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({
          operation: PROVIDER_OPERATIONS.grantVerify,
          resourceId: `${publicId}:${profileKey}`,
          body,
        }),
      },
      async (tx) => {
        const aggregate = await this.lockLive(tx, scope, publicId);
        const c = aggregate.connection;
        const grant = await this.grants.lockGrant(tx, scope, c.id, profileKey);
        if (!grant || grant.status === 'revoked') throw grantNotFound();
        let subjectEmail = grant.subjectEmail;
        let delegationConfirmed = false;
        if (body.subjectEmail !== undefined) {
          if (grant.authMethod !== 'platform_service_account') {
            throw authMethodNotAllowed(grant.authMethod);
          }
          const subject = body.subjectEmail.trim().toLowerCase();
          if (!isEmailAddress(subject)) throw credentialInvalid('subjectEmail');
          delegationConfirmed = subjectEmail === null;
          subjectEmail = subject;
        }
        if (grant.authMethod === 'platform_service_account' && subjectEmail === null) {
          throw credentialInvalid('subjectEmail');
        }
        if (
          (grant.authMethod === 'customer_app_secret' ||
            grant.authMethod === 'customer_service_account') &&
          grant.credentialSetAt === null
        ) {
          throw credentialInvalid('credentials');
        }
        if (grant.authMethod === 'platform_app' && grant.claimedTenantId === null) {
          throw credentialInvalid('consent');
        }
        const now = this.now();
        const updated = await this.grants.update(tx, scope, grant, {
          status: 'verifying',
          subjectEmail,
          verifyRequestedAt: now,
          lastErrorCode: null,
          ...(delegationConfirmed && {
            consentedAt: now,
            consentedByUserId: principalUserIdOf(principal),
          }),
        });
        if (!updated) throw grantExists('changed');
        await this.markConnecting(tx, scope, aggregate);
        await this.base.record(tx, principal, scope, sourceIp, {
          action: delegationConfirmed
            ? PROVIDER_AUDIT.grantConsented
            : PROVIDER_AUDIT.grantVerificationRequested,
          connectionPublicId: c.publicId,
          metadata: {
            grantId: grant.publicId,
            profile: grant.profile,
            method: grant.authMethod,
            ...(delegationConfirmed && { outcome: 'delegation_confirmed' }),
          },
        });
        return { statusCode: 200, body: toGrantView(updated) };
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
  }

  /**
   * `DELETE /provider-connections/{id}/grants/{profile}` (#12, D3.6): keyed; refused while
   * outbound is on (`409 outbound_active`). The grant becomes `revoked`, its ciphertext is wiped
   * and open consent states are closed; a connection without a live grant loses its tenant
   * binding (`active_tenant_key` NULL, back to `draft`). Returns the provider-side removal steps
   * (the gateway cannot revoke consent at the provider, I3).
   */
  async revoke(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; profile: unknown; idempotencyKey: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<RevokedGrantView>> {
    const publicId = parsePublicId(input.id, 'id');
    const profileKey = parseProfileKey(input.profile);
    const key = parseIdempotencyKey(input.idempotencyKey);
    return this.idempotency.execute<RevokedGrantView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: PROVIDER_OPERATIONS.grantRevoke,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({
          operation: PROVIDER_OPERATIONS.grantRevoke,
          resourceId: `${publicId}:${profileKey}`,
          body: {},
        }),
      },
      async (tx) => {
        const aggregate = await this.lockLive(tx, scope, publicId);
        const c = aggregate.connection;
        if (c.outboundMode !== 'off') throw outboundActive(c.outboundMode);
        const grant = await this.grants.lockGrant(tx, scope, c.id, profileKey);
        if (!grant || grant.status === 'revoked') throw grantNotFound();
        const now = this.now();
        const updated = await this.grants.update(tx, scope, grant, {
          status: 'revoked',
          credentialCiphertext: null,
          credentialKeyId: null,
          verifyRequestedAt: null,
        });
        if (!updated) throw grantExists('changed');
        await this.grants.closeConsentStates(tx, scope, grant.id, now);
        const liveGrants = aggregate.grants.filter(
          (g) => g.id !== grant.id && g.status !== 'revoked',
        );
        if (liveGrants.length === 0) {
          const ok = await this.connections.update(tx, scope, c.id, c.rowVersion, {
            status: 'draft',
            activeTenantKey: null,
          });
          if (!ok) throw connectionVersionConflict(c.rowVersion);
        }
        await this.base.record(tx, principal, scope, sourceIp, {
          action: PROVIDER_AUDIT.grantRevoked,
          connectionPublicId: c.publicId,
          metadata: {
            grantId: grant.publicId,
            profile: grant.profile,
            method: grant.authMethod,
            fromStatus: grant.status,
            bindingReleased: liveGrants.length === 0,
          },
        });
        return {
          statusCode: 200,
          body: {
            grant: toGrantView(updated),
            providerRemovalSteps: providerRemovalSteps(c.provider, grant.authMethod),
          },
        };
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
  }
}

const principalUserIdOf = (principal: Principal): bigint | null =>
  principal.kind === 'user' ? principal.userId : null;

export type { GrantRow };
