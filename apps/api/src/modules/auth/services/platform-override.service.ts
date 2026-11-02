import { randomUUID } from 'node:crypto';
import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { OverrideContext, UserPrincipal } from '../../../auth-contracts/principal';
import type { ApiConfig } from '../../../config';
import { KeyValueStore } from '../../../kv/key-value-store';
import { kvKeys } from '../auth.constants';
import { OrganizationsAuthRepository } from '../repositories/organizations-auth.repository';
import { failClosed } from './kv-fail-closed';
import type { ClientContext } from './session.service';
import { TokenService } from './token.service';

export type PlatformOverrideConfig = Pick<ApiConfig, 'PLATFORM_OVERRIDE_MAX_MINUTES'>;

/** `auth:override:<id>` (D9). Ids are decimal strings. */
export interface OverrideEntry {
  userId: string;
  sessionId: string;
  targetOrganizationId: string;
  targetOrganizationPublicId: string;
  reason: string;
  expiresAt: string;
}

export interface StartOverrideInput {
  organizationId: string;
  reason: string;
  durationMinutes: number;
}

export interface OverrideResponse {
  overrideId: string;
  accessToken: string;
  tokenType: 'Bearer';
  expiresAt: string;
  organization: { id: string; slug: string; name: string };
}

/** The permission that allows starting an override. */
export const OVERRIDE_PERMISSION = 'platform:tenant_override';

function parseEntry(raw: string): OverrideEntry | null {
  try {
    const value = JSON.parse(raw) as Partial<OverrideEntry>;
    const fields = [
      value.userId,
      value.sessionId,
      value.targetOrganizationId,
      value.targetOrganizationPublicId,
      value.reason,
      value.expiresAt,
    ];
    return fields.every((f) => typeof f === 'string') ? (value as OverrideEntry) : null;
  } catch {
    return null;
  }
}

/**
 * Audited platform override into one customer organization (D9, ADR-0016 §6). The override lives
 * in the key-value store with its TTL; its token is an ordinary access token with `ovr` that
 * expires with it and has no refresh token.
 */
@Injectable()
export class PlatformOverrideService {
  private readonly logger = new Logger(PlatformOverrideService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: PlatformOverrideConfig,
    private readonly organizations: OrganizationsAuthRepository,
    private readonly kv: KeyValueStore,
    private readonly tokens: TokenService,
    private readonly audit: AuditService,
  ) {}

  async start(
    principal: UserPrincipal,
    input: StartOverrideInput,
    context: ClientContext,
  ): Promise<OverrideResponse> {
    // The guards enforce the permission and MFA; these are the override's own rules.
    if (principal.organizationKind !== 'platform') {
      throw new ForbiddenException('Only platform users can start an override');
    }
    if (principal.override) throw new ForbiddenException('Already under an override');
    if (!principal.mfaAuthenticated) throw new ForbiddenException('MFA required');
    if (input.durationMinutes > this.config.PLATFORM_OVERRIDE_MAX_MINUTES) {
      throw new BadRequestException([
        `durationMinutes: must be at most ${this.config.PLATFORM_OVERRIDE_MAX_MINUTES}`,
      ]);
    }
    const target = await this.organizations.findByPublicId(input.organizationId);
    if (
      !target ||
      target.kind !== 'customer' ||
      target.deletedAt !== null ||
      target.status === 'deleted'
    ) {
      throw new NotFoundException('Organization not found');
    }

    const overrideId = randomUUID();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + input.durationMinutes * 60_000);
    const entry: OverrideEntry = {
      userId: principal.userId.toString(),
      sessionId: principal.sessionId,
      targetOrganizationId: target.id.toString(),
      targetOrganizationPublicId: target.publicId,
      reason: input.reason,
      expiresAt: expiresAt.toISOString(),
    };
    await this.audit.record({
      organizationId: target.id,
      actor: { type: 'user', id: principal.userPublicId },
      action: 'platform.override_started',
      resourceType: 'organization',
      resourceId: target.publicId,
      sourceIp: context.ip,
      metadata: { overrideId, reason: input.reason, expiresAt },
    });
    await failClosed(this.logger, 'override-start', () =>
      this.kv.set(kvKeys.override(overrideId), JSON.stringify(entry), input.durationMinutes * 60),
    );
    const access = await this.tokens.issue(
      {
        userPublicId: principal.userPublicId,
        organizationPublicId: principal.organizationPublicId,
        sessionId: principal.sessionId,
        amr: ['pwd', 'otp'],
        overrideId,
        expiresAt,
      },
      now,
    );
    return {
      overrideId,
      accessToken: access.token,
      tokenType: 'Bearer',
      expiresAt: expiresAt.toISOString(),
      organization: { id: target.publicId, slug: target.slug, name: target.name },
    };
  }

  /** `DELETE /platform/overrides/{id}`: only the user who started it; `404` otherwise. */
  async end(principal: UserPrincipal, overrideId: string, context: ClientContext): Promise<void> {
    const raw = await failClosed(this.logger, 'override-read', () =>
      this.kv.get(kvKeys.override(overrideId)),
    );
    const entry = raw === null ? null : parseEntry(raw);
    if (!entry || entry.userId !== principal.userId.toString()) {
      throw new NotFoundException('Override not found');
    }
    await failClosed(this.logger, 'override-end', () => this.kv.del(kvKeys.override(overrideId)));
    await this.audit.record({
      organizationId: BigInt(entry.targetOrganizationId),
      actor: { type: 'user', id: principal.userPublicId },
      action: 'platform.override_ended',
      resourceType: 'organization',
      resourceId: entry.targetOrganizationPublicId,
      sourceIp: context.ip,
      metadata: { overrideId, reason: entry.reason },
    });
  }

  /**
   * The override context of an access token's `ovr`, or null when it ended, expired, belongs to
   * another user or session, or its target organization no longer qualifies. KV errors propagate
   * (the guard answers `503`).
   */
  async resolve(
    overrideId: string,
    owner: { userId: bigint; sessionId: string },
  ): Promise<OverrideContext | null> {
    const raw = await this.kv.get(kvKeys.override(overrideId));
    const entry = raw === null ? null : parseEntry(raw);
    if (!entry) return null;
    if (entry.userId !== owner.userId.toString() || entry.sessionId !== owner.sessionId)
      return null;
    const expiresAt = new Date(entry.expiresAt);
    if (!(expiresAt > new Date())) return null;
    const target = await this.organizations.findById(BigInt(entry.targetOrganizationId));
    if (
      !target ||
      target.kind !== 'customer' ||
      target.deletedAt !== null ||
      target.status === 'deleted'
    ) {
      return null;
    }
    return {
      id: overrideId,
      reason: entry.reason,
      targetOrganizationId: target.id,
      targetOrganizationPublicId: target.publicId,
      expiresAt,
    };
  }
}
