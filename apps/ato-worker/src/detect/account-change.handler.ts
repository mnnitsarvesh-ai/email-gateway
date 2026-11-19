import { NonRetryableError } from '@email-gateway/common';
import { authAccountChangedV1, type EventEnvelope } from '@email-gateway/event-contracts';
import type { AtoEventResult } from '../metrics/ato-metrics';
import { atoEnabled } from '../reads/org-context';
import { LEDGERS } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';
import { detectLedgered, type DetectDeps } from './context';
import type { DetectionPipeline } from './pipeline';

/** Actions whose subject is the target user (the resource), not the actor (K3 "of the account"). */
const TARGET_USER_ACTIONS = new Set(['user.mfa_reset']);

/**
 * Actions the api audits with the system actor on a session family (`resourceType = 'session'`,
 * `resourceId` = the family id): the change belongs to the family's user. The api records a
 * refresh-token reuse this way (`SessionService.rotate`, actor `system`), so without this K1
 * (refresh token reused) never reached the user's account on real traffic (step 8.4 WP6 fix).
 */
const SESSION_FAMILY_ACTIONS = new Set(['auth.refresh_token_reused']);

/**
 * `auth.account.changed.v1` (D5): the `audit_logs` row is read back on the writer by its partition
 * key `(id, created_at)` and echo-checked (organization, action). The change belongs to the acting
 * user's `gateway_user` account (credentials, persistence, privileges, data access by the account),
 * or for `user.mfa_reset` to the target user, or for a refresh-token reuse (system actor on a
 * session family) to the family's user. Other changes by API keys or the system have no portal
 * account in 8.4 (API keys are not accounts, D1): counted `unattributed`.
 */
export class AccountChangeHandler {
  constructor(
    private readonly deps: DetectDeps,
    private readonly pipeline: DetectionPipeline,
  ) {}

  async handle(event: EventEnvelope<unknown>): Promise<AtoEventResult> {
    const parsed = authAccountChangedV1.safeParse(event.payload);
    if (!parsed.success) throw new NonRetryableError('payload_invalid');
    const p = parsed.data;
    const orgId = BigInt(event.organizationId);
    const org = await this.deps.orgs.get(orgId);
    if (!org.exists || !org.active) return 'skipped_org';
    if (!atoEnabled(org)) return 'skipped_feature';
    const createdAt = new Date(p.auditCreatedAt);
    const row = await this.deps.prisma.auditLog.findUnique({
      where: { id_createdAt: { id: BigInt(p.auditLogId), createdAt } },
      select: { id: true, createdAt: true, organizationId: true, action: true, actorType: true },
    });
    if (!row) return 'skipped_org';
    if (row.organizationId !== orgId || row.action !== p.action) {
      throw new InconsistentReadError('audit_log');
    }
    let userPublicId = TARGET_USER_ACTIONS.has(p.action)
      ? p.resourceType === 'user'
        ? p.resourcePublicId
        : null
      : p.actorType === 'user'
        ? p.actorPublicId
        : null;
    if (
      !userPublicId &&
      SESSION_FAMILY_ACTIONS.has(p.action) &&
      p.resourceType === 'session' &&
      p.resourcePublicId
    ) {
      const session = await this.deps.prisma.userSession.findFirst({
        where: { familyId: p.resourcePublicId, organizationId: orgId },
        select: { organizationId: true, user: { select: { publicId: true } } },
      });
      if (session && session.organizationId !== orgId) {
        throw new InconsistentReadError('user_session');
      }
      userPublicId = session?.user.publicId ?? null;
    }
    if (!userPublicId) return 'unattributed';
    const user = await this.deps.prisma.user.findUnique({
      where: { publicId: userPublicId },
      select: { id: true, organizationId: true, email: true },
    });
    if (!user || user.organizationId !== orgId) return 'unattributed';
    return detectLedgered(
      this.deps,
      {
        consumer: LEDGERS.events,
        eventId: event.eventId,
        source: 'account_change',
        occurredAt: row.createdAt,
      },
      [
        {
          org,
          subject: { kind: 'gateway_user', userId: user.id, address: user.email },
          observation: () => ({
            type: 'account_change',
            key: event.eventId,
            action: p.action,
            occurredAt: row.createdAt,
            auditRef: { id: row.id, createdAt: row.createdAt },
          }),
        },
      ],
    );
  }
}
