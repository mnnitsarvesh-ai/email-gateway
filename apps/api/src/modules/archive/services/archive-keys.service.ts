import { Injectable } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import {
  decodeListCursor,
  encodeListCursor,
  intKey,
  listBinding,
} from '../../messages/domain/v1-list';
import {
  ARCHIVE_AUDIT,
  ARCHIVE_CURSOR_RESOURCES,
  ARCHIVE_OPERATIONS,
  ARCHIVE_RESOURCE,
  ARCHIVE_TX_TIMEOUT_MS,
} from '../archive.constants';
import { keyView } from '../domain/archive-views';
import type {
  ArchiveKeyListQuery,
  ArchiveKeyPage,
  RotatedKeyView,
  RotateKeyBody,
} from '../dto/archive.schemas';
import { ArchiveConfigRepository } from '../repositories/archive-config.repository';
import { userIdOf } from './archive-common';
import { ArchiveContentService } from './archive-content.service';

const MAX_KEY_VERSION = 0xffff_ffff;

/**
 * Tenant key versions (step 8.1 §4.4 #8, #9; A9, ADR-0065): the metadata list (never key
 * material) and the audited rotation. Rotation runs under the organization and
 * `archive_settings` row locks (the capture path reads the active version): a new version
 * (max + 1) wrapped under the current root key becomes `active`, every previous active version
 * becomes `retired` (decrypt-only). Existing records keep their version (no DEK re-wrap in 8.1).
 */
@Injectable()
export class ArchiveKeysService {
  constructor(
    private readonly configs: ArchiveConfigRepository,
    private readonly content: ArchiveContentService,
    private readonly limits: OrganizationLimitsService,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    query: ArchiveKeyListQuery,
  ): Promise<ArchiveKeyPage> {
    const binding = listBinding({
      resource: ARCHIVE_CURSOR_RESOURCES.keys,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const beforeVersion = decoded ? intKey(decoded.keys[0], MAX_KEY_VERSION) : undefined;
    const rows = await this.configs.listKeys(scope, { take: query.limit + 1, beforeVersion });
    const decision = decideKeysetPage({
      fetched: rows,
      limit: query.limit,
      keyOf: (r) => r.version,
    });
    return {
      data: rows.slice(0, decision.rows).map(keyView),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [String(decision.next)]),
    };
  }

  /** `POST /archive/keys/rotate` (#9): `201` with the new active version. */
  async rotate(
    principal: Principal,
    scope: TenantScope,
    idempotencyKey: unknown,
    body: RotateKeyBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<RotatedKeyView>> {
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = ARCHIVE_OPERATIONS.keyRotate;
    return this.idempotency.execute<RotatedKeyView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: '-',
        fingerprint: requestFingerprint({ operation, resourceId: '-', body }),
      },
      async (tx) => {
        await this.limits.lockOrganization(tx, scope.organizationId);
        await this.configs.lockSettings(tx, scope);
        const keys = await this.configs.keysOnWriter(tx, scope);
        const from = keys.find((k) => k.status === 'active')?.version ?? null;
        const version = (keys[0]?.version ?? 0) + 1;
        const now = this.now();
        const wrapped = await this.content.newTenantKey(scope.organizationId, version);
        await this.configs.retireKeys(tx, scope, now);
        const row = await this.configs.insertKey(tx, scope, {
          publicId: uuidv7(now.getTime()),
          version,
          wrappedKey: wrapped.wrappedKey,
          rootKeyId: wrapped.rootKeyId,
          algorithm: wrapped.algorithm,
          rotationReason: body.reason,
          createdByUserId: userIdOf(principal),
          now,
        });
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: ARCHIVE_AUDIT.keyRotated,
            resourceType: ARCHIVE_RESOURCE.key,
            resourceId: row.publicId,
            sourceIp,
            metadata: {
              fromVersion: from,
              toVersion: version,
              reason: body.reason,
              rootKeyId: wrapped.rootKeyId,
            },
          },
          tx,
        );
        return { statusCode: 201, body: { key: keyView(row), previousVersion: from } };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }
}
