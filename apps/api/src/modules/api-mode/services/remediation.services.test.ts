import { randomBytes, randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
import { canonicalPolicySha256, DEFAULT_REMEDIATION_POLICY } from '@email-gateway/mailbox-api';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ApiModeWorld,
  type StoredConnection,
  type StoredCopy,
} from '../../../../test/support/api-mode-fixtures';
import { QuarantineWorld } from '../../../../test/support/in-memory-quarantine';
import type { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import { IdempotencyService } from '../../../http/idempotency/idempotency.service';
import { AuditedRefusal, hardBlockReleaseDisabled } from '../../quarantine/quarantine.errors';
import type { QuarantineReleaseService } from '../../quarantine/services/quarantine-release.service';
import type { QuarantineWriter } from '../../quarantine/services/quarantine-writer';
import { RemediationListQuerySchema } from '../dto/api-mode-remediation.schemas';
import type { ApiRemediationRepository } from '../repositories/api-remediation.repository';
import type { RemediationActionWriter } from '../repositories/remediation-action-writer';
import { RemediationActionsService } from './remediation-actions.service';
import { RemediationPolicyService, validatePolicyDocument } from './remediation-policy.service';

const ORG = 1n;
const OTHER = 2n;
const scope = systemScope(ORG);
const client = { ip: '203.0.113.9', userAgent: null };
const REASON = 'Tighten the policy for the pilot';

function user(permissions: string[] = ['remediation:read', 'remediation:write']): UserPrincipal {
  return {
    kind: 'user',
    userId: 10n,
    userPublicId: '0190a5b2-7c3d-7e4f-8a1b-00000000000a',
    organizationId: ORG,
    organizationPublicId: '0190a5b2-7c3d-7e4f-8a1b-0000000000aa',
    organizationKind: 'customer',
    sessionId: 's',
    mfaAuthenticated: true,
    mfaEnrollmentRequired: false,
    permissions: new Set(permissions),
  };
}

const P1 = structuredClone(DEFAULT_REMEDIATION_POLICY.document);

async function failure(
  promise: Promise<unknown>,
): Promise<{ status: number; code?: string; details?: unknown; message?: unknown }> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof CodedHttpException) {
      return { status: error.getStatus(), code: error.code, details: error.details };
    }
    if (error instanceof HttpException) {
      return { status: error.getStatus(), message: error.getResponse() };
    }
    throw error;
  }
  throw new Error('expected a failure');
}

function setup(hardDeleteEnabled = false) {
  const world = new ApiModeWorld();
  const q = new QuarantineWorld();
  const runner = { run: vi.fn((fn: (tx: unknown) => Promise<unknown>) => fn({})) };
  const idempotency = new IdempotencyService(
    runner as unknown as TransactionRunner,
    q.idempotencyRepository(),
  );
  const audit = q.auditService() as unknown as AuditService;
  const repository = world.remediationDouble() as unknown as ApiRemediationRepository;
  const writer = world.actionWriterDouble() as unknown as RemediationActionWriter;
  const policies = new RemediationPolicyService(
    { API_MODE_HARD_DELETE_ENABLED: hardDeleteEnabled },
    repository,
    idempotency,
    audit,
  );
  const release = { releaseInTx: vi.fn() };
  const quarantineWriter = { recordRefusal: vi.fn(() => Promise.resolve()) };
  const codec = new CursorCodec({
    API_CURSOR_KEY: randomBytes(32).toString('hex'),
    API_CURSOR_KEY_PREVIOUS: undefined,
    API_CURSOR_TTL_SECONDS: 86_400,
  });
  const actions = new RemediationActionsService(
    repository,
    writer,
    idempotency,
    audit,
    codec,
    release as unknown as QuarantineReleaseService,
    quarantineWriter as unknown as QuarantineWriter,
  );
  world.addOrganization(ORG, randomUUID());
  world.addOrganization(OTHER, randomUUID());
  const conn: StoredConnection = world.addConnection(ORG, {
    grant: {
      profile: 'm365.mailbox_remediation',
      status: 'active',
      authMethod: 'platform_app',
      clientId: null,
      subjectEmail: null,
    },
  });
  const domain = world.addDomain(ORG, 'contoso.example', { connectionId: conn.id });
  const foreignDomain = world.addDomain(OTHER, 'other.example');
  const mailbox = world.addMailbox(conn, 'alex@contoso.example');
  const foreignConn = world.addConnection(OTHER);
  const foreignMailbox = world.addMailbox(foreignConn, 'eve@other.example');
  return {
    world,
    q,
    policies,
    actions,
    release,
    quarantineWriter,
    conn,
    domain,
    foreignDomain,
    mailbox,
    foreignMailbox,
  };
}

let t: ReturnType<typeof setup>;
beforeEach(() => {
  t = setup();
});

const putBody = (patch: Record<string, unknown> = {}) => ({
  mode: 'enforce',
  document: P1,
  reason: REASON,
  expectedRowVersion: null,
  ...patch,
});

describe('validatePolicyDocument (R2.1, R-I2)', () => {
  it('accepts P1 and reports invalid documents with document paths', () => {
    expect(validatePolicyDocument(P1, false)).toEqual(P1);
    const bad = { v: 1, rules: [{ id: 'X Y', when: { verdicts: ['clean'] }, action: 'tag' }] };
    const error = (() => {
      try {
        validatePolicyDocument(bad, false);
      } catch (e) {
        return e as HttpException;
      }
      return null;
    })();
    expect(error?.getStatus()).toBe(400);
    const messages = (error?.getResponse() as { message: string[] }).message;
    expect(messages.some((m) => m.startsWith('document.rules.0.id'))).toBe(true);
    expect(messages.some((m) => m.startsWith('document.rules.0.when.verdicts'))).toBe(true);
  });

  it('refuses unknown keys and the reserved policyDispositions', () => {
    expect(() => validatePolicyDocument({ ...P1, extra: true }, false)).toThrow(HttpException);
    expect(() =>
      validatePolicyDocument(
        {
          v: 1,
          rules: [
            { id: 'r', when: { verdicts: ['spam'], policyDispositions: ['x'] }, action: 'tag' },
          ],
        },
        false,
      ),
    ).toThrow(HttpException);
  });

  it('a hard_delete rule needs the platform setting (422 with the rule ids)', () => {
    const doc = {
      v: 1,
      rules: [{ id: 'nuke', when: { verdicts: ['malware'] }, action: 'hard_delete' }],
    };
    try {
      validatePolicyDocument(doc, false);
      throw new Error('expected a refusal');
    } catch (error) {
      expect(error).toBeInstanceOf(CodedHttpException);
      expect((error as CodedHttpException).code).toBe('api_mode_hard_delete_disabled');
      expect((error as CodedHttpException).getStatus()).toBe(422);
      expect((error as CodedHttpException).details).toEqual({ ruleIds: 'nuke' });
    }
    expect(validatePolicyDocument(doc, true).rules[0]!.action).toBe('hard_delete');
  });
});

describe('RemediationPolicyService (R13 #1-#4)', () => {
  it('GET without rows: the platform default P1, presets, hard delete unavailable', async () => {
    const view = await t.policies.get(scope);
    expect(view.organization).toMatchObject({
      source: 'platform_default',
      id: null,
      mode: 'enforce',
      rowVersion: null,
      sha256: canonicalPolicySha256(DEFAULT_REMEDIATION_POLICY.document),
    });
    expect(view.organization.document.rules.map((r) => r.id)).toEqual([
      'p1-high-confidence-malware-phishing-hb',
      'p1-high-confidence-malware-phishing',
      'p1-other-malware-phishing',
      'p1-suspicious',
    ]);
    expect(view.presets.detectOnlyStart.mode).toBe('detect_only');
    expect(view.presets.strict.document.rules.at(-1)).toMatchObject({ action: 'move_junk' });
    expect(view.hardDeleteAvailable).toBe(false);
    expect(view.domains).toEqual([]);
  });

  it('PUT creates with expectedRowVersion null, then CAS; audit from/to with hashes', async () => {
    const created = await t.policies.putOrganization(
      user(),
      scope,
      { idempotencyKey: 'k1', body: putBody({ mode: 'detect_only' }) },
      client.ip,
    );
    expect(created.body).toMatchObject({
      scope: 'organization',
      domainId: null,
      mode: 'detect_only',
      rowVersion: 1,
      created: true,
      sha256: canonicalPolicySha256(P1),
    });
    expect(t.q.audits.at(-1)).toMatchObject({
      action: 'api_mode.remediation_policy_updated',
      resourceType: 'api_remediation_policy',
      metadata: {
        scope: 'organization',
        from: null,
        to: { mode: 'detect_only', sha256: canonicalPolicySha256(P1) },
        reason: REASON,
      },
    });
    // A second create, or a stale version, is a CAS conflict with the current version.
    expect(
      await failure(
        t.policies.putOrganization(user(), scope, { idempotencyKey: 'k2', body: putBody() }, null),
      ),
    ).toMatchObject({
      status: 409,
      code: 'api_mode_remediation_policy_conflict',
      details: { currentRowVersion: 1 },
    });
    const updated = await t.policies.putOrganization(
      user(),
      scope,
      { idempotencyKey: 'k3', body: putBody({ expectedRowVersion: 1 }) },
      null,
    );
    expect(updated.body).toMatchObject({ mode: 'enforce', rowVersion: 2, created: false });
    expect(t.q.audits.at(-1)!.metadata).toMatchObject({
      from: { mode: 'detect_only' },
      to: { mode: 'enforce' },
    });
    const view = await t.policies.get(scope);
    expect(view.organization).toMatchObject({ source: 'organization', rowVersion: 2 });
    // Replay of the first key returns the stored response, no new row or audit.
    const audits = t.q.audits.length;
    const replay = await t.policies.putOrganization(
      user(),
      scope,
      { idempotencyKey: 'k1', body: putBody({ mode: 'detect_only' }) },
      null,
    );
    expect(replay).toMatchObject({ replayed: true, body: created.body });
    expect(t.q.audits).toHaveLength(audits);
  });

  it('PUT for a domain: own domains only (404 otherwise), listed with its name; DELETE back to inherit', async () => {
    expect(
      await failure(
        t.policies.putDomain(
          user(),
          scope,
          { domainId: t.foreignDomain.publicId, idempotencyKey: 'd0', body: putBody() },
          null,
        ),
      ),
    ).toMatchObject({ status: 404, code: 'domain_not_found' });
    const res = await t.policies.putDomain(
      user(),
      scope,
      { domainId: t.domain.publicId, idempotencyKey: 'd1', body: putBody() },
      null,
    );
    expect(res.body).toMatchObject({ scope: 'domain', domainId: t.domain.publicId, rowVersion: 1 });
    const view = await t.policies.get(scope);
    expect(view.domains).toEqual([
      expect.objectContaining({ domainId: t.domain.publicId, domainName: 'contoso.example' }),
    ]);
    expect(view.organization.source).toBe('platform_default');
    const removed = await t.policies.deleteDomain(
      user(),
      scope,
      { domainId: t.domain.publicId, idempotencyKey: 'd2' },
      null,
    );
    expect(removed).toMatchObject({ statusCode: 204, body: { deleted: true } });
    expect(t.q.audits.at(-1)!.metadata).toMatchObject({ scope: 'domain', to: null });
    expect((await t.policies.get(scope)).domains).toEqual([]);
    // No override: 204 without an audit row.
    const audits = t.q.audits.length;
    const again = await t.policies.deleteDomain(
      user(),
      scope,
      { domainId: t.domain.publicId, idempotencyKey: 'd3' },
      null,
    );
    expect(again.body.deleted).toBe(false);
    expect(t.q.audits).toHaveLength(audits);
  });

  it('hard delete: refused while the platform setting is off, accepted when on', async () => {
    const doc = {
      v: 1,
      rules: [{ id: 'nuke', when: { verdicts: ['malware'] }, action: 'hard_delete' }],
    };
    expect(
      await failure(
        t.policies.putOrganization(
          user(),
          scope,
          { idempotencyKey: 'h1', body: putBody({ document: doc }) },
          null,
        ),
      ),
    ).toMatchObject({ status: 422, code: 'api_mode_hard_delete_disabled' });
    expect(t.world.policies).toHaveLength(0);
    const on = setup(true);
    const res = await on.policies.putOrganization(
      user(),
      scope,
      { idempotencyKey: 'h2', body: putBody({ document: doc }) },
      null,
    );
    expect(res.body.document.rules[0]!.action).toBe('hard_delete');
    expect((await on.policies.get(scope)).hardDeleteAvailable).toBe(true);
  });

  it('validation before any write: strict body, reason bounds, the Idempotency-Key first', async () => {
    expect(
      (
        await failure(
          t.policies.putOrganization(
            user(),
            scope,
            { idempotencyKey: undefined, body: putBody() },
            null,
          ),
        )
      ).status,
    ).toBe(400);
    for (const body of [
      putBody({ extra: 1 }),
      putBody({ reason: '   ' }),
      putBody({ mode: 'off' }),
      { mode: 'enforce', document: P1, reason: REASON },
    ]) {
      expect(
        (
          await failure(
            t.policies.putOrganization(user(), scope, { idempotencyKey: 'v', body }, null),
          )
        ).status,
      ).toBe(400);
    }
    expect(t.world.policies).toHaveLength(0);
  });
});

describe('RemediationPolicyService: policyMapping and the detect-only period (step API-4 A4.2, B7)', () => {
  const inDays = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

  it('accepts policyMapping (hard_delete refused) and shows the effective mapping', async () => {
    const doc = { ...P1, policyMapping: { reject: 'tag', allow_tagged: 'none' } };
    const out = await t.policies.putOrganization(
      user(),
      scope,
      { idempotencyKey: 'pm1', body: putBody({ document: doc }) },
      null,
    );
    expect(out.body.effectivePolicyMapping).toEqual({
      quarantine: 'move_quarantine',
      require_approval: 'move_quarantine',
      reject: 'tag',
      allow_tagged: 'none',
    });
    const meta = t.q.audits.at(-1)!.metadata as { to: { policyMappingSha256: string } };
    expect(meta.to.policyMappingSha256).toMatch(/^[0-9a-f]{64}$/);
    const view = await t.policies.get(scope);
    expect(view.organization.effectivePolicyMapping.reject).toBe('tag');
    expect(
      await failure(
        t.policies.putOrganization(
          user(),
          scope,
          {
            idempotencyKey: 'pm2',
            body: putBody({
              document: { ...P1, policyMapping: { quarantine: 'hard_delete' } },
              expectedRowVersion: 1,
            }),
          },
          null,
        ),
      ),
    ).toMatchObject({ status: 400 });
    // The reserved rule key is refused with the API-4 issue code.
    const refused = await failure(
      t.policies.putOrganization(
        user(),
        scope,
        {
          idempotencyKey: 'pm3',
          body: putBody({
            document: {
              v: 1,
              rules: [
                {
                  id: 'r',
                  when: { verdicts: ['spam'], policyDispositions: ['reject'] },
                  action: 'tag',
                },
              ],
            },
            expectedRowVersion: 1,
          }),
        },
        null,
      ),
    );
    expect(JSON.stringify(refused)).toContain('use_policy_mapping');
  });

  it('detectOnly only with detect_only and a 1 h … 30 d end (422 api_mode_detect_only_invalid)', async () => {
    for (const [body, reason] of [
      [
        putBody({ mode: 'enforce', detectOnly: { until: inDays(7), then: 'remind' } }),
        'mode_not_detect_only',
      ],
      [
        putBody({ mode: 'detect_only', detectOnly: { until: inDays(0.01), then: 'remind' } }),
        'until_too_soon',
      ],
      [
        putBody({ mode: 'detect_only', detectOnly: { until: inDays(31), then: 'enforce' } }),
        'until_too_late',
      ],
    ] as const) {
      expect(
        await failure(
          t.policies.putOrganization(user(), scope, { idempotencyKey: `d-${reason}`, body }, null),
        ),
      ).toMatchObject({
        status: 422,
        code: 'api_mode_detect_only_invalid',
        details: { reason },
      });
    }
  });

  it('stores a period (started now, not notified), keeps it without detectOnly, enforce clears it', async () => {
    const until = inDays(7);
    const created = await t.policies.putDomain(
      user(),
      scope,
      {
        domainId: t.domain.publicId,
        idempotencyKey: 'do1',
        body: putBody({ mode: 'detect_only', detectOnly: { until, then: 'remind' } }),
      },
      null,
    );
    expect(created.body.detectOnly).toMatchObject({
      until,
      then: 'remind',
      ended: false,
      simulatedSinceStart: 0,
    });
    const stored = t.world.policies.find((p) => p.domainId === t.domain.id)!;
    expect(stored).toMatchObject({ detectOnlyThen: 'remind', detectOnlyNotifiedAt: null });
    expect(stored.detectOnlyStartedAt).not.toBeNull();
    expect(t.q.audits.at(-1)!.metadata).toMatchObject({ detectOnly: { until, then: 'remind' } });
    // Simulated actions of the domain's mailboxes since the start are counted.
    const copy = t.world.addCopy(t.mailbox);
    t.world.addAction(copy, { status: 'simulated', trigger: 'policy', createdAt: new Date() });
    // A simulated action before the period started does not count.
    t.world.addAction(copy, {
      status: 'simulated',
      action: 'tag',
      createdAt: new Date(Date.now() - 3_600_000),
    });
    const view = await t.policies.get(scope);
    expect(view.domains[0]!.detectOnly).toMatchObject({ until, simulatedSinceStart: 1 });
    // An API-2 style body (no detectOnly) keeps the period.
    const kept = await t.policies.putDomain(
      user(),
      scope,
      {
        domainId: t.domain.publicId,
        idempotencyKey: 'do2',
        body: putBody({ mode: 'detect_only', expectedRowVersion: 1 }),
      },
      null,
    );
    expect(kept.body.detectOnly).toMatchObject({ until, simulatedSinceStart: 1 });
    const enforced = await t.policies.putDomain(
      user(),
      scope,
      {
        domainId: t.domain.publicId,
        idempotencyKey: 'do3',
        body: putBody({ mode: 'enforce', expectedRowVersion: 2 }),
      },
      null,
    );
    expect(enforced.body.detectOnly).toBeNull();
    expect(t.world.policies.find((p) => p.domainId === t.domain.id)!.detectOnlyUntil).toBeNull();
  });
});

describe('RemediationActionsService (R12, R13 #5-#9)', () => {
  const copyOf = (patch: Partial<StoredCopy> = {}) =>
    t.world.addCopy(t.mailbox, { verdict: 'phishing', riskScore: 900, ...patch });

  it('remediate: pending admin row (key of the copy, action, generation), copy pending, audit, 202', async () => {
    const c = copyOf({ remediationGeneration: 2 });
    const res = await t.actions.remediate(
      user(),
      scope,
      {
        id: c.publicId,
        idempotencyKey: 'r1',
        body: { action: 'move_quarantine', reason: 'campaign' },
      },
      null,
    );
    expect(res.statusCode).toBe(202);
    expect(res.body).toMatchObject({
      detectionId: c.publicId,
      remediation: {
        action: 'move_quarantine',
        trigger: 'admin',
        status: 'pending',
        generation: 2,
        detectionId: c.publicId,
        mailbox: { id: t.mailbox.publicId, address: 'alex@contoso.example' },
      },
    });
    const row = t.world.actions.at(-1)!;
    expect(row).toMatchObject({
      action: 'move_quarantine',
      generation: 2,
      trigger: 'admin',
      status: 'pending',
      requestedByType: 'user',
      requestedByUserId: 10n,
      requestReason: 'campaign',
      decision: { requestedAction: 'move_quarantine', reason: 'campaign' },
    });
    expect(row.nextAttemptAt).toBeInstanceOf(Date);
    expect(c).toMatchObject({
      remediationState: 'pending',
      remediationAction: 'move_quarantine',
      lastActionId: row.id,
    });
    expect(t.q.audits.at(-1)).toMatchObject({
      action: 'api_mode.remediation_requested',
      resourceId: c.publicId,
      metadata: { action: 'move_quarantine', generation: 2, verdictAuthority: 'copy' },
    });
    // A second request of the same detection: an action is queued.
    expect(
      await failure(
        t.actions.remediate(
          user(),
          scope,
          { id: c.publicId, idempotencyKey: 'r2', body: { action: 'tag', reason: 'x' } },
          null,
        ),
      ),
    ).toMatchObject({ status: 409, code: 'api_mode_remediation_in_progress' });
  });

  it('remediate refusals: hard delete 422, status, grant, already applied, foreign 404', async () => {
    const c = copyOf();
    const call = (id: string, action: string, key: string) =>
      failure(
        t.actions.remediate(
          user(),
          scope,
          { id, idempotencyKey: key, body: { action, reason: 'x' } },
          null,
        ),
      );
    expect(await call(c.publicId, 'hard_delete', 'a')).toMatchObject({
      status: 422,
      code: 'api_mode_hard_delete_not_manual',
    });
    const pending = copyOf({ status: 'pending' });
    expect(await call(pending.publicId, 'tag', 'b')).toMatchObject({
      status: 409,
      code: 'api_mode_detection_not_remediable',
      details: { status: 'pending' },
    });
    const applied = copyOf({ remediationState: 'remediated', remediationAction: 'tag' });
    expect(await call(applied.publicId, 'tag', 'c')).toMatchObject({
      code: 'api_mode_remediation_already_applied',
    });
    t.mailbox.grantActive = false;
    expect(await call(c.publicId, 'tag', 'd')).toMatchObject({
      code: 'api_mode_mailbox_access_required',
    });
    const foreign = t.world.addCopy(t.foreignMailbox);
    expect(await call(foreign.publicId, 'tag', 'e')).toMatchObject({
      status: 404,
      code: 'api_mode_detection_not_found',
    });
    expect(t.world.actions).toHaveLength(0);
  });

  it('remediate re-arms the row of the same key the policy skipped (never a duplicate)', async () => {
    const c = copyOf({ remediationState: 'skipped', remediationAction: 'move_quarantine' });
    const skipped = t.world.addAction(c, { status: 'skipped', reasonCode: 'remediation_paused' });
    const res = await t.actions.remediate(
      user(),
      scope,
      { id: c.publicId, idempotencyKey: 'rr', body: { action: 'move_quarantine', reason: 'now' } },
      null,
    );
    expect(res.body.remediation.id).toBe(skipped.publicId);
    expect(t.world.actions).toHaveLength(1);
    expect(t.world.actions[0]).toMatchObject({ status: 'pending', trigger: 'admin' });
    expect(t.q.audits.at(-1)!.metadata).toMatchObject({ rearmed: true });
  });

  it('restore of a tag: a remove_tag row reversing the tag; nothing in effect / hard delete refused', async () => {
    const c = copyOf({ remediationState: 'remediated', remediationAction: 'tag' });
    const tag = t.world.addAction(c, { action: 'tag' });
    c.lastActionId = tag.id;
    const res = await t.actions.restore(
      user(),
      scope,
      { id: c.publicId, idempotencyKey: 's1', body: { reason: 'false positive' } },
      client,
    );
    expect(res.body).toMatchObject({
      detectionId: c.publicId,
      via: 'mailbox_action',
      release: null,
      remediation: { action: 'remove_tag', trigger: 'admin', status: 'pending' },
    });
    expect(t.world.actions.at(-1)).toMatchObject({
      action: 'remove_tag',
      reversesActionId: tag.id,
    });
    expect(t.q.audits.at(-1)).toMatchObject({
      action: 'api_mode.restore_requested',
      metadata: { via: 'mailbox_action', action: 'remove_tag' },
    });
    expect(t.release.releaseInTx).not.toHaveBeenCalled();
    const none = copyOf();
    expect(
      await failure(
        t.actions.restore(
          user(),
          scope,
          { id: none.publicId, idempotencyKey: 's2', body: { reason: 'x' } },
          client,
        ),
      ),
    ).toMatchObject({
      status: 409,
      code: 'api_mode_nothing_to_restore',
      details: { remediationState: 'none' },
    });
    const hard = copyOf({ remediationState: 'remediated', remediationAction: 'hard_delete' });
    expect(
      await failure(
        t.actions.restore(
          user(),
          scope,
          { id: hard.publicId, idempotencyKey: 's3', body: { reason: 'x' } },
          client,
        ),
      ),
    ).toMatchObject({
      status: 409,
      code: 'api_mode_restore_not_possible',
      details: { cause: 'hard_delete' },
    });
  });

  it('restore of a quarantined copy delegates to the quarantine release (quarantine:release required)', async () => {
    const c = copyOf({ remediationState: 'remediated', remediationAction: 'move_quarantine' });
    const entryId = '0192f3a0-aaaa-7000-8000-00000000000a';
    t.world.copyEntries.set(c.id, { publicId: entryId, state: 'held' });
    expect(
      await failure(
        t.actions.restore(
          user(),
          scope,
          { id: c.publicId, idempotencyKey: 'q1', body: { reason: 'fp' } },
          client,
        ),
      ),
    ).toMatchObject({ status: 403, code: 'quarantine_permission_required' });
    const outcome = {
      outcome: 'queued' as const,
      entryId,
      state: 'releasing' as const,
      releaseId: randomUUID(),
      rowVersion: 2,
    };
    t.release.releaseInTx.mockResolvedValue({ statusCode: 202, body: outcome });
    const res = await t.actions.restore(
      user(['remediation:write', 'quarantine:release']),
      scope,
      { id: c.publicId, idempotencyKey: 'q2', body: { reason: 'fp' } },
      client,
    );
    expect(res.body).toEqual({
      detectionId: c.publicId,
      via: 'quarantine_release',
      remediation: null,
      release: outcome,
    });
    expect(t.release.releaseInTx).toHaveBeenCalledWith(
      {},
      expect.objectContaining({ entryId, key: 'q2', body: { reason: 'fp' } }),
    );
    expect(t.q.audits.at(-1)!.metadata).toMatchObject({
      via: 'quarantine_release',
      entryId,
      outcome: 'queued',
      releaseId: outcome.releaseId,
    });
    // No action row of its own: the release queues the restore_inbox row.
    expect(t.world.actions).toHaveLength(0);
  });

  it('a refused delegated release is audited through the quarantine writer and its error returned', async () => {
    const c = copyOf({ remediationState: 'remediated', remediationAction: 'move_junk' });
    t.world.copyEntries.set(c.id, { publicId: randomUUID(), state: 'held' });
    t.release.releaseInTx.mockRejectedValue(
      new AuditedRefusal(hardBlockReleaseDisabled(), {
        action: 'quarantine.release_refused',
        resourceId: 'e',
        metadata: {},
      }),
    );
    expect(
      await failure(
        t.actions.restore(
          user(['remediation:write', 'quarantine:release']),
          scope,
          { id: c.publicId, idempotencyKey: 'q3', body: { reason: 'fp' } },
          client,
        ),
      ),
    ).toMatchObject({ status: 409, code: 'quarantine_hard_block_release_disabled' });
    expect(t.quarantineWriter.recordRefusal).toHaveBeenCalledTimes(1);
  });

  it('retry: failed rows only, attempts reset, copy pending, audit; the restore of an entry is refused', async () => {
    const c = copyOf({ remediationState: 'failed', remediationAction: 'move_quarantine' });
    const failed = t.world.addAction(c, {
      status: 'failed',
      attempts: 8,
      lastErrorCode: 'provider_unavailable',
      completedAt: new Date(),
    });
    const res = await t.actions.retry(
      user(),
      scope,
      { id: failed.publicId, idempotencyKey: 'x1' },
      null,
    );
    expect(res.statusCode).toBe(202);
    expect(res.body).toMatchObject({
      id: failed.publicId,
      status: 'pending',
      attempts: 0,
      lastErrorCode: null,
    });
    expect(c.remediationState).toBe('pending');
    expect(t.q.audits.at(-1)).toMatchObject({ action: 'api_mode.remediation_retry_requested' });
    expect(
      await failure(
        t.actions.retry(user(), scope, { id: failed.publicId, idempotencyKey: 'x2' }, null),
      ),
    ).toMatchObject({
      status: 409,
      code: 'api_mode_remediation_not_retryable',
      details: { cause: 'pending' },
    });
    const restore = t.world.addAction(copyOf(), {
      action: 'restore_inbox',
      status: 'failed',
      quarantineEntryId: 99n,
    });
    expect(
      await failure(
        t.actions.retry(user(), scope, { id: restore.publicId, idempotencyKey: 'x3' }, null),
      ),
    ).toMatchObject({ details: { cause: 'use_quarantine_release' } });
    // A failed admin action of an older generation (the copy was restored since): refused, and
    // the copy keeps its state.
    const restored = copyOf({ remediationState: 'restored', remediationGeneration: 1 });
    const stale = t.world.addAction(restored, {
      action: 'move_junk',
      trigger: 'admin',
      status: 'failed',
      generation: 0,
    });
    expect(
      await failure(
        t.actions.retry(user(), scope, { id: stale.publicId, idempotencyKey: 'x5' }, null),
      ),
    ).toMatchObject({
      status: 409,
      code: 'api_mode_remediation_not_retryable',
      details: { cause: 'stale_generation' },
    });
    expect(restored.remediationState).toBe('restored');
    expect(stale.status).toBe('failed');
    expect(
      await failure(
        t.actions.retry(user(), scope, { id: randomUUID(), idempotencyKey: 'x4' }, null),
      ),
    ).toMatchObject({ status: 404, code: 'api_mode_remediation_not_found' });
  });

  it('list and detail: cursor pages, filters, provider ids never returned', async () => {
    const c = copyOf();
    for (let i = 0; i < 3; i += 1) {
      t.world.addAction(c, {
        action: i === 0 ? 'tag' : 'move_quarantine',
        actionKey: `k${i}`,
        createdAt: new Date(Date.now() - (i + 1) * 60_000),
      });
    }
    const query = (raw: Record<string, string>) => RemediationListQuerySchema.parse(raw);
    const first = await t.actions.list(user(), scope, query({ limit: '2' }));
    expect(first.data).toHaveLength(2);
    expect(first.nextCursor).not.toBeNull();
    const second = await t.actions.list(
      user(),
      scope,
      query({ limit: '2', cursor: first.nextCursor! }),
    );
    expect(second.data).toHaveLength(1);
    expect(second.nextCursor).toBeNull();
    const tags = await t.actions.list(user(), scope, query({ action: 'tag' }));
    expect(tags.data.map((d) => d.action)).toEqual(['tag']);
    const detail = await t.actions.detail(scope, first.data[0]!.id);
    expect(detail.providerRefs).toEqual({ container: 'quarantine_folder', before: 1, after: 1 });
    expect(JSON.stringify(detail)).not.toContain('provider-id');
    expect(JSON.stringify(first)).not.toContain('provider-id');
    // Another organization's action is 404.
    const foreignCopy = t.world.addCopy(t.foreignMailbox);
    const foreign = t.world.addAction(foreignCopy);
    expect(await failure(t.actions.detail(scope, foreign.publicId))).toMatchObject({
      status: 404,
      code: 'api_mode_remediation_not_found',
    });
    expect((await t.actions.list(user(), scope, query({}))).data.map((d) => d.id)).not.toContain(
      foreign.publicId,
    );
  });
});
