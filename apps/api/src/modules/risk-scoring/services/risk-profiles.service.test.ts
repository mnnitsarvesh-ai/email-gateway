import { HttpException } from '@nestjs/common';
import { canonicalJson, resolveProfile, sha256Hex } from '@email-gateway/risk-scoring';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryRiskProfiles } from '../../../../test/support/in-memory-risk-profiles';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import type { ClientContext } from '../../auth/services/session.service';
import type { RiskVersionDetail } from '../dto/risk-scoring.schemas';
import { RiskProfilesService } from './risk-profiles.service';
import { type RiskAuditor, type RiskMetrics, RISK_TX, RiskWriter } from './risk-writer';

const ORG_A = systemScope(5n);
const ORG_B = systemScope(6n);
const USER_ID = 77n;
const USER_PUBLIC = '0190f0f0-0000-7000-8000-0000000000aa';
const principal = { kind: 'user', userId: USER_ID } as unknown as Principal;
const client = { ip: '203.0.113.9' } as ClientContext;

interface AuditEntry {
  action: string;
  resourceType: string;
  resourceId: string;
  metadata: Record<string, unknown>;
  scope: { organizationId: bigint };
}

function setup(limit = 200) {
  const store = new InMemoryRiskProfiles();
  store.users.set(USER_ID, USER_PUBLIC);
  const audits: AuditEntry[] = [];
  const auditor = {
    record: vi.fn((_tx: unknown, entry: AuditEntry) => {
      audits.push(entry);
      return Promise.resolve();
    }),
  };
  const counts: Record<string, number> = {};
  const metrics = {
    profileChanges: {
      inc: vi.fn(({ operation }: { operation: string }) => {
        counts[operation] = (counts[operation] ?? 0) + 1;
      }),
    },
    dryRuns: { inc: vi.fn() },
  };
  const service = new RiskProfilesService(
    { RISK_PLATFORM_PROFILE: 'rsk-default/1', RISK_PROFILE_MAX_VERSIONS: limit },
    store.repository,
    new RiskWriter(store.transactions as unknown as TransactionRunner),
    auditor as unknown as RiskAuditor,
    metrics as unknown as RiskMetrics,
  );
  return { service, store, audits, counts };
}

async function refusal(promise: Promise<unknown>): Promise<{ status: number; body: unknown }> {
  const error: unknown = await promise.then(
    () => expect.fail('expected a refusal'),
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(HttpException);
  const http = error as HttpException;
  const coded = error instanceof CodedHttpException ? { code: error.code, ...error.details } : {};
  return { status: http.getStatus(), body: { ...(http.getResponse() as object), ...coded } };
}

const codeOf = (error: { body: unknown }) => (error.body as { code?: string }).code;

describe('RiskProfilesService: drafts (R10, R15)', () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => {
    t = setup();
  });

  it('creates the profile row lazily and numbers drafts per organization, audited with paths', async () => {
    const first = await t.service.createDraft(
      principal,
      ORG_A,
      { overrides: { thresholds: { medium: 350 } }, changeNote: 'tighter' },
      client,
    );
    expect(first).toMatchObject({
      versionNo: 1,
      status: 'draft',
      baseProfile: 'rsk-default/1',
      rowVersion: 1,
      changeNote: 'tighter',
      active: false,
      overrides: { thresholds: { medium: 350 } },
      overridesSha256: sha256Hex(canonicalJson({ thresholds: { medium: 350 } })),
      profileSha256: null,
      createdByUserId: USER_PUBLIC,
      resolved: { valid: true },
    });
    expect(t.store.profiles).toHaveLength(1);
    const second = await t.service.createDraft(principal, ORG_A, {}, client);
    expect(second.versionNo).toBe(2);
    expect(second.overrides).toEqual({});
    expect(t.audits.map((a) => a.action)).toEqual([
      'risk_profile.draft_created',
      'risk_profile.draft_created',
    ]);
    expect(t.audits[0]).toMatchObject({
      resourceType: 'risk_scoring_profile_version',
      resourceId: first.id,
      metadata: {
        versionId: first.id,
        versionNo: 1,
        baseProfile: 'rsk-default/1',
        overridesSha256: first.overridesSha256,
        changedPaths: ['thresholds.medium'],
      },
    });
    // Metadata never carries override values or the note.
    const metadata = JSON.stringify(t.audits.map((a) => a.metadata));
    expect(metadata).not.toContain('350');
    expect(metadata).not.toContain('tighter');
    expect(t.counts).toEqual({ draft_created: 2 });
    expect(t.store.txOptions[0]).toEqual(RISK_TX);
  });

  it('refuses invalid overrides with violations by path before any database access', async () => {
    const error = await refusal(
      t.service.createDraft(
        principal,
        ORG_A,
        { overrides: { thresholds: { low: 5 }, bogus: 1 } },
        client,
      ),
    );
    expect(error.status).toBe(400);
    expect(error.body).toMatchObject({ code: 'risk_profile_invalid' });
    expect(t.store.calls).toEqual([]);
  });

  it('copies the overrides of basedOnVersionId (a version of the same organization only)', async () => {
    const source = await t.service.createDraft(
      principal,
      ORG_A,
      { overrides: { trust: { mode: 'off' } } },
      client,
    );
    const copy = await t.service.createDraft(
      principal,
      ORG_A,
      { basedOnVersionId: source.id },
      client,
    );
    expect(copy.overrides).toEqual({ trust: { mode: 'off' } });
    expect(t.audits[1]!.metadata).toMatchObject({
      basedOnVersionId: source.id,
      basedOnVersionNo: 1,
      changedPaths: ['trust.mode'],
    });
    const foreign = await refusal(
      t.service.createDraft(principal, ORG_B, { basedOnVersionId: source.id }, client),
    );
    expect(foreign.status).toBe(404);
    expect(codeOf(foreign)).toBe('risk_profile_version_not_found');
    // The refused transaction left nothing behind for organization B.
    expect(t.store.profiles.filter((p) => p.organizationId === 6n)).toEqual([]);
  });

  it('caps the versions per organization (409 risk_profile_limit_reached)', async () => {
    const small = setup(2);
    await small.service.createDraft(principal, ORG_A, {}, client);
    await small.service.createDraft(principal, ORG_A, {}, client);
    const error = await refusal(small.service.createDraft(principal, ORG_A, {}, client));
    expect(error.status).toBe(409);
    expect(error.body).toMatchObject({ code: 'risk_profile_limit_reached', limit: 2 });
    // Another organization has its own cap.
    await small.service.createDraft(principal, ORG_B, {}, client);
  });

  it('replaces a draft with a row-version compare-and-set', async () => {
    const draft = await t.service.createDraft(
      principal,
      ORG_A,
      { overrides: { thresholds: { medium: 350 } } },
      client,
    );
    const updated = await t.service.updateDraft(
      principal,
      ORG_A,
      draft.id,
      {
        overrides: { thresholds: { medium: 360 }, ai: { tagOnAiOnlyRaise: false } },
        expectedRowVersion: 1,
      },
      client,
    );
    expect(updated).toMatchObject({ rowVersion: 2, overrides: { thresholds: { medium: 360 } } });
    expect(t.audits.at(-1)).toMatchObject({
      action: 'risk_profile.draft_updated',
      metadata: {
        rowVersion: 2,
        overridesSha256Before: draft.overridesSha256,
        overridesSha256: updated.overridesSha256,
        changedPaths: ['ai.tagOnAiOnlyRaise', 'thresholds.medium'],
      },
    });
    const stale = await refusal(
      t.service.updateDraft(
        principal,
        ORG_A,
        draft.id,
        { overrides: {}, expectedRowVersion: 1 },
        client,
      ),
    );
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({
      code: 'risk_profile_version_conflict',
      currentRowVersion: 2,
    });
    const invalid = await refusal(
      t.service.updateDraft(
        principal,
        ORG_A,
        draft.id,
        { overrides: { actions: { critical: 'tag' } }, expectedRowVersion: 2 },
        client,
      ),
    );
    expect(invalid.status).toBe(400);
    expect(codeOf(invalid)).toBe('risk_profile_invalid');
  });

  it('deletes drafts only, optionally at a row version', async () => {
    const draft = await t.service.createDraft(principal, ORG_A, {}, client);
    const stale = await refusal(t.service.deleteDraft(principal, ORG_A, draft.id, 9, client));
    expect(codeOf(stale)).toBe('risk_profile_version_conflict');
    await t.service.deleteDraft(principal, ORG_A, draft.id, 1, client);
    expect(t.store.versions).toEqual([]);
    expect(t.audits.at(-1)).toMatchObject({
      action: 'risk_profile.draft_deleted',
      metadata: { versionId: draft.id, versionNo: 1 },
    });
    const gone = await refusal(
      t.service.deleteDraft(principal, ORG_A, draft.id, undefined, client),
    );
    expect(gone.status).toBe(404);
  });

  it('never reveals or changes another organization’s version (404)', async () => {
    const draft = await t.service.createDraft(principal, ORG_A, {}, client);
    for (const attempt of [
      t.service.getVersion(ORG_B, draft.id),
      t.service.updateDraft(
        principal,
        ORG_B,
        draft.id,
        { overrides: {}, expectedRowVersion: 1 },
        client,
      ),
      t.service.deleteDraft(principal, ORG_B, draft.id, undefined, client),
      t.service.publish(
        principal,
        ORG_B,
        draft.id,
        { activate: true, expectedRowVersion: 1 },
        client,
      ),
      t.service.activate(principal, ORG_B, draft.id, {}, client),
    ]) {
      const error = await refusal(attempt);
      expect(error.status).toBe(404);
      expect(codeOf(error)).toBe('risk_profile_version_not_found');
    }
    expect((await t.service.listVersions(ORG_B, { limit: 25 })).data).toEqual([]);
    expect(t.store.versions[0]).toMatchObject({ status: 'draft', rowVersion: 1 });
  });
});

describe('RiskProfilesService: publish, activate, reset (R10, R15)', () => {
  let t: ReturnType<typeof setup>;
  let draft: RiskVersionDetail;
  beforeEach(async () => {
    t = setup();
    draft = await t.service.createDraft(
      principal,
      ORG_A,
      { overrides: { actions: { medium: 'quarantine' } } },
      client,
    );
  });

  it('publishes (profile hash, who, when), activates by default and makes the version immutable', async () => {
    const result = await t.service.publish(
      principal,
      ORG_A,
      draft.id,
      { activate: true, expectedRowVersion: 1 },
      client,
    );
    const expected = resolveProfile('rsk-default/1', {
      publicId: draft.id,
      versionNo: 1,
      baseProfile: 'rsk-default/1',
      overrides: { actions: { medium: 'quarantine' } },
    });
    expect(result.version).toMatchObject({
      status: 'published',
      rowVersion: 2,
      profileSha256: expected.sha256,
      publishedByUserId: USER_PUBLIC,
      active: true,
    });
    expect(result.profile.active).toMatchObject({
      source: 'tenant',
      versionId: draft.id,
      versionNo: 1,
      profileId: expected.id,
      sha256: expected.sha256,
    });
    expect(result.profile.profileVersion).toBe(2);
    expect(t.audits.slice(1).map((a) => a.action)).toEqual([
      'risk_profile.published',
      'risk_profile.activated',
    ]);
    expect(t.audits.at(-1)!.metadata).toMatchObject({
      versionId: draft.id,
      versionNo: 1,
      previousVersionId: null,
      profileSha256: expected.sha256,
    });
    expect(t.counts).toMatchObject({ published: 1, activated: 1 });

    // Immutable: no route changes or deletes it; publishing again is refused.
    for (const attempt of [
      t.service.updateDraft(
        principal,
        ORG_A,
        draft.id,
        { overrides: {}, expectedRowVersion: 2 },
        client,
      ),
      t.service.deleteDraft(principal, ORG_A, draft.id, undefined, client),
      t.service.publish(
        principal,
        ORG_A,
        draft.id,
        { activate: true, expectedRowVersion: 2 },
        client,
      ),
    ]) {
      const error = await refusal(attempt);
      expect(error.status).toBe(409);
      expect(codeOf(error)).toBe('risk_profile_version_immutable');
    }
    expect(t.store.versions[0]).toMatchObject({ status: 'published', rowVersion: 2 });
  });

  it('publishes without activation when asked, and refuses a stale row version', async () => {
    const stale = await refusal(
      t.service.publish(
        principal,
        ORG_A,
        draft.id,
        { activate: false, expectedRowVersion: 5 },
        client,
      ),
    );
    expect(codeOf(stale)).toBe('risk_profile_version_conflict');
    const result = await t.service.publish(
      principal,
      ORG_A,
      draft.id,
      { activate: false, expectedRowVersion: 1 },
      client,
    );
    expect(result.version.active).toBe(false);
    expect(result.profile.active.source).toBe('platform');
    expect(t.audits.at(-1)!.action).toBe('risk_profile.published');
  });

  it('refuses to publish a draft the platform bounds no longer accept', async () => {
    t.store.forceVersion(draft.id, { overrides: { thresholds: { low: 1 } } });
    const error = await refusal(
      t.service.publish(
        principal,
        ORG_A,
        draft.id,
        { activate: true, expectedRowVersion: 1 },
        client,
      ),
    );
    expect(error.status).toBe(400);
    expect(error.body).toMatchObject({ code: 'risk_profile_invalid' });
    expect(t.store.versions[0]!.status).toBe('draft');
  });

  it('activates published versions only (rollback), audited with previous and new', async () => {
    await t.service.publish(
      principal,
      ORG_A,
      draft.id,
      { activate: true, expectedRowVersion: 1 },
      client,
    );
    const second = await t.service.createDraft(principal, ORG_A, {}, client);
    const notPublished = await refusal(t.service.activate(principal, ORG_A, second.id, {}, client));
    expect(notPublished.status).toBe(409);
    expect(codeOf(notPublished)).toBe('risk_profile_version_not_published');
    await t.service.publish(
      principal,
      ORG_A,
      second.id,
      { activate: true, expectedRowVersion: 1 },
      client,
    );

    const stale = await refusal(
      t.service.activate(principal, ORG_A, draft.id, { expectedProfileVersion: 1 }, client),
    );
    expect(stale.body).toMatchObject({
      code: 'risk_profile_version_conflict',
      currentProfileVersion: 3,
    });
    const rolledBack = await t.service.activate(
      principal,
      ORG_A,
      draft.id,
      { expectedProfileVersion: 3 },
      client,
    );
    expect(rolledBack.active).toMatchObject({ versionId: draft.id, versionNo: 1 });
    expect(t.audits.at(-1)).toMatchObject({
      action: 'risk_profile.activated',
      metadata: {
        versionId: draft.id,
        versionNo: 1,
        previousVersionId: second.id,
        previousVersionNo: 2,
        profileVersion: 4,
      },
    });
    // Activating the active version changes nothing (no audit row, no counter).
    const auditCount = t.audits.length;
    const same = await t.service.activate(principal, ORG_A, draft.id, {}, client);
    expect(same.profileVersion).toBe(4);
    expect(t.audits).toHaveLength(auditCount);
  });

  it('resets the pointer to the platform default (versions kept)', async () => {
    const nothing = await t.service.reset(principal, ORG_A, {}, client);
    expect(nothing.active.source).toBe('platform');
    expect(t.audits.map((a) => a.action)).not.toContain('risk_profile.reset');
    await t.service.publish(
      principal,
      ORG_A,
      draft.id,
      { activate: true, expectedRowVersion: 1 },
      client,
    );
    const stale = await refusal(
      t.service.reset(principal, ORG_A, { expectedProfileVersion: 0 }, client),
    );
    expect(codeOf(stale)).toBe('risk_profile_version_conflict');
    const reset = await t.service.reset(principal, ORG_A, { expectedProfileVersion: 2 }, client);
    expect(reset).toMatchObject({
      profileVersion: 3,
      active: { source: 'platform', versionId: null, fallback: null },
      counts: { drafts: 0, published: 1 },
    });
    expect(t.audits.at(-1)).toMatchObject({
      action: 'risk_profile.reset',
      resourceType: 'risk_scoring_profile',
      metadata: { previousVersionId: draft.id, previousVersionNo: 1 },
    });
    expect(t.counts.reset).toBe(1);
  });

  it('reads the profile and versions (newest first, status filter, active flag)', async () => {
    await t.service.publish(
      principal,
      ORG_A,
      draft.id,
      { activate: true, expectedRowVersion: 1 },
      client,
    );
    const second = await t.service.createDraft(principal, ORG_A, {}, client);
    const page = await t.service.listVersions(ORG_A, { limit: 1 });
    expect(page.data.map((v) => v.id)).toEqual([second.id]);
    expect(page.nextCursor).not.toBeNull();
    const published = await t.service.listVersions(ORG_A, { limit: 25, status: 'published' });
    expect(published.data).toEqual([expect.objectContaining({ id: draft.id, active: true })]);
    const profile = await t.service.profile(ORG_A);
    expect(profile.counts).toEqual({ drafts: 1, published: 1, limit: 200 });
    expect(profile.effectiveProfile.actions.medium).toBe('quarantine');
    const detail = await t.service.getVersion(ORG_A, draft.id);
    expect(detail.resolved.valid).toBe(true);
    expect((await t.service.profile(ORG_B)).active.source).toBe('platform');
  });
});

describe('RiskProfilesService: wrong writer reads (§6)', () => {
  it('retries the transaction once on an echo mismatch and rolls the first attempt back', async () => {
    const t = setup();
    await t.service.createDraft(principal, ORG_A, {}, client);
    t.store.injectWrongRead = 'risk_profile';
    const draft = await t.service.createDraft(principal, ORG_A, {}, client);
    expect(draft.versionNo).toBe(2);
    expect(t.store.versions).toHaveLength(2);
    expect(t.store.txOptions).toHaveLength(3);
  });

  it('answers 503 inconsistent_read after a second mismatch', async () => {
    const t = setup();
    const draft = await t.service.createDraft(principal, ORG_A, {}, client);
    const original = t.store.repository.versionForUpdate.bind(t.store.repository);
    let calls = 0;
    t.store.repository.versionForUpdate = (...args) => {
      calls += 1;
      t.store.injectWrongRead = 'risk_profile_version';
      return original(...args);
    };
    const error = await refusal(
      t.service.updateDraft(
        principal,
        ORG_A,
        draft.id,
        { overrides: {}, expectedRowVersion: 1 },
        client,
      ),
    );
    expect(error.status).toBe(503);
    expect(codeOf(error)).toBe('inconsistent_read');
    expect(calls).toBe(2);
    expect(t.store.versions[0]!.rowVersion).toBe(1);
  });
});

describe('RiskProfilesService: platform profile', () => {
  it('serves the library data without any database access', () => {
    const t = setup();
    const view = t.service.platform();
    expect(view.id).toBe('rsk-default/1');
    expect(t.store.calls).toEqual([]);
  });
});
