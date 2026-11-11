import { RiskProfileError } from '@email-gateway/risk-scoring';
import { describe, expect, it } from 'vitest';
import { FakeRiskDb, ORG, riskSetup, series, VERSION_PUBLIC_ID } from './fakes.test-support';
import { readProfileSnapshot, RiskProfileProvider } from './profile-provider';
import { InconsistentRiskReadError } from './risk-reader';

const provider = (maxEntries = 100) =>
  new RiskProfileProvider({ platformId: 'rsk-default/1', maxEntries });

describe('risk profile snapshot at round open (step 5.1 R13, §6)', () => {
  it('reads the active version of the organization; none or a NULL pointer = platform', async () => {
    const db = new FakeRiskDb();
    expect(await readProfileSnapshot(db.tx(), ORG)).toBeNull();
    db.profiles.push({ organizationId: ORG, activeVersionId: null });
    expect(await readProfileSnapshot(db.tx(), ORG)).toBeNull();
    db.profiles[0]!.activeVersionId = 501n;
    expect(await readProfileSnapshot(db.tx(), ORG)).toBe(501n);
  });

  it('a profile row of another organization is a retryable wrong read', async () => {
    const db = new FakeRiskDb();
    db.profiles.push({ organizationId: 8n, activeVersionId: 9n });
    const tx = db.tx();
    // The fake filters by organization; force the wrong row as a defective read would.
    (tx.riskScoringProfile as unknown as { findUnique: unknown }).findUnique = () =>
      Promise.resolve({ organizationId: 8n, activeVersionId: 9n });
    const seen: string[] = [];
    await expect(readProfileSnapshot(tx, ORG, (read) => seen.push(read))).rejects.toBeInstanceOf(
      InconsistentRiskReadError,
    );
    expect(seen).toEqual(['profile']);
  });
});

describe('RiskProfileProvider (step 5.1 R10, R13)', () => {
  it('a NULL snapshot is the platform default without a fallback and without a read', async () => {
    const db = new FakeRiskDb();
    const p = provider();
    const { resolved, versionId } = await p.resolve(db.tx(), ORG, null);
    expect(resolved).toMatchObject({ source: 'platform', id: 'rsk-default/1', fallback: null });
    expect(versionId).toBeNull();
    expect(p.reads).toBe(0);
  });

  it('resolves a published tenant version and caches it by id', async () => {
    const db = new FakeRiskDb();
    db.addVersion();
    const p = provider();
    const first = await p.resolve(db.tx(), ORG, 501n);
    expect(first.resolved).toMatchObject({
      source: 'tenant',
      id: `rsk-default/1+t:${VERSION_PUBLIC_ID}#3`,
      versionNo: 3,
      fallback: null,
    });
    expect(first.resolved.profile.thresholds.medium).toBe(250);
    expect(first.versionId).toBe(501n);
    // A later edit of the row is never seen (published versions are immutable): the cache wins.
    db.versions[0]!.overrides = { thresholds: { medium: 400 } };
    const second = await p.resolve(db.tx(), ORG, 501n);
    expect(second).toBe(first);
    expect(p.reads).toBe(1);
  });

  it('checks the organization on every cache hit: another tenant gets the foreign fallback', async () => {
    const db = new FakeRiskDb();
    db.addVersion();
    const p = provider();
    await p.resolve(db.tx(), ORG, 501n);
    const foreign = await p.resolve(db.tx(), 8n, 501n);
    expect(foreign.resolved).toMatchObject({ source: 'platform', fallback: 'foreign' });
    expect(foreign.versionId).toBeNull();
    expect(p.reads).toBe(1);
  });

  it('a version of another organization falls back to the platform default (foreign)', async () => {
    const db = new FakeRiskDb();
    db.addVersion({ organizationId: 8n });
    const { resolved, versionId } = await provider().resolve(db.tx(), ORG, 501n);
    expect(resolved).toMatchObject({
      source: 'platform',
      id: 'rsk-default/1',
      fallback: 'foreign',
    });
    expect(versionId).toBeNull();
  });

  it('a missing row or a draft falls back (missing) and is never cached', async () => {
    const db = new FakeRiskDb();
    const p = provider();
    expect((await p.resolve(db.tx(), ORG, 501n)).resolved.fallback).toBe('missing');
    db.addVersion({ status: 'draft' });
    expect((await p.resolve(db.tx(), ORG, 501n)).resolved.fallback).toBe('missing');
    expect(p.size).toBe(0);
    db.versions[0]!.status = 'published';
    expect((await p.resolve(db.tx(), ORG, 501n)).resolved.source).toBe('tenant');
    expect(p.reads).toBe(3);
  });

  it('an invalid published version falls back with the violations (invalid)', async () => {
    const db = new FakeRiskDb();
    db.addVersion({ overrides: { thresholds: { low: 10 } } });
    const { resolved } = await provider().resolve(db.tx(), ORG, 501n);
    expect(resolved).toMatchObject({ source: 'platform', fallback: 'invalid' });
    expect(resolved.violations.length).toBeGreaterThan(0);
  });

  it('a retired base profile resolves against the platform default', async () => {
    const db = new FakeRiskDb();
    db.addVersion({ baseProfile: 'rsk-default/0' });
    const { resolved } = await provider().resolve(db.tx(), ORG, 501n);
    expect(resolved).toMatchObject({ source: 'platform', fallback: 'base_profile_retired' });
  });

  it('a malformed row (public id) throws RiskProfileError (the scorer writes the error row)', async () => {
    const db = new FakeRiskDb();
    db.addVersion({ publicId: 'not-a-uuid' });
    await expect(provider().resolve(db.tx(), ORG, 501n)).rejects.toBeInstanceOf(RiskProfileError);
  });

  it('a row of another id is a retryable wrong read', async () => {
    const db = new FakeRiskDb();
    db.addVersion({ id: 502n });
    const tx = db.tx();
    (tx.riskScoringProfileVersion as unknown as { findUnique: unknown }).findUnique = () =>
      Promise.resolve(db.versions[0]);
    const { metrics, registry } = riskSetup();
    const p = new RiskProfileProvider({
      platformId: 'rsk-default/1',
      maxEntries: 100,
      onInconsistent: (read) => metrics.inconsistent(read),
    });
    await expect(p.resolve(tx, ORG, 501n)).rejects.toMatchObject({ read: 'profile_version' });
    expect(
      await series(registry, 'scan_risk_inconsistent_reads_total', { read: 'profile_version' }),
    ).toBe(1);
  });

  it('evicts the least recently used version beyond RISK_PROFILE_CACHE_MAX_ENTRIES', async () => {
    const db = new FakeRiskDb();
    for (let i = 0; i < 3; i += 1) {
      db.addVersion({
        id: BigInt(600 + i),
        publicId: `0196f3a0-0000-7000-8000-00000000000${String(i)}`,
        versionNo: i + 1,
      });
    }
    const p = provider(2);
    await p.resolve(db.tx(), ORG, 600n);
    await p.resolve(db.tx(), ORG, 601n);
    await p.resolve(db.tx(), ORG, 600n); // refresh 600: 601 is now the oldest
    await p.resolve(db.tx(), ORG, 602n); // evicts 601
    expect(p.size).toBe(2);
    expect(p.reads).toBe(3);
    await p.resolve(db.tx(), ORG, 600n);
    expect(p.reads).toBe(3);
    await p.resolve(db.tx(), ORG, 601n);
    expect(p.reads).toBe(4);
  });
});
