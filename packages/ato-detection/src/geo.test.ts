import { describe, expect, it } from 'vitest';
import { assessTravel, haversineKm } from './geo';

const SETTINGS = { impossibleTravelKmh: 900, minDistanceKm: 500, maxAccuracyRadiusKm: 500 };
const mumbai = { country: 'IN', latitude: 19.076, longitude: 72.8777, accuracyKm: 20 };
const london = { country: 'GB', latitude: 51.5074, longitude: -0.1278, accuracyKm: 10 };
const pune = { country: 'IN', latitude: 18.5204, longitude: 73.8567, accuracyKm: 20 };
const t = (m: number) => new Date(Date.UTC(2026, 10, 18, 10, m));

describe('haversineKm', () => {
  it('matches known distances', () => {
    expect(Math.round(haversineKm(19.076, 72.8777, 51.5074, -0.1278))).toBeGreaterThan(7150);
    expect(Math.round(haversineKm(19.076, 72.8777, 51.5074, -0.1278))).toBeLessThan(7210);
    expect(Math.round(haversineKm(19.076, 72.8777, 18.5204, 73.8567))).toBeGreaterThan(110);
    expect(Math.round(haversineKm(19.076, 72.8777, 18.5204, 73.8567))).toBeLessThan(125);
    expect(haversineKm(0, 0, 0, 0)).toBe(0);
  });
});

describe('assessTravel (G2)', () => {
  it('Mumbai then London 30 minutes later is impossible', () => {
    const a = assessTravel({ ...mumbai, at: t(0) }, { ...london, at: t(30) }, SETTINGS);
    expect(a.comparable).toBe(true);
    expect(a.impossible).toBe(true);
    expect(a.elapsedMinutes).toBe(30);
    expect(a.effectiveKm).toBe(Math.round(haversineKm(19.076, 72.8777, 51.5074, -0.1278) - 30));
    expect(a.speedKmh).toBeGreaterThan(14000);
  });

  it('Mumbai then Pune is too close (< 500 km)', () => {
    expect(assessTravel({ ...mumbai, at: t(0) }, { ...pune, at: t(1) }, SETTINGS).impossible).toBe(
      false,
    );
  });

  it('a slow enough journey is possible', () => {
    const a = assessTravel(
      { ...mumbai, at: t(0) },
      { ...london, at: new Date(t(0).getTime() + 10 * 3_600_000) },
      SETTINGS,
    );
    expect(a.impossible).toBe(false);
  });

  it('subtracts both accuracy radii', () => {
    const wide = assessTravel(
      { ...mumbai, accuracyKm: 400, at: t(0) },
      { ...pune, accuracyKm: 400, at: t(1) },
      SETTINGS,
    );
    expect(wide.effectiveKm).toBe(0);
    expect(wide.impossible).toBe(false);
  });

  it('a country-only location (accuracy above the maximum) is never comparable', () => {
    const a = assessTravel(
      { ...mumbai, at: t(0) },
      { ...london, accuracyKm: 1000, at: t(5) },
      SETTINGS,
    );
    expect(a.comparable).toBe(false);
    expect(a.impossible).toBe(false);
  });

  it('trusted sides never count; anonymizers are flagged for the downgrade', () => {
    expect(
      assessTravel({ ...mumbai, at: t(0), trusted: true }, { ...london, at: t(5) }, SETTINGS)
        .impossible,
    ).toBe(false);
    const anon = assessTravel(
      { ...mumbai, at: t(0) },
      { ...london, at: t(5), anonymizerFlags: 1 },
      SETTINGS,
    );
    expect(anon.impossible).toBe(true);
    expect(anon.anonymized).toBe(true);
  });

  it('two sign-ins in the same minute have a finite speed', () => {
    const a = assessTravel({ ...mumbai, at: t(0) }, { ...london, at: t(0) }, SETTINGS);
    expect(Number.isFinite(a.speedKmh)).toBe(true);
    expect(a.impossible).toBe(true);
  });
});
