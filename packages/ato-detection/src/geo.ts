/**
 * Geography math (step 8.4 D7, D10 G2/G3): great-circle distance and the impossible-travel
 * assessment, with both accuracy radii subtracted and the anonymizer downgrade. Integer outputs
 * (kilometres, minutes, km/h) so explanations and tests are deterministic.
 */

/** Mean Earth radius in kilometres (IUGG). */
export const EARTH_RADIUS_KM = 6371.0088;

const rad = (deg: number): number => (deg * Math.PI) / 180;

/** Great-circle distance in kilometres (haversine). */
export function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const dLat = rad(lat2 - lat1);
  const dLon = rad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 + Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_RADIUS_KM * Math.asin(Math.min(1, Math.sqrt(a)));
}

export interface GeoPoint {
  /** ISO 3166-1 alpha-2. */
  country: string | null;
  latitude: number | null;
  longitude: number | null;
  accuracyKm: number | null;
  at: Date;
  /** Anonymizer flags of the address (0 or null = none). */
  anonymizerFlags?: number | null;
  /** In a trusted network or trusted context of the account. */
  trusted?: boolean;
}

export interface TravelSettings {
  impossibleTravelKmh: number;
  minDistanceKm: number;
  maxAccuracyRadiusKm: number;
}

export interface TravelAssessment {
  /** Whether both points are precise enough (accuracy ≤ maxAccuracyRadiusKm) for G2/G3. */
  comparable: boolean;
  distanceKm: number;
  /** Distance after subtracting both accuracy radii (never negative). */
  effectiveKm: number;
  elapsedMinutes: number;
  speedKmh: number;
  /** Effective distance ≥ minDistanceKm and implied speed > impossibleTravelKmh, neither trusted. */
  impossible: boolean;
  /** Either side is an anonymizer (G2 downgraded to weak). */
  anonymized: boolean;
}

/**
 * Assesses travel between two located sign-ins (D10 G2): consecutive successes ≥ 500 km apart
 * after subtracting both accuracy radii, implied speed above 900 km/h, neither in trusted
 * networks; a "country only" location (accuracy above the tenant maximum) is never comparable.
 */
export function assessTravel(
  prev: GeoPoint,
  next: GeoPoint,
  settings: TravelSettings,
): TravelAssessment {
  const anonymized = Boolean(prev.anonymizerFlags) || Boolean(next.anonymizerFlags);
  const located =
    prev.latitude !== null &&
    prev.longitude !== null &&
    next.latitude !== null &&
    next.longitude !== null;
  const precise =
    prev.accuracyKm !== null &&
    next.accuracyKm !== null &&
    prev.accuracyKm <= settings.maxAccuracyRadiusKm &&
    next.accuracyKm <= settings.maxAccuracyRadiusKm;
  const elapsedMinutes = Math.max(0, Math.floor((next.at.getTime() - prev.at.getTime()) / 60000));
  if (!located || !precise) {
    return {
      comparable: false,
      distanceKm: 0,
      effectiveKm: 0,
      elapsedMinutes,
      speedKmh: 0,
      impossible: false,
      anonymized,
    };
  }
  const distance = haversineKm(prev.latitude!, prev.longitude!, next.latitude!, next.longitude!);
  const effective = Math.max(0, distance - (prev.accuracyKm ?? 0) - (next.accuracyKm ?? 0));
  // At least one minute, so two sign-ins in the same minute have a finite speed.
  const hours = Math.max(1, elapsedMinutes) / 60;
  const speed = effective / hours;
  const impossible =
    !prev.trusted &&
    !next.trusted &&
    effective >= settings.minDistanceKm &&
    speed > settings.impossibleTravelKmh;
  return {
    comparable: true,
    distanceKm: Math.round(distance),
    effectiveKm: Math.round(effective),
    elapsedMinutes,
    speedKmh: Math.round(speed),
    impossible,
    anonymized,
  };
}
