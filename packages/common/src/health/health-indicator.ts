/** Anything a service depends on for readiness implements this. */
export interface HealthIndicator {
  readonly healthName: string;
  /** Resolves when the dependency is usable; rejects with a reason otherwise. */
  checkHealth(): Promise<void>;
}

export const HEALTH_INDICATORS = Symbol('HEALTH_INDICATORS');
export const SERVICE_INFO = Symbol('SERVICE_INFO');

export interface ServiceInfo {
  name: string;
  version: string;
}
