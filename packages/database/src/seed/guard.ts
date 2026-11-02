/**
 * Production guard for db:seed (D7). In staging or production (APP_ENV) or with
 * NODE_ENV=production, only `--catalog-only --allow-production` runs, and only the catalog.
 */
export interface SeedGuardInput {
  appEnv: string | undefined;
  nodeEnv: string | undefined;
  catalogOnly: boolean;
  allowProduction: boolean;
}

export type SeedGuardDecision =
  { allowed: true; catalog: true; demo: boolean } | { allowed: false; reason: string };

export function isProductionLike(appEnv: string | undefined, nodeEnv: string | undefined) {
  return appEnv === 'staging' || appEnv === 'production' || nodeEnv === 'production';
}

export function decideSeed(input: SeedGuardInput): SeedGuardDecision {
  if (isProductionLike(input.appEnv, input.nodeEnv)) {
    if (input.catalogOnly && input.allowProduction) {
      return { allowed: true, catalog: true, demo: false };
    }
    return {
      allowed: false,
      reason:
        'refusing to seed a staging/production environment; only ' +
        '`db:seed -- --catalog-only --allow-production` is allowed there',
    };
  }
  return { allowed: true, catalog: true, demo: !input.catalogOnly };
}
