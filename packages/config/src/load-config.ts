import { readFileSync } from 'node:fs';
import { type z } from 'zod';

export class ConfigValidationError extends Error {
  constructor(public readonly issues: string[]) {
    super(`Invalid configuration:\n  - ${issues.join('\n  - ')}`);
    this.name = 'ConfigValidationError';
  }
}

/**
 * Resolves the `<KEY>_FILE` convention used by Docker and Kubernetes secrets:
 * when `DATABASE_URL_FILE=/run/secrets/db_url` is set, `DATABASE_URL` is read from that file.
 * An explicit `<KEY>` always wins over `<KEY>_FILE`.
 */
export function resolveFileSecrets(env: NodeJS.ProcessEnv): Record<string, string | undefined> {
  const resolved: Record<string, string | undefined> = { ...env };
  for (const [key, path] of Object.entries(env)) {
    if (!key.endsWith('_FILE') || !path) continue;
    const target = key.slice(0, -'_FILE'.length);
    if (resolved[target] !== undefined && resolved[target] !== '') continue;
    resolved[target] = readFileSync(path, 'utf8').trim();
  }
  return resolved;
}

/** `KEY=` (empty) means "not set", so optional keys can be blanked in .env files and compose. */
function dropEmpty(env: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(env).filter(
      (entry): entry is [string, string] => entry[1] !== undefined && entry[1] !== '',
    ),
  );
}

/**
 * Validates the environment against a zod schema once at startup and returns a frozen,
 * typed config object. Services fail fast on invalid config instead of failing on first use.
 * Error messages name the offending keys but never echo their values.
 */
export function loadConfig<S extends z.ZodType>(
  schema: S,
  env: NodeJS.ProcessEnv = process.env,
): Readonly<z.infer<S>> {
  const result = schema.safeParse(dropEmpty(resolveFileSecrets(env)));
  if (!result.success) {
    throw new ConfigValidationError(
      result.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`),
    );
  }
  return Object.freeze(result.data);
}
