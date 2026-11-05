import { ClamdClient, type ClamdClientOptions } from '../../src';

/**
 * Connection to the clamd of the Compose stack from the host (CLAMAV_HOST_PORT from .env,
 * loaded by vitest.integration.config.ts). The suite FAILS with this explanation when clamd
 * does not answer.
 */
export const HOW_TO_START = [
  'The clamav integration suite needs the clamd container of the Compose stack:',
  '  docker compose up -d --wait clamav',
  '  (first start downloads the signature databases: up to 10 minutes)',
].join('\n');

export const clamdHost = process.env.CLAMAV_IT_HOST ?? '127.0.0.1';
export const clamdPort = Number(process.env.CLAMAV_HOST_PORT ?? '3310');

export function makeClient(overrides: Partial<ClamdClientOptions> = {}): ClamdClient {
  return new ClamdClient({
    host: clamdHost,
    port: clamdPort,
    timeoutMs: 60_000,
    maxConnections: 4,
    ...overrides,
  });
}

/** Fails with an explanation when clamd is down. */
export async function requireClamd(): Promise<void> {
  try {
    await makeClient({ timeoutMs: 5_000 }).ping();
  } catch (error) {
    throw new Error(
      `clamd does not answer on ${clamdHost}:${clamdPort} (${(error as Error).message})\n${HOW_TO_START}`,
    );
  }
}
