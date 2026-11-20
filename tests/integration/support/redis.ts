import { composeOk } from './compose';
import { containerHealth, waitForHealthy } from './messaging-stack';

/**
 * Redis chaos for the stack suites. The inbound Rspamd renders its Redis address once at start
 * (infrastructure/rspamd/entrypoint.sh resolves the host when RSPAMD_DNS_SERVERS is set).
 * docker-compose.yml pins redis to 172.31.254.10 on `rspamd-state`, so the address no longer
 * changes; Rspamd is still restarted after every Redis stop/restart, so a suite never leaves it
 * with broken Redis connections (Redis timeouts, inbound acceptance of about 1 msg/s, 4.3.5).
 */

/** `docker compose stop redis`. */
export async function stopRedis(): Promise<void> {
  await composeOk(['stop', 'redis'], { timeoutMs: 120_000 });
}

/** Restarts Rspamd (when it exists) and waits until it is healthy again. */
export async function restartRedisDependents(): Promise<void> {
  if ((await containerHealth('rspamd')) === '') return;
  await composeOk(['restart', 'rspamd'], { timeoutMs: 180_000 });
  await waitForHealthy('rspamd', 180_000);
}

/** Starts Redis (no dependencies), waits until it is healthy, then restarts Rspamd. */
export async function startRedis(): Promise<void> {
  await composeOk(['up', '-d', '--wait', '--no-deps', 'redis'], { timeoutMs: 120_000 });
  await restartRedisDependents();
}
