import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { RspamdClient, type RspamdEnvelope } from '../../src';

/**
 * Connection to the inbound rspamd of the Compose stack from the host (.env host ports and
 * controller passwords, loaded by vitest.integration.config.ts; values are never printed).
 * Requirements (the suite FAILS with this explanation when they are not met):
 *   docker compose up -d --wait rspamd
 *   docker compose --profile smtp-test up -d dns-sink      # scan.test zones
 *   .env: RSPAMD_DNS_SERVERS=172.31.250.53, RSPAMD_RBL_PROFILE=test, RSPAMD_BAYES_MIN_LEARNS=10
 */
export const HOW_TO_START = [
  'The rspamd integration suite needs the inbound rspamd with the test DNS profile:',
  '  docker compose up -d --wait rspamd',
  '  docker compose --profile smtp-test up -d dns-sink',
  '  .env: RSPAMD_DNS_SERVERS=172.31.250.53, RSPAMD_RBL_PROFILE=test, RSPAMD_BAYES_MIN_LEARNS=10',
  '  (then recreate rspamd: docker compose up -d --force-recreate rspamd)',
].join('\n');

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set in .env\n${HOW_TO_START}`);
  return value;
}

export const rspamdHost = process.env.RSPAMD_IT_HOST ?? '127.0.0.1';
export const scanUrl = `http://${rspamdHost}:${process.env.RSPAMD_HOST_PORT ?? '11333'}`;
export const controllerUrl = `http://${rspamdHost}:${process.env.RSPAMD_CONTROLLER_HOST_PORT ?? '11334'}`;

export function makeClient(overrides: Partial<ConstructorParameters<typeof RspamdClient>[0]> = {}) {
  return new RspamdClient({
    baseUrl: scanUrl,
    controllerUrl,
    controllerPassword: required('RSPAMD_CONTROLLER_PASSWORD'),
    controllerEnablePassword: required('RSPAMD_CONTROLLER_ENABLE_PASSWORD'),
    timeoutMs: 20_000,
    maxInFlight: 4,
    ...overrides,
  });
}

/** Fails with an explanation when rspamd is down or not running the test profile. */
export async function requireRspamd(): Promise<void> {
  try {
    const res = await fetch(`${scanUrl}/ping`, { signal: AbortSignal.timeout(3_000) });
    if (!res.ok) throw new Error(`GET /ping -> ${res.status}`);
  } catch (error) {
    throw new Error(
      `rspamd does not answer on ${scanUrl} (${(error as Error).message})\n${HOW_TO_START}`,
    );
  }
  if (process.env.RSPAMD_RBL_PROFILE !== 'test' || !process.env.RSPAMD_DNS_SERVERS) {
    throw new Error(`rspamd is not configured with the test DNS profile\n${HOW_TO_START}`);
  }
}

export const corpusRoot = resolve(__dirname, '../../../../tests/fixtures/scan-corpus');

export interface ManifestFixture {
  file: string;
  class: string;
  description: string;
  envelope: {
    direction: RspamdEnvelope['direction'];
    ip: string;
    helo: string;
    hostname: string;
    from: string;
    rcpt: string[];
  };
  expect: {
    verdict: string;
    reasonCodes: string[];
    symbols: string[];
    absentSymbols?: string[];
    auth?: Record<string, unknown>;
    scoreRange: [number, number];
    action?: string;
    passthroughModule?: string;
  };
  calibrated: { score: number; action: string };
}

export function loadManifest(): { rspamdVersion: string; fixtures: ManifestFixture[] } {
  return JSON.parse(readFileSync(join(corpusRoot, 'manifest.json'), 'utf8')) as {
    rspamdVersion: string;
    fixtures: ManifestFixture[];
  };
}

export function toEnvelope(fixture: ManifestFixture, queueId = 'ITCORPUS1'): RspamdEnvelope {
  return {
    direction: fixture.envelope.direction,
    organizationId: 1n,
    clientIp: fixture.envelope.ip,
    clientHelo: fixture.envelope.helo,
    clientName: fixture.envelope.hostname,
    envelopeFrom: fixture.envelope.from,
    recipients: fixture.envelope.rcpt,
    queueId,
  };
}
