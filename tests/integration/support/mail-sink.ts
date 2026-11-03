import { composeExec, waitFor } from './compose';

/**
 * Reader for the TEST-ONLY sinks (Compose profile smtp-test): each stores every accepted message
 * as a Maildir file under /var/mail/sink/<domain>/<local>/new/ inside its own container.
 * `mail-sink` is `mx.sink.test` (step 2.2); step 2.3 adds `sink-m365`
 * (`*.mail.protection.outlook.com`), `sink-google` (`aspmx.l` / `alt2`–`alt4.aspmx.l.google.com`)
 * and `sink-google-alt` (`alt1.aspmx.l.google.com`), the same image with other identities.
 */
export type SinkService = 'mail-sink' | 'sink-m365' | 'sink-google' | 'sink-google-alt';

export const SINK_SERVICES: readonly SinkService[] = [
  'mail-sink',
  'sink-m365',
  'sink-google',
  'sink-google-alt',
];

const DOMAIN = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+test$/;
const LOCAL = /^[a-z0-9][a-z0-9._+=-]{0,63}$/;

function mailbox(address: string): string {
  const at = address.lastIndexOf('@');
  const local = address.slice(0, at).toLowerCase();
  const domain = address.slice(at + 1).toLowerCase();
  if (!LOCAL.test(local) || !DOMAIN.test(domain)) throw new Error(`not a sink address: ${address}`);
  return `/var/mail/sink/${domain}/${local}`;
}

/** Paths of the stored messages of `address` in `service` (empty when none). */
export async function sinkFiles(
  address: string,
  service: SinkService = 'mail-sink',
): Promise<string[]> {
  const dir = `${mailbox(address)}/new`;
  const result = await composeExec(service, ['find', dir, '-type', 'f'], { timeoutMs: 20_000 });
  if (result.exitCode !== 0) return [];
  return result.stdout.split('\n').filter((line) => line.startsWith('/var/mail/sink/'));
}

/** Raw bytes of one stored message. */
export async function sinkMessage(
  path: string,
  service: SinkService = 'mail-sink',
): Promise<Buffer> {
  if (!/^\/var\/mail\/sink\/[a-z0-9.-]+\/[a-z0-9._+=-]+\/new\/[A-Za-z0-9.,:=_-]+$/.test(path)) {
    throw new Error(`unexpected sink path ${path}`);
  }
  const result = await composeExec(service, ['base64', '-w0', path], { timeoutMs: 20_000 });
  if (result.exitCode !== 0) throw new Error(`cannot read ${path}: ${result.stderr}`);
  return Buffer.from(result.stdout.trim(), 'base64');
}

/** Waits until `address` has at least one stored message; returns the first one's bytes. */
export async function waitForSinkMessage(
  address: string,
  timeoutMs = 90_000,
  service: SinkService = 'mail-sink',
): Promise<Buffer> {
  const path = await waitFor(
    `${service} delivery to ${address}`,
    async () => (await sinkFiles(address, service))[0],
    { timeoutMs, intervalMs: 1_000 },
  );
  return sinkMessage(path, service);
}

/** Every stored message of `address` in `service`. */
export async function sinkMessages(
  address: string,
  service: SinkService = 'mail-sink',
): Promise<Buffer[]> {
  const files = await sinkFiles(address, service);
  return Promise.all(files.map((path) => sinkMessage(path, service)));
}

/** Removes every stored message of a sink domain (in one sink, or in every sink). */
export async function clearSinkDomain(
  domain: string,
  service: SinkService | 'all' = 'mail-sink',
): Promise<void> {
  const name = domain.toLowerCase();
  if (!DOMAIN.test(name)) throw new Error(`not a sink domain: ${domain}`);
  for (const sink of service === 'all' ? SINK_SERVICES : [service]) {
    await composeExec(sink, ['rm', '-rf', `/var/mail/sink/${name}`], { timeoutMs: 20_000 });
  }
}
