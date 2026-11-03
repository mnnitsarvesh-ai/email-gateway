import { composeExec, waitFor } from './compose';

/**
 * Reader for the TEST-ONLY `mail-sink` (Compose profile smtp-test): it stores every accepted
 * message as a Maildir file under /var/mail/sink/<domain>/<local>/new/.
 */
const SINK = 'mail-sink';
const DOMAIN = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+test$/;
const LOCAL = /^[a-z0-9][a-z0-9._+=-]{0,63}$/;

function mailbox(address: string): string {
  const at = address.lastIndexOf('@');
  const local = address.slice(0, at).toLowerCase();
  const domain = address.slice(at + 1).toLowerCase();
  if (!LOCAL.test(local) || !DOMAIN.test(domain)) throw new Error(`not a sink address: ${address}`);
  return `/var/mail/sink/${domain}/${local}`;
}

/** Paths of the stored messages of `address` (empty when none). */
export async function sinkFiles(address: string): Promise<string[]> {
  const dir = `${mailbox(address)}/new`;
  const result = await composeExec(SINK, ['find', dir, '-type', 'f'], { timeoutMs: 20_000 });
  if (result.exitCode !== 0) return [];
  return result.stdout.split('\n').filter((line) => line.startsWith('/var/mail/sink/'));
}

/** Raw bytes of one stored message. */
export async function sinkMessage(path: string): Promise<Buffer> {
  if (!/^\/var\/mail\/sink\/[a-z0-9.-]+\/[a-z0-9._+=-]+\/new\/[A-Za-z0-9.]+$/.test(path)) {
    throw new Error(`unexpected sink path ${path}`);
  }
  const result = await composeExec(SINK, ['base64', '-w0', path], { timeoutMs: 20_000 });
  if (result.exitCode !== 0) throw new Error(`cannot read ${path}: ${result.stderr}`);
  return Buffer.from(result.stdout.trim(), 'base64');
}

/** Waits until `address` has at least one stored message; returns the first one's bytes. */
export async function waitForSinkMessage(address: string, timeoutMs = 90_000): Promise<Buffer> {
  const path = await waitFor(
    `mail-sink delivery to ${address}`,
    async () => (await sinkFiles(address))[0],
    { timeoutMs, intervalMs: 1_000 },
  );
  return sinkMessage(path);
}

/** Removes every stored message of a sink domain. */
export async function clearSinkDomain(domain: string): Promise<void> {
  const name = domain.toLowerCase();
  if (!DOMAIN.test(name)) throw new Error(`not a sink domain: ${domain}`);
  await composeExec(SINK, ['rm', '-rf', `/var/mail/sink/${name}`], { timeoutMs: 20_000 });
}
