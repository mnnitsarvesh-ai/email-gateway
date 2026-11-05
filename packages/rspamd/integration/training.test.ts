import { createHash, randomBytes } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { normalizeReply, RspamdHttpError, type RspamdEnvelope } from '../src';
import { makeClient, requireRspamd } from './support/env';

/**
 * Bayes learning and fuzzy add/delete round trips through the controller of the real rspamd.
 * Every run uses fresh random tokens, so repeated runs stay valid on the shared statfiles and
 * fuzzy storage (Redis DB RSPAMD_REDIS_DB); local min_learns is 10 (test only).
 */
const client = makeClient();
const run = randomBytes(5).toString('hex');

const envelope: RspamdEnvelope = {
  direction: 'inbound',
  organizationId: 1n,
  clientIp: '198.51.100.60',
  clientHelo: 'mail.spam-sender.scan.test',
  clientName: 'mail.spam-sender.scan.test',
  envelopeFrom: 'trainer@spam-sender.scan.test',
  recipients: ['bob@customer.scan.test'],
  queueId: 'ITTRAIN1',
};

/**
 * Text over a small per-run vocabulary (eight words). Rspamd's OSB tokenizer hashes word pairs,
 * so a small vocabulary makes the training and probe messages share most tokens.
 */
function words(vocabulary: string, count: number, seed: number): string {
  const out: string[] = [];
  let x = seed + 1;
  for (let i = 0; i < count; i += 1) {
    x = (x * 1103515245 + 12345) % 2147483648;
    out.push(`${vocabulary}${'abcdefgh'[(x >> 16) % 8]}`);
  }
  return out.join(' ');
}

/** Headers are identical apart from opaque ids, so only the body tokens differ by class. */
function message(tag: string, body: string): Buffer {
  const id = createHash('sha256').update(tag).digest('hex').slice(0, 24);
  const text = [
    `From: Trainer <trainer@spam-sender.scan.test>`,
    `To: bob@customer.scan.test`,
    `Subject: note ${id}`,
    `Date: Sun, 01 Nov 2026 10:00:00 +0000`,
    `Message-ID: <${id}@spam-sender.scan.test>`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=utf-8`,
    ``,
    body.replace(/(.{1,72})(\s|$)/g, '$1\r\n'),
  ].join('\r\n');
  return Buffer.from(text);
}

async function scan(body: Buffer) {
  const result = await client.check({
    body,
    sizeBytes: body.length,
    envelope,
    logTag: `ittrain-${run}`,
  });
  return normalizeReply(result.reply);
}

async function eventually<T>(
  probe: () => Promise<T>,
  done: (value: T) => boolean,
  timeoutMs = 30_000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let value = await probe();
  while (!done(value) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    value = await probe();
  }
  return value;
}

beforeAll(requireRspamd);

describe('Bayes learning', () => {
  it('learns spam and ham, refuses a duplicate learn, then classifies a similar message as spam', async () => {
    // Each training message uses its own vocabulary, so Rspamd's learn condition (skip when
    // already >= 95% in the class) never skips it; the probes mix chunks of every vocabulary.
    const spamVocabulary = (i: number) => `zq${run}q${i}x`;
    const hamVocabulary = (i: number) => `kv${run}v${i}x`;
    for (let i = 0; i < 10; i += 1) {
      const spam = message(`spam-${run}-${i}`, words(spamVocabulary(i), 80, i));
      await expect(client.learn('spam', spam, spam.length)).resolves.toBe('learned');
      const ham = message(`ham-${run}-${i}`, words(hamVocabulary(i), 80, i + 100));
      await expect(client.learn('ham', ham, ham.length)).resolves.toBe('learned');
    }
    const again = message(`spam-${run}-0`, words(spamVocabulary(0), 80, 0));
    await expect(client.learn('spam', again, again.length)).resolves.toBe('already_learned');

    const mix = (vocabulary: (i: number) => string, seed: number) =>
      Array.from({ length: 10 }, (_, i) => words(vocabulary(i), 12, seed + i)).join(' ');
    const result = await scan(message(`probe-${run}`, mix(spamVocabulary, 500)));
    const bayes = result.symbols.find((s) => s.name === 'BAYES_SPAM');
    expect(bayes, 'BAYES_SPAM after training').toBeDefined();
    expect(bayes!.score).toBeGreaterThan(0);
    expect(result.symbols.some((s) => s.name === 'BAYES_HAM')).toBe(false);

    const hamProbe = await scan(message(`hamprobe-${run}`, mix(hamVocabulary, 700)));
    expect(hamProbe.symbols.some((s) => s.name === 'BAYES_HAM')).toBe(true);
    expect(hamProbe.symbols.some((s) => s.name === 'BAYES_SPAM')).toBe(false);
  });

  it('refuses learning with the read password', async () => {
    const readOnly = makeClient({
      controllerEnablePassword: process.env.RSPAMD_CONTROLLER_PASSWORD,
    });
    const body = message(`ro-${run}`, words(`ro${run}`, 40, 1));
    const error = await readOnly.learn('spam', body, body.length).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RspamdHttpError);
    expect((error as RspamdHttpError).status).toBe(401);
    expect((error as Error).message).not.toContain(process.env.RSPAMD_CONTROLLER_PASSWORD!);
  });
});

describe('fuzzy hashes', () => {
  it.each([
    [11, 'EG_FUZZY_SPAM'],
    [12, 'EG_FUZZY_PHISH'],
  ] as const)('flag %i: add -> %s, delete -> gone', async (flag, symbol) => {
    const body = message(`fuzzy-${flag}-${run}`, words(`fz${run}f${flag}`, 160, flag));
    const before = await scan(body);
    expect(before.symbols.some((s) => s.name === symbol)).toBe(false);

    await expect(client.fuzzy('add', flag, 10, body, body.length)).resolves.toMatchObject({
      result: 'added',
    });
    const added = await eventually(
      () => scan(body),
      (r) => r.symbols.some((s) => s.name === symbol),
    );
    const hit = added.symbols.find((s) => s.name === symbol);
    expect(hit, `${symbol} after fuzzyadd`).toBeDefined();
    expect(hit!.score).toBeGreaterThan(0);
    expect(hit!.options[0]).toMatch(new RegExp(`^${flag}:`));

    await expect(client.fuzzy('delete', flag, 10, body, body.length)).resolves.toMatchObject({
      result: 'deleted',
    });
    const deleted = await eventually(
      () => scan(body),
      (r) => !r.symbols.some((s) => s.name === symbol),
    );
    expect(deleted.symbols.some((s) => s.name === symbol)).toBe(false);
  });

  it('answers 404 for a message without hashable content', async () => {
    const body = Buffer.from('Subject: x\r\n\r\nshort\r\n');
    const error = await client.fuzzy('add', 11, 10, body, body.length).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RspamdHttpError);
    expect((error as RspamdHttpError).status).toBe(404);
  });
});
