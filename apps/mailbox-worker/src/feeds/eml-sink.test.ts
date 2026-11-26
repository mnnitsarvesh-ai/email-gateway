import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { MeteredBody } from './eml-sink';

async function* chunks(...parts: string[]) {
  for (const part of parts) {
    await Promise.resolve();
    yield Buffer.from(part);
  }
}

async function drain(source: AsyncIterable<Uint8Array>) {
  const out: Buffer[] = [];
  for await (const chunk of source) out.push(Buffer.from(chunk));
  return Buffer.concat(out).toString();
}

describe('MeteredBody', () => {
  it('passes the bytes on with size, SHA-256 and the head', async () => {
    const metered = new MeteredBody(100, 5);
    expect(await drain(metered.pipe(chunks('abc', 'defg', 'h')))).toBe('abcdefgh');
    const result = metered.result();
    expect(result.sizeBytes).toBe(8);
    expect(result.sha256).toBe(createHash('sha256').update('abcdefgh').digest('hex'));
    expect(Buffer.from(result.head).toString()).toBe('abcde');
  });

  it('fails response_too_large above the cap', async () => {
    const metered = new MeteredBody(4, 2);
    await expect(drain(metered.pipe(chunks('abc', 'de')))).rejects.toMatchObject({
      code: 'response_too_large',
    });
  });
});
