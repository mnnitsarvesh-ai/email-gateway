import { createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { generateWebhookSecret, signatureHeader } from '@email-gateway/webhooks';
import { describe, expect, it } from 'vitest';

/**
 * The Node.js verification snippet of the API guide (docs/api/README.md, between the
 * `webhook-verify-snippet` markers; step 6.2 §4.2), executed as published against the
 * platform's signer (`signatureHeader` of @email-gateway/webhooks), so the guide cannot drift
 * from the delivery contract.
 */
type Verify = (
  rawBody: Buffer,
  header: string | undefined,
  secrets: string[],
  toleranceSeconds?: number,
  nowMs?: number,
) => boolean;

function loadSnippet(): Verify {
  const guide = readFileSync(resolve(__dirname, '../../../../../docs/api/README.md'), 'utf8');
  const block =
    /<!-- webhook-verify-snippet:start -->\s*```js\n([\s\S]*?)```\s*<!-- webhook-verify-snippet:end -->/.exec(
      guide,
    );
  if (!block) throw new Error('verification snippet not found in docs/api/README.md');
  const source = block[1]!;
  expect(source).toContain("import { createHmac, timingSafeEqual } from 'node:crypto';");
  // Only node:crypto is imported; run the module body with exactly those two functions.
  const body = source
    .replace("import { createHmac, timingSafeEqual } from 'node:crypto';", '')
    .replace('export function', 'function');
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  const factory = new Function(
    'createHmac',
    'timingSafeEqual',
    'Buffer',
    `${body}\nreturn verifyEmailGatewayWebhook;`,
  ) as (...args: unknown[]) => Verify;
  return factory(createHmac, timingSafeEqual, Buffer);
}

describe('API guide: webhook verification snippet (step 6.2 §4.2)', () => {
  const verify = loadSnippet();
  const secret = generateWebhookSecret();
  const other = generateWebhookSecret();
  const body = Buffer.from(JSON.stringify({ id: 'e1', type: 'webhook.ping', data: { x: 'é' } }));
  const now = 1_763_025_243_000;
  const t = Math.floor(now / 1000);

  it('accepts a signature of the platform signer and rejects a tampered body or a wrong secret', () => {
    const header = signatureHeader([secret], t, body);
    expect(verify(body, header, [secret], 300, now)).toBe(true);
    expect(verify(Buffer.from(`${body.toString()} `), header, [secret], 300, now)).toBe(false);
    expect(verify(body, header, [other], 300, now)).toBe(false);
  });

  it('rejects stale and future timestamps beyond 300 s', () => {
    const header = signatureHeader([secret], t, body);
    expect(verify(body, header, [secret], 300, now + 300_000)).toBe(true);
    expect(verify(body, header, [secret], 300, now + 301_000)).toBe(false);
    expect(verify(body, header, [secret], 300, now - 301_000)).toBe(false);
  });

  it('accepts either signature during a rotation overlap (two v1), with old or new secret', () => {
    const header = signatureHeader([secret, other], t, body);
    expect(header.split(',v1=')).toHaveLength(3);
    expect(verify(body, header, [secret], 300, now)).toBe(true);
    expect(verify(body, header, [other], 300, now)).toBe(true);
    expect(verify(body, header, [generateWebhookSecret()], 300, now)).toBe(false);
  });

  it('rejects malformed headers', () => {
    for (const header of [undefined, '', 't=1', 'v1=abc', `t=x,v1=${'a'.repeat(64)}`, 'garbage']) {
      expect(verify(body, header, [secret], 300, now), String(header)).toBe(false);
    }
  });
});
