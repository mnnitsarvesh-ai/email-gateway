import { createHmac, hkdfSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  canonicalJson,
  openResultToken,
  resultMac,
  SEALED_RESULT_TOKEN_PATTERN,
  sealResultToken,
  verifyResultMac,
} from './result-mac';
import { SandboxEnvelopeError } from './envelope/errors';
import { SandboxKeyError } from './keys';

const KEY = 'c3'.repeat(32);
const TASK = '01890a5d-ac96-774b-bcce-b302099a8070';
const OTHER_TASK = '01890a5d-ac96-774b-bcce-b302099a8071';
const payload = {
  taskId: TASK,
  analysisId: '42',
  sampleSha256: 'a'.repeat(64),
  resultMac: '0'.repeat(64),
  status: 'completed',
  backend: 'static',
  isolation: 'process',
  executed: false,
  durationMs: 1500,
  observations: { findings: [{ code: 'static.macro_autoexec', severity: 'high', count: 1 }] },
  artifacts: [{ seq: 0, key: 'k', wrappedKey: 'x1.k1.a.b.c.d' }],
};
const input = { organizationId: '7', tokenSha256: 'b'.repeat(64), payload };

const macSubkey = () =>
  Buffer.from(
    hkdfSync('sha256', Buffer.from(KEY, 'hex'), Buffer.alloc(0), 'eg-sandbox-result/v2 mac', 32),
  );

describe('result token (X11: one-time, per task, sealed)', () => {
  it('seals a fresh token per call; only the controller-side key opens it, to its SHA-256', () => {
    const a = sealResultToken(KEY, TASK);
    const b = sealResultToken(KEY, TASK);
    expect(a.sealed).toMatch(SEALED_RESULT_TOKEN_PATTERN);
    expect(a.tokenSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(a.tokenSha256).not.toBe(b.tokenSha256);
    expect(a.sealed).not.toBe(b.sealed);
    expect(openResultToken(KEY, TASK, a.sealed)).toBe(a.tokenSha256);
    expect(openResultToken(Buffer.from(KEY, 'hex'), TASK, b.sealed)).toBe(b.tokenSha256);
  });

  it('is bound to the task id and the key, and refuses tampering and malformed tokens', () => {
    const { sealed } = sealResultToken(KEY, TASK);
    const fail = (fn: () => unknown, reason: string) => {
      try {
        fn();
        expect.unreachable();
      } catch (error) {
        expect(error).toBeInstanceOf(SandboxEnvelopeError);
        expect((error as SandboxEnvelopeError).reason).toBe(reason);
      }
    };
    fail(() => openResultToken(KEY, OTHER_TASK, sealed), 'unauthentic');
    fail(() => openResultToken('d4'.repeat(32), TASK, sealed), 'unauthentic');
    const parts = sealed.split('.');
    const flip = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
    for (const i of [1, 2, 3]) {
      const tampered = [...parts];
      tampered[i] = flip(tampered[i]!);
      fail(() => openResultToken(KEY, TASK, tampered.join('.')), 'unauthentic');
    }
    for (const bad of ['', 't2' + sealed.slice(2), `${sealed}A`, sealed.replace(/\./g, '-')]) {
      fail(() => openResultToken(KEY, TASK, bad), 'malformed');
    }
    fail(() => openResultToken(KEY, 'not-a-task', sealed), 'malformed');
    fail(() => sealResultToken(KEY, 'not-a-task'), 'malformed');
    expect(() => sealResultToken('short', TASK)).toThrow(SandboxKeyError);
  });
});

describe('canonicalJson', () => {
  it('sorts keys at every level, keeps array order, omits undefined members', () => {
    expect(canonicalJson({ b: 1, a: [{ d: null, c: 'x' }, 2], u: undefined })).toBe(
      '{"a":[{"c":"x","d":null},2],"b":1}',
    );
    expect(canonicalJson({ a: 1, b: 2 })).toBe(canonicalJson({ b: 2, a: 1 }));
    expect(canonicalJson(JSON.parse(JSON.stringify(payload)))).toBe(canonicalJson(payload));
  });

  it('refuses non-JSON values', () => {
    for (const bad of [Number.NaN, Infinity, 1n, () => 1, new Date(0), Symbol('s')]) {
      expect(() => canonicalJson({ a: bad })).toThrow('Invalid result MAC input');
    }
  });
});

describe('result MAC (X11: whole result, token, organization)', () => {
  it('is HMAC-SHA256 under the HKDF mac subkey over the documented message, in hex', () => {
    const { resultMac: _m, ...body } = payload;
    const expected = createHmac('sha256', macSubkey())
      .update(`eg-sandbox-result/v2\0${'b'.repeat(64)}\x007\0${canonicalJson(body)}`)
      .digest('hex');
    expect(resultMac(KEY, input)).toBe(expected);
    expect(resultMac(Buffer.from(KEY, 'hex'), input)).toBe(expected);
    // The resultMac member itself is not covered (it carries the MAC).
    expect(resultMac(KEY, { ...input, payload: { ...payload, resultMac: 'f'.repeat(64) } })).toBe(
      expected,
    );
    // The seal subkey is not the MAC key.
    expect(expected).not.toBe(
      createHmac('sha256', Buffer.from(KEY, 'hex'))
        .update(`eg-sandbox-result/v2\0${'b'.repeat(64)}\x007\0${canonicalJson(body)}`)
        .digest('hex'),
    );
  });

  it('binds every field of the body, the token hash, the organization and the key', () => {
    const mac = resultMac(KEY, input);
    expect(verifyResultMac(KEY, input, mac)).toBe(true);
    // Key order of the body does not matter (JSON transport).
    const reordered = Object.fromEntries(Object.entries(payload).reverse());
    expect(verifyResultMac(KEY, { ...input, payload: reordered }, mac)).toBe(true);
    const variants: Record<string, unknown>[] = [
      { ...payload, status: 'not_executed' },
      { ...payload, backend: 'vm' },
      { ...payload, isolation: 'vm' },
      { ...payload, executed: true },
      { ...payload, durationMs: 30_000 },
      { ...payload, analysisId: '43' },
      { ...payload, sampleSha256: 'c'.repeat(64) },
      { ...payload, observations: { findings: [] } },
      { ...payload, artifacts: [] },
      { ...payload, artifacts: [{ seq: 0, key: 'k', wrappedKey: 'x1.k1.a.b.c.e' }] },
      { ...payload, extra: true },
    ];
    for (const body of variants) {
      expect(verifyResultMac(KEY, { ...input, payload: body }, mac)).toBe(false);
    }
    expect(verifyResultMac(KEY, { ...input, organizationId: '8' }, mac)).toBe(false);
    expect(verifyResultMac(KEY, { ...input, tokenSha256: 'c'.repeat(64) }, mac)).toBe(false);
    expect(verifyResultMac('d4'.repeat(32), input, mac)).toBe(false);
  });

  it('binds the token: a fresh token per task gives a different MAC for the same body', () => {
    const one = sealResultToken(KEY, TASK);
    const two = sealResultToken(KEY, TASK);
    const mac = resultMac(KEY, { ...input, tokenSha256: one.tokenSha256 });
    expect(
      verifyResultMac(KEY, { ...input, tokenSha256: openResultToken(KEY, TASK, one.sealed) }, mac),
    ).toBe(true);
    expect(verifyResultMac(KEY, { ...input, tokenSha256: two.tokenSha256 }, mac)).toBe(false);
  });

  it('rejects malformed MACs and inputs without throwing, and refuses a bad key', () => {
    const mac = resultMac(KEY, input);
    for (const bad of [
      '',
      mac.toUpperCase(),
      mac.slice(0, 63),
      `${mac}0`,
      'z'.repeat(64),
      undefined,
    ]) {
      expect(verifyResultMac(KEY, input, bad as never)).toBe(false);
    }
    for (const bad of [
      { ...input, organizationId: '0' },
      { ...input, organizationId: '7\0' },
      { ...input, tokenSha256: 'B'.repeat(64) },
      { ...input, tokenSha256: '' },
      { ...input, payload: null as never },
      { ...input, payload: [] as never },
      { ...input, payload: { ...payload, durationMs: Number.NaN } },
    ]) {
      expect(verifyResultMac(KEY, bad, mac)).toBe(false);
    }
    expect(() => resultMac('short', input)).toThrow(SandboxKeyError);
    expect(() => verifyResultMac('short', input, mac)).toThrow(SandboxKeyError);
    expect(() => resultMac(KEY, { ...input, organizationId: 'x' })).toThrow(
      'Invalid result MAC input',
    );
  });
});
