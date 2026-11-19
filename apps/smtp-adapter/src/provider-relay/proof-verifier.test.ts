import type { RedisService } from '@email-gateway/common';
import { DEFAULT_PROVIDER_RELAY_PROOF } from '@email-gateway/mail-routing';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  type DkimTestKey,
  generateDkimKey,
  keyRecordName,
  memoryResolver,
  signMessage,
  testMessage,
} from '../../integration/provider-relay-support/dkim';
import {
  type DkimRunResult,
  ProofVerifier,
  type ProofVerifierConfig,
  signatureIdOf,
  toSignatureEvidence,
} from './proof-verifier';

const TENANT = '11111111-2222-3333-4444-555555555555';
const config: ProofVerifierConfig = {
  PROVIDER_RELAY_DNS_SERVERS: [],
  PROVIDER_RELAY_DNS_TIMEOUT_MS: 500,
  PROVIDER_RELAY_DKIM_REPLAY_WINDOW_SECONDS: 604_800,
};

/** Redis double for the replay script: a set of queue ids per key, capped like the Lua. */
class ReplayRedis {
  readonly sets = new Map<string, Set<string>>();
  readonly ttls = new Map<string, number>();
  failing = false;
  readonly client = {
    eval: (
      _script: string,
      _keys: number,
      key: string,
      member: string,
      ttl: string,
      cap: string,
    ) => {
      if (this.failing) return Promise.reject(new Error('redis down'));
      const set = this.sets.get(key) ?? new Set<string>();
      if (set.has(member)) return Promise.resolve(set.size);
      if (set.size >= Number(cap)) return Promise.resolve(set.size + 1);
      if (set.size === 0) this.ttls.set(key, Number(ttl));
      set.add(member);
      this.sets.set(key, set);
      return Promise.resolve(set.size);
    },
  };
}

let acme: DkimTestKey;
let other: DkimTestKey;
let weak: DkimTestKey;
let edKey: DkimTestKey;
const records = new Map<string, string>();
const failing = new Set<string>();

beforeAll(() => {
  acme = generateDkimKey('acme.test');
  other = generateDkimKey('other.test');
  weak = generateDkimKey('acme.test', { selector: 'weak', bits: 768 });
  edKey = generateDkimKey('acme.test', { selector: 'ed', ed25519: true });
  for (const key of [acme, other, weak, edKey]) records.set(keyRecordName(key), key.txt);
});

function harness() {
  const redis = new ReplayRedis();
  const verifier = new ProofVerifier(
    redis as unknown as RedisService,
    config,
    memoryResolver(records, failing),
  );
  return { redis, verifier };
}

async function verifyDkim(verifier: ProofVerifier, message: string, now = new Date()) {
  const run = verifier.startDkim(now);
  const bytes = Buffer.from(message);
  // Several chunks, as the LMTP stream delivers them.
  for (let i = 0; i < bytes.length; i += 97) await run.write(bytes.subarray(i, i + 97));
  return run.finish();
}

const evidence = (now = new Date()) => ({
  provider: 'microsoft_365' as const,
  expectedTenantId: TENANT,
  tenantHeaderValues: [TENANT],
  headerFromDomain: 'acme.test',
  linkedDomains: ['acme.test'],
  headerBlockComplete: true,
  now,
});

describe('ProofVerifier: streaming DKIM through mailauth', () => {
  it('reports an aligned RSA pass with its tags', async () => {
    const { verifier } = harness();
    const signed = await signMessage(testMessage({ from: 'alice@acme.test', to: 'bob@ext.test' }), [
      acme,
    ]);
    const result = await verifyDkim(verifier, signed);
    expect(result.ok).toBe(true);
    const [signature] = (result as Extract<DkimRunResult, { ok: true }>).signatures;
    expect(signature).toMatchObject({
      status: 'pass',
      domain: 'acme.test',
      algorithm: 'rsa-sha256',
      bodyLengthLimited: false,
      keyBits: 2048,
    });
    expect(signature!.signedHeaders).toContain('from');
    expect(signature!.signedAt).toBeInstanceOf(Date);
    expect(signature!.signatureId).toMatch(/^[0-9a-f]{64}$/);
  });

  it('reports l= tags, short keys and ed25519 keys', async () => {
    const { verifier } = harness();
    const message = testMessage({ from: 'alice@acme.test', to: 'bob@ext.test' });
    const limited = await verifyDkim(
      verifier,
      await signMessage(message, [acme], { maxBodyLength: 5 }),
    );
    expect(limited.ok && limited.signatures[0]!.bodyLengthLimited).toBe(true);
    const short = await verifyDkim(verifier, await signMessage(message, [weak]));
    // mailauth refuses keys under 1024 bits (policy result), never a pass.
    expect(short.ok && short.signatures[0]!.status).not.toBe('pass');
    const ed = await verifyDkim(verifier, await signMessage(message, [edKey]));
    expect(ed.ok && ed.signatures[0]).toMatchObject({
      status: 'pass',
      algorithm: 'ed25519-sha256',
      keyBits: null,
    });
  });

  it('an unsigned message has no signatures; a DNS failure is temperror', async () => {
    const { verifier } = harness();
    const message = testMessage({ from: 'alice@acme.test', to: 'bob@ext.test' });
    expect(await verifyDkim(verifier, message)).toEqual({ ok: true, signatures: [] });
    failing.add(keyRecordName(acme));
    try {
      const result = await verifyDkim(verifier, await signMessage(message, [acme]));
      expect(result.ok && result.signatures[0]!.status).toBe('temperror');
    } finally {
      failing.clear();
    }
  });

  it('an aborted run reports aborted', async () => {
    const { verifier } = harness();
    const run = verifier.startDkim(new Date());
    await run.write(Buffer.from('From: a@acme.test\r\n'));
    run.abort();
    expect(await run.finish()).toEqual({ ok: false, reason: 'aborted' });
  });

  it('hashes b= without whitespace for the replay key', () => {
    expect(signatureIdOf('ab c\r\n d')).toBe(signatureIdOf('abcd'));
    expect(toSignatureEvidence([{ status: { result: 'none' } }])).toEqual([]);
  });
});

describe('ProofVerifier.evaluate', () => {
  it('passes a Microsoft 365 message with tenant header and aligned DKIM', async () => {
    const { verifier } = harness();
    const signed = await signMessage(testMessage({ from: 'alice@acme.test', to: 'bob@ext.test' }), [
      acme,
    ]);
    const outcome = await verifier.evaluate({
      evidence: evidence(),
      policy: DEFAULT_PROVIDER_RELAY_PROOF.microsoft_365,
      dkim: await verifyDkim(verifier, signed),
      queueId: 'Q1',
    });
    expect(outcome).toMatchObject({ result: 'pass', tenantHeader: 'match', dkim: 'aligned_pass' });
  });

  it('fails a signature of another domain and a tampered body', async () => {
    const { verifier } = harness();
    const message = testMessage({ from: 'alice@acme.test', to: 'bob@ext.test' });
    const foreign = await verifier.evaluate({
      evidence: evidence(),
      policy: DEFAULT_PROVIDER_RELAY_PROOF.microsoft_365,
      dkim: await verifyDkim(verifier, await signMessage(message, [other])),
      queueId: 'Q1',
    });
    expect(foreign).toMatchObject({ result: 'fail', failureCode: 'dkim_unaligned' });
    const tampered = (await signMessage(message, [acme])).replace('please find', 'please wire');
    const outcome = await verifier.evaluate({
      evidence: evidence(),
      policy: DEFAULT_PROVIDER_RELAY_PROOF.microsoft_365,
      dkim: await verifyDkim(verifier, tampered),
      queueId: 'Q1',
    });
    expect(outcome.result).toBe('fail');
  });

  it('a verifier error is temperror', async () => {
    const { verifier } = harness();
    const outcome = await verifier.evaluate({
      evidence: evidence(),
      policy: DEFAULT_PROVIDER_RELAY_PROOF.microsoft_365,
      dkim: { ok: false, reason: 'verifier_error' },
      queueId: 'Q1',
    });
    expect(outcome).toMatchObject({ result: 'temperror', failureCode: 'verifier_error' });
  });

  describe('Google replay counter', () => {
    const google = (now: Date) => ({
      ...evidence(now),
      provider: 'google_workspace' as const,
      expectedTenantId: 'C01abcdef',
      tenantHeaderValues: [],
    });

    it('accepts five queue files with one signature and refuses the sixth; a retry never counts', async () => {
      const { verifier, redis } = harness();
      const now = new Date();
      const signed = await signMessage(
        testMessage({ from: 'alice@acme.test', to: 'bob@ext.test' }),
        [acme],
        { signTime: now },
      );
      const dkim = await verifyDkim(verifier, signed, now);
      const run = (queueId: string) =>
        verifier.evaluate({
          evidence: google(now),
          policy: DEFAULT_PROVIDER_RELAY_PROOF.google_workspace,
          dkim,
          queueId,
        });
      for (const queueId of ['Q1', 'Q2', 'Q3', 'Q4', 'Q5']) {
        expect((await run(queueId)).result).toBe('pass');
      }
      expect((await run('Q1')).result).toBe('pass');
      expect(await run('Q6')).toMatchObject({ result: 'fail', dkim: 'replayed' });
      expect(await run('Q7')).toMatchObject({ result: 'fail', dkim: 'replayed' });
      expect(redis.sets.size).toBe(1);
      const [key, members] = [...redis.sets][0]!;
      expect(key).toMatch(/^sa:prelay:dkim:[0-9a-f]{64}$/);
      // The set stops growing one above the cap.
      expect(members.size).toBe(6);
      expect(redis.ttls.get(key)).toBe(604_800);
    });

    it('a stale signature never touches the counter; a Redis error is temperror', async () => {
      const { verifier, redis } = harness();
      const now = new Date();
      const old = new Date(now.getTime() - 2 * 3600_000);
      const message = testMessage({ from: 'alice@acme.test', to: 'bob@ext.test' });
      const stale = await verifier.evaluate({
        evidence: google(now),
        policy: DEFAULT_PROVIDER_RELAY_PROOF.google_workspace,
        dkim: await verifyDkim(
          verifier,
          await signMessage(message, [acme], { signTime: old }),
          now,
        ),
        queueId: 'Q1',
      });
      expect(stale).toMatchObject({ result: 'fail', dkim: 'stale' });
      expect(redis.sets.size).toBe(0);
      redis.failing = true;
      const down = await verifier.evaluate({
        evidence: google(now),
        policy: DEFAULT_PROVIDER_RELAY_PROOF.google_workspace,
        dkim: await verifyDkim(
          verifier,
          await signMessage(message, [acme], { signTime: now }),
          now,
        ),
        queueId: 'Q2',
      });
      expect(down).toMatchObject({ result: 'temperror', failureCode: 'replay_counter_error' });
    });
  });
});
