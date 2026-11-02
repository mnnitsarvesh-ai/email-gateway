import { describe, expect, it } from 'vitest';
import { canonicalizeArgon2Hash, PasswordHasher } from './password-hasher';

const config = {
  AUTH_ARGON2_MEMORY_KIB: 19456,
  AUTH_ARGON2_TIME_COST: 2,
  AUTH_ARGON2_PARALLELISM: 1,
};

describe('PasswordHasher', () => {
  const hasher = new PasswordHasher(config);

  it('hashes with Argon2id and the OWASP parameters, in reference parameter order', async () => {
    const hash = await hasher.hash('correct horse battery');
    expect(hash.startsWith('$argon2id$v=19$m=19456,t=2,p=1$')).toBe(true);
    expect(hash).not.toContain('correct horse battery');
  });

  it('salts every hash', async () => {
    expect(await hasher.hash('same password!')).not.toBe(await hasher.hash('same password!'));
  });

  it('verifies the right password only', async () => {
    const hash = await hasher.hash('correct horse battery');
    expect(await hasher.verify(hash, 'correct horse battery')).toBe(true);
    expect(await hasher.verify(hash, 'Correct horse battery')).toBe(false);
  });

  it('compares NFKC-normalized passwords', async () => {
    const composed = 'café au lait 123';
    const decomposed = 'café au lait 123';
    expect(await hasher.verify(await hasher.hash(composed), decomposed)).toBe(true);
  });

  it.each([null, undefined, '', 'not-a-hash', '$argon2id$garbage', '$2b$10$bcrypthashvalue'])(
    'returns false (never throws) for the stored hash %j',
    async (stored) => {
      await expect(hasher.verify(stored, 'whatever')).resolves.toBe(false);
    },
  );

  it('flags hashes made with weaker parameters for rehash', async () => {
    const stronger = new PasswordHasher({ ...config, AUTH_ARGON2_TIME_COST: 3 });
    const hash = await hasher.hash('rehash me please');
    expect(hasher.needsRehash(hash)).toBe(false);
    expect(stronger.needsRehash(hash)).toBe(true);
    expect(hasher.needsRehash('$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaA')).toBe(true);
    expect(hasher.needsRehash('garbage')).toBe(true);
  });

  it('verifyDummy runs a verification and always fails', async () => {
    await hasher.onModuleInit();
    await expect(hasher.verifyDummy('anything at all')).resolves.toBe(false);
  });
});

describe('canonicalizeArgon2Hash', () => {
  it('reorders m,p,t to m,t,p and leaves the rest untouched', () => {
    expect(canonicalizeArgon2Hash('$argon2id$v=19$m=19456,p=1,t=2$c2FsdA$aGFzaA')).toBe(
      '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA',
    );
    expect(canonicalizeArgon2Hash('$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA')).toBe(
      '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA',
    );
    expect(canonicalizeArgon2Hash('other')).toBe('other');
  });
});
