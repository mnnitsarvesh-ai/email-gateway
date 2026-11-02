import { randomBytes } from 'node:crypto';
import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import * as argon2 from 'argon2';
import { API_CONFIG } from '../api-config.token';
import type { ApiConfig } from '../config';

export type PasswordHasherConfig = Pick<
  ApiConfig,
  'AUTH_ARGON2_MEMORY_KIB' | 'AUTH_ARGON2_TIME_COST' | 'AUTH_ARGON2_PARALLELISM'
>;

const PHC_PARAMS = /^(\$argon2id\$v=\d+\$)([^$]+)(\$.*)$/;

/**
 * Rewrites the parameter segment in the reference order `m=…,t=…,p=…`. The `argon2` package
 * (0.44+) serializes it as `m,p,t`, which the reference implementation (libargon2 and the
 * libraries built on it) refuses to parse. Both orders verify with `argon2`.
 */
export function canonicalizeArgon2Hash(hash: string): string {
  const match = PHC_PARAMS.exec(hash);
  if (!match) return hash;
  const [, head, params, tail] = match as unknown as [string, string, string, string];
  const values = new Map(
    params.split(',').map((kv) => kv.split('=', 2) as [string, string | undefined]),
  );
  const m = values.get('m');
  const t = values.get('t');
  const p = values.get('p');
  if (!m || !t || !p || values.size !== 3) return hash;
  return `${head}m=${m},t=${t},p=${p}${tail}`;
}

/** NIST SP 800-63B: compare passwords after Unicode NFKC normalization. */
export function normalizePassword(password: string): string {
  return password.normalize('NFKC');
}

/**
 * Argon2id password hashing with the OWASP parameters from config (D4). `verify` never throws
 * for a malformed stored hash; `verifyDummy` spends the same time as a real verification so
 * unknown and passwordless accounts are indistinguishable by timing.
 */
@Injectable()
export class PasswordHasher implements OnModuleInit {
  private readonly params: { memoryCost: number; timeCost: number; parallelism: number };
  private dummyHash: Promise<string> | undefined;

  constructor(@Inject(API_CONFIG) config: PasswordHasherConfig) {
    this.params = {
      memoryCost: config.AUTH_ARGON2_MEMORY_KIB,
      timeCost: config.AUTH_ARGON2_TIME_COST,
      parallelism: config.AUTH_ARGON2_PARALLELISM,
    };
  }

  /** Precomputes the dummy hash at startup so the first unknown-user login is not faster. */
  async onModuleInit(): Promise<void> {
    await this.getDummyHash();
  }

  async hash(password: string): Promise<string> {
    const hash = await argon2.hash(normalizePassword(password), {
      type: argon2.argon2id,
      ...this.params,
    });
    return canonicalizeArgon2Hash(hash);
  }

  async verify(hash: string | null | undefined, password: string): Promise<boolean> {
    if (typeof hash !== 'string' || !hash.startsWith('$argon2')) return false;
    try {
      return await argon2.verify(hash, normalizePassword(password));
    } catch {
      return false;
    }
  }

  /** True when the stored hash is not Argon2id with the current parameters. */
  needsRehash(hash: string): boolean {
    if (!hash.startsWith('$argon2id$')) return true;
    try {
      return argon2.needsRehash(hash, this.params);
    } catch {
      return true;
    }
  }

  /** Runs one verification against a fixed hash and always resolves false. */
  async verifyDummy(password: string): Promise<false> {
    await this.verify(await this.getDummyHash(), password);
    return false;
  }

  private getDummyHash(): Promise<string> {
    this.dummyHash ??= this.hash(randomBytes(32).toString('base64url'));
    return this.dummyHash;
  }
}
