import { randomBytes, randomUUID } from 'node:crypto';
import { SignJWT, UnsecuredJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { CLOCK_TOLERANCE_SECONDS, TokenService, type TokenServiceConfig } from './token.service';

const secret = () => randomBytes(32).toString('hex');

function service(overrides: Partial<TokenServiceConfig> = {}): TokenService {
  return new TokenService({
    AUTH_JWT_SECRET: secret(),
    AUTH_JWT_ISSUER: 'email-gateway',
    AUTH_JWT_AUDIENCE: 'email-gateway-api',
    AUTH_ACCESS_TOKEN_TTL_SECONDS: 600,
    ...overrides,
  });
}

const input = {
  userPublicId: randomUUID(),
  organizationPublicId: randomUUID(),
  sessionId: randomUUID(),
  amr: ['pwd'] as const,
};

describe('TokenService', () => {
  it('issues HS256 tokens with the D4 claims and verifies them', async () => {
    const tokens = service();
    const now = new Date('2026-11-02T10:00:00Z');
    const issued = await tokens.issue({ ...input, mfaEnrollmentRequired: true }, now);
    expect(issued.expiresIn).toBe(600);
    expect(issued.expiresAt.toISOString()).toBe('2026-11-02T10:10:00.000Z');

    const [header] = issued.token.split('.');
    expect(JSON.parse(Buffer.from(header!, 'base64url').toString())).toEqual({
      alg: 'HS256',
      kid: 'current',
      typ: 'JWT',
    });
    const claims = await tokens.verify(issued.token, now);
    expect(claims).toMatchObject({
      iss: 'email-gateway',
      aud: 'email-gateway-api',
      sub: input.userPublicId,
      org: input.organizationPublicId,
      sid: input.sessionId,
      typ: 'access',
      amr: ['pwd'],
      mfa_enroll: true,
      iat: now.getTime() / 1000,
      exp: now.getTime() / 1000 + 600,
    });
    expect(claims?.jti).toMatch(/^[0-9a-f-]{36}$/);
    expect(claims?.ovr).toBeUndefined();
  });

  it('gives override tokens the override id and expiry', async () => {
    const tokens = service();
    const now = new Date('2026-11-02T10:00:00Z');
    const overrideId = randomUUID();
    const expiresAt = new Date('2026-11-02T11:00:00Z');
    const issued = await tokens.issue(
      { ...input, amr: ['pwd', 'otp'], overrideId, expiresAt },
      now,
    );
    expect(issued.expiresIn).toBe(3600);
    expect(await tokens.verify(issued.token, now)).toMatchObject({
      ovr: overrideId,
      amr: ['pwd', 'otp'],
      exp: expiresAt.getTime() / 1000,
    });
  });

  it('rejects expired tokens after the 30 s clock tolerance', async () => {
    const tokens = service();
    const now = new Date('2026-11-02T10:00:00Z');
    const { token } = await tokens.issue(input, now);
    const at = (seconds: number) => new Date(now.getTime() + seconds * 1000);
    expect(await tokens.verify(token, at(600 + CLOCK_TOLERANCE_SECONDS - 1))).not.toBeNull();
    expect(await tokens.verify(token, at(600 + CLOCK_TOLERANCE_SECONDS + 1))).toBeNull();
  });

  it('rejects another key, issuer or audience', async () => {
    const { token } = await service().issue(input);
    expect(await service().verify(token)).toBeNull();
    const shared = secret();
    const signed = await service({ AUTH_JWT_SECRET: shared, AUTH_JWT_ISSUER: 'other' }).issue(
      input,
    );
    expect(await service({ AUTH_JWT_SECRET: shared }).verify(signed.token)).toBeNull();
    const aud = await service({ AUTH_JWT_SECRET: shared, AUTH_JWT_AUDIENCE: 'other' }).issue(input);
    expect(await service({ AUTH_JWT_SECRET: shared }).verify(aud.token)).toBeNull();
  });

  it('pins the algorithm (alg=none and HS512 are refused)', async () => {
    const key = secret();
    const tokens = service({ AUTH_JWT_SECRET: key });
    const claims = {
      org: input.organizationPublicId,
      sid: input.sessionId,
      typ: 'access',
      amr: ['pwd'],
    };
    const unsecured = new UnsecuredJWT(claims)
      .setIssuer('email-gateway')
      .setAudience('email-gateway-api')
      .setSubject(input.userPublicId)
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime('5m')
      .encode();
    expect(await tokens.verify(unsecured)).toBeNull();
    const hs512 = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'HS512' })
      .setIssuer('email-gateway')
      .setAudience('email-gateway-api')
      .setSubject(input.userPublicId)
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(new TextEncoder().encode(key));
    expect(await tokens.verify(hs512)).toBeNull();
  });

  it('rejects tokens that are not access tokens or are malformed', async () => {
    const key = secret();
    const tokens = service({ AUTH_JWT_SECRET: key });
    const refreshLike = await new SignJWT({
      org: input.organizationPublicId,
      sid: input.sessionId,
      typ: 'refresh',
      amr: ['pwd'],
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer('email-gateway')
      .setAudience('email-gateway-api')
      .setSubject(input.userPublicId)
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(new TextEncoder().encode(key));
    expect(await tokens.verify(refreshLike)).toBeNull();
    for (const junk of ['', 'abc', 'a.b.c', 'x'.repeat(5000)]) {
      expect(await tokens.verify(junk)).toBeNull();
    }
  });

  it('accepts tokens signed with the previous secret during rotation', async () => {
    const oldKey = secret();
    const { token } = await service({ AUTH_JWT_SECRET: oldKey }).issue(input);
    const rotated = service({ AUTH_JWT_SECRET: secret(), AUTH_JWT_PREVIOUS_SECRET: oldKey });
    expect(await rotated.verify(token)).toMatchObject({ sub: input.userPublicId });
    expect(await service({ AUTH_JWT_SECRET: secret() }).verify(token)).toBeNull();
  });
});
