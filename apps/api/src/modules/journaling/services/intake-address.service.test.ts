import { randomBytes } from 'node:crypto';
import {
  deriveIntakeAddressToken,
  deriveIntakeHeaderToken,
  intakeAddressHash,
  intakeHeaderTokenHash,
  intakeLocalPart,
} from '@email-gateway/archive';
import { describe, expect, it } from 'vitest';
import { CodedHttpException } from '../../../http/coded-exception';
import { IntakeAddressService } from './intake-address.service';

const SECRET = randomBytes(32);
const SOURCE = '0193a1c2-aaaa-7a00-8000-000000000001';
const DOMAIN = 'journal.gateway.test';

const service = (domain?: string) =>
  new IntakeAddressService({
    JOURNAL_INTAKE_DOMAIN: domain,
    JOURNAL_INTAKE_ADDRESS_SECRET: SECRET.toString('hex'),
  });

describe('IntakeAddressService (step 8.6 D1)', () => {
  it('derives the address and the Google header token with their stored hashes', () => {
    const token = deriveIntakeAddressToken(SECRET, SOURCE, 3);
    const header = deriveIntakeHeaderToken(SECRET, SOURCE, 3);
    expect(service(DOMAIN).derive(SOURCE, 3, true)).toEqual({
      address: `journal-${token}@${DOMAIN}`,
      addressHash: intakeAddressHash(intakeLocalPart(token)),
      headerToken: header,
      headerTokenHash: intakeHeaderTokenHash(header),
    });
    expect(service(DOMAIN).derive(SOURCE, 3, false)).toMatchObject({
      headerToken: null,
      headerTokenHash: null,
    });
  });

  it('masks unless revealing; every version differs', () => {
    const svc = service(DOMAIN);
    const token = deriveIntakeAddressToken(SECRET, SOURCE, 1);
    expect(svc.shown(SOURCE, 1, false, false)).toEqual({
      address: `journal-••••${token.slice(-4)}@${DOMAIN}`,
      headerToken: null,
    });
    expect(svc.shown(SOURCE, 1, true, true).address).toBe(`journal-${token}@${DOMAIN}`);
    expect(svc.derive(SOURCE, 1, false).addressHash).not.toBe(
      svc.derive(SOURCE, 2, false).addressHash,
    );
  });

  it('is off without an intake domain: views show null, derivation is 503', () => {
    const svc = service(undefined);
    expect(svc.available).toBe(false);
    expect(svc.shown(SOURCE, 1, true, true)).toEqual({ address: null, headerToken: null });
    const err = (() => {
      try {
        svc.derive(SOURCE, 1, false);
      } catch (e) {
        return e;
      }
      return null;
    })();
    expect(err).toBeInstanceOf(CodedHttpException);
    expect((err as CodedHttpException).code).toBe('journal_intake_unavailable');
    expect((err as CodedHttpException).getStatus()).toBe(503);
  });
});
