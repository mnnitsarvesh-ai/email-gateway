import { randomBytes } from 'node:crypto';
import {
  dlpEvidenceDocumentSchema,
  dlpHoldsRawNumber,
  dlpMaskedValueSchema,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { detect } from '../detect';
import { DlpDictionarySet } from '../dictionaries';
import { maskCandidate } from '../mask';
import { NOW, platformSettings } from '../test-support/pipeline.test-support';
import { luhnCheckDigit, verhoeffCheckDigit } from '../validators';
import { buildEvidence, redactedSlice, redactionsIn } from './build';
import {
  DLP_EVIDENCE_KEY_ID,
  DLP_EVIDENCE_MAGIC,
  DlpEvidenceCryptoError,
  DlpEvidenceKeyError,
  evidenceAad,
  openEvidence,
  sealEvidence,
} from './envelope';

// Synthetic credentials, assembled at runtime so secret scanners (GitHub push protection) do not
// flag the source as holding real AWS keys.
const FAKE_AWS_KEY_ID = ['AKIA', 'QWERTYUIOPASDFGH'].join('');
const FAKE_AWS_SECRET = ['Ab3dEf/Gh1jKl+Mn0p', 'QrStUvWxYz12345678AbCd'].join('');
const FAKE_AWS_SECRET_2 = ['Zx9cVb/Nm1qWe+Rt5', 'yUi7oPa3sDf6gHj8kLz2xCv'].join('');

const dictionaries = DlpDictionarySet.create();
const aadhaar = `23456789012${verhoeffCheckDigit('23456789012')}`;
const cardBody = '453201511283036';
const card = `${cardBody}${luhnCheckDigit(cardBody)}`;

async function evidenceFor(
  text: string,
  aadhaarEnabled = false,
  maxMatches = 50,
  maxBytes = 32_768,
) {
  const detection = await detect({
    segments: [{ source: { kind: 'body_text' }, format: 'text', kind: 'text', text }],
    settings: platformSettings(),
    aadhaarEnabled,
    dictionaries,
    now: NOW,
  });
  return {
    detection,
    evidence: buildEvidence({
      matches: detection.candidates,
      credentialCandidates: detection.credentialCandidates,
      segments: detection.segments,
      aadhaarEnabled,
      maxMatches,
      maxBytes,
    }),
  };
}

describe('masking (D15)', () => {
  const masks = async (text: string, aadhaarEnabled = false) =>
    (await evidenceFor(text, aadhaarEnabled)).detection.candidates.map((c) => [
      c.detector,
      maskCandidate(c),
    ]);
  it('masks every detector as the D15 table says', async () => {
    expect(await masks(`Card: ${card}`)).toEqual([['PC1', '************0366']]);
    expect(await masks('IBAN GB82WEST12345698765432')).toEqual([['BA1', 'GB****************5432']]);
    expect(await masks('PAN: ABCPD1234E')).toEqual([['NI1', '******234E']]);
    expect(await masks(`Aadhaar ${aadhaar}`, true)).toEqual([
      ['NI2', `********${aadhaar.slice(-4)}`],
    ]);
    expect(await masks('Write to anita.rao@example.test')).toEqual([['PI1', 'a***@example.test']]);
    expect(await masks('DOB: 12/03/1985')).toEqual([['PI3', '**/**/****']]);
    expect(await masks(`key ${FAKE_AWS_KEY_ID}`)).toEqual([['CR2', 'AKIA************DFGH']]);
    expect(
      await masks(
        `-----BEGIN EC PRIVATE KEY-----\n${'Q'.repeat(70)}\n-----END EC PRIVATE KEY-----`,
      ),
    ).toEqual([['CR1', '[private key: EC]']]);
    expect(await masks('CONFIDENTIAL')).toEqual([['CF1', 'en.labels.001']]);
  });
  it('masked values pass the view schema (no raw-looking numbers)', async () => {
    const { detection } = await evidenceFor(
      `Card ${card}; aadhaar ${aadhaar}; mobile 9123456780`,
      true,
    );
    for (const c of detection.candidates) {
      expect(dlpMaskedValueSchema.safeParse(maskCandidate(c)).success, c.detector).toBe(true);
    }
  });
});

describe('evidence build (D16)', () => {
  it('keeps cards as first 6 + last 4 and masks Aadhaar in value and context', async () => {
    const { evidence } = await evidenceFor(
      `Card: ${card} Aadhaar: ${aadhaar} PAN: ABCPD1234E`,
      true,
    );
    expect(evidence).not.toBeNull();
    const json = evidence!.json;
    expect(json).not.toContain(card);
    expect(json).not.toContain(aadhaar);
    expect(
      dlpHoldsRawNumber(json.replace(/"start":\d+|"end":\d+|"segment":\d+|"dropped":\d+/g, '')),
    ).toBe(false);
    const pc1 = evidence!.document.matches.find((m) => m.detector === 'PC1')!;
    expect(pc1.value).toBe('453201******0366');
    const pan = evidence!.document.matches.find((m) => m.detector === 'NI1')!;
    expect(pan.value).toBe('ABCPD1234E');
    expect(pan.context.before).toContain('[aadhaar]');
    expect(evidence!.document.aadhaar).toBe('enabled');
  });

  it('redacts Aadhaar-shaped Verhoeff-valid runs in context even with Aadhaar gating off', async () => {
    const { evidence } = await evidenceFor(
      `PAN: ABCPD1234E and ${aadhaar.slice(0, 4)} ${aadhaar.slice(4, 8)} ${aadhaar.slice(8)}`,
      false,
    );
    const pan = evidence!.document.matches.find((m) => m.detector === 'NI1')!;
    expect(pan.context.after).toContain('[aadhaar]');
    expect(evidence!.json).not.toContain(aadhaar.slice(4, 8) + ' ' + aadhaar.slice(8));
    expect(evidence!.document.aadhaar).toBe('disabled');
  });

  it('CR2 + CR3 neighbours: the CR2 context holds the secret mask, never the secret', async () => {
    const secret = FAKE_AWS_SECRET;
    const { evidence } = await evidenceFor(
      `aws_access_key_id=${FAKE_AWS_KEY_ID} aws_secret_access_key=${secret}`,
    );
    const cr2 = evidence!.document.matches.find((m) => m.detector === 'CR2')!;
    expect(cr2.context.after).toContain('[secret: 40 chars]');
    expect(evidence!.json).not.toContain(secret);
    expect(evidence!.document.matches.find((m) => m.detector === 'CR3')!.value).toBe(
      '[secret: 40 chars]',
    );
  });

  it('card + CVV: the context holds CVV ***', async () => {
    const { evidence } = await evidenceFor(`Card ${card} CVV 123 expiry 09/29`);
    const pc1 = evidence!.document.matches.find((m) => m.detector === 'PC1')!;
    expect(pc1.context.after).toContain('CVV ***');
    expect(pc1.context.after).toContain('09/29');
    expect(evidence!.json).not.toMatch(/CVV 123/);
  });

  it('a non-reportable credential candidate next to a reportable PI1 is redacted', async () => {
    const secret = FAKE_AWS_SECRET_2;
    const { evidence, detection } = await evidenceFor(
      `Mail anita.rao@example.test token ${secret}`,
    );
    expect(detection.candidates.find((c) => c.detector === 'CR3')!.reportable).toBe(false);
    const pi1 = evidence!.document.matches.find((m) => m.detector === 'PI1')!;
    expect(pi1.context.after).toContain('[secret: 40 chars]');
    expect(evidence!.json).not.toContain(secret);
  });

  it('PEM keys keep only their BEGIN line; JWT only its header', async () => {
    const body = 'M'.repeat(70);
    const jwt = `${Buffer.from('{"alg":"HS256"}').toString('base64url')}.${Buffer.from('{"sub":"7"}').toString('base64url')}.c2lnbmF0dXJl`;
    const { evidence } = await evidenceFor(
      `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----\n${'x'.repeat(80)}\ntoken ${jwt}`,
    );
    const cr1 = evidence!.document.matches.find((m) => m.detector === 'CR1')!;
    expect(cr1.value).toBe('-----BEGIN RSA PRIVATE KEY-----');
    expect(evidence!.json).not.toContain(body);
    expect(evidence!.document.matches.find((m) => m.detector === 'CR4')!.value).toBe(
      jwt.split('.')[0],
    );
    expect(evidence!.json).not.toContain(jwt.split('.')[1]!);
  });

  it('bounds: ≤ 5 per detector, ≤ maxMatches, ≤ maxBytes (lowest severity dropped first)', async () => {
    const pans = Array.from({ length: 8 }, (_, i) => `PAN: ABCPD${String(1000 + i)}E`).join('\n');
    const many = await evidenceFor(pans);
    expect(many.evidence!.document.matches).toHaveLength(5);
    expect(many.evidence!.document.dropped).toBe(3);
    const capped = await evidenceFor(pans, false, 2);
    expect(capped.evidence!.document.matches).toHaveLength(2);
    const text = `PAN: ABCPD1234E\n${'x'.repeat(80)}\nWrite to anita.rao@example.test`;
    const full = Buffer.byteLength((await evidenceFor(text)).evidence!.json);
    const mixed = await evidenceFor(text, false, 50, full - 1);
    expect(Buffer.byteLength(mixed.evidence!.json)).toBeLessThan(full);
    expect(mixed.evidence!.document.dropped).toBe(1);
    expect(mixed.evidence!.document.matches.map((m) => m.detector)).toEqual(['NI1']);
    expect((await evidenceFor('nothing here')).evidence).toBeNull();
    expect(dlpEvidenceDocumentSchema.safeParse(many.evidence!.document).success).toBe(true);
  });

  it('redaction primitives', () => {
    const text = `x ${card} y`;
    const r = redactionsIn(text, 0, text.length, []);
    expect(redactedSlice(text, 0, text.length, r)).toBe('x 453201******0366 y');
    expect(redactedSlice(text, 5, text.length, r)).toBe('453201******0366 y');
  });
});

describe('dlp-evidence/1 envelope', () => {
  const kek = randomBytes(32);
  const previous = randomBytes(32);
  const ids = { organizationId: '11', messageId: '22', scanId: '33' };
  const plaintext = JSON.stringify({ hello: 'synthetic evidence' });

  it('round trips; object = EGDLP1 ‖ IV ‖ tag ‖ ct; wrapped key in SecretBox format', () => {
    const sealed = sealEvidence({ current: kek }, plaintext, ids);
    expect(sealed.object.subarray(0, 6).equals(DLP_EVIDENCE_MAGIC)).toBe(true);
    expect(sealed.object.length).toBe(6 + 12 + 16 + Buffer.byteLength(plaintext));
    expect(sealed.wrappedKey).toMatch(
      /^v1\.k1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/,
    );
    expect(sealed).toMatchObject({
      keyId: DLP_EVIDENCE_KEY_ID,
      algorithm: 'dlp-evidence/1',
      size: sealed.object.length,
    });
    expect(sealed.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(sealed.object.includes(Buffer.from('synthetic evidence'))).toBe(false);
    const opened = openEvidence(
      { current: kek.toString('hex') },
      sealed.object,
      sealed.wrappedKey,
      ids,
    );
    expect(opened.plaintext.toString('utf8')).toBe(plaintext);
    expect(opened.usedPreviousKey).toBe(false);
    expect(evidenceAad(ids)).toBe('eg-dlp-evidence/v1\u000011\u000022\u000033');
  });

  it('a fresh data key and IV per evidence', () => {
    const a = sealEvidence({ current: kek }, plaintext, ids);
    const b = sealEvidence({ current: kek }, plaintext, ids);
    expect(a.object.equals(b.object)).toBe(false);
    expect(a.wrappedKey).not.toBe(b.wrappedKey);
  });

  it('opens with the previous key during a rotation', () => {
    const sealed = sealEvidence({ current: previous }, plaintext, ids);
    const opened = openEvidence({ current: kek, previous }, sealed.object, sealed.wrappedKey, ids);
    expect(opened).toMatchObject({ usedPreviousKey: true });
    expect(opened.plaintext.toString()).toBe(plaintext);
  });

  it('refuses a wrong AAD, tampering and a wrong key without detail', () => {
    const sealed = sealEvidence({ current: kek }, plaintext, ids);
    const fail = (fn: () => unknown) => {
      try {
        fn();
      } catch (error) {
        expect(error).toBeInstanceOf(DlpEvidenceCryptoError);
        expect((error as Error).message).toBe('Unable to open the DLP evidence');
        return;
      }
      throw new Error('expected a failure');
    };
    fail(() =>
      openEvidence({ current: kek }, sealed.object, sealed.wrappedKey, { ...ids, scanId: '34' }),
    );
    fail(() =>
      openEvidence({ current: kek }, sealed.object, sealed.wrappedKey, {
        ...ids,
        organizationId: '12',
      }),
    );
    const tampered = Buffer.from(sealed.object);
    tampered[tampered.length - 1]! ^= 1;
    fail(() => openEvidence({ current: kek }, tampered, sealed.wrappedKey, ids));
    const badMagic = Buffer.from(sealed.object);
    badMagic[0] = 0x41;
    fail(() => openEvidence({ current: kek }, badMagic, sealed.wrappedKey, ids));
    const parts = sealed.wrappedKey.split('.');
    const ct = Buffer.from(parts[4]!, 'base64url');
    ct[0]! ^= 1;
    fail(() =>
      openEvidence(
        { current: kek },
        sealed.object,
        [...parts.slice(0, 4), ct.toString('base64url')].join('.'),
        ids,
      ),
    );
    fail(() => openEvidence({ current: kek }, sealed.object, 'v2.k1.a.b.c', ids));
    fail(() => openEvidence({ current: randomBytes(32) }, sealed.object, sealed.wrappedKey, ids));
    fail(() =>
      openEvidence({ current: kek }, sealed.object.subarray(0, 20), sealed.wrappedKey, ids),
    );
  });

  it('refuses malformed keys and ids', () => {
    expect(() => sealEvidence({ current: 'abc' }, plaintext, ids)).toThrow(DlpEvidenceKeyError);
    expect(() => sealEvidence({ current: randomBytes(16) }, plaintext, ids)).toThrow(
      DlpEvidenceKeyError,
    );
    expect(() =>
      sealEvidence({ current: kek }, plaintext, { ...ids, messageId: 'a\u0000b' }),
    ).toThrow(DlpEvidenceCryptoError);
  });
});
