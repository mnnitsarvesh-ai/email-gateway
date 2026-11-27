import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  SEARCH_MESSAGE_ID_KEY_LENGTH,
  SEARCH_SUBJECT_KEY_LENGTH,
  SUBJECT_KEY_REPLY_MARKER_WORDS,
  messageIdKeyOf,
  SEARCH_KEY_WHITE_SPACE_CLASS,
  subjectKeyOf,
} from './search-keys';

// Parity vectors (design note 37 C4.4): copied verbatim from the api's
// apps/api/src/modules/messages/domain/search-keys.test.ts (subject key, Message-ID key and the
// White_Space class); only the function names differ. Keep both tables identical.
const codePointLength = (value: string): number => Array.from(value).length;

describe('search-key parity with the api (step 7.2 §2 E1, note 37 C4.4)', () => {
  it('the White_Space class is exactly Unicode White_Space (not \\s)', { timeout: 30_000 }, () => {
    const cls = new RegExp(`^[${SEARCH_KEY_WHITE_SPACE_CLASS}]$`, 'u');
    const property = /^\p{White_Space}$/u;
    const members: number[] = [];
    const mismatches: number[] = [];
    for (let cp = 0; cp <= 0x10ffff; cp += 1) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const ch = String.fromCodePoint(cp);
      const inClass = cls.test(ch);
      if (inClass !== property.test(ch)) mismatches.push(cp);
      if (inClass) members.push(cp);
    }
    expect(mismatches).toEqual([]);
    // The 25 code points ICU's [[:space:]] matched on MySQL 8.4.13 (2026-11-14).
    expect(members).toEqual([
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003,
      0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f,
      0x3000,
    ]);
    // JavaScript's \s differs: U+FEFF is not White_Space, U+0085 is.
    expect(/\s/u.test('﻿')).toBe(true);
    expect(cls.test('﻿')).toBe(false);
    expect(cls.test('\u0085')).toBe(true);
  });

  it.each([
    ['Re: Hello', 'Hello'],
    ['RE:Hello', 'Hello'],
    ['re : Hello', 'Hello'],
    ['Fwd: Re: AW: WG: Hello', 'Hello'],
    ['FW: fwd: Hello', 'Hello'],
    ['Re[3]: Hello', 'Hello'],
    ['RE [12] : Hello', 'Hello'],
    ['Sv: Vs: Antw: TR: RIF: Enc: Odp: Hello', 'Hello'],
    ['  \tRe: 　Hello  world\n', 'Hello world'],
    ['Hello   world', 'Hello world'],
    ['Hello: Re: world', 'Hello: Re: world'],
    ['Report: Q3', 'Report: Q3'],
    ['trace: x', 'trace: x'],
    ['Re', 'Re'],
    ['Re:', ''],
    ['Re: Re:  ', ''],
    ['   ', ''],
    ['', ''],
    ['RE [ 2]: x', 'RE [ 2]: x'],
    ['Re[]: x', 'Re[]: x'],
    ['Re[٣]: x', 'Re[٣]: x'],
    ['ſv: x', 'x'],
    ['Ré: x', 'Ré: x'],
    ['Rechnung', 'Rechnung'],
    ['Re: Überweisung für Müller', 'Überweisung für Müller'],
    ['Re: מסמך חשוב', 'מסמך חשוב'],
    ['Re: ‮evil‬', '‮evil‬'],
    ['Re:​Hello', '​Hello'],
    ['a﻿b', 'a﻿b'],
    ['a\u0085b', 'a b'],
  ])('subject key of %j is %j', (subject, key) => {
    expect(subjectKeyOf(subject)).toBe(key);
  });

  it('truncates the subject key to 128 code points (never UTF-16 units)', () => {
    const long = `Re: ${'x'.repeat(200)}`;
    expect(subjectKeyOf(long)).toBe('x'.repeat(128));
    const emoji = '😀'.repeat(130);
    const key = subjectKeyOf(emoji);
    expect(codePointLength(key)).toBe(128);
    expect(key).toBe('😀'.repeat(128));
    // Collapse and trim happen before the truncation, so a key may end with a space (as LEFT).
    expect(subjectKeyOf(`${'a  '.repeat(70)}`)).toBe('a '.repeat(64));
  });

  it('stays linear on hostile subjects (the MySQL 3699 shapes)', () => {
    const started = Date.now();
    for (const subject of [
      `re${' '.repeat(990)}x`,
      `re${' '.repeat(480)}[12]${' '.repeat(500)}x`,
      're: '.repeat(249),
      `${'re '.repeat(330)}x`,
      `${'re[1]'.repeat(190)}x`,
      `re[${'1'.repeat(990)}x`,
      ' '.repeat(998),
    ]) {
      subjectKeyOf(subject);
    }
    expect(Date.now() - started).toBeLessThan(200);
    expect(subjectKeyOf(`re${' '.repeat(990)}x`)).toBe('re x');
    expect(subjectKeyOf('re: '.repeat(249))).toBe('');
  });

  it.each([
    ['<abc@mx.example>', 'abc@mx.example'],
    ['abc@mx.example', 'abc@mx.example'],
    ['  <abc@mx.example>  ', 'abc@mx.example'],
    ['<<<abc@mx.example>>>', 'abc@mx.example'],
    ['< abc@mx.example >', ' abc@mx.example '],
    ['\t<abc>\t', '\t<abc>\t'],
    ['<>', ''],
    ['', ''],
    ['a>b<c', 'a>b<c'],
  ])('Message-ID key of %j is %j', (id, key) => {
    expect(messageIdKeyOf(id)).toBe(key);
  });

  it('truncates the Message-ID key to 255 code points', () => {
    expect(messageIdKeyOf(`<${'m'.repeat(300)}@x>`)).toBe('m'.repeat(255));
    expect(codePointLength(messageIdKeyOf(`<${'é'.repeat(300)}>`))).toBe(255);
  });

  it('repeats the api source constants (drift guard)', () => {
    const api = readFileSync(
      join(__dirname, '../../../../apps/api/src/modules/messages/domain/search-keys.ts'),
      'utf8',
    );
    expect(api).toContain(`'${SEARCH_KEY_WHITE_SPACE_CLASS.replaceAll('\\', '\\\\')}'`);
    for (const word of SUBJECT_KEY_REPLY_MARKER_WORDS) expect(api).toContain(`  '${word}',`);
    expect(api).toContain(`SUBJECT_KEY_LENGTH = ${SEARCH_SUBJECT_KEY_LENGTH};`);
    expect(api).toContain(`MESSAGE_ID_KEY_LENGTH = ${SEARCH_MESSAGE_ID_KEY_LENGTH};`);
    expect(api).toContain("const trimmed = messageId.replace(/^ +| +$/gu, '');");
  });
});
