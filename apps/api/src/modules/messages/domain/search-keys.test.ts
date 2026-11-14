import { describe, expect, it } from 'vitest';
import {
  codePointLength,
  domainOf,
  escapeLike,
  firstCodePoints,
  normalizeMessageIdKey,
  normalizeSubjectKey,
  normalizeSubjectPrefix,
  subjectPrefixPattern,
  WHITE_SPACE_CLASS,
} from './search-keys';

describe('message search keys (step 7.2 §2 E1, §3.1)', () => {
  it('the White_Space class is exactly Unicode White_Space (not \\s)', { timeout: 30_000 }, () => {
    const cls = new RegExp(`^[${WHITE_SPACE_CLASS}]$`, 'u');
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
    expect(normalizeSubjectKey(subject)).toBe(key);
  });

  it('truncates the subject key to 128 code points (never UTF-16 units)', () => {
    const long = `Re: ${'x'.repeat(200)}`;
    expect(normalizeSubjectKey(long)).toBe('x'.repeat(128));
    const emoji = '😀'.repeat(130);
    const key = normalizeSubjectKey(emoji);
    expect(codePointLength(key)).toBe(128);
    expect(key).toBe('😀'.repeat(128));
    // Collapse and trim happen before the truncation, so a key may end with a space (as LEFT).
    expect(normalizeSubjectKey(`${'a  '.repeat(70)}`)).toBe('a '.repeat(64));
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
      normalizeSubjectKey(subject);
    }
    expect(Date.now() - started).toBeLessThan(200);
    expect(normalizeSubjectKey(`re${' '.repeat(990)}x`)).toBe('re x');
    expect(normalizeSubjectKey('re: '.repeat(249))).toBe('');
  });

  it('normalizes a prefix like the key, without truncating', () => {
    expect(normalizeSubjectPrefix('  Re: Inv\toice  ')).toBe('Inv oice');
    expect(normalizeSubjectPrefix('x'.repeat(200))).toHaveLength(200);
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
    expect(normalizeMessageIdKey(id)).toBe(key);
  });

  it('truncates the Message-ID key to 255 code points', () => {
    expect(normalizeMessageIdKey(`<${'m'.repeat(300)}@x>`)).toBe('m'.repeat(255));
    expect(codePointLength(normalizeMessageIdKey(`<${'é'.repeat(300)}>`))).toBe(255);
  });

  it.each([
    ['alice@example.com', 'example.com'],
    ['Alice@Mail.Example.COM', 'Mail.Example.COM'],
    ['"a@b"@c.example', 'c.example'],
    ['a@b@c.example', 'c.example'],
    ['x@', ''],
    ['', null],
    ['postmaster', null],
    ['a＠b.example', null],
  ])('domain of %j is %j', (address, domain) => {
    expect(domainOf(address)).toBe(domain);
  });

  it('truncates a domain to 253 code points', () => {
    expect(domainOf(`a@${'d'.repeat(300)}`)).toBe('d'.repeat(253));
  });

  it('escapes LIKE wildcards and the escape character', () => {
    expect(escapeLike('100% off_now!')).toBe('100!% off!_now!!');
    expect(escapeLike('plain')).toBe('plain');
    expect(subjectPrefixPattern('50%_x')).toBe('50!%!_x%');
  });

  it('counts and cuts code points', () => {
    expect(codePointLength('a😀b')).toBe(3);
    expect(firstCodePoints('a😀b', 2)).toBe('a😀');
    expect(firstCodePoints('ab', 5)).toBe('ab');
  });
});
