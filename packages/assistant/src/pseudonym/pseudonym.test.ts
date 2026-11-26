import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  PLACEHOLDER_MAX_LENGTH,
  PLACEHOLDER_PATTERN,
  PSEUDONYM_KINDS,
  Pseudonymizer,
  TextDemapper,
  UNKNOWN_PLACEHOLDER_CODE,
  canonicalIp,
  isPlaceholderPrefix,
  neutralizePlaceholders,
  normalizePseudonymValue,
  parsePlaceholder,
  pseudonymValueSha256,
  type PseudonymEntry,
} from './index';

/**
 * Step AI-6 D3: the `pseudonymized` level. Synthetic values only (example/test domains,
 * documentation IP ranges).
 */

const fresh = (maxEntries = 5_000, entries: readonly PseudonymEntry[] = []) =>
  new Pseudonymizer({ entries, maxEntries });

const entry = (kind: PseudonymEntry['kind'], token: string, value: string): PseudonymEntry => ({
  kind,
  token,
  value,
  valueSha256: pseudonymValueSha256(kind, value),
});

describe('tokens and normalization', () => {
  it('exports the kinds, the grammar and the unknown-placeholder code', () => {
    expect(PSEUDONYM_KINDS).toEqual(['email', 'ip', 'domain', 'name']);
    expect(UNKNOWN_PLACEHOLDER_CODE).toBe('assistant_unknown_placeholder');
    expect('[EMAIL_1] [IP_22] [DOMAIN_333333] [PERSON_4]'.match(PLACEHOLDER_PATTERN)).toHaveLength(
      4,
    );
    expect('[EMAIL_1234567] [EMAIL_] [email_1] [USER_1]'.match(PLACEHOLDER_PATTERN)).toBeNull();
    expect(PLACEHOLDER_MAX_LENGTH).toBe('[PERSON_999999]'.length);
    expect(parsePlaceholder('[PERSON_12]')).toEqual({ kind: 'name', n: 12 });
    expect(parsePlaceholder('[IP_0]')).toBeNull();
    expect(parsePlaceholder('[EMAIL_REDACTED]')).toBeNull();
  });

  it('neutralizes forged tokens to (KIND_n)', () => {
    expect(neutralizePlaceholders('See [EMAIL_1] and [PERSON_22], keep [x] and (IP_1)')).toBe(
      'See (EMAIL_1) and (PERSON_22), keep [x] and (IP_1)',
    );
    expect(neutralizePlaceholders('[EMAIL_REDACTED] [EMAIL_1234567]')).toBe(
      '[EMAIL_REDACTED] [EMAIL_1234567]',
    );
  });

  it('normalizes: e-mail domain lower-cased, IPs canonical, domains without trailing dot, names collapsed', () => {
    expect(normalizePseudonymValue('email', 'Ada.Admin@Alpha.Example.TEST')).toBe(
      'Ada.Admin@alpha.example.test',
    );
    expect(normalizePseudonymValue('ip', '2001:DB8:0:0:0:0:0:1')).toBe('2001:db8::1');
    expect(canonicalIp('[2001:db8::0:1]')).toBe('2001:db8::1');
    expect(canonicalIp('192.0.2.10')).toBe('192.0.2.10');
    expect(normalizePseudonymValue('domain', 'Mail.Example.TEST.')).toBe('mail.example.test');
    expect(normalizePseudonymValue('name', '  Ada \n  Admin ')).toBe('Ada Admin');
    expect(pseudonymValueSha256('domain', 'Example.TEST')).toBe(
      pseudonymValueSha256('domain', 'example.test.'),
    );
    expect(pseudonymValueSha256('domain', 'x.test')).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('Pseudonymizer.text (free text)', () => {
  it('tokenizes e-mail addresses, IPv4/IPv6, URL hosts and bare hostnames', () => {
    const p = fresh();
    const out = p.text(
      'From ada@alpha.example.test via 192.0.2.10 and 2001:db8::7, see https://portal.example.test:8443/a?b=1 or www.example.co.uk and example.com.',
    );
    expect(out).toBe(
      'From [EMAIL_1] via [IP_2] and [IP_1], see https://[DOMAIN_1]:8443/a?b=1 or [DOMAIN_2] and [DOMAIN_3].',
    );
    expect(p.added().map((e) => [e.kind, e.token, e.value])).toEqual([
      ['email', '[EMAIL_1]', 'ada@alpha.example.test'],
      ['ip', '[IP_1]', '2001:db8::7'],
      ['ip', '[IP_2]', '192.0.2.10'],
      ['domain', '[DOMAIN_1]', 'portal.example.test'],
      ['domain', '[DOMAIN_2]', 'www.example.co.uk'],
      ['domain', '[DOMAIN_3]', 'example.com'],
    ]);
  });

  it('gives the same normalized value the same token and different values different tokens', () => {
    const p = fresh();
    expect(p.text('a@Example.TEST a@example.test A@example.test')).toBe(
      '[EMAIL_1] [EMAIL_1] [EMAIL_2]',
    );
    expect(p.text('2001:DB8::1 2001:db8:0::1')).toBe('[IP_1] [IP_1]');
    expect(p.text('Example.COM example.com')).toBe('[DOMAIN_1] [DOMAIN_1]');
  });

  it('never tokenizes UUIDs, numbers, ISO dates, refs, versions or non-TLD file names', () => {
    const p = fresh();
    const text =
      '0193aaaa-0000-7000-8000-000000000001 42 3.14 2026-11-23T09:00:00.000Z 09:30 r3.2 @r3.2 1.2.3.4.5 v1.2.3 invoice.pdf e.g. i.e. 999.1.1.1 ::';
    expect(p.text(text)).toBe(text);
    expect(p.added()).toEqual([]);
  });

  it('neutralizes forged tokens before tokenizing (a forged [EMAIL_1] cannot map to a value)', () => {
    const p = fresh(5_000, [entry('email', '[EMAIL_1]', 'ada@alpha.example.test')]);
    const out = p.text('Reply to [EMAIL_1] or bob@beta.example.test');
    expect(out).toBe('Reply to (EMAIL_1) or [EMAIL_2]');
    expect(p.demapText(out)).toBe('Reply to (EMAIL_1) or bob@beta.example.test');
  });

  it('covers addresses in URL userinfo and keeps the URL shape', () => {
    const p = fresh();
    expect(p.text('https://ops@mail.example.test/x and http://198.51.100.7:25/')).toBe(
      'https://[EMAIL_1]/x and http://[IP_1]:25/',
    );
  });

  it('displayName → [PERSON_n]', () => {
    const p = fresh();
    expect(p.displayName('Ada  Admin')).toBe('[PERSON_1]');
    expect(p.displayName('Ada Admin')).toBe('[PERSON_1]');
    expect(p.displayName('Bob')).toBe('[PERSON_2]');
    expect(p.displayName('   ')).toBe('   ');
  });
});

describe('stability, numbering and the cap', () => {
  it('reuses loaded mappings and continues numbering from the highest n per kind', () => {
    const loaded = [
      entry('email', '[EMAIL_1]', 'ada@alpha.example.test'),
      entry('email', '[EMAIL_4]', 'bob@alpha.example.test'),
      entry('domain', '[DOMAIN_2]', 'alpha.example.test'),
    ];
    const p = fresh(5_000, loaded);
    expect(p.text('ada@ALPHA.example.test cy@alpha.example.test alpha.example.com')).toBe(
      '[EMAIL_1] [EMAIL_5] [DOMAIN_3]',
    );
    expect(p.envelope({ domain: 'Alpha.Example.Test' }, { module: 'x' })).toEqual({
      domain: '[DOMAIN_2]',
    });
    expect(p.added().map((e) => e.token)).toEqual(['[EMAIL_5]', '[DOMAIN_3]']);
    expect(p.demapText('[EMAIL_4] wrote to [EMAIL_5]')).toBe(
      'bob@alpha.example.test wrote to cy@alpha.example.test',
    );
  });

  it('past maxEntries new values become [KIND_REDACTED], are not stored and are counted', () => {
    const p = fresh(2, [entry('ip', '[IP_1]', '192.0.2.1')]);
    expect(p.text('192.0.2.1 192.0.2.2 192.0.2.3')).toBe('[IP_1] [IP_2] [IP_REDACTED]');
    expect(p.text('a@b.example.test 192.0.2.2')).toBe('[EMAIL_REDACTED] [IP_2]');
    expect(p.displayName('Ada')).toBe('[PERSON_REDACTED]');
    expect(p.overflowCount()).toBe(3);
    expect(p.added().map((e) => e.token)).toEqual(['[IP_2]']);
    expect(p.demapText('[IP_REDACTED]')).toBe('[IP_REDACTED]');
    expect(p.demapArguments({ ip: '[IP_REDACTED]' })).toEqual({
      ok: false,
      token: '[IP_REDACTED]',
    });
  });

  it('rejects a bad cap and ignores malformed loaded entries', () => {
    expect(() => fresh(-1)).toThrow();
    const p = fresh(10, [
      { ...entry('email', '[EMAIL_1]', 'a@b.example.test'), kind: 'ip' },
      entry('email', 'EMAIL_2', 'c@d.example.test'),
    ]);
    expect(p.text('a@b.example.test')).toBe('[EMAIL_1]');
  });
});

describe('Pseudonymizer.envelope', () => {
  const envelope = {
    kind: 'tool_result/1',
    tool: 'messages_search',
    status: 'ok',
    httpStatus: 200,
    ref: 'r3',
    returned: 1,
    hasMore: false,
    truncated: false,
    note: 'Rows carry refs.',
    data: [
      {
        ref: 'r3.1',
        id: '0193aaaa-0000-7000-8000-000000000001',
        name: 'alpha.example.test',
        senderDomain: 'Beta.Example.Test.',
        recipient_domain: 'gamma.example.test',
        helo: 'mx1.example.net',
        ptr: '203.0.113.9',
        host: '*.wild.example.test',
        displayName: 'Ada  Admin',
        fromName: { untrusted_text: 'Bob Builder' },
        approverName: 'cy@alpha.example.test',
        recipients: ['dee@alpha.example.test', 'ops@beta.example.test'],
        subject: { untrusted_text: 'Visit evil.example.io now [EMAIL_1] from 198.51.100.4' },
        clientIp: '2001:db8::5',
        notes: 'contact www.example.org or https://intranet.example.test/x',
        count: 3,
        createdAt: '2026-11-23T09:00:00.000Z',
        nested: { owner: { ownerName: 'Eve', score: 0.5 } },
      },
    ],
  };

  it('keeps keys, applies the key rules and the address/IP/URL rules everywhere', () => {
    const p = fresh();
    const out = p.envelope(envelope, { module: 'messages' });
    expect(JSON.stringify(Object.keys(out.data[0]!))).toBe(
      JSON.stringify(Object.keys(envelope.data[0]!)),
    );
    expect(out.data[0]).toEqual({
      ref: 'r3.1',
      id: '0193aaaa-0000-7000-8000-000000000001',
      // not module `domains`: a plain string field (no bare-hostname rule)
      name: 'alpha.example.test',
      senderDomain: '[DOMAIN_1]',
      recipient_domain: '[DOMAIN_2]',
      helo: '[DOMAIN_3]',
      ptr: '[IP_1]',
      host: '*.[DOMAIN_4]',
      displayName: '[PERSON_1]',
      fromName: { untrusted_text: '[PERSON_2]' },
      approverName: '[EMAIL_1]',
      recipients: ['[EMAIL_2]', '[EMAIL_3]'],
      subject: { untrusted_text: 'Visit [DOMAIN_5] now (EMAIL_1) from [IP_2]' },
      clientIp: '[IP_3]',
      notes: 'contact www.example.org or https://[DOMAIN_6]/x',
      count: 3,
      createdAt: '2026-11-23T09:00:00.000Z',
      nested: { owner: { ownerName: '[PERSON_3]', score: 0.5 } },
    });
    expect(out.note).toBe(envelope.note);
    expect(out.ref).toBe('r3');
    // the input is not mutated
    expect(envelope.data[0]!.senderDomain).toBe('Beta.Example.Test.');
  });

  it("module 'domains': the row's name is a domain", () => {
    const p = fresh();
    const out = p.envelope(
      { status: 'ok', data: [{ ref: 'r1.1', name: 'Alpha.Example.Test', status: 'verified' }] },
      { module: 'domains' },
    );
    expect(out.data[0]).toEqual({ ref: 'r1.1', name: '[DOMAIN_1]', status: 'verified' });
    const combined = fresh().envelope(
      { data: { name: 'x.example.test' } },
      { module: 'a,domains' },
    );
    expect(combined.data.name).toBe('[DOMAIN_1]');
  });

  it('handles error envelopes and leaves non-strings unchanged', () => {
    const p = fresh();
    expect(
      p.envelope(
        {
          status: 'error',
          httpStatus: 409,
          code: 'conflict',
          message: 'Address ada@alpha.example.test already exists',
          flags: [true, null, 7],
        },
        { module: 'users' },
      ),
    ).toEqual({
      status: 'error',
      httpStatus: 409,
      code: 'conflict',
      message: 'Address [EMAIL_1] already exists',
      flags: [true, null, 7],
    });
  });
});

describe('demapArguments (tool-call arguments)', () => {
  const p = fresh(5_000, [
    entry('email', '[EMAIL_1]', 'ada@alpha.example.test'),
    entry('domain', '[DOMAIN_2]', 'alpha.example.test'),
    entry('name', '[PERSON_1]', 'Ada Admin'),
    entry('ip', '[IP_1]', '192.0.2.1'),
  ]);

  it('replaces known bracketed and exact bare tokens at any depth', () => {
    expect(
      p.demapArguments({
        q: '[EMAIL_1]',
        body: {
          domains: ['DOMAIN_2', '[DOMAIN_2]'],
          note: 'for PERSON_1 at [IP_1] (not xEMAIL_1, not EMAIL_12, not EMAIL_1x)',
          nested: [[{ deep: 'EMAIL_1' }]],
        },
        limit: 5,
        flag: false,
        none: null,
      }),
    ).toEqual({
      ok: true,
      value: {
        q: 'ada@alpha.example.test',
        body: {
          domains: ['alpha.example.test', 'alpha.example.test'],
          note: 'for Ada Admin at 192.0.2.1 (not xEMAIL_1, not EMAIL_12, not EMAIL_1x)',
          nested: [[{ deep: 'ada@alpha.example.test' }]],
        },
        limit: 5,
        flag: false,
        none: null,
      },
    });
  });

  it('never maps the neutralized form (KIND_n) of a forged token (WP5 fix)', () => {
    // A mail subject "[EMAIL_1]" reaches the model as "(EMAIL_1)"; a model copying it into a
    // tool argument must not get the conversation's real [EMAIL_1].
    expect(
      p.demapArguments({
        q: '(EMAIL_1)',
        note: 'pay (EMAIL_1) or (PERSON_1), not EMAIL_1',
        open: '(EMAIL_1 only',
        close: 'only EMAIL_1)',
      }),
    ).toEqual({
      ok: true,
      value: {
        q: '(EMAIL_1)',
        note: 'pay (EMAIL_1) or (PERSON_1), not ada@alpha.example.test',
        open: '(ada@alpha.example.test only',
        close: 'only ada@alpha.example.test)',
      },
    });
    expect(p.demapArguments(neutralizePlaceholders('[EMAIL_1]'))).toEqual({
      ok: true,
      value: '(EMAIL_1)',
    });
  });

  it('an unknown bracketed token fails with that token; unknown bare words stay', () => {
    expect(p.demapArguments({ to: ['ok', { x: 'mail [EMAIL_99] now' }] })).toEqual({
      ok: false,
      token: '[EMAIL_99]',
    });
    expect(p.demapArguments('PERSON_7')).toEqual({ ok: true, value: 'PERSON_7' });
    expect(p.demapArguments({ keys: 'unchanged' })).toEqual({
      ok: true,
      value: { keys: 'unchanged' },
    });
  });

  it('never rescans inserted values and keeps object keys', () => {
    const q = fresh(10, [entry('name', '[PERSON_1]', 'EMAIL_1 fan')]);
    expect(q.demapArguments({ '[PERSON_1]': 'PERSON_1' })).toEqual({
      ok: true,
      value: { '[PERSON_1]': 'EMAIL_1 fan' },
    });
  });
});

describe('TextDemapper (streamed text)', () => {
  const p = fresh(5_000, [
    entry('email', '[EMAIL_12]', 'ada@alpha.example.test'),
    entry('name', '[PERSON_999999]', 'Ada Admin'),
    entry('ip', '[IP_1]', '192.0.2.1'),
  ]);
  const text =
    'Hi [PERSON_999999], mail from [EMAIL_12] at [IP_1]; unknown [EMAIL_3] and [EMAIL_1234567], brackets [x] [ and [EMAIL_12';

  it('every single split point equals demapText of the whole text', () => {
    const expected = p.demapText(text);
    expect(expected).toBe(
      'Hi Ada Admin, mail from ada@alpha.example.test at 192.0.2.1; unknown [EMAIL_3] and [EMAIL_1234567], brackets [x] [ and [EMAIL_12',
    );
    for (let i = 0; i <= text.length; i += 1) {
      const demapper = p.createTextDemapper();
      const out = demapper.push(text.slice(0, i)) + demapper.push(text.slice(i)) + demapper.flush();
      expect(out, `split at ${i}`).toBe(expected);
    }
  });

  it('character by character and holds back at most one token prefix', () => {
    const demapper = p.createTextDemapper();
    let out = '';
    for (const char of text) {
      const emitted = demapper.push(char);
      out += emitted;
    }
    out += demapper.flush();
    expect(out).toBe(p.demapText(text));
    const held = new TextDemapper(() => null);
    expect(held.push('abc [PERSON_99999')).toBe('abc ');
    expect(held.push('9')).toBe('');
    expect(held.push(']')).toBe('[PERSON_999999]');
    expect(held.flush()).toBe('');
    expect(isPlaceholderPrefix('[DOMAIN_')).toBe(true);
    expect(isPlaceholderPrefix('[DOMAINS')).toBe(false);
    expect(isPlaceholderPrefix('[EMAIL_1234567')).toBe(false);
  });

  it('random multi-way splits equal demapText (property)', () => {
    fc.assert(
      fc.property(fc.array(fc.integer({ min: 0, max: text.length }), { maxLength: 12 }), (cuts) => {
        const points = [...new Set(cuts)].sort((a, b) => a - b);
        const demapper = p.createTextDemapper();
        let out = '';
        let last = 0;
        for (const point of [...points, text.length]) {
          out += demapper.push(text.slice(last, point));
          last = point;
        }
        out += demapper.flush();
        return out === p.demapText(text);
      }),
    );
  });
});

describe('properties (fast-check)', () => {
  const word = fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789 ,;!?()-_'), {
    maxLength: 12,
  });
  const segment = fc.oneof(
    fc.emailAddress(),
    fc.ipV4(),
    word,
    fc.constantFrom('[EMAIL_1]', '[IP_2] ', '(PERSON_3)', 'DOMAIN_4', 'example.com', 'r3.2'),
  );
  const segments = fc.array(segment, { maxLength: 12 });
  const sensitive = (parts: string[]) =>
    parts.filter((part) => part.includes('@') || /^\d+\.\d+\.\d+\.\d+$/.test(part));

  it('no generated address or IPv4 survives text()', () => {
    fc.assert(
      fc.property(segments, (parts) => {
        const out = fresh().text(parts.join(' '));
        return sensitive(parts).every((value) => !out.includes(value));
      }),
    );
  });

  it('no generated address or IPv4 survives envelope()', () => {
    fc.assert(
      fc.property(segments, fc.constantFrom('messages', 'domains', 'users'), (parts, module) => {
        const env = {
          kind: 'tool_result/1',
          data: parts.map((part, index) => ({
            ref: `r1.${index + 1}`,
            value: part,
            subject: { untrusted_text: `re: ${part}` },
            list: [part, { deep: part }],
          })),
          message: parts.join(', '),
        };
        const out = JSON.stringify(fresh().envelope(env, { module }));
        return sensitive(parts).every((value) => !out.includes(JSON.stringify(value).slice(1, -1)));
      }),
    );
  });

  it('demapText(text(x)) === neutralizePlaceholders(x)', () => {
    fc.assert(
      fc.property(segments, (parts) => {
        const x = parts.join(' ');
        const p = fresh();
        return p.demapText(p.text(x)) === neutralizePlaceholders(x);
      }),
    );
  });
});

describe('long untrusted text', () => {
  it('stays fast on adversarial runs (linear scans)', () => {
    const big = `${'a'.repeat(100_000)} ${'a.'.repeat(50_000)} ${'1.'.repeat(30_000)}${':'.repeat(30_000)}${'@'.repeat(10_000)} https://${'b'.repeat(50_000)}`;
    const started = Date.now();
    fresh().text(big);
    expect(Date.now() - started).toBeLessThan(2_000);
  });
});
