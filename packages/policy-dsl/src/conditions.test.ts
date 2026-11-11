import { describe, expect, it } from 'vitest';
import {
  buildFacts,
  compileNode,
  evalNode,
  FALSE,
  quantify,
  TRUE,
  UNKNOWN,
  type Tri,
} from './conditions';
import type { PolicyNode } from './definition';
import { validatePolicyDefinition } from './definition';
import { DEPT, input, leaf, policy, rule, USER } from './fixtures.test-support';
import type { PolicyInput } from './input';
import {
  cidrContains,
  domainIn,
  formatIp,
  globMatch,
  normalizeAddress,
  normalizeDomain,
  parseCidr,
  parseIp,
} from './matchers';
import type { SyntheticFacts } from './synthetic';
import { isValidTimeZone, localTime } from './time';

/** Evaluates a node on facts; asserts the node is valid in a `when` first. */
function ev(node: unknown, facts: SyntheticFacts | PolicyInput = {}): Tri {
  const doc = policy([rule(1, node, [{ type: 'TAG', label: 't' }])]);
  const v = validatePolicyDefinition(doc);
  if (!v.ok) throw new Error(JSON.stringify(v.violations));
  const i = 'version' in facts ? facts : input(facts);
  return evalNode(compileNode(node as PolicyNode, 'when'), buildFacts(i)).value;
}

const T = TRUE;
const F = FALSE;
const U = UNKNOWN;

describe('operators: true / false / unknown', () => {
  it('equals with case and NFC normalization', () => {
    const facts = { recipients: [{ address: 'José@Example.COM' }] };
    expect(ev(leaf('recipient.address', 'equals', 'josé@example.com'), facts)).toBe(T);
    expect(ev(leaf('recipient.address', 'equals', 'JOSÉ@EXAMPLE.COM'), facts)).toBe(T);
    expect(ev(leaf('recipient.address', 'equals', 'jose@example.com'), facts)).toBe(F);
    expect(ev(leaf('sender.authenticated.address', 'equals', 'a@b.example'), {})).toBe(U);
    expect(ev(leaf('direction', 'equals', 'inbound'), {})).toBe(T);
  });
  it('in / not_in', () => {
    const facts = { sender: { envelope: 'Boss@Corp.Example' } };
    expect(ev(leaf('sender.envelope.domain', 'in', ['corp.example', 'x.example']), facts)).toBe(T);
    expect(ev(leaf('sender.envelope.domain', 'in', ['x.example']), facts)).toBe(F);
    expect(ev(leaf('sender.envelope.domain', 'not_in', ['x.example']), facts)).toBe(T);
    expect(ev(leaf('sender.envelope.domain', 'not_in', ['corp.example']), facts)).toBe(F);
    expect(
      ev(leaf('sender.envelope.domain', 'not_in', ['x.example']), { sender: { envelope: null } }),
    ).toBe(U);
    expect(ev(leaf('sender.envelope.local_part', 'in', ['boss']), facts)).toBe(T);
  });
  it('domain_in matches on labels, with punycode', () => {
    const host = (h: string) => ({ urls: [{ host: h }] });
    expect(ev(leaf('url.host', 'domain_in', ['example.com']), host('a.example.com'))).toBe(T);
    expect(ev(leaf('url.host', 'domain_in', ['example.com']), host('example.com'))).toBe(T);
    expect(ev(leaf('url.host', 'domain_in', ['example.com']), host('badexample.com'))).toBe(F);
    expect(ev(leaf('url.host', 'domain_in', ['example.com']), host('example.com.evil.net'))).toBe(
      F,
    );
    expect(
      ev(leaf('url.host', 'domain_in', ['bücher.example']), host('shop.xn--bcher-kva.example')),
    ).toBe(T);
    expect(
      ev(leaf('url.host', 'domain_in', ['xn--bcher-kva.example']), host('BÜCHER.example')),
    ).toBe(T);
    expect(ev(leaf('url.domain', 'domain_in', ['example.com']), host('192.0.2.1'))).toBe(U);
    expect(ev(leaf('url.domain', 'equals', 'example.co.uk'), host('a.b.example.co.uk'))).toBe(T);
  });
  it('glob (case-insensitive, linear)', () => {
    const file = (filename: string | null) => ({ attachments: [{ filename }] });
    expect(ev(leaf('attachment.filename', 'glob', ['*.ISO']), file('Disk Image.iso'))).toBe(T);
    expect(
      ev(leaf('attachment.filename', 'glob', ['invoice-??.pdf']), file('invoice-07.pdf')),
    ).toBe(T);
    expect(ev(leaf('attachment.filename', 'glob', ['invoice-??.pdf']), file('invoice-7.pdf'))).toBe(
      F,
    );
    expect(ev(leaf('attachment.filename', 'glob', ['*.iso']), file(null))).toBe(U);
    expect(
      ev(leaf('client.hostname', 'glob', ['mail*.partner.example']), {
        client: { hostname: 'MAIL01.partner.example' },
      }),
    ).toBe(T);
  });
  it('regex (RE2, subject cut to 1 024 characters)', () => {
    const file = (filename: string | null) => ({ attachments: [{ filename }] });
    expect(ev(leaf('attachment.filename', 'regex', ['^inv.*\\.pdf$']), file('invoice.pdf'))).toBe(
      T,
    );
    expect(ev(leaf('attachment.filename', 'regex', ['^inv.*\\.pdf$']), file('Invoice.PDF'))).toBe(
      F,
    );
    expect(
      ev(
        leaf('attachment.filename', 'regex', [{ pattern: '^inv.*\\.pdf$', flags: 'i' }]),
        file('Invoice.PDF'),
      ),
    ).toBe(T);
    expect(ev(leaf('attachment.filename', 'regex', ['x']), file(null))).toBe(U);
    const long = `${'a'.repeat(250)}`;
    const i = input(file(long));
    const items = [{ ...i.attachments.items[0]!, filename: `${'a'.repeat(1024)}Z` }];
    const cut = { ...i, attachments: { ...i.attachments, items } };
    expect(ev(leaf('attachment.filename', 'regex', ['Z']), cut)).toBe(F);
    expect(ev(leaf('attachment.filename', 'regex', ['a{10}']), cut)).toBe(T);
  });
  it('in_cidr and ip equals (v4, v6, mapped)', () => {
    const ip = (v: string | null) => ({ client: { ip: v } });
    expect(ev(leaf('client.ip', 'in_cidr', ['10.0.0.0/8']), ip('10.1.2.3'))).toBe(T);
    expect(ev(leaf('client.ip', 'in_cidr', ['10.0.0.0/8']), ip('11.1.2.3'))).toBe(F);
    expect(ev(leaf('client.ip', 'in_cidr', ['10.0.0.0/8']), ip('::ffff:10.1.2.3'))).toBe(T);
    expect(ev(leaf('client.ip', 'in_cidr', ['::ffff:10.0.0.0/104']), ip('10.9.9.9'))).toBe(T);
    expect(ev(leaf('client.ip', 'in_cidr', ['2001:db8::/32']), ip('2001:DB8:0:1::25'))).toBe(T);
    expect(ev(leaf('client.ip', 'in_cidr', ['2001:db8::/32']), ip('2001:db9::1'))).toBe(F);
    expect(ev(leaf('client.ip', 'in_cidr', ['0.0.0.0/0']), ip('2001:db8::1'))).toBe(F);
    expect(ev(leaf('client.ip', 'in_cidr', ['10.0.0.0/8']), ip(null))).toBe(U);
    expect(ev(leaf('client.ip', 'equals', '2001:db8::1'), ip('2001:0db8:0:0:0:0:0:1'))).toBe(T);
    expect(ev(leaf('client.ip', 'equals', '192.0.2.1'), ip('192.0.2.2'))).toBe(F);
  });
  it('numeric comparisons and between', () => {
    const score = (s: number) => ({ risk: { rev0: { score: s } } });
    const cases: Array<[string, unknown, number, Tri]> = [
      ['eq', 300, 300, T],
      ['eq', 300, 301, F],
      ['gt', 300, 301, T],
      ['gt', 300, 300, F],
      ['gte', 300, 300, T],
      ['gte', 300, 299, F],
      ['lt', 300, 299, T],
      ['lt', 300, 300, F],
      ['lte', 300, 300, T],
      ['lte', 300, 301, F],
      ['between', [100, 200], 100, T],
      ['between', [100, 200], 200, T],
      ['between', [100, 200], 201, F],
    ];
    for (const [op, value, s, expected] of cases) {
      expect(ev(leaf('risk.score', op, value), score(s)), `${op} ${String(value)} ${s}`).toBe(
        expected,
      );
    }
    expect(ev(leaf('risk.score', 'gte', 1), { risk: null })).toBe(U);
    expect(
      ev(leaf('recipients.count', 'gt', 1), {
        recipients: [{ address: 'a@x.example' }, { address: 'b@x.example' }],
      }),
    ).toBe(T);
  });
  it('ordered enums (risk level, recommended action, dlp action and severity)', () => {
    expect(ev(leaf('risk.level', 'gte', 'medium'), { risk: { rev0: { level: 'high' } } })).toBe(T);
    expect(ev(leaf('risk.level', 'gte', 'medium'), { risk: { rev0: { level: 'low' } } })).toBe(F);
    expect(ev(leaf('risk.level', 'lte', 'low'), { risk: { rev0: { level: 'low' } } })).toBe(T);
    expect(ev(leaf('risk.level', 'gte', 'low'), { risk: null })).toBe(U);
    expect(
      ev(leaf('risk.recommended_action', 'gte', 'quarantine'), {
        risk: { rev0: { recommendedAction: 'block' } },
      }),
    ).toBe(T);
    expect(ev(leaf('dlp.action', 'gte', 'require_approval'), { dlp: { action: 'alert' } })).toBe(F);
    expect(ev(leaf('dlp.action', 'gte', 'require_approval'), {})).toBe(U);
    expect(
      ev(leaf('dlp.max_severity', 'gte', 'high'), {
        dlp: { action: 'alert', maxSeverity: 'critical' },
      }),
    ).toBe(T);
    expect(ev(leaf('dlp.max_severity', 'gte', 'high'), { dlp: { action: 'alert' } })).toBe(U);
  });
  it('maxima and unions over revisions; revision 1 only raises', () => {
    const facts = {
      risk: {
        rev0: { level: 'high' as const, score: 600, reasonCodes: ['risk.level.high'] },
        rev1: {
          level: 'low' as const,
          score: 150,
          reasonCodes: ['risk.sandbox.included'],
          sandboxOutcome: 'clean' as const,
        },
      },
    };
    expect(ev(leaf('risk.level', 'equals', 'high'), facts)).toBe(T);
    expect(ev(leaf('risk.score', 'eq', 600), facts)).toBe(T);
    expect(
      ev(
        leaf('risk.reason_codes', 'contains_all', ['risk.level.high', 'risk.sandbox.included']),
        facts,
      ),
    ).toBe(T);
    expect(ev(leaf('risk.sandbox_outcome', 'equals', 'clean'), facts)).toBe(T);
    expect(ev(leaf('risk.sandbox_outcome', 'equals', 'clean'), {})).toBe(U);
    expect(
      ev(leaf('risk.status', 'equals', 'error'), { risk: { rev0: {}, rev1: { status: 'error' } } }),
    ).toBe(T);
  });
  it('code sets: contains_any / contains_all / exists', () => {
    const facts = {
      risk: {
        rev0: {
          hardBlocks: [{ id: 'hb.malware_url' as const, action: 'block' as const }],
          recommendedAction: 'block' as const,
        },
      },
    };
    expect(
      ev(leaf('risk.hard_blocks', 'contains_any', ['hb.malware_url', 'hb.dlp_block']), facts),
    ).toBe(T);
    expect(
      ev(leaf('risk.hard_blocks', 'contains_all', ['hb.malware_url', 'hb.dlp_block']), facts),
    ).toBe(F);
    expect(ev(leaf('risk.hard_blocks', 'exists'), facts)).toBe(T);
    expect(ev(leaf('risk.hard_blocks', 'exists'), {})).toBe(F);
    expect(ev(leaf('risk.hard_blocks', 'exists'), { risk: null })).toBe(F);
    expect(ev(leaf('risk.hard_blocks', 'contains_any', ['hb.malware_url']), { risk: null })).toBe(
      U,
    );
    expect(
      ev(leaf('dlp.categories', 'contains_any', ['payment_card']), {
        dlp: { action: 'alert', categories: ['payment_card'] },
      }),
    ).toBe(T);
    expect(
      ev(leaf('scan.failed_engines', 'contains_any', ['dlp']), {
        scan: { engines: [{ engine: 'dlp', outcome: 'timeout' }] },
      }),
    ).toBe(T);
    expect(
      ev(leaf('scan.unknown_engines', 'exists'), {
        scan: { engines: [{ engine: 'url', outcome: 'unknown' }] },
      }),
    ).toBe(T);
    expect(ev(leaf('scan.failed_engines', 'exists'), { trigger: 'parse_failed' })).toBe(F);
    expect(
      ev(leaf('url.reason_codes', 'contains_any', ['url.phishing']), {
        urls: [{ host: 'a.example' }],
      }),
    ).toBe(U);
  });
  it('exists and is', () => {
    expect(ev(leaf('sender.envelope.address', 'exists'), {})).toBe(T);
    expect(ev(leaf('sender.envelope.address', 'exists'), { sender: { envelope: null } })).toBe(F);
    expect(
      ev(leaf('sender.envelope.address', 'exists'), { sender: { envelope: 'not an address' } }),
    ).toBe(F);
    expect(
      ev(leaf('sender.authenticated.address', 'exists'), { sender: { authenticated: true } }),
    ).toBe(T);
    expect(ev(leaf('sender.trusted', 'is', true), {})).toBe(U);
    expect(ev(leaf('sender.trusted', 'is', false), { direction: 'outbound' })).toBe(T);
    expect(ev(leaf('risk.present', 'is', false), { risk: null })).toBe(T);
    expect(ev(leaf('dlp.present', 'is', true), {})).toBe(F);
    expect(ev(leaf('bec.ai_raised', 'is', true), {})).toBe(U);
  });
  it('directory ids (department/user)', () => {
    const facts = {
      direction: 'outbound' as const,
      sender: { envelope: 'cfo@corp.example', authenticated: true },
      recipients: [{ address: 'a@ext.example' }],
      directory: { departments: { 'CFO@corp.example': [DEPT.finance] } },
    };
    expect(ev(leaf('sender.department', 'in', [DEPT.finance]), facts)).toBe(T);
    expect(ev(leaf('sender.department', 'not_in', [DEPT.finance]), facts)).toBe(F);
    expect(ev(leaf('sender.department', 'in', [DEPT.legal]), facts)).toBe(F);
    expect(
      ev(leaf('sender.department', 'in', [DEPT.finance]), { ...facts, direction: 'inbound' }),
    ).toBe(U);
    expect(
      ev(leaf('sender.department', 'in', [DEPT.finance]), {
        ...facts,
        sender: { envelope: 'cfo@corp.example' },
      }),
    ).toBe(U);
    expect(
      ev(leaf('recipient.department', 'in', [DEPT.finance]), {
        recipients: [{ address: 'x@corp.example' }],
        directory: { departments: { 'x@corp.example': [DEPT.finance] } },
      }),
    ).toBe(T);
    expect(
      ev(leaf('recipient.department', 'not_in', [DEPT.finance]), {
        recipients: [{ address: 'y@corp.example' }],
      }),
    ).toBe(T);
  });
  it('directory user ids (sender.user / recipient.user)', () => {
    const facts = {
      direction: 'outbound' as const,
      sender: { envelope: 'CEO@corp.example', authenticated: true },
      recipients: [{ address: 'a@ext.example' }],
      directory: { users: { 'ceo@corp.example': [USER.ceo] } },
    };
    expect(ev(leaf('sender.user', 'in', [USER.ceo]), facts)).toBe(T);
    expect(ev(leaf('sender.user', 'not_in', [USER.ceo]), facts)).toBe(F);
    expect(ev(leaf('sender.user', 'in', [DEPT.finance]), facts)).toBe(F);
    // Inbound mail and an unauthenticated sender have no directory identity: unknown.
    expect(ev(leaf('sender.user', 'in', [USER.ceo]), { ...facts, direction: 'inbound' })).toBe(U);
    expect(
      ev(leaf('sender.user', 'in', [USER.ceo]), {
        ...facts,
        sender: { envelope: 'ceo@corp.example' },
      }),
    ).toBe(U);
    const rcpts = {
      recipients: [{ address: 'CEO@corp.example' }, { address: 'x@corp.example' }],
      directory: { users: { 'ceo@corp.example': [USER.ceo] } },
    };
    expect(ev(leaf('recipient.user', 'in', [USER.ceo]), rcpts)).toBe(T);
    expect(ev(leaf('recipient.user', 'in', [USER.ceo], 'all'), rcpts)).toBe(F);
    expect(
      ev(leaf('recipient.user', 'in', [USER.ceo], 'all'), {
        ...rcpts,
        recipients: [{ address: 'ceo@corp.example' }],
      }),
    ).toBe(T);
    expect(
      ev(leaf('recipient.user', 'not_in', [USER.ceo]), {
        recipients: [{ address: 'y@corp.example' }],
      }),
    ).toBe(T);
  });
  it('auth outcomes are unknown without an authentication row', () => {
    expect(ev(leaf('auth.dmarc', 'equals', 'pass'), {})).toBe(U);
    expect(ev(leaf('auth.dmarc', 'in', ['fail', 'none']), { auth: { dmarc: 'fail' } })).toBe(T);
  });
});

describe('Kleene logic', () => {
  const t = leaf('risk.present', 'is', true);
  const f = leaf('risk.present', 'is', false);
  const u = leaf('sender.trusted', 'is', true); // inbound without bec/auth facts → unknown
  const node = { t, f, u } as const;
  const vals = { t: T, f: F, u: U } as const;
  const keys = ['t', 'f', 'u'] as const;
  it('leaves', () => {
    for (const k of keys) expect(ev(node[k])).toBe(vals[k]);
  });
  it('not', () => {
    expect(ev({ not: t })).toBe(F);
    expect(ev({ not: f })).toBe(T);
    expect(ev({ not: u })).toBe(U);
  });
  it('all / any truth tables', () => {
    for (const a of keys) {
      for (const b of keys) {
        const and = Math.min(vals[a], vals[b]);
        const or = Math.max(vals[a], vals[b]);
        expect(ev({ all: [node[a], node[b]] }), `${a} ∧ ${b}`).toBe(and);
        expect(ev({ any: [node[a], node[b]] }), `${a} ∨ ${b}`).toBe(or);
      }
    }
  });
  it('missing facts never make a rule match', () => {
    expect(ev({ all: [t, u] })).toBe(U);
    expect(ev({ not: { all: [t, u] } })).toBe(U);
  });
});

describe('quantifiers', () => {
  it('table', () => {
    expect(quantify([], 'any', false)).toBe(F);
    expect(quantify([], 'all', false)).toBe(F);
    expect(quantify([T, F], 'any', false)).toBe(T);
    expect(quantify([T, F], 'all', false)).toBe(F);
    expect(quantify([T, T], 'all', false)).toBe(T);
    expect(quantify([F, U], 'any', false)).toBe(U);
    expect(quantify([T, U], 'all', false)).toBe(U);
    // Truncated lists: a seen match is still a match for any; all is unknown unless a seen one fails.
    expect(quantify([T], 'any', true)).toBe(T);
    expect(quantify([F], 'any', true)).toBe(U);
    expect(quantify([T, T], 'all', true)).toBe(U);
    expect(quantify([T, F], 'all', true)).toBe(F);
  });
  it('on recipients, attachments and urls', () => {
    const fin = (addresses: string[]) => ({
      recipients: addresses.map((address) => ({ address })),
      directory: { departments: { 'f@corp.example': [DEPT.finance] } },
    });
    const all = leaf('recipient.department', 'in', [DEPT.finance], 'all');
    const any = leaf('recipient.department', 'in', [DEPT.finance], 'any');
    expect(ev(all, fin(['f@corp.example']))).toBe(T);
    expect(ev(all, fin(['f@corp.example', 'o@corp.example']))).toBe(F);
    expect(ev(any, fin(['f@corp.example', 'o@corp.example']))).toBe(T);
    expect(ev(all, fin([]))).toBe(F);
    expect(ev(any, fin([]))).toBe(F);
    const i = input(fin(['f@corp.example']));
    const truncated = { ...i, recipientsTruncated: true };
    expect(ev(all, truncated)).toBe(U);
    expect(ev(any, truncated)).toBe(T);
    expect(ev(leaf('attachment.extension', 'in', ['iso']), { attachments: [] })).toBe(F);
    const a = input({ attachments: [{ filename: 'a.pdf' }] });
    expect(
      ev(leaf('attachment.extension', 'in', ['iso']), {
        ...a,
        attachments: { ...a.attachments, truncated: true },
      }),
    ).toBe(U);
    const u = input({ urls: [{ host: 'ok.example', verdict: 'clean' }] });
    expect(
      ev(leaf('url.verdict', 'equals', 'clean', 'all'), {
        ...u,
        urls: { ...u.urls, truncated: true },
      }),
    ).toBe(U);
  });
});

describe('time conditions', () => {
  const at = (evaluationTime: string) => ({ evaluationTime });
  const win = (timeZone: string, days: string[], from: string, to: string) =>
    leaf('time.window', 'within', { timeZone, days, from, to });
  it('Asia/Kolkata (UTC+05:30) and day of week at local midnight', () => {
    const w = win('Asia/Kolkata', ['mon'], '09:00', '17:00');
    expect(ev(w, at('2026-11-09T03:30:00.000Z'))).toBe(T); // Mon 09:00 IST
    expect(ev(w, at('2026-11-09T11:29:59.999Z'))).toBe(T); // Mon 16:59:59
    expect(ev(w, at('2026-11-09T11:30:00.000Z'))).toBe(F); // Mon 17:00
    expect(ev(w, at('2026-11-09T03:29:00.000Z'))).toBe(F); // Mon 08:59
    const day = win('Asia/Kolkata', ['mon'], '00:00', '24:00');
    expect(ev(day, at('2026-11-08T18:29:59.000Z'))).toBe(F); // Sun 23:59:59 IST
    expect(ev(day, at('2026-11-08T18:30:00.000Z'))).toBe(T); // Mon 00:00 IST
  });
  it('America/New_York spring-forward gap and fall-back overlap', () => {
    const gap = win('America/New_York', ['sun'], '02:00', '03:00');
    expect(ev(gap, at('2026-03-08T06:59:59.000Z'))).toBe(F); // 01:59:59 EST
    expect(ev(gap, at('2026-03-08T07:00:00.000Z'))).toBe(F); // 03:00 EDT (02:xx never exists)
    const early = win('America/New_York', ['sun'], '01:00', '02:00');
    expect(ev(early, at('2026-11-01T05:30:00.000Z'))).toBe(T); // 01:30 EDT
    expect(ev(early, at('2026-11-01T06:30:00.000Z'))).toBe(T); // 01:30 EST (repeated hour)
    expect(ev(early, at('2026-11-01T07:30:00.000Z'))).toBe(F); // 02:30 EST
  });
  it('Europe/London BST transitions', () => {
    const w = win('Europe/London', ['sun'], '01:00', '02:00');
    expect(ev(w, at('2026-03-29T00:59:59.000Z'))).toBe(F); // 00:59:59 GMT
    expect(ev(w, at('2026-03-29T01:00:00.000Z'))).toBe(F); // 02:00 BST
    expect(ev(w, at('2026-10-25T00:30:00.000Z'))).toBe(T); // 01:30 BST
    expect(ev(w, at('2026-10-25T01:30:00.000Z'))).toBe(T); // 01:30 GMT
  });
  it('Australia/Lord_Howe half-hour DST', () => {
    const gap = win('Australia/Lord_Howe', ['sun'], '02:00', '02:30');
    expect(ev(gap, at('2026-10-03T15:29:59.000Z'))).toBe(F); // 01:59:59 LHST
    expect(ev(gap, at('2026-10-03T15:30:00.000Z'))).toBe(F); // 02:30 LHDT
    const after = win('Australia/Lord_Howe', ['sun'], '02:30', '03:00');
    expect(ev(after, at('2026-10-03T15:30:00.000Z'))).toBe(T);
    const overlap = win('Australia/Lord_Howe', ['sun'], '01:30', '02:00');
    expect(ev(overlap, at('2026-04-04T14:45:00.000Z'))).toBe(T); // 01:45 LHDT
    expect(ev(overlap, at('2026-04-04T15:15:00.000Z'))).toBe(T); // 01:45 LHST
  });
  it('overnight windows wrap midnight and belong to their start day', () => {
    const w = win('UTC', ['fri'], '22:00', '06:00');
    expect(ev(w, at('2026-11-13T23:00:00.000Z'))).toBe(T); // Fri 23:00
    expect(ev(w, at('2026-11-14T05:59:00.000Z'))).toBe(T); // Sat 05:59
    expect(ev(w, at('2026-11-14T06:00:00.000Z'))).toBe(F); // Sat 06:00
    expect(ev(w, at('2026-11-14T23:00:00.000Z'))).toBe(F); // Sat 23:00
    expect(ev(w, at('2026-11-13T05:00:00.000Z'))).toBe(F); // Fri 05:00 (Thu not listed)
    expect(ev(win('UTC', ['sun'], '22:00', '06:00'), at('2026-11-16T03:00:00.000Z'))).toBe(T); // Mon 03:00
  });
  it('date ranges at zone boundaries', () => {
    const r = leaf('time.date_range', 'within', {
      timeZone: 'America/New_York',
      from: '2026-12-25',
      to: '2026-12-25',
    });
    expect(ev(r, at('2026-12-25T04:59:59.000Z'))).toBe(F); // Dec 24 23:59:59 EST
    expect(ev(r, at('2026-12-25T05:00:00.000Z'))).toBe(T);
    expect(ev(r, at('2026-12-26T04:59:59.000Z'))).toBe(T);
    expect(ev(r, at('2026-12-26T05:00:00.000Z'))).toBe(F);
    const k = leaf('time.date_range', 'within', {
      timeZone: 'Asia/Kolkata',
      from: '2026-01-01',
      to: '2026-01-31',
    });
    expect(ev(k, at('2025-12-31T18:30:00.000Z'))).toBe(T); // Jan 1 00:00 IST
    expect(ev(k, at('2025-12-31T18:29:59.000Z'))).toBe(F);
  });
  it('time zone validation accepts canonical zones and aliases only', () => {
    for (const z of [
      'Asia/Kolkata',
      'Asia/Calcutta',
      'America/New_York',
      'Europe/London',
      'Australia/Lord_Howe',
      'UTC',
      'Etc/GMT+5',
    ]) {
      expect(isValidTimeZone(z), z).toBe(true);
    }
    for (const z of ['Mars/Phobos', '', 'Asia', 'asia/kolkata ', '+05:30', 'A/B/C/D']) {
      expect(isValidTimeZone(z), z).toBe(false);
    }
    expect(localTime(Date.parse('2026-11-09T03:30:00Z'), 'Asia/Kolkata')).toEqual({
      weekday: 0,
      minutes: 540,
      date: '2026-11-09',
    });
  });
});

describe('matchers', () => {
  it('glob matcher', () => {
    expect(globMatch('*', '')).toBe(true);
    expect(globMatch('a*b*c', 'axxbyyc')).toBe(true);
    expect(globMatch('a*b*c', 'axxbyy')).toBe(false);
    expect(globMatch('?', '')).toBe(false);
    expect(globMatch('*.*', 'a.b')).toBe(true);
    expect(globMatch('ab', 'abc')).toBe(false);
    // Adversarial input stays fast (bounded pattern × subject).
    const started = performance.now();
    for (let i = 0; i < 1000; i += 1) globMatch(`${'*a'.repeat(60)}b`, 'a'.repeat(1024));
    expect(performance.now() - started).toBeLessThan(5000);
  });
  it('IP parsing and formatting', () => {
    expect(formatIp(parseIp('2001:0db8:0000:0000:0000:ff00:0042:8329')!)).toBe(
      '2001:db8::ff00:42:8329',
    );
    expect(formatIp(parseIp('::ffff:192.0.2.1')!)).toBe('192.0.2.1');
    expect(formatIp(parseIp('::1')!)).toBe('::1');
    expect(formatIp(parseIp('::')!)).toBe('::');
    expect(formatIp(parseIp('1:0:0:1:0:0:0:1')!)).toBe('1:0:0:1::1');
    expect(parseIp('fe80::1%eth0')).toBeNull();
    expect(parseIp('1.2.3')).toBeNull();
    const c = parseCidr('2001:db8::/32')!;
    expect(cidrContains(c, parseIp('2001:db8:ffff::1')!)).toBe(true);
    expect(parseCidr('::ffff:10.0.0.0/104')).toEqual({
      family: 4,
      network: 0x0a000000n,
      prefix: 8,
    });
  });
  it('domains and addresses', () => {
    expect(normalizeDomain('Bücher.Example.')).toBe('xn--bcher-kva.example');
    expect(normalizeDomain('192.0.2.1')).toBeNull();
    expect(normalizeDomain('a..b')).toBeNull();
    expect(normalizeDomain('-a.example')).toBeNull();
    expect(normalizeAddress('User@Bücher.Example')).toEqual({
      address: 'user@xn--bcher-kva.example',
      domain: 'xn--bcher-kva.example',
      localPart: 'user',
    });
    expect(normalizeAddress('nodomain')).toEqual({
      address: 'nodomain',
      domain: null,
      localPart: 'nodomain',
    });
    expect(domainIn('a.b.example', 'b.example')).toBe(true);
    expect(domainIn('ab.example', 'b.example')).toBe(false);
  });
});
