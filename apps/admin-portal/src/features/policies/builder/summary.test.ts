import { describe, expect, it } from 'vitest';
import {
  formatBytesExact,
  humanizeValue,
  lineText,
  NOTE_CONTINUE,
  NOTE_OVERRIDE,
  NOTE_STOP,
  summarizeDefinition,
  summaryToText,
  timeKindOf,
} from './summary';
import { DEPT_FINANCE, DEPT_LEGAL, TEST_CATALOG, USER_ALICE } from './test-support/catalog';
import { BRIEF_EXAMPLE, BRIEF_EXAMPLE_TEXT, docsPolicyBlocks } from './test-support/documents';

const policy = (rules: unknown[], extra: Record<string, unknown> = {}) => ({
  dslVersion: 'policy-dsl/1',
  direction: 'any',
  priority: 10,
  rules,
  ...extra,
});
const rule = (when: unknown, extra: Record<string, unknown> = {}) => ({
  id: 'r1',
  priority: 10,
  when,
  actions: [{ type: 'TAG', label: 'x' }],
  ...extra,
});
/** The `IF:` lines of the only rule, as text. */
const ifLines = (doc: unknown): string[] =>
  summarizeDefinition(doc, TEST_CATALOG).rules[0]!.when.map(
    (line) => `${'  '.repeat(line.depth - 1)}${lineText(line)}`,
  );
const leafText = (leaf: Record<string, unknown>) => ifLines(policy([rule(leaf)]))[0];

describe('summarizeDefinition (design B5)', () => {
  it("renders the brief's example exactly as the design states", () => {
    const summary = summarizeDefinition(BRIEF_EXAMPLE, TEST_CATALOG);
    expect(summaryToText(summary)).toBe(BRIEF_EXAMPLE_TEXT);
    expect(summary.floorNote).toBe(TEST_CATALOG.enforcement);
    expect(summary.header).toEqual([]);
    const r = summary.rules[0]!;
    expect(r.ruleId).toBe('quarantine-confidential');
    expect(r.priority).toBe(10);
    expect(r.enabled).toBe(true);
    expect(r.when[0]!.path).toBe('direction');
    expect(r.when[1]!.path).toBe('rules[0].when.all[0]');
    expect(r.then[1]!.path).toBe('rules[0].actions[1]');
    expect(r.when[1]!.tokens.map((t) => t.kind)).toEqual([
      'keyword',
      'text',
      'field',
      'text',
      'op',
      'text',
      'value',
    ]);
  });

  it('never states an outcome for a message', () => {
    const blocks = docsPolicyBlocks();
    for (const { doc } of blocks) {
      const text = summaryToText(summarizeDefinition(doc, TEST_CATALOG));
      expect(text).not.toMatch(/will be|would be|is quarantined|is rejected|is delivered/i);
    }
  });

  it('takes the direction line from rule directions, else from the policy direction', () => {
    expect(ifLines(policy([rule({ all: [] }, { directions: ['inbound', 'internal'] })]))[0]).toBe(
      'Email direction is one of Inbound, Internal',
    );
    expect(ifLines(policy([rule({ all: [] }, { directions: ['outbound'] })]))[0]).toBe(
      'Email direction is Outbound',
    );
    expect(ifLines(policy([rule({ all: [] })], { direction: 'inbound' }))).toEqual([
      'Email direction is Inbound',
    ]);
    // `any` adds no direction line.
    expect(ifLines(policy([rule({ all: [] })]))).toEqual(['No conditions']);
  });

  it('joins groups with AND/OR, nests groups under "all of:"/"any of:" and prefixes NOT:', () => {
    const doc = policy([
      rule({
        any: [
          { field: 'auth.spf', op: 'equals', value: 'fail' },
          {
            all: [
              { field: 'urls.count', op: 'gt', value: 0 },
              { not: { field: 'url.verdict', op: 'in', value: ['clean'] } },
            ],
          },
          { not: { any: [{ field: 'risk.hard_blocks', op: 'exists' }] } },
        ],
      }),
    ]);
    expect(ifLines(doc)).toEqual([
      'SPF result is Fail',
      'OR all of:',
      '  Number of links is greater than 0',
      '  AND NOT: Link verdict is one of Clean',
      'OR NOT: any of:',
      '  Fired hard blocks is present',
    ]);
    // A policy direction keeps the AND semantics of an `any` root.
    expect(ifLines({ ...doc, direction: 'outbound' }).slice(0, 3)).toEqual([
      'Email direction is Outbound',
      'AND any of:',
      '  SPF result is Fail',
    ]);
  });

  it('formats every value shape', () => {
    expect(leafText({ field: 'message.size_bytes', op: 'gt', value: 10485760 })).toBe(
      'Message size is greater than 10 MiB',
    );
    expect(
      leafText({ field: 'attachments.total_bytes', op: 'between', value: [1536, 2 * 1024 ** 3] }),
    ).toBe('Total attachment size is between 1.5 KiB and 2 GiB');
    expect(leafText({ field: 'risk.score', op: 'gte', value: 700 })).toBe(
      'Risk score is at least 700',
    );
    expect(leafText({ field: 'risk.level', op: 'gte', value: 'high' })).toBe(
      'Risk level is at least High',
    );
    expect(leafText({ field: 'sender.trusted', op: 'is', value: false })).toBe(
      'Trusted sender is No',
    );
    expect(leafText({ field: 'sender.envelope.address', op: 'exists' })).toBe(
      'Envelope sender address is present',
    );
    expect(
      leafText({
        field: 'attachment.filename',
        op: 'regex',
        value: ['^invoice', { pattern: 'x+y', flags: 'i' }, { pattern: 'z', flags: '' }],
      }),
    ).toBe('Attachment file name matches the regular expressions /^invoice/, /x+y/i, /z/');
    expect(
      leafText({
        field: 'client.ip',
        op: 'in_cidr',
        value: ['198.51.100.0/24', '2001:db8:25::/48'],
      }),
    ).toBe('Client IP address is in the networks 198.51.100.0/24, 2001:db8:25::/48');
    expect(
      leafText({ field: 'sender.envelope.domain', op: 'domain_in', value: ['partner.example'] }),
    ).toBe('Envelope sender domain is in or under the domains partner.example');
    expect(leafText({ field: 'url.host', op: 'glob', value: ['*.example', 'login.*'] })).toBe(
      'Link host matches the patterns *.example, login.*',
    );
    expect(
      leafText({
        field: 'attachment.reason_codes',
        op: 'contains_all',
        value: ['attachment.malware'],
      }),
    ).toBe('Attachment reason codes contain all of attachment.malware');
    expect(
      leafText({
        field: 'dlp.categories',
        op: 'contains_any',
        value: ['payment_card', 'personal_info'],
      }),
    ).toBe('DLP data categories contain any of Payment card, Personal info');
    expect(
      leafText({
        field: 'time.window',
        op: 'within',
        value: { timeZone: 'Asia/Kolkata', days: ['mon', 'tue'], from: '09:00', to: '18:00' },
      }),
    ).toBe('Time window is within Mon, Tue 09:00-18:00 (Asia/Kolkata)');
    expect(
      leafText({
        field: 'time.date_range',
        op: 'within',
        value: { timeZone: 'Europe/London', from: '2026-12-24', to: '2026-12-26' },
      }),
    ).toBe('Date range is within 2026-12-24 to 2026-12-26 (Europe/London)');
    expect(leafText({ field: 'auth.spf', op: 'equals' })).toBe('SPF result is …');
    expect(leafText({})).toBe('Incomplete condition');
  });

  it('prints quantifiers only when set or inside exceptions', () => {
    expect(leafText({ field: 'recipient.domain', op: 'in', value: ['corp.example'] })).toBe(
      'Recipient domain is one of corp.example',
    );
    expect(
      leafText({
        field: 'recipient.domain',
        op: 'not_in',
        value: ['corp.example'],
        quantifier: 'any',
      }),
    ).toBe('Any recipient: Recipient domain is not one of corp.example');
    const doc = policy([
      rule(
        { field: 'attachments.count', op: 'gt', value: 0 },
        {
          unless: [
            { field: 'recipient.department', op: 'in', value: [DEPT_FINANCE], quantifier: 'all' },
            { field: 'url.verdict', op: 'equals', value: 'clean' },
          ],
        },
      ),
    ]);
    const summary = summarizeDefinition(doc, TEST_CATALOG, {
      departments: new Map([[DEPT_FINANCE, 'Finance']]),
    });
    expect(summary.rules[0]!.unless.map(lineText)).toEqual([
      'Every recipient: Recipient department is one of Finance',
      // In an exception without a quantifier the default quantifier is named.
      'OR Any link: Link verdict is Clean',
    ]);
    expect(summaryToText(summary)).toContain('UNLESS:\n  Every recipient');
  });

  it('replaces directory ids by names when known, else shows their first 8 characters', () => {
    const doc = policy([
      rule({ field: 'sender.department', op: 'in', value: [DEPT_FINANCE, DEPT_LEGAL, USER_ALICE] }),
    ]);
    const names = {
      departments: new Map([[DEPT_FINANCE, 'Finance']]),
      users: new Map([[USER_ALICE, 'alice@example.com']]),
    };
    expect(summarizeDefinition(doc, TEST_CATALOG, names).rules[0]!.when.map(lineText)).toEqual([
      `Sender department is one of Finance, ${DEPT_LEGAL.slice(0, 8)}, alice@example.com`,
    ]);
  });

  it('cuts long lists after five items', () => {
    const values = Array.from({ length: 17 }, (_, i) => `d${i}.example`);
    expect(leafText({ field: 'recipient.domain', op: 'in', value: values })).toBe(
      'Recipient domain is one of d0.example, d1.example, d2.example, d3.example, d4.example and 12 more',
    );
  });

  it('formats actions with parameter labels, quoted strings and yes/no booleans', () => {
    const doc = policy([
      rule(
        { field: 'auth.dmarc', op: 'equals', value: 'fail' },
        {
          actions: [
            { type: 'REJECT', notifySender: false },
            { type: 'TAG', label: 'external', subjectPrefix: '[EXT]', addHeader: true },
            { type: 'WARN', level: 'danger', text: 'Possible impersonation' },
            { type: 'URL_REWRITE' },
            { type: 'CUSTOM_ACTION', mystery: 3 },
          ],
        },
      ),
    ]);
    expect(summarizeDefinition(doc, TEST_CATALOG).rules[0]!.then.map(lineText)).toEqual([
      'Reject (notify the sender: no)',
      'AND Tag (label: "external", subject prefix: "[EXT]", add the tag header: yes)',
      'AND Warn recipients (level: danger, text: "Possible impersonation")',
      'AND Require URL rewriting',
      'AND CUSTOM_ACTION (mystery: 3)',
    ]);
  });

  it('adds notes for explicit stop and override, and marks disabled rules', () => {
    const doc = policy([
      rule(
        { field: 'auth.spf', op: 'equals', value: 'pass' },
        {
          id: 'a',
          priority: 1,
          stop: true,
          override: true,
          enabled: false,
          actions: [{ type: 'ALLOW' }],
        },
      ),
      rule(
        { field: 'auth.spf', op: 'equals', value: 'pass' },
        { id: 'b', priority: 2, stop: false, description: 'Keep going' },
      ),
      rule({ field: 'auth.spf', op: 'equals', value: 'pass' }, { id: 'c', priority: 3 }),
    ]);
    const summary = summarizeDefinition(doc, TEST_CATALOG);
    expect(summary.rules.map((r) => r.title)).toEqual([
      'Rule a (priority 1) (disabled)',
      'Rule b (priority 2): Keep going',
      'Rule c (priority 3)',
    ]);
    expect(summary.rules[0]!.notes).toEqual([NOTE_STOP, NOTE_OVERRIDE]);
    expect(summary.rules[0]!.enabled).toBe(false);
    expect(summary.rules[1]!.notes).toEqual([NOTE_CONTINUE]);
    expect(summary.rules[2]!.notes).toEqual([]);
    expect(summaryToText(summary)).toContain(
      'THEN:\n  Allow\n  Then stop evaluating later rules\n  May override',
    );
  });

  it('lists rules in evaluation order and the policy-wide exceptions last', () => {
    const doc = policy(
      [
        rule({ field: 'auth.spf', op: 'equals', value: 'fail' }, { id: 'late', priority: 50 }),
        rule({ field: 'auth.spf', op: 'equals', value: 'fail' }, { id: 'early', priority: 5 }),
      ],
      {
        exceptions: [
          { field: 'sender.authenticated.domain', op: 'domain_in', value: ['partner.example'] },
          { field: 'sender.trusted', op: 'is', value: true },
        ],
      },
    );
    const summary = summarizeDefinition(doc, TEST_CATALOG);
    expect(summary.rules.map((r) => r.ruleId)).toEqual(['early', 'late']);
    expect(summary.rules[0]!.when[0]!.path).toBe('rules[1].when');
    const text = summaryToText(summary);
    expect(
      text.endsWith(
        'Policy-wide exceptions:\n  Authenticated sender domain is in or under the domains partner.example\n  OR Trusted sender is Yes',
      ),
    ).toBe(true);
  });

  it('falls back to raw names for fields and operators the catalogue does not know', () => {
    expect(leafText({ field: 'future.field', op: 'future_op', value: ['a', 'b'] })).toBe(
      'future.field future_op a, b',
    );
  });

  it('explains documents it cannot summarize', () => {
    expect(summarizeDefinition({ dslVersion: null }, TEST_CATALOG).header.map(lineText)).toEqual([
      'This definition is not a policy-dsl/1 document; it is shown as JSON only.',
    ]);
    expect(
      summarizeDefinition({ ...BRIEF_EXAMPLE, extra: true }, TEST_CATALOG).header.map(lineText)[0],
    ).toContain('(extra)');
    expect(summaryToText(summarizeDefinition(policy([]), TEST_CATALOG))).toBe(
      'This policy has no rules.',
    );
  });
});

describe('value helpers', () => {
  it('humanizes vocabulary values but keeps dotted machine codes', () => {
    expect(humanizeValue('payment_card')).toBe('Payment card');
    expect(humanizeValue('dlp_violation')).toBe('DLP violation');
    expect(humanizeValue('hb.dlp_block')).toBe('hb.dlp_block');
  });

  it('formats bytes with exact binary units', () => {
    expect(formatBytesExact(0)).toBe('0 B');
    expect(formatBytesExact(1500)).toBe('1500 B');
    expect(formatBytesExact(1024)).toBe('1 KiB');
    expect(formatBytesExact(1536)).toBe('1.5 KiB');
    expect(formatBytesExact(25 * 1024 ** 2)).toBe('25 MiB');
    expect(formatBytesExact(3 * 1024 ** 3)).toBe('3 GiB');
  });

  it('tells the two time value kinds apart by the field name', () => {
    expect(timeKindOf({ name: 'time.window', type: 'time' })).toBe('window');
    expect(timeKindOf({ name: 'time.date_range', type: 'time' })).toBe('date_range');
    expect(timeKindOf({ name: 'time.other', type: 'time' })).toBeNull();
    expect(timeKindOf({ name: 'time.window', type: 'string' })).toBeNull();
  });
});
