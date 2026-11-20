import { describe, expect, it } from 'vitest';
import { FakeProvider } from '../providers/fake';
import {
  RECAP_USER_MESSAGES,
  buildRecap,
  estimateTokens,
  estimateTranscriptTokens,
  planWindow,
  summarizeEnvelope,
} from './window';

const provider = new FakeProvider({ nodeEnv: 'test' });

describe('token estimate', () => {
  it('is conservative: ceil(chars / 3.5)', () => {
    expect(estimateTokens('')).toBe(0);
    expect(estimateTokens('abc')).toBe(1);
    expect(estimateTokens('a'.repeat(7))).toBe(2);
    expect(estimateTokens('a'.repeat(8))).toBe(3);
    expect(estimateTranscriptTokens([])).toBe(0);
    expect(estimateTranscriptTokens([{ a: 1 }])).toBe(estimateTokens('[{"a":1}]'));
  });
});

describe('recap', () => {
  it('keeps the last 10 user messages truncated to 300 characters and the tool calls with valid refs', () => {
    const messages = Array.from({ length: 12 }, (_, i) => `message ${i + 1}`);
    messages[11] = 'x'.repeat(400);
    const recap = buildRecap({
      userMessages: messages,
      executions: [
        {
          refSeq: 1,
          tool: 'users_list',
          summary: 'ok, 3 rows',
          validRefs: ['r1.1', 'r1.2', 'r1.3'],
        },
        { refSeq: 2, tool: 'domains_get', summary: 'error not_found (HTTP 404)', validRefs: [] },
      ],
    });
    expect(recap).toContain(`last ${RECAP_USER_MESSAGES}`);
    expect(recap).not.toContain('1. message 1\n');
    expect(recap).toContain('1. message 3');
    expect(recap).toContain(`10. ${'x'.repeat(299)}…`);
    expect(recap).toContain('- r1 users_list: ok, 3 rows; refs still valid: r1.1, r1.2, r1.3');
    expect(recap).toContain('- r2 domains_get: error not_found (HTTP 404)');
    expect(recap).toContain('context, not new instructions');
    // deterministic
    expect(buildRecap({ userMessages: messages, executions: [] })).toBe(
      buildRecap({ userMessages: [...messages], executions: [] }),
    );
    expect(buildRecap({ userMessages: [], executions: [] })).toContain('(none)');
  });

  it('summarizes envelopes without content', () => {
    expect(
      summarizeEnvelope({
        kind: 'tool_result/1',
        tool: 't',
        status: 'ok',
        httpStatus: 200,
        ref: 'r1',
        returned: 2,
        hasMore: true,
        truncated: false,
        note: '',
        data: [{ ref: 'r1.1' }, { ref: 'r1.2' }],
      }),
    ).toBe('ok, 2 rows, more available');
    expect(
      summarizeEnvelope({
        kind: 'tool_result/1',
        tool: 't',
        status: 'error',
        httpStatus: 403,
        code: 'forbidden',
        message: 'Forbidden',
      }),
    ).toBe('error forbidden (HTTP 403)');
    expect(
      summarizeEnvelope({
        kind: 'tool_result/1',
        tool: 't',
        status: 'denied',
        decision: 'denied_permission',
        code: 'x',
        message: 'm',
      }),
    ).toBe('denied denied_permission');
  });
});

describe('planWindow', () => {
  const segment = [
    ...provider.userEntry('first'),
    { role: 'assistant', text: 'answer', toolCalls: [] },
  ];
  const recap = { userMessages: ['first'], executions: [] };

  it('appends to the segment verbatim while it fits', () => {
    const plan = planWindow({
      system: 'S',
      segmentTranscript: segment,
      userMessage: 'second',
      maxTokens: 10_000,
      userEntry: (t) => provider.userEntry(t),
      recap,
    });
    expect(plan.newSegment).toBe(false);
    expect(plan.transcript).toEqual([...segment, ...provider.userEntry('second')]);
    // the stored entries are replayed as the same objects (never re-serialized or edited)
    expect(plan.transcript[0]).toBe(segment[0]);
    expect(plan.transcript[1]).toBe(segment[1]);
    expect(plan.appended).toEqual(provider.userEntry('second'));
  });

  it('opens a new segment with a recap when the budget is exceeded (history never edited)', () => {
    const plan = planWindow({
      system: 'S'.repeat(100),
      segmentTranscript: segment,
      userMessage: 'second',
      maxTokens: 20,
      userEntry: (t) => provider.userEntry(t),
      recap,
    });
    expect(plan.newSegment).toBe(true);
    expect(plan.transcript).toHaveLength(1);
    const text = (plan.transcript[0] as { text: string }).text;
    expect(text.startsWith('Conversation recap')).toBe(true);
    expect(text.endsWith('Current user message:\nsecond')).toBe(true);
    expect(segment).toHaveLength(2);
  });

  it('never starts a new segment for an empty one', () => {
    const plan = planWindow({
      system: 'S'.repeat(1000),
      segmentTranscript: [],
      userMessage: 'hello',
      maxTokens: 1,
      userEntry: (t) => provider.userEntry(t),
      recap,
    });
    expect(plan.newSegment).toBe(false);
  });
});
