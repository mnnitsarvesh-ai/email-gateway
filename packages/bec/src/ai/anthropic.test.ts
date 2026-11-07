import { describe, expect, it } from 'vitest';
import { BEC_DEFAULT_RULE_SETTINGS } from '../rules/defaults';
import { evaluateBecRules } from '../rules/evaluate';
import type { BecEvaluationInput } from '../rules/types';
import { loadBecStaticData } from '../static-data';
import {
  AnthropicBecProvider,
  SERVER_SIDE_FALLBACK_BETA,
  type LlmCallInfo,
  type RefusalFallback,
} from './anthropic';
import { buildAiInput } from './input';
import { canonicalJson } from './llm-schema';
import { loadPromptTemplate } from './prompt';
import type { AiInput } from './types';
import { createHash } from 'node:crypto';

/**
 * The provider never calls the network here: the SDK client gets an injected `fetch` that
 * records the request and answers with recorded fixture responses.
 */

const data = loadBecStaticData();

// Marker strings placed in addresses, display names, URLs, digits and tenant names: none may
// appear in any serialized request.
const MARKERS = [
  'mrkfromaddr',
  'mrkfromdom',
  'Zorbulon',
  'Quaxtrel',
  'mrkreplyto',
  'mrklinkhost',
  '74129638',
  'Vendrixa',
  'mrktenantorg',
];

const markerInput: BecEvaluationInput = {
  headers: {
    From: ['Zorbulon Quaxtrel <mrkfromaddr@mrkfromdom.test>'],
    'Reply-To': ['mrkreplyto@gmail.com'],
    Subject: ['Zorbulon needs 74129638 now'],
  },
  envelope: {
    direction: 'inbound',
    envelopeFrom: 'mrkfromaddr@mrkfromdom.test',
    recipients: ['ap@mrktenantorg.test'],
    clientIp: '198.51.100.7',
    receivedAt: new Date('2026-11-02T09:15:00Z'),
  },
  auth: {
    state: 'available',
    row: {
      spf: 'none',
      spfDomain: null,
      dkim: 'none',
      dkimSignatures: [],
      dmarc: 'none',
      dmarcPolicy: null,
      dmarcDomain: null,
      arc: null,
    },
  },
  url: {
    state: 'available',
    rows: [
      {
        urlSeq: 1,
        verdict: 'suspicious',
        reasonCodes: ['url.credential_form'],
        host: 'mrklinkhost.test',
      },
    ],
  },
  text: {
    subject: 'Zorbulon needs 74129638 now',
    textBody: {
      content:
        'Hi, this is Zorbulon Quaxtrel from mrktenantorg. Buy gift cards today and keep this confidential. ' +
        'Pay Vendrixa account 74129638 or write to mrkreplyto@gmail.com, details at https://mrklinkhost.test/pay and mrklinkhost.test. Urgent!',
      truncated: false,
    },
    htmlBody: null,
    parseIncomplete: false,
  },
  tenant: {
    tenantDomains: ['mrktenantorg.test'],
    executives: [{ publicId: 'e1', name: 'Zorbulon Quaxtrel', aliases: [], knownAddresses: [] }],
    vendors: [
      {
        publicId: 'v1',
        name: 'Vendrixa',
        aliases: [],
        domains: ['vendrixa.test'],
        knownSenders: [],
        paymentChangeSensitive: true,
      },
    ],
    trustedSenders: [],
    suppressions: [],
    freemailExtraDomains: [],
    extraProtectedDomains: [],
  },
  history: 'disabled',
};

const rules = evaluateBecRules(markerInput, BEC_DEFAULT_RULE_SETTINGS, data, {
  now: new Date('2026-11-03T00:00:00Z'),
});
const aiInput: AiInput = buildAiInput(rules, markerInput.tenant, { maxExcerptChars: 1500 });

interface Captured {
  url: string;
  headers: Headers;
  body: Record<string, unknown>;
  raw: string;
}

const message = (over: Record<string, unknown> = {}) => ({
  id: 'msg_test',
  type: 'message',
  role: 'assistant',
  model: 'claude-opus-5-5',
  content: [{ type: 'text', text: JSON.stringify(validOutput()) }],
  stop_reason: 'end_turn',
  stop_details: null,
  stop_sequence: null,
  container: null,
  context_management: null,
  diagnostics: null,
  usage: { input_tokens: 812, output_tokens: 95 },
  ...over,
});

function validOutput(over: Record<string, unknown> = {}) {
  const at = aiInput.excerpt!.text.indexOf('gift cards');
  return {
    labels: [
      { label: 'benign', confidence: 0.05 },
      { label: 'bec', confidence: 0.93 },
    ],
    indicators: ['gift_card_request', 'secrecy', 'executive_impersonation'],
    citedFeatures: [{ feature: 'rule_x1', weight: 2.5 }],
    spans: [{ start: at, end: at + 'gift cards'.length, indicator: 'gift_card_request' }],
    ...over,
  };
}

function setup(
  respond: (captured: Captured, init: RequestInit) => Promise<Response> | Response,
  options: { fallback?: RefusalFallback; timeoutMs?: number } = {},
) {
  const calls: Captured[] = [];
  const infos: LlmCallInfo[] = [];
  const fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const raw = typeof init?.body === 'string' ? init.body : '';
    const captured: Captured = {
      url: String(input instanceof Request ? input.url : input),
      headers: new Headers(init?.headers),
      body: JSON.parse(raw) as Record<string, unknown>,
      raw,
    };
    calls.push(captured);
    return respond(captured, init ?? {});
  };
  const provider = new AnthropicBecProvider({
    apiKey: 'sk-ant-test-not-a-real-key',
    model: 'claude-opus-5-5',
    maxOutputTokens: 4096,
    timeoutMs: options.timeoutMs ?? 20_000,
    refusalFallback: options.fallback ?? 'default',
    fetch,
    onResult: (info) => infos.push(info),
  });
  return { provider, calls, infos };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'request-id': 'req_test' },
  });
const signal = () => new AbortController().signal;

describe('AnthropicBecProvider request', () => {
  it('sends the B10 request shape through the beta endpoint with the server-side fallback', async () => {
    const { provider, calls } = setup(() => json(message()));
    const result = await provider.assess(aiInput, signal());
    expect(result.status).toBe('ok');
    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call.url).toMatch(/\/v1\/messages\?beta=true$/);
    expect(call.headers.get('anthropic-beta')).toBe(SERVER_SIDE_FALLBACK_BETA);
    expect(call.body).toMatchObject({
      model: 'claude-opus-5-5',
      max_tokens: 4096,
      fallbacks: 'default',
      output_config: { effort: 'low', format: { type: 'json_schema' } },
      system: loadPromptTemplate().text,
    });
    for (const forbidden of [
      'thinking',
      'temperature',
      'top_p',
      'top_k',
      'tools',
      'betas',
      'metadata',
    ]) {
      expect(call.body, forbidden).not.toHaveProperty(forbidden);
    }
    const schema = (call.body.output_config as { format: { schema: Record<string, unknown> } })
      .format.schema;
    expect(schema.additionalProperties).toBe(false);
    expect(schema.required).toEqual(['labels', 'indicators', 'citedFeatures', 'spans']);
    const messages = call.body.messages as Array<{ role: string; content: string }>;
    expect(messages).toHaveLength(1);
    const content = JSON.parse(messages[0]!.content) as Record<string, unknown>;
    expect(Object.keys(content).sort()).toEqual(['excerpt', 'facts', 'features']);
  });

  it('BEC_LLM_REFUSAL_FALLBACK=off uses messages.create without betas or fallbacks', async () => {
    const { provider, calls } = setup(() => json(message()), { fallback: 'off' });
    expect((await provider.assess(aiInput, signal())).status).toBe('ok');
    expect(calls[0]!.url).toMatch(/\/v1\/messages$/);
    expect(calls[0]!.headers.get('anthropic-beta')).toBeNull();
    expect(calls[0]!.body).not.toHaveProperty('fallbacks');
  });

  it('never sends addresses, names, URLs, digits or tenant names (marker strings)', async () => {
    const { provider, calls } = setup(() => json(message()));
    await provider.assess(aiInput, signal());
    const raw = calls[0]!.raw;
    for (const marker of MARKERS) expect(raw, marker).not.toContain(marker);
    const content = JSON.parse(
      (calls[0]!.body.messages as Array<{ content: string }>)[0]!.content,
    ) as {
      excerpt: { subject: string; text: string };
    };
    expect(`${content.excerpt.subject}\n${content.excerpt.text}`).not.toMatch(/\d{4}/);
    expect(raw).toContain('[EXECUTIVE]');
    expect(raw).toContain('[EMAIL]');
    expect(raw).toContain('[URL]');
    expect(raw).toContain('[NUMBER]');
    expect(raw).toContain('[ORG]');
  });

  it('refuses to construct without an API key', () => {
    expect(
      () =>
        new AnthropicBecProvider({
          apiKey: '',
          model: 'm',
          maxOutputTokens: 1,
          timeoutMs: 1,
          refusalFallback: 'off',
        }),
    ).toThrow(/BEC_LLM_API_KEY/);
  });
});

describe('AnthropicBecProvider responses', () => {
  it('valid output: labels sorted, spans mapped back to source offsets, stable response hash', async () => {
    const { provider, infos } = setup(() => json(message({ model: 'claude-opus-5-5' })));
    const a = await provider.assess(aiInput, signal());
    expect(a).toMatchObject({
      status: 'ok',
      confidence: 0.93,
      modelId: 'claude-opus-5-5',
      modelVersion: 'claude-opus-5-5',
      promptTemplateVersion: 'bec-llm-prompt/1',
      indicators: ['gift_card_request', 'secrecy', 'executive_impersonation'],
      citedFeatures: [{ feature: 'rule_x1', contribution: 2.5 }],
    });
    expect(a.labels.map((l) => l.label)).toEqual(['bec', 'benign']);
    const span = a.spans[0]!;
    expect(span.source).toBe('text');
    expect(markerInput.text.textBody!.content.slice(span.start, span.end)).toBe('gift cards');
    const expectedHash = createHash('sha256').update(canonicalJson(validOutput())).digest('hex');
    expect(a.responseSha256).toBe(expectedHash);
    // key order of the response does not change the hash
    const reordered = setup(() =>
      json(
        message({
          content: [
            {
              type: 'text',
              text: JSON.stringify(Object.fromEntries(Object.entries(validOutput()).reverse())),
            },
          ],
        }),
      ),
    );
    expect((await reordered.provider.assess(aiInput, signal())).responseSha256).toBe(expectedHash);
    expect(infos[0]).toMatchObject({
      status: 'ok',
      inputTokens: 812,
      outputTokens: 95,
      respondedModel: 'claude-opus-5-5',
    });
  });

  it('records the model that answered after a server-side fallback', async () => {
    const { provider } = setup(() =>
      json(
        message({
          model: 'claude-opus-4-8',
          content: [
            {
              type: 'fallback',
              from: { model: 'claude-opus-5-5' },
              to: { model: 'claude-opus-4-8' },
            },
            { type: 'text', text: JSON.stringify(validOutput()) },
          ],
        }),
      ),
    );
    const a = await provider.assess(aiInput, signal());
    expect(a).toMatchObject({
      status: 'ok',
      modelId: 'claude-opus-5-5',
      modelVersion: 'claude-opus-4-8',
    });
  });

  it('stop_reason refusal → refused; max_tokens → invalid_output', async () => {
    const refusal = setup(() =>
      json(
        message({
          stop_reason: 'refusal',
          stop_details: { type: 'refusal', category: 'cyber', explanation: null },
          content: [],
        }),
      ),
    );
    expect(await refusal.provider.assess(aiInput, signal())).toMatchObject({
      status: 'refused',
      labels: [],
      confidence: null,
    });
    expect(refusal.infos[0]!.reason).toBe('refusal');
    const truncated = setup(() =>
      json(
        message({ stop_reason: 'max_tokens', content: [{ type: 'text', text: '{"labels":[' }] }),
      ),
    );
    expect((await truncated.provider.assess(aiInput, signal())).status).toBe('invalid_output');
  });

  const invalid: Array<[string, unknown]> = [
    ['extra field', { ...validOutput(), rationale: 'free text' }],
    ['missing field', (({ spans: _spans, ...rest }) => rest)(validOutput())],
    ['confidence out of range', validOutput({ labels: [{ label: 'bec', confidence: 1.4 }] })],
    [
      'span out of bounds',
      validOutput({ spans: [{ start: 0, end: 999_999, indicator: 'urgency' }] }),
    ],
    ['span start ≥ end', validOutput({ spans: [{ start: 5, end: 5, indicator: 'urgency' }] })],
    ['unknown label', validOutput({ labels: [{ label: 'fraud', confidence: 0.9 }] })],
    ['unknown indicator', validOutput({ indicators: ['ignore_previous_instructions'] })],
    ['unknown feature', validOutput({ citedFeatures: [{ feature: 'rule_zz', weight: 1 }] })],
    [
      'too many labels',
      validOutput({ labels: Array.from({ length: 5 }, () => ({ label: 'bec', confidence: 0.5 })) }),
    ],
    ['no labels', validOutput({ labels: [] })],
  ];
  it.each(invalid)('schema violation (%s) → invalid_output', async (_name, output) => {
    const { provider } = setup(() =>
      json(message({ content: [{ type: 'text', text: JSON.stringify(output) }] })),
    );
    expect((await provider.assess(aiInput, signal())).status).toBe('invalid_output');
  });

  it('non-JSON text → invalid_output; unmappable spans are dropped', async () => {
    const notJson = setup(() =>
      json(message({ content: [{ type: 'text', text: 'I think this is BEC.' }] })),
    );
    expect((await notJson.provider.assess(aiInput, signal())).status).toBe('invalid_output');
    const sep = aiInput.excerpt!.text.indexOf('\n…\n');
    const spans = sep >= 0 ? [{ start: sep, end: sep + 3, indicator: 'urgency' }] : [];
    const dropped = setup(() =>
      json(message({ content: [{ type: 'text', text: JSON.stringify(validOutput({ spans })) }] })),
    );
    const a = await dropped.provider.assess(aiInput, signal());
    expect(a.status).toBe('ok');
    expect(a.spans).toEqual([]);
  });
});

describe('AnthropicBecProvider errors (typed SDK classes, no retries)', () => {
  const apiError = (status: number, type: string) =>
    json({ type: 'error', error: { type, message: 'fixture' } }, status);

  it('429 → error (rate_limited), one call only', async () => {
    const { provider, calls, infos } = setup(() => apiError(429, 'rate_limit_error'));
    expect((await provider.assess(aiInput, signal())).status).toBe('error');
    expect(calls).toHaveLength(1);
    expect(infos[0]).toMatchObject({ status: 'error', reason: 'rate_limited', httpStatus: 429 });
  });
  it('500 / 529 → error (server_error); 400 → error (client_error)', async () => {
    for (const [status, reason] of [
      [500, 'server_error'],
      [529, 'server_error'],
      [400, 'client_error'],
    ] as const) {
      const { provider, calls, infos } = setup(() => apiError(status, 'api_error'));
      expect((await provider.assess(aiInput, signal())).status).toBe('error');
      expect(calls).toHaveLength(1);
      expect(infos[0]).toMatchObject({ reason, httpStatus: status });
    }
  });
  it('network failure → error (connection)', async () => {
    const { provider, infos } = setup(() => Promise.reject(new TypeError('fetch failed')));
    expect((await provider.assess(aiInput, signal())).status).toBe('error');
    expect(infos[0]!.reason).toBe('connection');
  });
  it('request timeout → timeout', async () => {
    const { provider, calls, infos } = setup(
      (_captured, init) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener('abort', () =>
            reject(new DOMException('aborted', 'AbortError')),
          );
        }),
      { timeoutMs: 50 },
    );
    expect((await provider.assess(aiInput, signal())).status).toBe('timeout');
    expect(calls).toHaveLength(1);
    expect(infos[0]!.reason).toBe('timeout');
  });
  it('caller abort (engine deadline) → timeout', async () => {
    const controller = new AbortController();
    const { provider, infos } = setup(
      (_captured, init) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener('abort', () =>
            reject(new DOMException('aborted', 'AbortError')),
          );
          setTimeout(() => controller.abort(), 10);
        }),
    );
    expect((await provider.assess(aiInput, controller.signal)).status).toBe('timeout');
    expect(infos[0]!.reason).toBe('aborted');
  });
});
