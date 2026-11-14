import 'server-only';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { SeededRandom, hashString, stableUuid } from '../generator';
import {
  fixtureDatasetAnchor,
  maskAddress,
  maskAddressesInText,
  transitionsFor,
  type FixtureMessage,
  type FixtureRecipient,
} from './message-dataset';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Data builders of the Email Details operations in dev fixture mode (step 7.2 WP4, §2 E14): the
 * engine details of every scan round (attachment, sandbox, url and rewrite, bec, dlp, risk
 * contributions), the lifecycle and its history, recipients, deliveries and their events, the
 * stored header allow-list (every availability state across messages), the DLP evidence and the
 * historic audit rows of messages. Pure functions of the synthetic dataset (`message-dataset.ts`);
 * the handlers in `messages.ts` apply the api's masks and permission rules. Never real data.
 */

type ScanRound = ListItem<'MessageScansController_scansOf_v1'>;
type Engine = ScanRound['engines'][number];
type Bec = NonNullable<Engine['bec']>;
type Dlp = NonNullable<Engine['dlp']>;
type UrlResult = NonNullable<Engine['urls']>[number];
type AttachmentResult = NonNullable<Engine['attachments']>[number];
type Submission = NonNullable<Engine['submissions']>[number];
type Revision = ScanRound['risk'][number];
type Lifecycle = SuccessBody<'MessageLifecycleController_lifecycle_v1'>;
type HistoryItem = ListItem<'MessageLifecycleController_history_v1'>;
type RecipientItem = ListItem<'MessagesController_recipients_v1'>;
type Delivery = SuccessBody<'DeliveriesController_forMessage_v1'>['deliveries'][number];
type DeliveryEvent = ListItem<'DeliveriesController_events_v1'>;
type HeadersBody = SuccessBody<'MessageHeadersController_headers_v1'>;
type Evidence = SuccessBody<'DlpMessageEvidenceController_read_v1'>;
type AuditRow = ListItem<'AuditLogsController_search_v1'>;
type MessageState = FixtureMessage['detail']['status'];

const SECOND = 1_000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const at = (base: string, offsetMs: number) => new Date(Date.parse(base) + offsetMs).toISOString();
const isoSeconds = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString();
const sha = (seed: string) =>
  Array.from({ length: 4 }, (_, i) => stableUuid(`${seed}:${i}`).replace(/-/g, ''))
    .join('')
    .slice(0, 64);

// ---------------------------------------------------------------------------------------------
// Engine details of a round (step 4.2–5.1 shapes).
// ---------------------------------------------------------------------------------------------

function attachmentResults(message: FixtureMessage, round: ScanRound): AttachmentResult[] {
  return message.attachments.map((a): AttachmentResult => {
    const scan = a.latestScan;
    const malicious = scan?.verdict === 'malicious';
    return {
      partIndex: a.partIndex,
      sha256: a.sha256,
      sizeBytes: a.sizeBytes,
      detectedType: scan?.detectedType ?? 'unknown',
      typeFamily: scan?.typeFamily ?? 'other',
      typeMismatch: scan?.typeMismatch ?? false,
      verdict: scan?.verdict ?? 'unknown',
      reasonCodes: scan?.reasonCodes ?? ['attachment.not_scanned'],
      clamav: scan?.clamav ?? null,
      yara: scan?.yara ?? null,
      archive: null,
      knownHash: scan?.knownHash ?? null,
      filename: a.filename,
      declaredContentType: a.declaredContentType,
      sandbox: {
        submissionId: stableUuid(`${message.detail.id}:sandbox:${round.round}:${a.partIndex}`),
        status: malicious ? 'completed' : 'skipped',
        skipReason: malicious ? null : 'type_excluded',
        verdict: malicious ? 'unknown' : null,
        reasonCodes: malicious ? ['sandbox.not_executed.backend_disabled'] : [],
        executed: malicious ? false : null,
        isolation: malicious ? 'process' : null,
        completedAt: malicious ? isoSeconds(Date.parse(round.startedAt ?? '') + 40 * SECOND) : null,
      },
    };
  });
}

function sandboxSubmissions(message: FixtureMessage, round: ScanRound): Submission[] {
  return attachmentResults(message, round)
    .filter((a) => a.sandbox?.status === 'completed')
    .map((a): Submission => ({
      submissionId: a.sandbox?.submissionId ?? stableUuid(`${a.sha256}:submission`),
      status: 'completed',
      skipReason: null,
      verdict: 'unknown',
      reasonCodes: ['sandbox.not_executed.backend_disabled'],
      executed: false,
      isolation: 'process',
      completedAt: a.sandbox?.completedAt ?? null,
      partIndex: a.partIndex,
      sha256: a.sha256,
      backend: 'static',
      versions: {
        controller: 'sandbox/1.0.0',
        backend: 'static/1.0.0',
        analyzer: 'analyzer/1.3.0',
        map: 'map/1',
      },
      findings: [
        { code: 'static.pe_packed', severity: 'high', count: 1 },
        { code: 'static.embedded_urls', severity: 'low', count: 2 },
      ],
      indicators: {
        dns: ['update.example.test'],
        httpHosts: ['198.51.100.23'],
        tlsSni: [],
        ips: ['198.51.100.23'],
      },
      processes: { count: 0, images: [] },
      droppedFiles: [],
      limitsHit: [],
      artifacts: [
        {
          seq: 0,
          kind: 'static_report',
          contentType: 'application/json',
          sizeBytes: 2_048,
          sha256: sha(`${a.sha256}:report`),
          expiresAt: new Date(
            Math.floor((fixtureDatasetAnchor() + 30 * DAY) / DAY) * DAY,
          ).toISOString(),
          purged: false,
        },
      ],
    }));
}

const LOOKALIKE_TARGET = 'microsoft-example.example.test';

function urlResults(message: FixtureMessage): UrlResult[] {
  return message.urls.map((u): UrlResult => {
    const bad = u.latest?.verdict === 'malicious';
    return {
      urlSeq: u.urlSeq,
      url: u.url,
      host: u.host,
      unicodeHost: u.unicodeHost,
      registrableDomain: u.registrableDomain,
      hostKind: u.hostKind,
      sources: u.sources,
      flags: u.flags,
      verdict: u.latest?.verdict ?? 'unknown',
      reasonCodes: bad ? ['url.lookalike_homoglyph', 'url.credential_form'] : ['clean.no_findings'],
      landing: bad
        ? {
            passwordFields: 1,
            forms: 1,
            crossOriginFormAction: true,
            titleBrandMatches: ['microsoft'],
          }
        : null,
      dynamic: null,
      rewritten: u.latest?.rewritten ?? false,
      reputation: bad
        ? [
            { provider: 'local_feed', kind: 'domain', status: 'listed', category: 'phishing' },
            { provider: 'dnsbl', kind: 'domain', status: 'clear', category: null },
          ]
        : [{ provider: 'dnsbl', kind: 'domain', status: 'clear', category: null }],
      lookalike: bad
        ? [{ rule: 'L1', targetKind: 'brand', targetDomain: LOOKALIKE_TARGET, score: 0.92 }]
        : [],
      fetch: {
        status: 'completed',
        error: null,
        hops: bad ? 2 : 1,
        chain: bad
          ? [
              { host: u.host, status: 302, kind: 'initial', blocked: null },
              {
                host: `cdn.${u.registrableDomain ?? 'example.test'}`,
                status: 200,
                kind: 'http',
                blocked: null,
              },
            ]
          : [{ host: u.host, status: 200, kind: 'initial', blocked: null }],
        finalUrl: null,
        finalStatus: 200,
      },
      clicks: {
        total: u.clicks.total,
        lastDecision: bad ? 'blocked' : u.clicks.total > 0 ? 'allowed' : null,
        lastAt:
          u.clicks.total > 0 ? isoSeconds(Date.parse(message.detail.receivedAt) + 2 * HOUR) : null,
      },
    };
  });
}

function becDetails(message: FixtureMessage, engine: Engine): Bec {
  const d = message.detail;
  const bec = d.finalVerdict === 'bec';
  const phishing = d.finalVerdict === 'phishing';
  const fromDomain = (d.headerFrom ?? d.envelopeFrom).split('@')[1] ?? 'example.test';
  const rules: Bec['rules'] = [];
  if (bec || phishing) {
    rules.push({
      id: 'L2',
      code: 'bec.lookalike.sender_brand',
      category: 'lookalike',
      severity: 'high',
      weight: 180,
      suppressed: null,
      evidence: [
        {
          header: 'From',
          domain: fromDomain,
          lookalike: {
            rule: 'L1',
            targetKind: 'brand',
            targetDomain: LOOKALIKE_TARGET,
            score: 0.9,
          },
        },
      ],
    });
  }
  if (bec) {
    rules.push(
      {
        id: 'I1',
        code: 'bec.impersonation.executive_name',
        category: 'impersonation',
        severity: 'high',
        weight: 220,
        suppressed: null,
        evidence: [
          {
            header: 'From',
            address: d.headerFrom ?? d.envelopeFrom,
            displayName: '<b>Chief Executive</b>',
            profile: { kind: 'executive', id: stableUuid('bec-profile:ceo'), match: 'token_set' },
          },
        ],
      },
      {
        id: 'C1',
        code: 'bec.content.payment_request',
        category: 'intent',
        severity: 'medium',
        weight: 120,
        suppressed: null,
        evidence: [
          {
            keywords: {
              category: 'payment_request',
              language: 'en',
              lexiconIds: ['lex-payment-en-1'],
              spans: [
                { source: 'subject', start: 0, end: 7 },
                { source: 'text', start: 42, end: 61 },
              ],
            },
            patterns: { iban: 1, swift: 0, ifsc_account: 0, amount: 2 },
          },
        ],
      },
      {
        id: 'H1',
        code: 'bec.history.first_contact',
        category: 'history',
        severity: 'low',
        weight: 40,
        suppressed: null,
        evidence: [{ history: { firstContact: true, priorMessages: '0' } }],
      },
    );
  }
  const score = rules.reduce((sum, rule) => sum + rule.weight, 0);
  const verdict: Bec['verdict'] =
    engine.outcome === 'suspicious' ? 'suspicious' : score >= 400 ? 'suspicious' : 'clean';
  return {
    rulesVersion: 'bec-rules/7',
    engineVersion: engine.engineVersion ?? 'bec/1.2.0',
    settingsVersion: 'bec-settings/3',
    lexiconVersion: 'lexicon/12',
    verdict,
    deterministicVerdict: verdict,
    score,
    deterministicScore: score,
    thresholds: { suspicious: 400, malicious: 800 },
    inputs: { auth: 'available', url: 'available', text: 'complete', history: 'enabled' },
    rules,
    ai: bec
      ? [
          {
            layer: 'local',
            mode: 'active',
            provider: 'local',
            modelId: 'bec-local',
            modelVersion: '2026.10',
            promptTemplateVersion: null,
            status: 'ok',
            labels: [
              { label: 'bec', confidence: 0.81 },
              { label: 'benign', confidence: 0.12 },
            ],
            confidence: 0.81,
            indicators: ['executive_impersonation', 'payment_redirection', 'urgency'],
            citedFeatures: [
              { feature: 'rule_i1', contribution: 0.4 },
              { feature: 'lex_payment_request', contribution: 0.3 },
            ],
            spans: [{ source: 'text', start: 42, end: 61, label: 'payment_redirection' }],
            effect: 'none',
          },
        ]
      : [],
    aiShadow: bec
      ? [
          {
            layer: 'llm',
            mode: 'shadow',
            provider: 'fake',
            modelId: 'shadow-model',
            modelVersion: '1',
            promptTemplateVersion: 'bec-prompt/2',
            status: 'ok',
            labels: [{ label: 'bec', confidence: 0.77 }],
            confidence: 0.77,
            indicators: ['executive_impersonation'],
            citedFeatures: [],
            spans: [],
          },
        ]
      : [],
    feedback:
      bec && hashString(d.id) % 3 === 0
        ? [
            {
              id: stableUuid(`bec-feedback:${d.id}`),
              kind: 'false_positive',
              createdAt: at(d.receivedAt, 3 * HOUR),
            },
          ]
        : [],
  };
}

function dlpDetails(message: FixtureMessage, engine: Engine): Dlp {
  const d = message.detail;
  const violation = d.finalVerdict === 'dlp_violation';
  const findings: Dlp['findings'] = violation
    ? [
        {
          detector: 'PC1',
          code: 'dlp.payment_card',
          category: 'payment_card',
          severity: 'high',
          confidence: 0.97,
          count: 2,
          capped: false,
          sources: [{ kind: 'body_text' }],
          // Masked samples (first 6 + last 4 kept), never raw values.
          masked: ['4111 11•• •••• 1111', '5500 00•• •••• 0004'],
        },
        {
          detector: 'NI1',
          code: 'dlp.national_id',
          category: 'national_id',
          severity: 'critical',
          confidence: 0.91,
          count: 1,
          capped: false,
          sources:
            message.attachments.length > 0
              ? [{ kind: 'attachment', partIndex: 2 }]
              : [{ kind: 'body_text' }],
          masked: ['•••-••-6789'],
        },
      ]
    : [];
  return {
    engineVersion: engine.engineVersion ?? 'dlp/1.1.0',
    rulesVersion: 'dlp-rules/4',
    settingsVersion: 'dlp-settings/2',
    policyVersion: 'dlp-policy/9',
    extractorVersion: 'extractor/3',
    verdict: violation ? 'suspicious' : 'clean',
    action: violation
      ? d.finalAction === 'quarantine'
        ? 'quarantine'
        : 'require_approval'
      : 'allow',
    actionSource: violation ? 'tenant_policy' : 'none',
    coverage: message.attachments.length > 1 ? 'partial' : 'complete',
    coverageDetail: [
      {
        source: 'subject',
        format: 'text',
        status: 'scanned',
        reasons: [],
        chars: 48,
        truncated: false,
      },
      {
        source: 'body_text',
        format: 'text',
        status: 'scanned',
        reasons: [],
        chars: 2_310,
        truncated: false,
      },
      ...message.attachments.map((a, index): Dlp['coverageDetail'][number] => ({
        source: 'attachment',
        partIndex: a.partIndex,
        format: index === 0 ? 'pdf' : 'image',
        status: index === 0 ? 'scanned' : 'not_extracted',
        reasons: index === 0 ? [] : ['dlp.not_extracted.image'],
        chars: index === 0 ? 5_120 : 0,
        truncated: false,
      })),
    ],
    aadhaar: 'disabled',
    categories: violation
      ? [
          { category: 'payment_card', count: 2, maxSeverity: 'high', maxConfidence: 0.97 },
          { category: 'national_id', count: 1, maxSeverity: 'critical', maxConfidence: 0.91 },
        ]
      : [],
    findings,
    policy: violation
      ? {
          winner: {
            policyId: stableUuid('dlp-policy:pci'),
            ruleId: stableUuid('dlp-rule:pci-block'),
          },
          matched: [
            {
              policyId: stableUuid('dlp-policy:pci'),
              ruleId: stableUuid('dlp-rule:pci-block'),
              action: d.finalAction === 'quarantine' ? 'quarantine' : 'require_approval',
              mode: 'enforce',
            },
          ],
          exceptionsApplied: [],
        }
      : { winner: null, matched: [], exceptionsApplied: [] },
    evidence: violation
      ? { status: 'stored', expiresAt: at(d.receivedAt, 30 * DAY), purged: false }
      : { status: 'none', expiresAt: null, purged: false },
  };
}

function riskDetails(message: FixtureMessage, revision: Revision): Revision {
  const verdict = message.detail.finalVerdict;
  const contributions: Revision['contributions'] = [];
  const add = (
    signal: Revision['contributions'][number]['signal'],
    group: Revision['contributions'][number]['group'],
    weight: number,
    codes: string[],
  ) => contributions.push({ signal, group, weight, codes, applied: weight });
  if (verdict === 'phishing') {
    add('url_known_phishing', 'url_threat', 450, ['url.feed_malicious']);
    add('lookalike_url', 'lookalike', 220, ['url.lookalike_homoglyph']);
    add('auth_dmarc_fail', 'auth_dmarc', 150, ['auth.dmarc_fail']);
  } else if (verdict === 'malware') {
    add('attachment_malware', 'attachment_malware', 900, ['malware.clamav']);
  } else if (verdict === 'bec') {
    add('bec_exec_name', 'bec_impersonation', 260, ['bec.impersonation.executive_name']);
    add('bec_payment_request', 'bec_intent', 180, ['bec.content.payment_request']);
    add('bec_first_contact', 'bec_history', 60, ['bec.history.first_contact']);
  } else if (verdict === 'spam' || verdict === 'bulk') {
    add('spam_score', 'spam', revision.score, ['spam.score']);
  } else if (verdict === 'dlp_violation') {
    add('dlp_severity_critical', 'dlp', 500, ['dlp.national_id']);
    add('dlp_action_require_approval', 'dlp', 200, ['dlp.action.require_approval']);
  }
  const groups = [...new Set(contributions.map((c) => c.group))].map((group) => {
    const raw = contributions.filter((c) => c.group === group).reduce((s, c) => s + c.weight, 0);
    return {
      group,
      rule: 'capped_sum' as const,
      raw,
      multiplierPermille: 1000,
      trustFactorPermille: null,
      cap: 900,
      total: Math.min(raw, 900),
    };
  });
  return {
    ...revision,
    contributions,
    groups,
    engines: (['rspamd', 'attachment', 'url', 'bec', 'dlp'] as const).map((engine) => ({
      engine,
      required: true,
      status: 'definite' as const,
      outcome: null,
      errorCode: null,
      engineVersion: null,
      settingsVersion: null,
      attempts: 1,
    })),
    explanation: {
      lines: revision.explanation.lines,
      text:
        contributions.length > 0
          ? `${revision.explanation.text} Signals: ${contributions.map((c) => `${c.signal} (+${c.weight})`).join(', ')}.`
          : revision.explanation.text,
    },
  };
}

/** A round with the engine details the api returns since steps 4.2–5.1 (dlp before masking). */
export function enrichRound(message: FixtureMessage, round: ScanRound): ScanRound {
  const engines: Engine[] = round.engines.map((engine): Engine => {
    switch (engine.engine) {
      case 'attachment':
        return { ...engine, attachments: attachmentResults(message, round) };
      case 'url':
        return {
          ...engine,
          urls: urlResults(message),
          rewrite:
            message.urls.length > 0
              ? {
                  status: 'rewritten',
                  skipReason: null,
                  linksRewritten: message.urls.length,
                  partsRewritten: 1,
                  dkimSigned: false,
                  expiresAt: isoSeconds(Date.parse(message.detail.receivedAt) + 30 * DAY),
                }
              : {
                  status: 'skipped',
                  skipReason: 'no_urls',
                  linksRewritten: 0,
                  partsRewritten: 0,
                  dkimSigned: false,
                  expiresAt: null,
                },
        };
      case 'bec':
        return { ...engine, bec: becDetails(message, engine) };
      case 'dlp':
        return { ...engine, dlp: dlpDetails(message, engine) };
      default:
        return engine;
    }
  });
  const submissions = sandboxSubmissions(message, round);
  if (submissions.length > 0) {
    engines.push({
      engine: 'sandbox',
      final: true,
      engineVersion: 'sandbox/1.0.0',
      outcome: 'unknown',
      score: null,
      requiredScore: null,
      action: null,
      reasonCodes: ['sandbox.not_executed.backend_disabled'],
      symbols: [],
      attempts: [],
      durationMs: null,
      settingsVersion: 'sandbox/1',
      completedAt: submissions[0]?.completedAt ?? null,
      submissions,
    });
  }
  return { ...round, engines, risk: round.risk.map((r) => riskDetails(message, r)) };
}

const enriched = new WeakMap<FixtureMessage, ScanRound[]>();

/** The message's rounds with engine details (newest first), built once per message. */
export function enrichedRounds(message: FixtureMessage): readonly ScanRound[] {
  let rounds = enriched.get(message);
  if (!rounds) {
    rounds = message.rounds.map((round) => enrichRound(message, round));
    enriched.set(message, rounds);
  }
  return rounds;
}

// ---------------------------------------------------------------------------------------------
// Lifecycle and history.
// ---------------------------------------------------------------------------------------------

const ROLE_OF: Partial<Record<MessageState, HistoryItem['actor']['role']>> = {
  received: 'ingestion',
  persisted: 'ingestion',
  scanning: 'scanner',
  scanned: 'scanner',
  policy_evaluated: 'policy',
  quarantined: 'policy',
  held_for_review: 'policy',
  rejected: 'policy',
  delivery_pending: 'policy',
  delivery_retry: 'delivery',
  delivered: 'delivery',
};

/** A rescan started by a fixture user (state overlay of `messages.ts`). */
export interface FixtureRescan {
  readonly version: number;
  readonly lifecycleRound: number;
  readonly startedAt: number;
  readonly completedAt: number;
  readonly previousStatus: MessageState;
  readonly actorId: string;
}

/** The current state of a message, with a fixture rescan applied (running, then completed). */
export function currentState(
  message: FixtureMessage,
  rescans: readonly FixtureRescan[],
  now = Date.now(),
): { status: MessageState; version: number; lifecycleRound: number; statusChangedAt: string } {
  const last = rescans.at(-1);
  if (!last) {
    return {
      status: message.detail.status,
      version: message.detail.version,
      lifecycleRound: message.detail.lifecycleRound,
      statusChangedAt: message.detail.statusChangedAt,
    };
  }
  const done = now >= last.completedAt;
  return {
    status: done ? last.previousStatus : 'scanning',
    version: done ? last.version + 3 : last.version,
    lifecycleRound: last.lifecycleRound,
    statusChangedAt: new Date(done ? last.completedAt : last.startedAt).toISOString(),
  };
}

/** `GET /messages/{id}/lifecycle/history`, oldest first (with fixture rescans). */
export function historyOf(
  message: FixtureMessage,
  rescans: readonly FixtureRescan[],
  now = Date.now(),
): HistoryItem[] {
  const d = message.detail;
  const base = transitionsFor(d.status, d.lifecycleRound);
  const items: HistoryItem[] = base.map((transition, index) => {
    const operator = transition.state === 'scanning' && transition.round > 0;
    return {
      version: index + 1,
      fromState: index === 0 ? null : (base[index - 1]?.state ?? null),
      toState: transition.state,
      reasonCode:
        transition.state === 'quarantined' || transition.state === 'held_for_review'
          ? (d.statusReason ?? 'policy_decision')
          : operator
            ? 'operator_rescan'
            : null,
      lifecycleRound: transition.round,
      actor: operator
        ? { role: 'operator', type: 'user', service: 'api', id: stableUuid('user:analyst') }
        : {
            role: ROLE_OF[transition.state] ?? 'legacy',
            type: 'system',
            service: transition.state === 'delivered' ? 'delivery-worker' : 'email-worker',
            id: null,
          },
      causationEventId: stableUuid(`${d.id}:event:${index}`),
      correlationId: stableUuid(`${d.id}:correlation`),
      occurredAt: at(d.receivedAt, index * 900 + transition.round * MINUTE),
      changedAt: at(d.receivedAt, index * 900 + transition.round * MINUTE + 15),
    };
  });
  for (const rescan of rescans) {
    const previous = items.at(-1)?.toState ?? null;
    const push = (toState: MessageState, offset: number, operator = false) =>
      items.push({
        version: items.length + 1,
        fromState: items.at(-1)?.toState ?? previous,
        toState,
        reasonCode: operator ? 'operator_rescan' : null,
        lifecycleRound: rescan.lifecycleRound,
        actor: operator
          ? { role: 'operator', type: 'user', service: 'api', id: rescan.actorId }
          : {
              role: ROLE_OF[toState] ?? 'legacy',
              type: 'system',
              service: 'email-worker',
              id: null,
            },
        causationEventId: null,
        correlationId: stableUuid(`${d.id}:rescan:${rescan.lifecycleRound}`),
        occurredAt: new Date(rescan.startedAt + offset).toISOString(),
        changedAt: new Date(rescan.startedAt + offset).toISOString(),
      });
    push('scanning', 0, true);
    if (now >= rescan.completedAt) {
      push('scanned', rescan.completedAt - rescan.startedAt - 2_000);
      push('policy_evaluated', rescan.completedAt - rescan.startedAt - 1_000);
      push(rescan.previousStatus, rescan.completedAt - rescan.startedAt);
    }
  }
  return items;
}

const RESCAN_FROM: readonly MessageState[] = [
  'scanning',
  'scanned',
  'scan_failed',
  'policy_evaluated',
  'quarantined',
  'held_for_review',
  'expired',
];

/** Whether the lifecycle allows a rescan from a state (`POST /messages/{id}/rescan`). */
export function rescanAllowed(state: MessageState): boolean {
  return RESCAN_FROM.includes(state);
}

/** `GET /messages/{id}/lifecycle`. */
export function lifecycleOf(
  message: FixtureMessage,
  rescans: readonly FixtureRescan[],
  now = Date.now(),
): Lifecycle {
  const d = message.detail;
  const state = currentState(message, rescans, now);
  const byStatus: Record<string, number> = {};
  for (const row of message.recipientRows) {
    const status = recipientStatus(message, row);
    byStatus[status] = (byStatus[status] ?? 0) + 1;
  }
  const delivering = message.recipientRows.some((row) => row.delivery !== null);
  return {
    messageId: d.id,
    receivedAt: d.receivedAt,
    direction: d.direction,
    state: state.status,
    statusReason: d.statusReason,
    version: state.version,
    lifecycleRound: state.lifecycleRound,
    statusChangedAt: state.statusChangedAt,
    parse:
      d.finalVerdict === null
        ? { status: 'parsing', completedAt: null }
        : { status: 'parsed', completedAt: at(d.receivedAt, 700) },
    recipients: { total: message.recipientRows.length, byStatus },
    deliverySeq: delivering
      ? Math.max(...message.recipientRows.map((r) => (r.quarantine === 'released' ? 1 : 0)))
      : null,
    actions: {
      rescan: rescanAllowed(state.status),
      release: state.status === 'quarantined' || state.status === 'held_for_review',
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Recipients, deliveries and delivery events (masked like the api, §2 E5, E9).
// ---------------------------------------------------------------------------------------------

function recipientStatus(message: FixtureMessage, row: FixtureRecipient): RecipientItem['status'] {
  if (row.quarantine === 'released') return 'delivered';
  if (row.quarantine === 'rejected' || row.quarantine === 'deleted' || row.quarantine === 'expired')
    return 'discarded';
  if (row.quarantine) return 'quarantined';
  switch (row.delivery) {
    case 'delivered':
      return 'delivered';
    case 'deferred':
      return 'deferred';
    case 'bounced':
      return 'bounced';
    case 'failed':
    case 'expired':
      return 'failed';
    case 'suppressed':
      return 'discarded';
    case null:
      return message.detail.finalAction === 'reject' || message.detail.finalAction === 'discard'
        ? 'discarded'
        : 'pending';
    default:
      return 'pending';
  }
}

const smtpCode = (text: string | null) => {
  const match = text?.match(/^(\d{3}) (\d\.\d{1,3}\.\d{1,3})/);
  return match ? { code: Number(match[1]), enhanced: match[2] ?? null } : null;
};

const deliverySeqOf = (row: FixtureRecipient) => (row.quarantine === 'released' ? 1 : 0);

function deliveredAtOf(message: FixtureMessage, row: FixtureRecipient): string | null {
  if (row.delivery !== 'delivered') return null;
  return at(
    message.detail.receivedAt,
    row.quarantine === 'released' ? 2 * HOUR + 30 * SECOND : 8 * SECOND,
  );
}

/** `GET /messages/{id}/recipients` items (address masked, matched user withheld). */
export function recipientItems(message: FixtureMessage): RecipientItem[] {
  return message.recipientRows.map((row) => {
    const reply = smtpCode(row.smtpResponse);
    return {
      rcptSeq: row.rcptSeq,
      address: maskAddress(row.address),
      addressMasked: true,
      status: recipientStatus(message, row),
      finalAction: message.detail.finalAction,
      direction: message.detail.direction,
      userId: null,
      latestDelivery: row.delivery
        ? {
            deliverySeq: deliverySeqOf(row),
            status: row.delivery,
            finalSmtpCode: reply?.code ?? null,
            deliveredAt: deliveredAtOf(message, row),
          }
        : null,
    };
  });
}

/** The user a recipient address matches (tenant recipients only), for the reveal. */
export function matchedUserOf(address: string): string | null {
  const domain = address.slice(address.lastIndexOf('@') + 1);
  return domain.startsWith('alpha-') || address.endsWith('@example.com')
    ? stableUuid(`user:${address}`)
    : null;
}

const ERROR_CLASS: Partial<Record<NonNullable<FixtureRecipient['delivery']>, string>> = {
  deferred: 'greylisted',
  bounced: 'recipient_unknown',
  failed: 'policy_rejected',
  expired: 'connection_timeout',
};

/** `GET /messages/{id}/deliveries` (recipient and SMTP reply masked). */
export function deliveriesOf(message: FixtureMessage): Delivery[] {
  return message.recipientRows
    .filter((row) => row.delivery !== null)
    .map((row): Delivery => {
      const reply = smtpCode(row.smtpResponse);
      const domain = row.address.slice(row.address.lastIndexOf('@') + 1);
      const status = row.delivery ?? 'unknown';
      const lastAttempt =
        row.attemptCount > 0
          ? at(message.detail.receivedAt, 8 * SECOND + (row.attemptCount - 1) * 15 * MINUTE)
          : null;
      return {
        rcptSeq: row.rcptSeq,
        deliverySeq: deliverySeqOf(row),
        recipient: maskAddress(row.address),
        recipientMasked: true,
        direction: message.detail.direction,
        status,
        attemptCount: row.attemptCount,
        lastAttemptAt: lastAttempt,
        deliveredAt: deliveredAtOf(message, row),
        remoteHost: row.attemptCount > 0 ? `mx1.${domain}` : null,
        finalSmtpCode: reply?.code ?? null,
        enhancedStatus: reply?.enhanced ?? null,
        finalSmtpResponse: row.smtpResponse ? maskAddressesInText(row.smtpResponse) : null,
        lastErrorClass: ERROR_CLASS[status] ?? null,
        failureReason: status === 'bounced' || status === 'failed' ? 'permanent_failure' : null,
        dsnGenerated: status === 'bounced' && message.detail.direction !== 'inbound',
        statusChangedAt: lastAttempt ?? at(message.detail.receivedAt, 6 * SECOND),
      };
    });
}

/** `GET /messages/{id}/deliveries/events`, oldest first (event details masked). */
export function deliveryEventsOf(message: FixtureMessage): DeliveryEvent[] {
  const events: DeliveryEvent[] = [];
  for (const row of message.recipientRows) {
    if (!row.delivery) continue;
    const seq = deliverySeqOf(row);
    const base = Date.parse(message.detail.receivedAt) + (seq === 1 ? 2 * HOUR : 5 * SECOND);
    const event = (
      offset: number,
      source: DeliveryEvent['source'],
      fromStatus: DeliveryEvent['fromStatus'],
      toStatus: DeliveryEvent['toStatus'],
      detail: string | null,
      reply: string | null = null,
    ) => {
      const parsed = smtpCode(reply);
      events.push({
        rcptSeq: row.rcptSeq,
        deliverySeq: seq,
        source,
        fromStatus,
        toStatus,
        applied: true,
        occurredAt: new Date(base + offset).toISOString(),
        queueId: `4X${message.detail.id.slice(0, 6).toUpperCase()}${row.rcptSeq}`,
        smtpCode: parsed?.code ?? null,
        enhancedStatus: parsed?.enhanced ?? null,
        remoteHost: reply ? `mx1.${row.address.slice(row.address.lastIndexOf('@') + 1)}` : null,
        errorClass:
          reply && parsed && parsed.code >= 400
            ? (ERROR_CLASS[row.delivery ?? 'unknown'] ?? null)
            : null,
        detail: detail ? maskAddressesInText(detail) : null,
      });
    };
    event(0, seq === 1 ? 'reinjection' : 'planner', null, 'pending', null);
    if (row.delivery === 'pending') continue;
    event(1_000, 'planner', 'pending', 'queued', `queued for <${row.address}>`);
    if (row.delivery === 'queued' || row.delivery === 'in_progress') continue;
    for (let attempt = 1; attempt < row.attemptCount; attempt += 1) {
      event(
        attempt * 15 * MINUTE,
        'postfix_log',
        'queued',
        'deferred',
        row.smtpResponse,
        row.smtpResponse,
      );
    }
    if (row.delivery === 'deferred') continue;
    event(
      row.attemptCount * 3_000,
      'postfix_log',
      row.attemptCount > 1 ? 'deferred' : 'queued',
      row.delivery,
      row.smtpResponse,
      row.smtpResponse,
    );
  }
  return events.sort((a, b) => a.occurredAt.localeCompare(b.occurredAt) || a.rcptSeq - b.rcptSeq);
}

// ---------------------------------------------------------------------------------------------
// Headers (the 3.1 allow-list; §2 E7 safe subset applied by the handler).
// ---------------------------------------------------------------------------------------------

export const STORED_HEADER_NAMES = [
  'From',
  'Sender',
  'Reply-To',
  'To',
  'Cc',
  'Subject',
  'Message-ID',
  'Date',
  'In-Reply-To',
  'References',
  'Return-Path',
  'Authentication-Results',
];
export const SAFE_HEADER_NAMES = [
  'From',
  'Sender',
  'Reply-To',
  'Return-Path',
  'Date',
  'Message-ID',
  'In-Reply-To',
  'References',
  'Authentication-Results',
];
const MASKED_HEADERS = new Set(['to', 'cc', 'subject']);

export function isSafeHeader(name: string): boolean {
  return SAFE_HEADER_NAMES.some((safe) => safe.toLowerCase() === name.toLowerCase());
}
export function isRevealableHeader(name: string): boolean {
  return MASKED_HEADERS.has(name.toLowerCase());
}

/** Availability of the stored headers: every state appears across the dataset. */
export function headerAvailability(message: FixtureMessage): HeadersBody['availability'] {
  if (message.detail.finalVerdict === null) return 'not_parsed';
  const h = hashString(`${message.detail.id}:headers`) % 40;
  if (h === 7) return 'none_stored';
  if (h === 11) return 'retention_expired';
  return 'available';
}

/** The stored header rows in clear (the handler masks To, Cc, Subject). */
export function storedHeaders(
  message: FixtureMessage,
): { seq: number; name: string; value: string }[] {
  if (headerAvailability(message) !== 'available') return [];
  const d = message.detail;
  const random = new SeededRandom(`${d.id}:headers`);
  const rows: [string, string][] = [];
  const from = d.headerFrom ?? d.envelopeFrom;
  rows.push(['Return-Path', `<${d.envelopeFrom}>`]);
  const round = message.rounds.at(-1);
  if (round?.auth) {
    rows.push([
      'Authentication-Results',
      `mx.alpha-1.example.test; spf=${round.auth.spf ?? 'none'} smtp.mailfrom=${d.envelopeFrom || '<>'}; dkim=${round.auth.dkim ?? 'none'} header.d=${round.auth.dmarcDomain ?? 'example.test'}; dmarc=${round.auth.dmarc ?? 'none'} header.from=${from.split('@')[1] ?? ''}`,
    ]);
  }
  rows.push([
    'From',
    d.finalVerdict === 'bec'
      ? `"<b>Chief Executive</b>" <${from}>`
      : `"${from.split('@')[0]}" <${from}>`,
  ]);
  if (d.headerFrom && d.headerFrom !== d.envelopeFrom) rows.push(['Sender', `<${d.envelopeFrom}>`]);
  if (d.finalVerdict === 'bec') rows.push(['Reply-To', `<payments@freemail.example.com>`]);
  const [first, ...others] = message.recipients;
  rows.push(['To', [first, ...(random.bool(0.5) ? others : [])].filter(Boolean).join(', ')]);
  if (others.length > 0 && random.bool(0.5)) rows.push(['Cc', others.join(', ')]);
  if (d.subject !== null) rows.push(['Subject', d.subject]);
  rows.push([
    'Date',
    new Date(Date.parse(d.receivedAt) - 4_000).toUTCString().replace('GMT', '+0000'),
  ]);
  if (d.internetMessageId) rows.push(['Message-ID', d.internetMessageId]);
  if (d.subject && /^(re|aw|sv)/i.test(d.subject)) {
    rows.push(['In-Reply-To', `<prev.${d.id.slice(0, 6)}@mail.example.test>`]);
    rows.push([
      'References',
      `<root.${d.id.slice(0, 6)}@mail.example.test> <prev.${d.id.slice(0, 6)}@mail.example.test>`,
    ]);
  }
  return rows.map(([name, value], seq) => ({ seq, name, value }));
}

// ---------------------------------------------------------------------------------------------
// DLP evidence and historic audit rows.
// ---------------------------------------------------------------------------------------------

/** The decrypted evidence of a round (synthetic values built at runtime, never stored). */
export function dlpEvidenceOf(message: FixtureMessage, scanId: string): Evidence['evidence'] {
  const card = ['4111', '1111', '1111', '1111'].join(' ');
  const card2 = ['5500', '0000', '0000', '0004'].join(' ');
  const id = ['078', '05', '6789'].join('-');
  return {
    format: 'dlp-evidence/1',
    textDerivationVersion: 'text/2',
    extractorVersion: 'extractor/3',
    aadhaar: 'disabled',
    matches: [
      {
        detector: 'PC1',
        code: 'dlp.payment_card',
        source: { kind: 'body_text', segment: 0 },
        start: 118,
        end: 137,
        value: card,
        context: { before: 'Please charge card ', after: ' for the order <b>4471</b>' },
      },
      {
        detector: 'PC1',
        code: 'dlp.payment_card',
        source: { kind: 'body_text', segment: 0 },
        start: 204,
        end: 223,
        value: card2,
        context: { before: 'backup card ', after: ', expiry next year' },
      },
      {
        detector: 'NI1',
        code: 'dlp.national_id',
        source:
          message.attachments.length > 0
            ? { kind: 'attachment', partIndex: 2, segment: 1 }
            : { kind: 'body_text', segment: 1 },
        start: 12,
        end: 23,
        value: id,
        context: { before: 'Employee SSN ', after: ' (payroll)' },
      },
    ],
    dropped: scanId.endsWith('0') ? 1 : 0,
  };
}

/**
 * Deterministic audit rows of the dataset's messages (resource `message`): the operator rescans
 * that created round 1. Shown by `audit.ts` next to the in-memory rows of reveals, rescans and
 * evidence reads made in fixture mode.
 */
export function historicMessageAuditRows(messages: readonly FixtureMessage[]): AuditRow[] {
  return messages
    .filter((message) => message.detail.lifecycleRound > 0)
    .map((message, index) => ({
      id: String(9_400_000 + index),
      createdAt: at(message.detail.receivedAt, MINUTE),
      actor: { type: 'user', id: stableUuid('user:analyst') },
      action: 'message.rescan_requested',
      resourceType: 'message',
      resourceId: message.detail.id,
      correlationId: stableUuid(`${message.detail.id}:rescan:audit`),
      sourceIp: '198.51.100.10',
      metadata: { fromState: 'quarantined', lifecycleRound: 1, quarantineEntriesSuperseded: 0 },
    }));
}
