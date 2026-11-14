/**
 * Engine and metadata rows of the step 7.2 details sections (design §1.4, §9; WP5): parse row,
 * the stored header subset, attachments and URLs with their results, the final engine rows of
 * the initial round (Rspamd symbols with address options, URL, attachment, BEC, DLP), the
 * authentication results, the BEC and DLP results, the risk score and the policy evaluation
 * (computed with the real `@email-gateway/risk-scoring` and `@email-gateway/policy-dsl`
 * functions, as the email-worker and the policy-engine compute them), the lifecycle history and
 * delivery status events with SMTP texts.
 *
 * Rows are written on the writer with explicit columns, in the shapes of the api integration
 * helpers (apps/api/integration: messages-data.ts, scans.test.ts, bec.test.ts, dlp.test.ts,
 * risk-scoring.test.ts, policies.test.ts, messages-sensitive.test.ts); never a generated column.
 * Every child row copies the message's `received_at` (partition key). Message content is never
 * stored in MySQL: only metadata, hashes and masked DLP samples.
 */
import { createHash, randomUUID } from 'node:crypto';
import type {
  MessageStatus,
  MessageVerdict,
  Prisma,
  PrismaClient,
  ScanVerdict,
} from '@email-gateway/database';
import {
  buildPolicyInput,
  compileSnapshot,
  evaluatePolicy,
  evaluationResultToRow,
  type PolicyRoundRows,
} from '@email-gateway/policy-dsl';
import {
  buildScoringInput,
  platformProfile,
  riskResultToRowJson,
  scoreRisk,
  type RoundRows,
} from '@email-gateway/risk-scoring';
import { type MessagePlan, recipientsOf } from './plan';

const sha = (text: string) => createHash('sha256').update(text).digest('hex');

/** The rows the details writer needs of one seeded message (see seed.ts SeededMessage). */
export interface DetailTarget {
  plan: MessagePlan;
  id: bigint;
  recipientIds: bigint[];
  scanId: bigint | null;
}

export interface HistoryStep {
  from: MessageStatus | null;
  to: MessageStatus;
  reason: string | null;
  role: string;
  service: string;
}

/**
 * The lifecycle path of a plan (transitions of packages/message-lifecycle): ingestion, then for
 * a scanned message scan → policy → disposition (→ delivery); `email_messages.version` is the
 * last step's index. A message without a scan round keeps the 7.1 three-step history
 * (received → persisted → quarantined) that the quarantine release executor was verified with.
 */
export function historyOf(plan: MessagePlan): HistoryStep[] {
  const steps: HistoryStep[] = [
    {
      from: null,
      to: 'received',
      reason: 'smtp_accepted',
      role: 'ingestion',
      service: 'smtp-adapter',
    },
    {
      from: 'received',
      to: 'persisted',
      reason: 'committed',
      role: 'ingestion',
      service: 'smtp-adapter',
    },
  ];
  const policy = (from: MessageStatus, to: MessageStatus, reason: string | null): HistoryStep => ({
    from,
    to,
    reason,
    role: 'policy',
    service: 'policy-engine',
  });
  if (!plan.scan) {
    steps.push(
      policy('persisted', plan.action === 'quarantine' ? 'quarantined' : 'rejected', null),
    );
    return steps;
  }
  const scanner = (from: MessageStatus, to: MessageStatus, reason: string): HistoryStep => ({
    from,
    to,
    reason,
    role: 'scanner',
    service: 'email-worker',
  });
  steps.push(scanner('persisted', 'scanning', 'scan_started'));
  if (plan.scan.status === 'completed') {
    steps.push(scanner('scanning', 'scanned', 'scan_complete'));
    steps.push(policy('scanned', 'policy_evaluated', 'policy_decided'));
  } else {
    steps.push(scanner('scanning', 'scan_failed', 'scan_error'));
    steps.push(policy('scan_failed', 'policy_evaluated', 'scan_failed_fail_safe'));
  }
  if (plan.action === 'quarantine') {
    steps.push(policy('policy_evaluated', 'quarantined', 'policy_quarantine'));
    return steps;
  }
  if (plan.action === 'reject' || plan.action === 'discard') {
    steps.push(policy('policy_evaluated', 'rejected', `policy_${plan.action}`));
    return steps;
  }
  steps.push(
    policy('policy_evaluated', 'approved', plan.action === 'tag' ? 'policy_tag' : 'policy_deliver'),
  );
  const delivery = (from: MessageStatus, to: MessageStatus, reason: string): HistoryStep => ({
    from,
    to,
    reason,
    role: 'delivery',
    service: 'delivery-worker',
  });
  steps.push(delivery('approved', 'delivery_pending', 'delivery_planned'));
  const delivered = plan.deliveries.filter((d) => d.status === 'delivered').length;
  if (delivered > 0) {
    steps.push(
      delivery(
        'delivery_pending',
        'delivered',
        delivered === plan.deliveries.length ? 'delivery_complete' : 'delivery_partial',
      ),
    );
  } else if (plan.deliveries.length > 0) {
    steps.push(delivery('delivery_pending', 'rejected', 'delivery_failed'));
  }
  return steps;
}

/** `email_scans.required_engines` of the initial round. */
export function requiredEnginesOf(plan: MessagePlan): string[] {
  if (plan.details === 'phish') return ['rspamd', 'attachment', 'url', 'bec'];
  if (plan.details === 'outbound') return ['rspamd', 'attachment', 'dlp'];
  return ['rspamd'];
}

const SCAN_VERDICT: Record<MessageVerdict, ScanVerdict> = {
  clean: 'clean',
  spam: 'spam',
  bulk: 'spam',
  phishing: 'malicious',
  malware: 'malicious',
  bec: 'suspicious',
  suspicious: 'suspicious',
  dlp_violation: 'suspicious',
  unknown: 'unknown',
};

/** `email_scans.scan_verdict` of a completed round (7.1 rows keep `clean`). */
export function scanVerdictOf(plan: MessagePlan): ScanVerdict {
  return plan.details ? SCAN_VERDICT[plan.verdict] : 'clean';
}

/** The stored header subset of a details message (3.1 allow-list, decoded, ≤ 2 048). */
function headersOf(plan: MessagePlan): Array<{ name: string; value: string }> {
  const recipients = recipientsOf(plan);
  const to = recipients.slice(0, 2);
  const cc = recipients.slice(2);
  const fromAddress = plan.headerFrom ?? plan.envelopeFrom;
  const fromDomain = fromAddress.split('@')[1] ?? 'unknown.e2e-portal.test';
  const failing = plan.details === 'phish';
  const rows: Array<{ name: string; value: string }> = [
    { name: 'Return-Path', value: `<${plan.envelopeFrom}>` },
    {
      name: 'Authentication-Results',
      value: failing
        ? `mx.alpha.e2e-portal.test; spf=fail smtp.mailfrom=${fromDomain}; dkim=none; dmarc=fail header.from=${fromDomain}`
        : `mx.alpha.e2e-portal.test; spf=pass smtp.mailfrom=${fromDomain}; dkim=pass header.d=${fromDomain}; dmarc=pass header.from=${fromDomain}`,
    },
    { name: 'From', value: `"${failing ? 'IT Support' : 'Sender'}" <${fromAddress}>` },
  ];
  if (failing) rows.push({ name: 'Reply-To', value: 'helpdesk-reset@freemail.e2e-portal.test' });
  rows.push({ name: 'To', value: to.join(', ') });
  if (cc.length > 0) rows.push({ name: 'Cc', value: cc.join(', ') });
  rows.push(
    { name: 'Subject', value: plan.subject },
    { name: 'Date', value: plan.receivedAt.toUTCString() },
    { name: 'Message-ID', value: plan.internetMessageId ?? `<${randomUUID()}@e2e-portal.test>` },
  );
  return rows;
}

/** Rspamd's final row: score, threshold, action and symbols (options hold addresses). */
function rspamdFinal(plan: MessagePlan) {
  const phish = plan.details === 'phish';
  const spammy = phish || plan.verdict === 'spam' || plan.verdict === 'bulk';
  const signals = phish
    ? [
        { name: 'PHISHING', score: 4.5, options: ['login.lookalike-alpha.e2e-portal.test'] },
        {
          name: 'FREEMAIL_REPLYTO',
          score: 1.2,
          options: ['helpdesk-reset@freemail.e2e-portal.test'],
        },
        { name: 'TO_DN_SOME', score: 0, options: recipientsOf(plan) },
        { name: 'R_SPF_FAIL', score: 1, options: ['-all'] },
        {
          name: 'DMARC_POLICY_REJECT',
          score: 2,
          options: ['lookalike-alpha.e2e-portal.test : No valid SPF, No valid DKIM'],
        },
      ]
    : [
        { name: 'TO_DN_SOME', score: 0, options: recipientsOf(plan) },
        {
          name: spammy ? 'BAYES_SPAM' : 'R_SPF_ALLOW',
          score: spammy ? 5.1 : -0.2,
          options: spammy ? ['99.12%'] : ['+ip4:198.51.100.7'],
        },
      ];
  return {
    engine: 'rspamd',
    engineVersion: '3.12.1',
    outcome: spammy ? ('spam' as const) : ('clean' as const),
    score: phish ? '12.400' : spammy ? '7.500' : '1.100',
    requiredScore: '15.000',
    action: phish ? 'add header' : spammy ? 'add header' : 'no action',
    durationMs: 640,
    reasonCodes: phish
      ? ['spam.score', 'auth.spf_fail', 'auth.dmarc_fail']
      : spammy
        ? ['spam.score']
        : [],
    settingsVersion: 'rspamd-map/1;p=0123456789ab;t=none',
    evidence: { signals },
  };
}

/** BEC rule evidence as the engine stores it (bec.test.ts RULES shape). */
const BEC_RULES = [
  {
    id: 'R2',
    code: 'bec.reply_to.freemail',
    category: 'identity',
    severity: 'medium',
    weight: 20,
    suppressed: null,
    evidence: [
      {
        header: 'Reply-To',
        address: 'helpdesk-reset@freemail.e2e-portal.test',
        domain: 'freemail.e2e-portal.test',
      },
    ],
  },
  {
    id: 'R1',
    code: 'bec.reply_to.domain_mismatch',
    category: 'identity',
    severity: 'medium',
    weight: 15,
    suppressed: null,
    evidence: [{ header: 'Reply-To', domain: 'freemail.e2e-portal.test' }],
  },
  {
    id: 'C7',
    code: 'bec.content.urgency',
    category: 'intent',
    severity: 'low',
    weight: 10,
    suppressed: null,
    evidence: [
      {
        keywords: {
          category: 'urgency',
          language: 'en',
          lexiconIds: ['en.urgency.001'],
          spans: [{ source: 'subject', start: 3, end: 11 }],
        },
      },
    ],
  },
];

/** Masked DLP findings (never the matched values; dlp.test.ts FINDINGS shape). */
const DLP_FINDINGS = [
  {
    detector: 'PC1',
    code: 'dlp.payment_card.number',
    category: 'payment_card',
    severity: 'high',
    confidence: 0.95,
    count: 2,
    capped: false,
    sources: [{ kind: 'body_text' }, { kind: 'attachment', partIndex: 1, path: '0' }],
    masked: ['************0366', '************1111'],
  },
];
const DLP_CATEGORIES = [
  { category: 'payment_card', count: 2, maxSeverity: 'high', maxConfidence: 0.95 },
];

type EngineRow =
  | ReturnType<typeof rspamdFinal>
  | {
      engine: string;
      engineVersion: string;
      outcome: 'clean' | 'suspicious' | 'malicious';
      score: string | null;
      requiredScore: string | null;
      action: string | null;
      durationMs: number;
      reasonCodes: string[];
      settingsVersion: string;
      evidence: Prisma.InputJsonValue;
    };

const worst = (verdicts: readonly string[]): 'clean' | 'suspicious' | 'malicious' =>
  verdicts.includes('malicious')
    ? 'malicious'
    : verdicts.includes('suspicious')
      ? 'suspicious'
      : 'clean';

/** Attachments and URLs of every plan that has them; the details rows of `plan.details`. */
export async function writeMessageDetails(
  p: PrismaClient,
  organizationId: bigint,
  messages: readonly DetailTarget[],
): Promise<void> {
  for (const m of messages) {
    const { plan } = m;
    const base = { receivedAt: plan.receivedAt, messageId: m.id, organizationId };
    const completedAt = new Date(
      plan.receivedAt.getTime() + (plan.scan?.completedAfterMs ?? 1_000),
    );
    const attachments = plan.attachments ?? [];
    const urls = plan.urls ?? [];

    // Attachments (metadata only; parts are never stored in MySQL) and their results.
    for (const [index, attachment] of attachments.entries()) {
      const partIndex = index + 1;
      const digest = sha(`e2e-portal:${m.id.toString()}:${attachment.filename}`);
      const row = await p.emailAttachment.create({
        data: {
          ...base,
          partIndex,
          depth: 1,
          disposition: 'attachment',
          filename: attachment.filename,
          originalFilename: attachment.filename,
          declaredContentType: attachment.contentType,
          detectedContentType: attachment.contentType,
          sizeBytes: attachment.sizeBytes,
          sha256: digest,
          objectKey: `org/${organizationId.toString()}/part/e2e/${m.id.toString()}/${partIndex}.att`,
          verdict: attachment.verdict,
        },
        select: { id: true },
      });
      if (m.scanId === null) continue;
      await p.attachmentScanResult.create({
        data: {
          ...base,
          scanId: m.scanId,
          attachmentId: row.id,
          partIndex,
          sha256: digest,
          sizeBytes: attachment.sizeBytes,
          detectedType: attachment.contentType === 'text/html' ? 'html' : 'document',
          typeFamily: 'document',
          typeMismatch: false,
          verdict: attachment.verdict,
          reasonCodes:
            attachment.verdict === 'clean'
              ? ['clean.no_findings']
              : ['attachment.html_credential_form'],
          clamavEngineVersion: '1.4.1',
          clamavDbVersion: 27450,
          cacheResult: 'miss',
          durationMs: 14,
        },
      });
    }

    // URLs as the URL engine stores them, with results and the rewrite of the round.
    for (const [urlSeq, url] of urls.entries()) {
      const urlSha256 = sha(url.url);
      await p.messageUrl.create({
        data: {
          ...base,
          urlSeq,
          url: url.url,
          urlSha256,
          scheme: 'https',
          host: url.host,
          registrableDomain: 'e2e-portal.test',
          hostKind: 'domain',
          sources: { html_href: 1 },
          occurrences: 1,
          firstLifecycleRound: 0,
          extractorVersion: 'url-extract/1',
        },
      });
      if (m.scanId === null) continue;
      await p.urlScanResult.create({
        data: {
          ...base,
          scanId: m.scanId,
          urlSeq,
          urlSha256,
          verdict: url.verdict,
          reasonCodes: url.verdict === 'clean' ? ['clean.no_findings'] : ['url.feed_malicious'],
          reputation: [],
          fetchStatus: 'not_attempted',
          rewritten: true,
          dynamicRequested: false,
          fetchCache: 'none',
          durationMs: 3,
        },
      });
    }
    if (urls.length > 0 && m.scanId !== null) {
      await p.urlRewrite.create({
        data: {
          ...base,
          scanId: m.scanId,
          lifecycleRound: 0,
          status: 'rewritten',
          linksRewritten: urls.length,
          partsRewritten: 1,
          tokenKid: 1,
          expiresAt: new Date(plan.receivedAt.getTime() + 30 * 86_400_000),
          settingsVersion: 'e2e',
        },
      });
    }

    if (!plan.details) continue;

    // The 3.1 parse row and the stored header subset.
    const headers = headersOf(plan);
    await p.emailMessageParse.create({
      data: {
        ...base,
        status: 'parsed',
        parserVersion: 'e2e/1',
        partCount: 1 + attachments.length,
        attachmentCount: attachments.length,
        headerCount: headers.length,
        startedAt: plan.receivedAt,
        completedAt: new Date(plan.receivedAt.getTime() + 300),
      },
    });
    await p.emailHeader.createMany({
      data: headers.map((h, seq) => ({ ...base, seq, name: h.name, value: h.value })),
    });

    // Deliveries: SMTP replies (with addresses, masked by the api) and their status events.
    const deliveries = await p.emailDelivery.findMany({
      where: { messageId: m.id, receivedAt: plan.receivedAt, organizationId },
      select: { id: true, recipientId: true, status: true },
    });
    for (const d of deliveries) {
      const address =
        recipientsOf(plan)[m.recipientIds.indexOf(d.recipientId)] ?? 'unknown@e2e-portal.test';
      const reply =
        d.status === 'delivered'
          ? `250 2.0.0 Ok: queued as E2E${d.id.toString()} <${address}>`
          : d.status === 'deferred'
            ? `451 4.7.1 <${address}>: Greylisted, try again later`
            : `550 5.1.1 <${address}>: Recipient address rejected: User unknown`;
      await p.emailDelivery.updateMany({
        where: { id: d.id, receivedAt: plan.receivedAt },
        data: { finalSmtpResponse: reply },
      });
      const events: Array<{ from: 'queued' | null; to: typeof d.status; detail: string }> = [
        { from: null, to: 'queued', detail: 'planned by the delivery planner' },
        {
          from: 'queued',
          to: d.status,
          detail: `relay=mx.partner-three.e2e-portal.test said: ${reply}`,
        },
      ];
      for (const [index, event] of events.entries()) {
        await p.deliveryStatusEvent.create({
          data: {
            ...base,
            deliveryId: d.id,
            recipientId: d.recipientId,
            source: index === 0 ? 'planner' : 'postfix_log',
            signalKey: sha(`e2e-portal:${d.id.toString()}:${index}`),
            occurredAt: new Date(plan.receivedAt.getTime() + 4_000 + index * 1_500),
            fromStatus: event.from,
            toStatus: event.to,
            applied: true,
            queueId: index === 0 ? null : 'E2EQUEUE1',
            smtpCode:
              index === 0
                ? null
                : d.status === 'delivered'
                  ? 250
                  : d.status === 'deferred'
                    ? 451
                    : 550,
            remoteHost: index === 0 ? null : 'mx.partner-three.e2e-portal.test',
            detail: event.detail,
          },
        });
      }
    }

    if (m.scanId === null || plan.scan?.status !== 'completed') continue;
    const scanId = m.scanId;

    // Final engine rows of the initial round.
    const finals: EngineRow[] = [rspamdFinal(plan)];
    if (attachments.length > 0) {
      const outcome = worst(attachments.map((a) => a.verdict));
      finals.push({
        engine: 'attachment',
        engineVersion: 'attachment/1;clamav=1.4.1;yara=e2e',
        outcome,
        score: null,
        requiredScore: null,
        action: null,
        durationMs: 210,
        reasonCodes:
          outcome === 'clean' ? ['clean.no_findings'] : ['attachment.html_credential_form'],
        settingsVersion: 'attachment-map/1;p=0123456789ab;t=none',
        evidence: { signals: [] },
      });
    }
    if (urls.length > 0) {
      const outcome = worst(urls.map((u) => u.verdict));
      finals.push({
        engine: 'url',
        engineVersion: 'url/1;feeds=e2e',
        outcome,
        score: null,
        requiredScore: null,
        action: null,
        durationMs: 95,
        reasonCodes: outcome === 'clean' ? ['clean.no_findings'] : ['url.feed_malicious'],
        settingsVersion: 'url-map/1;p=0123456789ab;t=none',
        evidence: { signals: [] },
      });
    }
    let bec: RoundRows['bec'] = null;
    if (plan.details === 'phish') {
      finals.push({
        engine: 'bec',
        engineVersion: 'bec/1;lex=2876a3ab;fm=35f13669;br=fb362bf9',
        outcome: 'suspicious',
        score: '45.000',
        requiredScore: '40.000',
        action: null,
        durationMs: 321,
        reasonCodes: [...BEC_RULES.map((r) => r.code), 'bec.ai.unavailable'],
        settingsVersion: 'bec-map/1;p=0123456789ab;t=none',
        evidence: { signals: [], thresholds: { suspicious: 40, malicious: 80 } },
      });
      bec = { deterministicVerdict: 'suspicious', verdict: 'suspicious', rules: BEC_RULES };
    }
    let dlp: RoundRows['dlp'] = null;
    if (plan.details === 'outbound') {
      finals.push({
        engine: 'dlp',
        engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
        outcome: 'suspicious',
        score: null,
        requiredScore: null,
        action: null,
        durationMs: 2_345,
        reasonCodes: ['dlp.action.alert', 'dlp.payment_card.number'],
        settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
        evidence: { signals: [] },
      });
      dlp = {
        action: 'alert',
        verdict: 'suspicious',
        coverage: 'complete',
        categories: DLP_CATEGORIES,
      };
    }
    for (const final of finals) {
      await p.scanEngineResult.create({
        data: {
          ...base,
          scanId,
          engine: final.engine,
          engineVersion: final.engineVersion,
          outcome: final.outcome,
          score: final.score,
          requiredScore: final.requiredScore,
          action: final.action,
          durationMs: final.durationMs,
          attempt: 1,
          isFinal: true,
          reasonCodes: final.reasonCodes,
          settingsVersion: final.settingsVersion,
          evidence: final.evidence,
          completedAt,
        },
      });
    }

    const auth =
      plan.details === 'phish'
        ? ({
            spf: 'fail',
            dkim: 'none',
            dmarc: 'fail',
            dmarcPolicy: 'reject',
            arc: 'none',
          } as const)
        : ({
            spf: 'pass',
            dkim: 'pass',
            dmarc: 'pass',
            dmarcPolicy: 'reject',
            arc: 'none',
          } as const);
    const fromDomain = (plan.headerFrom ?? plan.envelopeFrom).split('@')[1] ?? null;
    await p.emailAuthResult.create({
      data: {
        ...base,
        scanId,
        engine: 'rspamd',
        ...auth,
        spfDomain: plan.envelopeFrom.split('@')[1] ?? null,
        dkimSignatures:
          auth.dkim === 'pass' ? [{ domain: fromDomain, selector: 'e2e', result: 'pass' }] : [],
        dmarcDomain: fromDomain,
      },
    });

    if (bec) {
      await p.becScanResult.create({
        data: {
          ...base,
          scanId,
          lifecycleRound: 0,
          engineVersion: 'bec/1;lex=2876a3ab;fm=35f13669;br=fb362bf9',
          rulesVersion: 'bec-map/1',
          settingsVersion: 'bec-map/1;p=0123456789ab;t=none',
          lexiconVersion: '2876a3ab',
          textVersion: 'bec-text/1',
          deterministicScore: 45,
          score: 45,
          deterministicVerdict: 'suspicious',
          verdict: 'suspicious',
          inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' },
          rules: BEC_RULES,
          features: { rule_r1: 1, rule_r2: 1, rule_c7: 1, fromFreemail: false },
          identity: {
            from: {
              displayName: 'IT Support',
              address: plan.headerFrom ?? plan.envelopeFrom,
              domain: 'lookalike-alpha.e2e-portal.test',
              registrableDomain: 'e2e-portal.test',
              kind: 'external',
            },
            fromCount: 1,
            replyTo: [],
            sender: null,
            returnPath: null,
            envelopeFrom: plan.envelopeFrom,
            isReply: true,
            flags: [],
          },
          ai: [],
          aiShadow: [],
          durationMs: 321,
        },
      });
    }
    if (dlp) {
      await p.dlpScanResult.create({
        data: {
          ...base,
          scanId,
          lifecycleRound: 0,
          direction: plan.direction,
          engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
          rulesVersion: 'dlp-map/1',
          settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
          policyVersion: 'pol/1;h=0123456789ab',
          extractorVersion: 'dlp-extract/1',
          verdict: 'suspicious',
          action: 'alert',
          actionSource: 'default_policy',
          coverage: 'complete',
          coverageDetail: {
            aadhaar: 'disabled',
            sources: [
              {
                source: 'subject',
                format: 'text',
                status: 'scanned',
                reasons: [],
                chars: 39,
                truncated: false,
              },
              {
                source: 'body_text',
                format: 'text',
                status: 'scanned',
                reasons: [],
                chars: 410,
                truncated: false,
              },
            ],
          },
          categories: DLP_CATEGORIES,
          findings: DLP_FINDINGS,
          policy: { winner: null, matched: [], exceptionsApplied: [] },
          findingCount: 2,
          // No evidence object: the evidence view is verified by the api suites (step 4.5).
          evidenceStatus: 'none',
          durationMs: 2_345,
        },
      });
    }

    // Risk score (revision 0) with the platform profile, as the email-worker computes it.
    const rows: RoundRows = {
      scan: {
        requiredEngines: requiredEnginesOf(plan),
        scanKind: 'initial',
        lifecycleRound: 0,
        status: 'completed',
      },
      message: {
        direction: plan.direction,
        attachmentCount: attachments.length,
        recipientCount: recipientsOf(plan).length,
      },
      finals: finals.map((f) => ({
        engine: f.engine,
        outcome: f.outcome,
        errorCode: null,
        reasonCodes: f.reasonCodes,
        score: f.score === null ? null : String(Number(f.score)),
        engineVersion: f.engineVersion,
        settingsVersion: f.settingsVersion,
        attempt: 1,
        completedAt,
      })),
      auth,
      bec,
      dlp,
    };
    const risk = scoreRisk(buildScoringInput(rows, 0), platformProfile('rsk-default/1'));
    const riskJson = riskResultToRowJson(risk);
    await p.messageRiskScore.create({
      data: {
        ...base,
        scanId,
        lifecycleRound: 0,
        revision: 0,
        direction: plan.direction,
        ...riskJson,
        explanation: risk.explanation.lines,
        profileVersionId: null,
        durationUs: 250,
      } as never,
    });

    // Policy evaluation with the platform default snapshot, as the policy-engine computes it.
    const policyRows: PolicyRoundRows = {
      trigger: 'scanned',
      message: {
        direction: plan.direction,
        envelopeFrom: plan.envelopeFrom,
        headerFrom: plan.headerFrom ?? plan.envelopeFrom,
        clientIp: '198.51.100.7',
        clientName: 'mx.external.e2e-portal.test',
        sizeBytes: 2048,
        recipientCount: recipientsOf(plan).length,
        attachmentCount: attachments.length,
        lifecycleRound: 0,
      },
      recipients: recipientsOf(plan).map((address, rcptSeq) => ({ rcptSeq, address })),
      scan: {
        scanId,
        lifecycleRound: 0,
        scanKind: 'initial',
        status: 'completed',
        scanVerdict: scanVerdictOf(plan),
        reasonCodes: [],
        requiredEngines: requiredEnginesOf(plan),
        completedAt,
      },
      parseFailedAt: null,
      finals: finals.map((f) => ({
        engine: f.engine,
        outcome: f.outcome,
        reasonCodes: f.reasonCodes,
      })),
      auth,
      bec,
      dlp,
      risk: [{ revision: 0, ...riskJson }],
      attachments: [],
      attachmentResults: [],
      urls: [],
      urlResults: [],
      urlRewrite: null,
      directory: { departmentsByAddress: {}, usersByAddress: {} },
    };
    const evaluation = evaluatePolicy(
      buildPolicyInput(policyRows),
      compileSnapshot({
        generation: '0',
        settings: null,
        platformDefaultId: 'pol-default/1',
        policies: [],
      }),
    );
    const json = evaluationResultToRow(evaluation, { policyVersionIds: {} });
    await p.policyExecutionLog.create({
      data: {
        ...json,
        ...base,
        scanId,
        decisivePolicyVersionId: null,
        policyGeneration: BigInt(json.policyGeneration),
        delivery: json.delivery ?? undefined,
        overrideDetail: json.overrideDetail ?? undefined,
        durationUs: 310,
        evaluatedAt: completedAt,
      } as never,
    });
  }
}
