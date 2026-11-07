import { normalizeDomainInput, registrableDomainOf } from '@email-gateway/url-security';
import { parse as parseDomain } from 'tldts';
import { computeAlignment, type Alignment } from '../identity/alignment';
import { isFreemailDomain, normalizeExtraDomains } from '../identity/freemail';
import {
  BecProtectedSet,
  detectDomainLookalike,
  type DomainLookalike,
} from '../identity/lookalike';
import {
  parseAddrSpec,
  parseEnvelopeAddress,
  parseMailboxList,
  type ParsedMailbox,
} from '../identity/mailbox';
import {
  matchProfileNames,
  normalizeName,
  type NameMatchKind,
  type NormalizedName,
} from '../identity/names';
import type { BecStaticData } from '../static-data';
import { analyzeText, type TextAnalysis } from '../text/analyze';
import { Deadline } from '../text/deadline';
import { LEXICON_CATEGORIES } from '../text/lexicon';
import {
  BEC_CATEGORY_CAPS,
  BEC_CLEAN_CODE,
  BEC_ENGINE_CODES,
  BEC_MAX_EVIDENCE_PER_RULE,
  BEC_MAX_REASON_CODES,
  BEC_MAX_SIGNALS,
  BEC_RULE_BY_ID,
  BEC_RULES_VERSION,
  BEC_SCORE_CAP,
  IDENTITY_EVIDENCE_RULE_IDS,
  INTENT_EVIDENCE_RULE_IDS,
  LEXICON_RULES,
  SEVERITY_RANK,
  type BecRuleCategory,
  type BecRuleId,
  type BecVerdict,
} from './codes';
import { buildFeatures } from './features';
import { applySuppressions } from './suppression';
import { applyTrust } from './trust';
import type {
  BecEvaluationInput,
  BecHeaders,
  BecRuleSettings,
  BecRulesResult,
  BecSignal,
  DomainKind,
  FiredRule,
  HistoryRow,
  IdentitySummary,
  IdentitySummaryEntry,
  InputState,
  RuleEvidence,
} from './types';

/**
 * `evaluateBecRules` (B6): the deterministic verdict map `bec-map/1`. Pure apart from the
 * clock (`options.now`, default `new Date()`, used for expiry of trusted senders and
 * suppressions) and the text time budget (`options.deadline`).
 */

export interface EvaluateOptions {
  now?: Date;
  deadline?: Deadline;
}

const headerValues = (headers: BecHeaders, name: string): string[] => {
  const out: string[] = [];
  const lower = name.toLowerCase();
  for (const [key, values] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) out.push(...values);
  }
  return out;
};

const reg = (domain: string | null | undefined): string | null =>
  domain ? (registrableDomainOf(domain) ?? null) : null;

const lower = (value: string | null | undefined): string | null =>
  value === null || value === undefined ? null : value.toLowerCase();

/** A domain-like token with a known (ICANN or private) public suffix. */
function knownSuffixDomain(token: string): string | null {
  const normalized = normalizeDomainInput(token);
  if (!normalized.ok) return null;
  const info = parseDomain(normalized.domain, { allowPrivateDomains: true });
  if (!info.isIcann && !info.isPrivate) return null;
  return normalized.registrableDomain;
}

const priorBucket = (count: number): '0' | '1-2' | '3-9' | '10+' =>
  count <= 0 ? '0' : count <= 2 ? '1-2' : count <= 9 ? '3-9' : '10+';

const time = (value: Date | string): number =>
  value instanceof Date ? value.getTime() : new Date(value).getTime();

/** Evidence entries omit absent values (B15 view schema: optional keys, never null). */
function compactEvidence(evidence: RuleEvidence): RuleEvidence {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(evidence)) {
    if (value === null || value === undefined || value === '') continue;
    out[key] = value;
  }
  return out;
}

interface PreparedProfile<T> {
  profile: T;
  names: NormalizedName[];
}

class RuleSet {
  readonly fired = new Map<BecRuleId, FiredRule>();

  fire(id: BecRuleId, evidence: RuleEvidence | RuleEvidence[] = []): void {
    const definition = BEC_RULE_BY_ID.get(id)!;
    let entry = this.fired.get(id);
    if (!entry) {
      entry = {
        id,
        code: definition.code,
        category: definition.category,
        severity: definition.severity,
        weight: definition.weight,
        suppressed: null,
        evidence: [],
      };
      this.fired.set(id, entry);
    }
    for (const item of Array.isArray(evidence) ? evidence : [evidence]) {
      if (entry.evidence.length >= BEC_MAX_EVIDENCE_PER_RULE) break;
      const compact = compactEvidence(item);
      if (Object.keys(compact).length > 0) entry.evidence.push(compact);
    }
  }

  has(id: BecRuleId): boolean {
    return this.fired.has(id);
  }
}

export function evaluateBecRules(
  input: BecEvaluationInput,
  settings: BecRuleSettings,
  data: BecStaticData,
  options: EvaluateOptions = {},
): BecRulesResult {
  const now = options.now ?? new Date();
  const deadline = options.deadline ?? Deadline.none();
  const receivedAt = input.envelope.receivedAt;

  // ---- Inputs (B2) --------------------------------------------------------------------------
  const historyState: InputState['history'] =
    input.history === 'disabled' ? 'disabled' : input.history === 'error' ? 'error' : 'enabled';

  // ---- Identities (B5) ----------------------------------------------------------------------
  const fromHeaders = headerValues(input.headers, 'From');
  const fromList = parseMailboxList(fromHeaders[0] ?? null);
  const from: ParsedMailbox | null =
    fromList.mailboxes.find((m) => m.address !== null) ?? fromList.mailboxes[0] ?? null;
  const fromAddress = lower(from?.address);
  const fromDomain = from?.domain ?? null;
  const fromReg = reg(fromDomain);
  const envelope = parseEnvelopeAddress(input.envelope.envelopeFrom);
  const envAddress = lower(envelope?.address);
  const envReg = reg(envelope?.domain);
  const senderMailbox =
    parseMailboxList(headerValues(input.headers, 'Sender')[0] ?? null).mailboxes[0] ?? null;
  const replyTo: ParsedMailbox[] = [];
  for (const value of headerValues(input.headers, 'Reply-To')) {
    for (const mailbox of parseMailboxList(value).mailboxes) {
      if (mailbox.address && replyTo.length < 20) replyTo.push(mailbox);
    }
  }
  const returnPathValues = headerValues(input.headers, 'Return-Path');
  const returnPath =
    returnPathValues.length > 0 ? parseEnvelopeAddress(returnPathValues[0]) : undefined;
  const isReply =
    headerValues(input.headers, 'In-Reply-To').some((v) => v.trim() !== '') ||
    headerValues(input.headers, 'References').some((v) => v.trim() !== '');

  // ---- Tenant data ----------------------------------------------------------------------------
  const tenantRegs = normalizeExtraDomains(input.tenant.tenantDomains);
  const freemailExtra = normalizeExtraDomains(input.tenant.freemailExtraDomains);
  const isFreemail = (domain: string | null): boolean =>
    isFreemailDomain(domain, data.freemail, freemailExtra);
  const executives: Array<PreparedProfile<(typeof input.tenant.executives)[number]>> =
    input.tenant.executives.map((profile) => ({
      profile,
      names: [profile.name, ...profile.aliases].map(normalizeName),
    }));
  const vendors = input.tenant.vendors.map((profile) => ({
    profile,
    names: [profile.name, ...profile.aliases].map(normalizeName),
    domains: normalizeExtraDomains(profile.domains),
    knownSenders: new Set(profile.knownSenders.map((a) => a.toLowerCase())),
  }));
  const protectedSet = new BecProtectedSet({
    brands: data.brands,
    tenantDomains: input.tenant.tenantDomains,
    vendorDomains: input.tenant.vendors.map((v) => ({ vendorId: v.publicId, domains: v.domains })),
    extraDomains: input.tenant.extraProtectedDomains,
  });
  const vendorById = new Map(vendors.map((v) => [v.profile.publicId, v]));
  const vendorOfDomain = (registrable: string | null): (typeof vendors)[number] | null =>
    registrable === null ? null : (vendors.find((v) => v.domains.has(registrable)) ?? null);

  const fromLook: DomainLookalike = detectDomainLookalike(
    fromDomain,
    fromReg,
    protectedSet,
    settings.lookalike,
  );
  const envLook: DomainLookalike =
    envelope?.domain && envReg !== fromReg
      ? detectDomainLookalike(envelope.domain, envReg, protectedSet, settings.lookalike)
      : { findings: [], mixedScript: false, idn: false };
  const replyLooks = replyTo.map((m) => ({
    mailbox: m,
    look: detectDomainLookalike(m.domain, reg(m.domain), protectedSet, settings.lookalike),
  }));

  const domainKind = (domain: string | null, look?: DomainLookalike): DomainKind | null => {
    const r = reg(domain);
    if (!r) return null;
    if (tenantRegs.has(r)) return 'tenant';
    if (vendorOfDomain(r)) return 'vendor';
    if (look && look.findings.some((f) => f.attributedKind !== 'brand' || f.highConfidence)) {
      return 'lookalike';
    }
    if (isFreemail(r)) return 'freemail';
    return 'external';
  };
  const summaryEntry = (
    m: ParsedMailbox | null,
    look?: DomainLookalike,
  ): IdentitySummaryEntry | null =>
    m
      ? {
          displayName: m.displayName,
          address: m.address ? m.address.slice(0, 320) : null,
          domain: m.domain,
          registrableDomain: reg(m.domain),
          kind: domainKind(m.domain, look),
        }
      : null;
  const identity: IdentitySummary = {
    from: summaryEntry(from, fromLook),
    fromCount: fromHeaders.length === 0 ? 0 : fromList.mailboxes.length,
    replyTo: replyLooks.slice(0, 5).map((r) => summaryEntry(r.mailbox, r.look)!),
    sender: summaryEntry(senderMailbox),
    returnPath: returnPath === undefined ? null : (returnPath?.address ?? ''),
    envelopeFrom: envelope?.address ?? null,
    isReply,
    flags: [
      ...new Set([...fromList.flags, ...(fromHeaders.length > 1 ? ['multiple_from'] : [])]),
    ].sort(),
  };

  // ---- E0: not inbound ------------------------------------------------------------------------
  const authState = input.auth.state;
  const urlState = input.url.state;
  if (input.envelope.direction !== 'inbound') {
    return {
      rulesVersion: BEC_RULES_VERSION,
      verdict: 'skipped',
      score: 0,
      codes: ['bec.not_inbound'],
      signals: [],
      firedRules: [],
      identityEvidence: false,
      intentEvidence: false,
      anyRuleFired: false,
      engineCodes: ['bec.not_inbound'],
      inputs: { auth: authState, url: urlState, text: 'absent', history: historyState },
      identity,
      features: {},
      text: null,
      authenticatedAsFrom: false,
    };
  }

  // ---- Authentication (B5) --------------------------------------------------------------------
  const auth = input.auth.state === 'available' ? input.auth.row : null;
  const alignment: Alignment = computeAlignment(auth, fromDomain, envelope?.domain ?? null);
  const authenticated = alignment.authenticatedAsFrom;
  const authEvidence = (): RuleEvidence => ({
    header: 'From',
    domain: fromReg,
    auth: {
      spf: auth?.spf ?? null,
      dkim: auth?.dkim ?? null,
      dmarc: auth?.dmarc ?? null,
      dmarcPolicy: auth?.dmarcPolicy ?? null,
      aligned: { dkim: alignment.dkimAligned, spf: alignment.spfAligned },
    },
  });

  // ---- Text (B8) ------------------------------------------------------------------------------
  const text: TextAnalysis = analyzeText(input.text, data.lexicon, {
    maxChars: settings.textMaxChars,
    deadline,
  });

  const rules = new RuleSet();
  const fromEvidence = (extra: RuleEvidence = {}): RuleEvidence => ({
    header: 'From',
    address: from?.address ?? null,
    displayName: from?.displayName ?? null,
    domain: fromReg,
    ...extra,
  });

  // ---- Identity rules -------------------------------------------------------------------------
  if (
    envAddress !== null &&
    envReg !== null &&
    fromReg !== null &&
    envReg !== fromReg &&
    !alignment.dkimAligned
  ) {
    rules.fire('P1', [
      fromEvidence(),
      { header: 'envelope', address: envelope!.address, domain: envReg },
    ]);
  }
  if (returnPath !== undefined) {
    const headerAddress = lower(returnPath?.address);
    if (headerAddress !== envAddress) {
      rules.fire('P2', [
        {
          header: 'Return-Path',
          address: returnPath?.address ?? null,
          domain: reg(returnPath?.domain),
        },
        { header: 'envelope', address: envelope?.address ?? null, domain: envReg },
      ]);
    }
  }
  if (
    fromHeaders.length !== 1 ||
    fromList.mailboxes.length !== 1 ||
    !from?.address ||
    fromList.flags.includes('parse_error')
  ) {
    rules.fire('I1', fromEvidence());
  }
  if (senderMailbox?.address) {
    const senderReg = reg(senderMailbox.domain);
    if (senderReg !== fromReg) {
      rules.fire('I2', [
        { header: 'Sender', address: senderMailbox.address, domain: senderReg },
        fromEvidence(),
      ]);
    }
  }
  if (auth && !authenticated) rules.fire('I3', authEvidence());

  const display = from?.displayName ? normalizeName(from.displayName) : null;
  if (from?.displayName) {
    // D1: an address or a domain-like token (known public suffix) in the display name.
    for (const piece of from.displayName.split(/[\s()<>"',;[\]]+/u)) {
      if (!piece) continue;
      if (piece.includes('@')) {
        const spec = parseAddrSpec(piece);
        if (spec.address && spec.address.toLowerCase() !== fromAddress) {
          rules.fire('D1', fromEvidence({ domain: reg(spec.domain) }));
          break;
        }
        continue;
      }
      if (!piece.includes('.')) continue;
      const embedded = knownSuffixDomain(piece.replace(/[.:!?]+$/u, ''));
      if (embedded !== null && embedded !== fromReg) {
        rules.fire('D1', fromEvidence({ domain: embedded }));
        break;
      }
    }
  }
  if (display) {
    // D2: a protected brand label or a tenant domain label as a whole token.
    const tokens = new Set(display.tokens);
    const skeletons = new Set(display.skeletons);
    for (const brand of data.brands) {
      const label = brand.label.toLowerCase();
      if (label.length < 3) continue;
      if (
        (tokens.has(label) || skeletons.has(label)) &&
        !(fromReg && brand.officialDomains.includes(fromReg))
      ) {
        rules.fire('D2', fromEvidence());
        break;
      }
    }
    if (!rules.has('D2')) {
      for (const tenantReg of tenantRegs) {
        const label = tenantReg.split('.')[0]!;
        if (
          label.length >= 3 &&
          tokens.has(label) &&
          fromReg !== null &&
          !tenantRegs.has(fromReg)
        ) {
          rules.fire('D2', fromEvidence());
          break;
        }
      }
    }
    if (display.invisibleChars || display.mixedScript) rules.fire('D3', fromEvidence());
  }

  const fromVendor = vendorOfDomain(fromReg);
  const fromFreemail = isFreemail(fromReg);
  for (const { mailbox } of replyLooks) {
    const replyReg = reg(mailbox.domain);
    if (
      replyReg !== null &&
      replyReg !== fromReg &&
      !tenantRegs.has(replyReg) &&
      !(fromVendor && fromVendor.domains.has(replyReg))
    ) {
      rules.fire('R1', { header: 'Reply-To', address: mailbox.address, domain: replyReg });
    }
    if (isFreemail(replyReg) && !fromFreemail) {
      rules.fire('R2', { header: 'Reply-To', address: mailbox.address, domain: replyReg });
    }
  }
  for (const { mailbox, look } of replyLooks) {
    for (const finding of look.findings) {
      const tenantOrVendor =
        finding.attributedKind === 'tenant' || finding.attributedKind === 'vendor';
      if (finding.highConfidence || (finding.rule === 'L5' && tenantOrVendor)) {
        rules.fire('R3', {
          header: 'Reply-To',
          address: mailbox.address,
          domain: reg(mailbox.domain),
          lookalike: {
            rule: finding.rule,
            targetKind: finding.attributedKind,
            targetDomain: finding.targetDomain,
            score: finding.score,
          },
        });
        break;
      }
    }
  }

  // ---- Authentication rules (only with the auth row) -------------------------------------------
  if (auth) {
    if (auth.dmarc === 'fail') rules.fire('A1', authEvidence());
    if (auth.spf === 'fail') rules.fire('A2', authEvidence());
    const fromSignatureFail = auth.dkimSignatures.some(
      (s) => s.result === 'fail' && fromReg !== null && reg(s.domain.toLowerCase()) === fromReg,
    );
    if (auth.dkim === 'fail' || fromSignatureFail) rules.fire('A3', authEvidence());
    const dkimPass = auth.dkim === 'pass' || auth.dkimSignatures.some((s) => s.result === 'pass');
    if (auth.spf !== 'pass' && !dkimPass && (auth.dmarc === null || auth.dmarc === 'none')) {
      rules.fire('A4', authEvidence());
    }
    const temp = (v: string | null): boolean => v === 'temperror' || v === 'permerror';
    if (temp(auth.spf) || temp(auth.dkim) || temp(auth.dmarc)) rules.fire('A5', authEvidence());
    if (fromReg !== null && tenantRegs.has(fromReg) && !authenticated)
      rules.fire('A6', authEvidence());
  }

  // ---- Lookalike rules ------------------------------------------------------------------------
  const senderFindings = [
    ...fromLook.findings.map((f) => ({ f, header: 'From' as const, domain: fromReg })),
    ...envLook.findings.map((f) => ({ f, header: 'envelope' as const, domain: envReg })),
  ];
  const lookEvidence = (x: (typeof senderFindings)[number]): RuleEvidence => ({
    header: x.header,
    domain: x.domain,
    lookalike: {
      rule: x.f.rule,
      targetKind: x.f.attributedKind,
      targetDomain: x.f.targetDomain,
      score: x.f.score,
    },
  });
  for (const x of senderFindings) {
    if (x.f.attributedKind === 'tenant') rules.fire('L1', lookEvidence(x));
    if (x.f.attributedKind === 'vendor') rules.fire('L2', lookEvidence(x));
  }
  for (const f of fromLook.findings) {
    if ((f.attributedKind === 'brand' || f.attributedKind === 'extra') && f.highConfidence) {
      rules.fire('L3', lookEvidence({ f, header: 'From', domain: fromReg }));
    }
  }
  if (fromLook.mixedScript) rules.fire('L4', fromEvidence());

  // ---- Impersonation ---------------------------------------------------------------------------
  let profileMatched = false;
  if (display) {
    let best: { exec: (typeof executives)[number]; match: NameMatchKind } | null = null;
    for (const exec of executives) {
      const match = matchProfileNames(display, exec.names);
      if (match) {
        best = { exec, match };
        break;
      }
    }
    if (best) {
      profileMatched = true;
      const profile = {
        kind: 'executive' as const,
        id: best.exec.profile.publicId,
        match: best.match,
      };
      const known =
        fromAddress !== null &&
        best.exec.profile.knownAddresses.some((a) => a.toLowerCase() === fromAddress);
      if (!known || !authenticated) {
        rules.fire('X1', fromEvidence({ profile }));
        if (fromFreemail) rules.fire('X2', fromEvidence({ profile }));
      }
      for (const { mailbox } of replyLooks) {
        const replyReg = reg(mailbox.domain);
        if (replyReg !== null && (!tenantRegs.has(replyReg) || isFreemail(replyReg))) {
          rules.fire('X3', [
            fromEvidence({ profile }),
            { header: 'Reply-To', address: mailbox.address, domain: replyReg },
          ]);
          break;
        }
      }
    }
  }
  const matchedVendors = new Map<string, 'domain' | 'lookalike' | NameMatchKind>();
  if (fromVendor) matchedVendors.set(fromVendor.profile.publicId, 'domain');
  for (const x of senderFindings) {
    if (x.f.attributedKind === 'vendor' && x.f.vendorId && !matchedVendors.has(x.f.vendorId)) {
      matchedVendors.set(x.f.vendorId, 'lookalike');
    }
  }
  if (display) {
    for (const vendor of vendors) {
      const match = matchProfileNames(display, vendor.names);
      if (!match) continue;
      profileMatched = true;
      if (fromReg === null || !vendor.domains.has(fromReg)) {
        rules.fire(
          'V1',
          fromEvidence({ profile: { kind: 'vendor', id: vendor.profile.publicId, match } }),
        );
        if (!matchedVendors.has(vendor.profile.publicId))
          matchedVendors.set(vendor.profile.publicId, match);
      }
    }
  }
  if (fromVendor) {
    // Matched by domain: the From domain is the evidence (B15 `profile` is for name matches).
    if (auth && !authenticated) rules.fire('V2', [fromEvidence(), authEvidence()]);
    if (
      fromVendor.knownSenders.size > 0 &&
      (fromAddress === null || !fromVendor.knownSenders.has(fromAddress))
    ) {
      rules.fire('V3', fromEvidence());
    }
  }

  // ---- Content (C1–C10) -----------------------------------------------------------------------
  for (const category of LEXICON_CATEGORIES) {
    if (category === 'authority') continue;
    const summary = text.categories[category];
    if (summary.count === 0) continue;
    const evidence: RuleEvidence[] = [];
    for (const language of summary.languages) {
      const matches = text.matches.filter(
        (m) => m.category === category && m.language === language,
      );
      evidence.push({
        keywords: {
          category,
          language,
          lexiconIds: [...new Set(matches.map((m) => m.id))].slice(0, 5),
          spans: matches.slice(0, 5).map((m) => ({ source: m.source, start: m.start, end: m.end })),
        },
      });
    }
    rules.fire(LEXICON_RULES[category], evidence);
  }
  const p = text.patterns;
  if (p.iban + p.swift + p.ifscAccount + p.amount > 0) {
    rules.fire('C10', {
      patterns: { iban: p.iban, swift: p.swift, ifsc_account: p.ifscAccount, amount: p.amount },
    });
  }
  if (rules.has('C2') || rules.has('C5')) {
    for (const [vendorId, match] of matchedVendors) {
      const vendor = vendorById.get(vendorId);
      if (vendor?.profile.paymentChangeSensitive) {
        rules.fire(
          'V4',
          match === 'domain' || match === 'lookalike'
            ? { header: 'From', domain: fromReg }
            : { profile: { kind: 'vendor', id: vendorId, match } },
        );
      }
    }
  }

  // ---- Links (K1–K4) ----------------------------------------------------------------------------
  if (input.url.state === 'available') {
    const rows = input.url.rows;
    const isLookalikeCode = (c: string): boolean =>
      c.startsWith('url.lookalike_') || c === 'url.mixed_script';
    const isCredential = (c: string): boolean =>
      c === 'url.credential_form' || c === 'url.credential_form_cross_origin';
    const k1 = rows.filter(
      (r) =>
        r.reasonCodes.includes('url.phishing_high_confidence') ||
        r.reasonCodes.includes('url.dynamic_phishing') ||
        (r.reasonCodes.some(isCredential) && r.reasonCodes.some(isLookalikeCode)),
    );
    const seqs = (list: typeof rows): RuleEvidence => ({
      urls: list.slice(0, 5).map((r) => r.urlSeq),
    });
    if (k1.length > 0) rules.fire('K1', seqs(k1));
    const k2 = rows.filter((r) => r.reasonCodes.some(isCredential));
    if (k1.length === 0 && k2.length > 0) rules.fire('K2', seqs(k2));
    const k3 = rows.filter((r) => r.reasonCodes.some(isLookalikeCode));
    if (k3.length > 0) rules.fire('K3', seqs(k3));
    const k4 = rows.filter((r) => r.verdict === 'malicious');
    if (k1.length === 0 && k4.length > 0) rules.fire('K4', seqs(k4));
  }

  // ---- History (H1–H5) ----------------------------------------------------------------------------
  if (typeof input.history === 'object') {
    const snapshot = input.history;
    const seenBefore = (row: HistoryRow | null): boolean =>
      row !== null && row.firstSeenAt.getTime() < receivedAt.getTime();
    const sender = snapshot.sender;
    const firstContact = !seenBefore(sender);
    const includesThis =
      sender !== null &&
      sender.lastSeenAt.getTime() >= receivedAt.getTime() &&
      sender.firstSeenAt.getTime() <= receivedAt.getTime();
    const prior = sender === null ? 0 : Math.max(0, sender.messageCount - (includesThis ? 1 : 0));
    const historyEvidence: RuleEvidence = {
      header: 'From',
      address: from?.address ?? null,
      history: { firstContact, priorMessages: priorBucket(firstContact ? 0 : prior) },
    };
    if (fromAddress !== null && firstContact) {
      rules.fire('H1', historyEvidence);
      if (rules.has('L1') || rules.has('L2') || rules.has('R3')) rules.fire('H2', historyEvidence);
      if ((['C1', 'C2', 'C3', 'C4', 'C5', 'C6'] as const).some((id) => rules.has(id))) {
        rules.fire('H5', historyEvidence);
      }
    }
    if (isReply && fromAddress !== null && !snapshot.pairs.some((row) => seenBefore(row))) {
      rules.fire('H3', historyEvidence);
    }
    if (
      fromAddress !== null &&
      !firstContact &&
      prior >= settings.historyMinMessages &&
      snapshot.fingerprintHash
    ) {
      const seen = (sender?.infra ?? []).some(
        (entry) =>
          entry.fp === snapshot.fingerprintHash &&
          (entry.count > 1 || time(entry.lastSeenAt) < receivedAt.getTime()),
      );
      if (!seen) rules.fire('H4', historyEvidence);
    }
  }

  // ---- Trust (B7) and suppression (B11) ------------------------------------------------------------
  applyTrust(
    rules.fired,
    input.tenant.trustedSenders,
    { fromAddress, fromReg, authenticated, now },
    (id, evidence) => rules.fire(id, evidence),
  );
  applySuppressions(
    rules.fired,
    input.tenant.suppressions,
    {
      fromAddress,
      fromReg,
      fromFreemail,
      now,
      maxWeight: settings.suppressionMaxWeight,
    },
    (id, evidence) => rules.fire(id, evidence),
  );

  // ---- Score, evidence classes, verdict ---------------------------------------------------------------
  const fired = [...rules.fired.values()];
  const active = fired.filter((r) => r.suppressed === null);
  const perCategory = new Map<BecRuleCategory, number>();
  for (const r of active)
    perCategory.set(r.category, (perCategory.get(r.category) ?? 0) + r.weight);
  let score = 0;
  for (const [category, sum] of perCategory)
    score += Math.min(sum, BEC_CATEGORY_CAPS[category] ?? sum);
  score = Math.min(BEC_SCORE_CAP, score);
  const identityEvidence = active.some((r) => IDENTITY_EVIDENCE_RULE_IDS.has(r.id));
  const intentEvidence = active.some((r) => INTENT_EVIDENCE_RULE_IDS.has(r.id));

  const engineCodes: string[] = [];
  if (authState !== 'available') engineCodes.push('bec.input_unavailable.auth');
  if (urlState !== 'available') engineCodes.push('bec.input_unavailable.url');
  if (text.state === 'incomplete' || input.headersIncomplete === true) {
    engineCodes.push('bec.content_incomplete');
  }
  if (historyState === 'error') engineCodes.push('bec.history_unavailable');
  engineCodes.sort(
    (a, b) =>
      BEC_ENGINE_CODES.indexOf(a as (typeof BEC_ENGINE_CODES)[number]) -
      BEC_ENGINE_CODES.indexOf(b as (typeof BEC_ENGINE_CODES)[number]),
  );

  let verdict: BecVerdict;
  if (score >= settings.maliciousScore && identityEvidence && intentEvidence) verdict = 'malicious';
  else if (score >= settings.suspiciousScore) verdict = 'suspicious';
  else if (engineCodes.length > 0) verdict = 'unknown';
  else verdict = 'clean';

  const ruleCodes = active
    .slice()
    .sort(
      (a, b) =>
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        b.weight - a.weight ||
        (a.code < b.code ? -1 : a.code > b.code ? 1 : 0),
    )
    .map((r) => r.code);
  const tail = [...engineCodes, ...(verdict === 'clean' ? [BEC_CLEAN_CODE] : [])];
  const codes = [...ruleCodes.slice(0, BEC_MAX_REASON_CODES - tail.length), ...tail];
  const signals: BecSignal[] = fired.slice(0, BEC_MAX_SIGNALS).map((r) => ({
    name: `bec:${r.id}`,
    score: r.suppressed === null ? r.weight : 0,
    options: [r.category],
  }));

  const features = buildFeatures({
    active,
    text,
    fromFreemail,
    replyToPresent: replyTo.length > 0,
    displayNameMatchesProfile: profileMatched,
    urlCount: input.url.state === 'available' ? input.url.rows.length : 0,
    isReply,
    authenticatedAsFrom: authenticated,
  });

  return {
    rulesVersion: BEC_RULES_VERSION,
    verdict,
    score,
    codes,
    signals,
    firedRules: fired,
    identityEvidence,
    intentEvidence,
    anyRuleFired: active.some((r) => r.id !== 'T1' && r.id !== 'S1'),
    engineCodes,
    inputs: { auth: authState, url: urlState, text: text.state, history: historyState },
    identity,
    features,
    text,
    authenticatedAsFrom: authenticated,
  };
}
