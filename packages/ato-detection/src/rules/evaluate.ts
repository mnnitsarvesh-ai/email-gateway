/**
 * Pure rule evaluation (step 8.4 D10): `evaluateRules` over one observation with the account
 * snapshot, baseline view, window snapshot, seen-today sets and context; `evaluateCorrelation` over
 * the account's recent persisted signals plus the fresh candidates (run inside the transaction
 * after the account lock). No I/O, no clock: `context.now` and the observation times only.
 */
import { anyCidrContains, cidrContains } from '../net';
import { assessTravel, haversineKm } from '../geo';
import { assertEvidenceSafe } from '../explain';
import { localHour, robustThreshold } from '../baseline';
import { signalDedupeKey } from '../keys';
import type { ResolvedAtoSettings, ResolvedRuleSettings } from '../settings';
import type {
  ObservationSource,
  SignalCategory,
  SignalSourceKind,
  SignalStrength,
} from '../taxonomy';
import {
  ATO_RULES,
  DEDUPE_BUCKET_MINUTES,
  ruleAvailability,
  ruleByCode,
  type CapabilitySet,
  type RuleDefinition,
} from './catalogue';
import {
  sumLast,
  type AuthObservation,
  type CorrelationInput,
  type Observation,
  type RuleInput,
  type SignalCandidate,
} from './types';

const FAILURE_OUTCOMES = new Set(['failure', 'locked', 'rate_limited', 'throttled', 'blocked']);

/** BEC observation categories that P4 treats as payment fraud or credential requests (D10). */
export const P4_CATEGORIES = [
  'bank_change',
  'gift_card',
  'payroll_change',
  'wire_transfer',
  'invoice_change',
  'credential_request',
] as const;

/** Mailbox rule traits that make an inbox rule suspicious (M2). */
export const SUSPICIOUS_RULE_TRAITS = [
  'delete',
  'move_rare_folder',
  'mark_read',
  'forward',
  'finance_keywords',
  'security_keywords',
] as const;

/** OAuth scopes that make a user consent strong when the publisher is unverified (Q1). */
export const RISKY_OAUTH_SCOPES = [
  'mail_read',
  'mail_send',
  'full_access',
  'offline_access',
] as const;

const ACCOUNT_CHANGE_RULES: Readonly<Record<string, string>> = Object.freeze({
  'auth.refresh_token_reused': 'ato.account.refresh_token_reuse',
  'auth.mfa_disabled': 'ato.account.mfa_disabled',
  'auth.password_changed': 'ato.account.credentials_changed',
  'auth.password_reset': 'ato.account.credentials_changed',
  'auth.mfa_enabled': 'ato.account.credentials_changed',
  'auth.recovery_codes_regenerated': 'ato.account.credentials_changed',
  'user.mfa_reset': 'ato.account.credentials_changed',
  'apikey.created': 'ato.account.persistence_created',
  'smtp_connector.created': 'ato.account.persistence_created',
  'smtp_connector.secret_rotated': 'ato.account.persistence_created',
  'webhook.created': 'ato.account.persistence_created',
  'user.roles_changed': 'ato.account.privilege_change',
  'role.created': 'ato.account.privilege_change',
  'role.updated': 'ato.account.privilege_change',
  'user.invited': 'ato.account.privilege_change',
  'platform.override_started': 'ato.account.privilege_change',
  'message.revealed': 'ato.account.bulk_data_access',
  'quarantine.downloaded': 'ato.account.bulk_data_access',
  // Releases are audited as an operator release (or approval request) and an end-user
  // self-release (step 8.4 WP3 deviation 1: there is no `quarantine.entry_released` action).
  'quarantine.release_requested': 'ato.account.bulk_data_access',
  'quarantine.self_released': 'ato.account.bulk_data_access',
});

/** Audit actions counted as data access (K6, window metric `data`). */
export const DATA_ACCESS_ACTIONS: readonly string[] = [
  'message.revealed',
  'quarantine.downloaded',
  'quarantine.release_requested',
  'quarantine.self_released',
];

/** The observation source a rule's `sources` list is matched against. */
export function observationSource(observation: Observation): ObservationSource {
  switch (observation.type) {
    case 'auth':
      return observation.source;
    case 'account_change':
      return 'account_change';
    case 'outbound_message':
      return 'outbound_message';
    case 'smtp_submission':
      return 'smtp_submission';
    case 'provider':
      return 'provider';
  }
}

function bucketOf(rule: RuleDefinition, at: Date, eventSubject: string): string {
  if (rule.dedupe.bucket === 'event') return `e:${eventSubject}`;
  const minutes = DEDUPE_BUCKET_MINUTES[rule.dedupe.bucket];
  return String(Math.floor(at.getTime() / (minutes * 60_000)));
}

const safeCode = (value: string): string =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9_.]/g, '_')
    .slice(0, 48);

interface HitOptions {
  strength?: SignalStrength;
  weight?: number;
  subject: string;
  evidence: Record<string, unknown>;
  /** Whether this hit is baseline-relative (default: the rule's flag). */
  relative?: boolean;
  seen?: SignalCandidate['seen'];
}

class Evaluator {
  readonly out: SignalCandidate[] = [];

  constructor(
    private readonly input: RuleInput,
    private readonly settings: Pick<ResolvedAtoSettings, 'rules' | 'geo'>,
    private readonly capabilities: CapabilitySet,
  ) {}

  /** The rule if enabled, applicable to the account kind and source, and available. */
  rule(code: string): (RuleDefinition & { s: ResolvedRuleSettings }) | null {
    const rule = ruleByCode(code);
    if (!rule) return null;
    const s = this.settings.rules[code];
    if (!s || !s.enabled) return null;
    if (!rule.kinds.includes(this.input.account.kind)) return null;
    if (!rule.sources.includes(observationSource(this.input.observation))) return null;
    if (!ruleAvailability(rule, this.capabilities).available) return null;
    return { ...rule, s };
  }

  get baseline() {
    return this.input.baseline;
  }

  get mature(): boolean {
    return this.input.baseline?.mature === true;
  }

  hit(rule: RuleDefinition & { s: ResolvedRuleSettings }, options: HitOptions): void {
    const obs = this.input.observation;
    const evidence = Object.fromEntries(
      Object.entries(options.evidence).filter(([, v]) => v !== undefined),
    );
    assertEvidenceSafe(evidence);
    const relative = options.relative ?? rule.baselineRelative;
    const sourceKind: SignalSourceKind =
      obs.type === 'auth'
        ? 'auth_event'
        : obs.type === 'account_change'
          ? 'audit'
          : obs.type === 'outbound_message'
            ? 'message'
            : obs.type === 'smtp_submission'
              ? 'telemetry'
              : 'provider';
    this.out.push({
      code: rule.code,
      category: rule.category,
      strength: options.strength ?? rule.strength,
      weight: options.weight ?? rule.s.weight,
      dedupeKey: signalDedupeKey(
        rule.code,
        this.input.account.id,
        options.subject,
        bucketOf(rule, obs.occurredAt, obs.key),
      ),
      dedupeWindowMinutes: DEDUPE_BUCKET_MINUTES[rule.dedupe.bucket],
      evidence,
      sourceKind,
      sourceRef: obs.key.slice(0, 64),
      messageRef: obs.type === 'outbound_message' ? obs.message : null,
      authEventRef: obs.type === 'auth' ? obs.authEventRef : null,
      informational: this.input.context.learning && relative,
      seen: options.seen ?? null,
    });
  }

  trustedIp(ip: string | null): boolean {
    if (!ip) return false;
    const ctx = this.input.context;
    if (anyCidrContains(ctx.trustedNetworks, ip)) return true;
    return ctx.trustedContexts.some(
      (t) => t.kind === 'ip_cidr' && t.expiresAt > ctx.now && cidrContains(t.value, ip),
    );
  }

  trustedPrefix(prefix: string | null): boolean {
    if (!prefix) return false;
    const network = prefix.split('/')[0] ?? '';
    return this.trustedIp(network);
  }

  trusted(kind: 'asn' | 'country' | 'device', value: string | null): boolean {
    if (value === null) return false;
    const ctx = this.input.context;
    return ctx.trustedContexts.some(
      (t) =>
        t.kind === kind && t.expiresAt > ctx.now && t.value.toLowerCase() === value.toLowerCase(),
    );
  }
}

// ------------------------------------------------------------------ authentication observations

function evaluateAuth(
  e: Evaluator,
  obs: AuthObservation,
  input: RuleInput,
  settings: Pick<ResolvedAtoSettings, 'geo'>,
): void {
  const w = input.windows;
  const failure = FAILURE_OUTCOMES.has(obs.outcome);
  const success = obs.outcome === 'success';
  const ip = obs.ip;
  const listed = obs.blockedNetwork || obs.reputation?.status === 'listed';

  if (failure) {
    const a1 = e.rule('ato.auth.bruteforce');
    if (a1) {
      const minutes = a1.s.params.windowMinutes!;
      const count = sumLast(w.minutes.af, minutes);
      if (count >= a1.s.params.failures!) {
        e.hit(a1, {
          subject: 'account',
          evidence: { failures: count, windowMinutes: minutes, threshold: a1.s.params.failures },
        });
      }
    }
    const a4 = e.rule('ato.auth.lockout');
    if (a4 && (obs.lockedByThrottle === true || obs.outcome === 'locked')) {
      e.hit(a4, { subject: 'account', evidence: {} });
    }
    const t5 = e.rule('ato.ti.targeted_by_campaign');
    if (t5 && obs.ipFlag?.flagged) {
      e.hit(t5, {
        subject: 'account',
        evidence: { ip, distinctAccounts: obs.ipFlag.distinctAccounts },
      });
    }
    const t6 = e.rule('ato.ti.malicious_ip_attempt');
    if (t6 && listed) e.hit(t6, { subject: 'account', evidence: { ip } });
  }

  if (obs.outcome === 'mfa_failure') {
    const a3 = e.rule('ato.auth.mfa_failures');
    if (a3) {
      const minutes = a3.s.params.windowMinutes!;
      const count = sumLast(w.minutes.mf, minutes);
      if (count >= a3.s.params.failures!) {
        e.hit(a3, {
          subject: 'account',
          evidence: { failures: count, windowMinutes: minutes, threshold: a3.s.params.failures },
        });
      }
    }
  }

  const t4 = e.rule('ato.ti.breach_listed');
  if (t4 && obs.breachListed === true) e.hit(t4, { subject: 'account', evidence: {} });

  if (!success) return;
  const b = e.baseline;
  const geo = obs.geo;
  const trustedIp = obs.trustedNetwork || e.trustedIp(ip);

  const a2 = e.rule('ato.auth.success_after_failures');
  if (a2) {
    const minutes = a2.s.params.windowMinutes!;
    const failures = sumLast(w.minutes.af, minutes);
    if (failures >= a2.s.params.failures!) {
      const distinctIps = w.distinctFailureIps30m;
      const strong = distinctIps >= a2.s.params.strongDistinctIps! || obs.ipFlag?.flagged === true;
      e.hit(a2, {
        subject: obs.key,
        strength: strong ? 'strong' : 'moderate',
        weight: strong ? a2.s.params.strongWeight! : a2.s.weight,
        evidence: { failures, distinctIps, windowMinutes: minutes, ip },
      });
    }
  }

  if (e.mature && b) {
    const c1 = e.rule('ato.access.new_ip_prefix');
    if (
      c1 &&
      obs.ipPrefix &&
      !b.prefixes.has(obs.ipPrefix) &&
      !input.seen.prefixes.has(obs.ipPrefix) &&
      !trustedIp
    ) {
      e.hit(c1, {
        subject: obs.ipPrefix,
        evidence: { ipPrefix: obs.ipPrefix },
        seen: { kind: 'prefixes', value: obs.ipPrefix },
      });
    }
    const c2 = e.rule('ato.access.new_asn');
    if (
      c2 &&
      geo?.asn !== null &&
      geo?.asn !== undefined &&
      !b.asns.has(geo.asn) &&
      !input.seen.asns.has(String(geo.asn)) &&
      !e.trusted('asn', String(geo.asn)) &&
      !trustedIp
    ) {
      e.hit(c2, {
        subject: String(geo.asn),
        evidence: { asn: geo.asn, asnOrg: geo.asnOrg?.slice(0, 120) ?? null },
        seen: { kind: 'asns', value: String(geo.asn) },
      });
    }
    const c3 = e.rule('ato.access.new_device');
    if (
      c3 &&
      obs.device &&
      !b.devices.has(obs.device.hash) &&
      !input.seen.devices.has(obs.device.hash) &&
      !e.trusted('device', obs.device.hash)
    ) {
      e.hit(c3, {
        subject: obs.device.hash,
        evidence: { deviceLabel: obs.device.label },
        seen: { kind: 'devices', value: obs.device.hash },
      });
    }
    const c4 = e.rule('ato.access.unusual_hour');
    if (c4) {
      const total = b.hourHistogram.reduce((s, n) => s + n, 0);
      if (total >= c4.s.params.minBaselineEvents!) {
        const hour = localHour(obs.occurredAt, input.context.timeZone);
        const tol = c4.s.params.toleranceHours!;
        let around = 0;
        for (let d = -tol; d <= tol; d++) around += b.hourHistogram[(hour + d + 24) % 24] ?? 0;
        const permille = Math.floor((around * 1000) / total);
        if (permille < c4.s.params.maxSharePermille!) {
          e.hit(c4, { subject: 'account', evidence: { permille, baseline: total } });
        }
      }
    }
    const c5 = e.rule('ato.access.channel_change');
    if (
      c5 &&
      obs.channel === 'api' &&
      b.channels.size > 0 &&
      [...b.channels].every((c) => c === 'portal')
    ) {
      e.hit(c5, { subject: 'account', evidence: {} });
    }
    const g1 = e.rule('ato.geo.new_country');
    if (
      g1 &&
      geo?.country &&
      (geo.status === 'located' || geo.status === 'stale') &&
      !b.countries.has(geo.country) &&
      !input.seen.countries.has(geo.country) &&
      !e.trusted('country', geo.country) &&
      !trustedIp
    ) {
      e.hit(g1, {
        subject: geo.country,
        evidence: { country: geo.country },
        seen: { kind: 'countries', value: geo.country },
      });
    }
  }

  const c6 = e.rule('ato.access.concurrent_ips');
  if (c6) {
    const count = w.distinctSuccessPrefixes60m;
    const usual = b?.maxHourlyPrefixes ?? 0;
    if (count >= c6.s.params.distinctPrefixes! && count > usual) {
      e.hit(c6, { subject: 'account', evidence: { count, windowMinutes: 60, baseline: usual } });
    }
  }

  const located = geo && (geo.status === 'located' || geo.status === 'stale');
  const g2 = e.rule('ato.geo.impossible_travel');
  const prev = input.account.lastSuccess;
  if (g2 && located && prev && prev.at < obs.occurredAt) {
    const travel = assessTravel(
      {
        country: prev.country,
        latitude: prev.latitude,
        longitude: prev.longitude,
        accuracyKm: prev.accuracyKm,
        at: prev.at,
        anonymizerFlags: prev.anonymizerFlags,
        trusted: prev.trusted,
      },
      {
        country: geo.country,
        latitude: geo.latitude,
        longitude: geo.longitude,
        accuracyKm: geo.accuracyKm,
        at: obs.occurredAt,
        anonymizerFlags: geo.anonymizerFlags,
        trusted: trustedIp,
      },
      settings.geo,
    );
    if (travel.impossible) {
      const from = prev.country ?? 'unknown';
      const to = geo.country ?? 'unknown';
      e.hit(g2, {
        subject: `${from}>${to}`,
        strength: travel.anonymized ? 'weak' : 'moderate',
        weight: travel.anonymized ? g2.s.params.downgradedWeight! : g2.s.weight,
        evidence: {
          fromCountry: from,
          toCountry: to,
          distanceKm: travel.effectiveKm,
          elapsedMinutes: travel.elapsedMinutes,
          speedKmh: travel.speedKmh,
        },
      });
    }
  }

  const g3 = e.rule('ato.geo.inconsistent_sessions');
  if (
    g3 &&
    located &&
    geo.latitude !== null &&
    geo.longitude !== null &&
    geo.country &&
    geo.accuracyKm !== null &&
    geo.accuracyKm <= settings.geo.maxAccuracyRadiusKm &&
    !trustedIp
  ) {
    const minutes = g3.s.params.windowMinutes!;
    const since = obs.occurredAt.getTime() - minutes * 60_000;
    const countries = new Set<string>([geo.country]);
    let maxKm = 0;
    for (const l of obs.concurrentLocations ?? []) {
      if (l.at.getTime() < since || l.country === geo.country) continue;
      if (l.accuracyKm > settings.geo.maxAccuracyRadiusKm) continue;
      const km =
        haversineKm(geo.latitude, geo.longitude, l.latitude, l.longitude) -
        l.accuracyKm -
        geo.accuracyKm;
      if (km >= settings.geo.minDistanceKm) {
        countries.add(l.country);
        maxKm = Math.max(maxKm, Math.round(km));
      }
    }
    if (countries.size >= 2) {
      e.hit(g3, {
        subject: 'account',
        evidence: { count: countries.size, distanceKm: maxKm, windowMinutes: minutes },
      });
    }
  }

  const g4 = e.rule('ato.geo.anonymizer');
  if (g4 && geo?.anonymizerFlags) e.hit(g4, { subject: ip ?? '-', evidence: { ip } });

  const t1 = e.rule('ato.ti.malicious_ip_success');
  if (t1 && listed) {
    const rep = obs.reputation;
    let strong: boolean;
    if (obs.blockedNetwork) strong = true;
    else if (rep?.confidence) strong = rep.confidence === 'high';
    else strong = rep?.severity === 'high' || rep?.severity === 'critical';
    e.hit(t1, {
      subject: ip ?? '-',
      strength: strong ? 'strong' : 'moderate',
      weight: strong ? t1.s.weight : t1.s.params.moderateWeight!,
      evidence: {
        ip,
        codes: obs.blockedNetwork ? ['blocked_network'] : [rep?.category ?? 'listed'],
      },
    });
  }
  const t2 = e.rule('ato.ti.dnsbl_listed_success');
  if (t2 && obs.dnsblListed === true) e.hit(t2, { subject: ip ?? '-', evidence: { ip } });
  const t3 = e.rule('ato.ti.attack_source_success');
  if (t3 && obs.ipFlag?.flagged) {
    e.hit(t3, {
      subject: ip ?? '-',
      evidence: { ip, distinctAccounts: obs.ipFlag.distinctAccounts },
    });
  }
}

// ------------------------------------------------------------------ other observations

function evaluateAccountChange(e: Evaluator, input: RuleInput): void {
  const obs = input.observation;
  if (obs.type !== 'account_change') return;
  const code = ACCOUNT_CHANGE_RULES[obs.action];
  if (!code) return;
  const rule = e.rule(code);
  if (!rule) return;
  if (code === 'ato.account.bulk_data_access') {
    const minutes = rule.s.params.windowMinutes!;
    const count = sumLast(input.windows.minutes.data, minutes);
    if (count >= rule.s.params.count!) {
      e.hit(rule, { subject: 'account', evidence: { count, windowMinutes: minutes } });
    }
    return;
  }
  e.hit(rule, {
    subject: rule.dedupe.bucket === 'event' ? obs.key : 'account',
    evidence: { action: obs.action },
  });
}

function evaluateOutbound(
  e: Evaluator,
  input: RuleInput,
  settings: Pick<ResolvedAtoSettings, 'baselines'>,
): void {
  const obs = input.observation;
  if (obs.type !== 'outbound_message') return;
  if (input.account.kind === 'smtp_connector' && !obs.connectorAttributed) return;
  const w = input.windows;
  const b = e.baseline;
  const messageId = obs.message.id.toString();

  const o1 = e.rule('ato.outbound.volume_spike');
  if (o1) {
    const hour = sumLast(w.minutes.msg, 60);
    const day = sumLast(w.hourlyMessages, 24);
    const pm = o1.s.params;
    let fired: { count: number; threshold: number; windowMinutes: number } | null = null;
    let relative = false;
    if (e.mature && b) {
      relative = true;
      const hourly = Math.max(
        pm.absMinPerHour!,
        Math.floor((Math.max(0, ...b.maxHourlyMessages) * pm.hourlyMultiplierPermille!) / 1000),
      );
      const daily = robustThreshold(b.dailyMessages, settings.baselines.volumeK, pm.absMinPerDay!);
      if (hour > hourly) fired = { count: hour, threshold: hourly, windowMinutes: 60 };
      else if (day > daily) fired = { count: day, threshold: daily, windowMinutes: 1440 };
    } else {
      if (hour > pm.immaturePerHour!) {
        fired = { count: hour, threshold: pm.immaturePerHour!, windowMinutes: 60 };
      } else if (day > pm.immaturePerDay!) {
        fired = { count: day, threshold: pm.immaturePerDay!, windowMinutes: 1440 };
      }
    }
    if (fired) {
      const strong =
        fired.count >= pm.strongMultiplier! * fired.threshold &&
        fired.count >= pm.strongMinMessages!;
      e.hit(o1, {
        subject: 'account',
        relative,
        strength: strong ? 'strong' : 'moderate',
        weight: strong ? pm.strongWeight! : o1.s.weight,
        evidence: fired,
      });
    }
  }

  if (e.mature && b) {
    const o2 = e.rule('ato.outbound.recipient_fanout');
    if (o2) {
      const threshold = Math.max(
        o2.s.params.minDomains!,
        o2.s.params.baselineMultiplier! * b.maxHourlyExternalDomains,
      );
      if (w.distinctExternalDomains60m >= threshold) {
        e.hit(o2, {
          subject: 'account',
          evidence: { count: w.distinctExternalDomains60m, threshold },
        });
      }
    }
    const o3 = e.rule('ato.outbound.new_recipient_domains');
    if (o3) {
      const ext = sumLast(w.minutes.ext, 60);
      const fresh = sumLast(w.minutes.newdom, 60);
      if (ext >= o3.s.params.minRecipients!) {
        const permille = Math.floor((fresh * 1000) / ext);
        if (permille >= o3.s.params.newSharePermille!) {
          e.hit(o3, { subject: 'account', evidence: { permille, count: ext } });
        }
      }
    }
    const o6 = e.rule('ato.outbound.unusual_hour');
    if (o6) {
      const thisHour = w.hourlyMessages[0] ?? 0;
      const total = b.messageHourHistogram.reduce((s, n) => s + n, 0);
      if (thisHour >= o6.s.params.minMessages! && total > 0) {
        const hour = localHour(obs.occurredAt, input.context.timeZone);
        const permille = Math.floor(((b.messageHourHistogram[hour] ?? 0) * 1000) / total);
        if (permille < o6.s.params.maxSharePermille!) {
          e.hit(o6, { subject: 'account', evidence: { count: thisHour, permille } });
        }
      }
    }
    const o7 = e.rule('ato.outbound.new_client_ip');
    const prefix = obs.clientIpPrefix;
    if (
      o7 &&
      prefix &&
      !b.clientPrefixes.has(prefix) &&
      !input.seen.clientPrefixes.has(prefix) &&
      !e.trustedPrefix(prefix)
    ) {
      e.hit(o7, {
        subject: prefix,
        evidence: { ipPrefix: prefix },
        seen: { kind: 'clientPrefixes', value: prefix },
      });
    }
    const o10 = e.rule('ato.outbound.sender_identity_mismatch');
    if (o10 && !obs.headerFromMatches && !b.fromMismatchSeen) {
      const count = sumLast(w.minutes.hfm, 60);
      if (count >= o10.s.params.minMessages!) {
        e.hit(o10, { subject: 'account', evidence: { count } });
      }
    }
    const p4 = e.rule('ato.content.bec_language');
    if (p4 && obs.findings.becCategories) {
      for (const cat of obs.findings.becCategories) {
        if (!(P4_CATEGORIES as readonly string[]).includes(cat) || b.becCategories.has(cat))
          continue;
        e.hit(p4, { subject: cat, evidence: { categories: [cat], messageId } });
      }
    }
    const p5 = e.rule('ato.content.financial_identifiers');
    if (p5 && obs.findings.financial && !b.financialSeen) {
      e.hit(p5, { subject: 'account', evidence: { messageId } });
    }
  }

  const o4 = e.rule('ato.outbound.attachment_spread');
  const spread = w.attachmentSpread;
  if (
    o4 &&
    spread &&
    spread.recipients >= o4.s.params.minRecipients! &&
    spread.domains >= o4.s.params.minDomains! &&
    !(spread.type && b?.attachmentTypes.has(spread.type))
  ) {
    e.hit(o4, {
      subject: spread.sha256,
      evidence: {
        count: spread.recipients,
        domainCount: spread.domains,
        attachmentType: spread.type ? safeCode(spread.type) : 'unknown',
      },
    });
  }
  const o5 = e.rule('ato.outbound.mass_subject');
  if (o5 && w.subjectMessages60m >= o5.s.params.minMessages! && !b?.massSubjectSeen) {
    e.hit(o5, { subject: 'account', evidence: { count: w.subjectMessages60m } });
  }
  const o9 = e.rule('ato.outbound.reply_without_parent');
  if (o9 && obs.replyWithoutParent) {
    const count = sumLast(w.minutes.rnp, 60);
    if (count >= o9.s.params.minReplies!) e.hit(o9, { subject: 'account', evidence: { count } });
  }
  const p1 = e.rule('ato.content.phishing_sent');
  if (p1 && obs.findings.phishing) {
    e.hit(p1, {
      subject: messageId,
      evidence: { messageId, codes: obs.findings.phishingCodes.slice(0, 8).map(safeCode) },
    });
  }
  const p2 = e.rule('ato.content.malware_sent');
  if (p2 && obs.findings.malware) e.hit(p2, { subject: messageId, evidence: { messageId } });
  const p3 = e.rule('ato.content.spam_sent');
  if (p3 && obs.findings.spam) {
    const count = sumLast(w.minutes.spam, 60);
    if (count >= p3.s.params.minSpam!) e.hit(p3, { subject: 'account', evidence: { count } });
  }
  const t4 = e.rule('ato.ti.breach_listed');
  if (t4 && obs.breachListed === true) e.hit(t4, { subject: 'account', evidence: {} });
}

function evaluateSubmission(e: Evaluator, input: RuleInput): void {
  const obs = input.observation;
  if (obs.type !== 'smtp_submission') return;
  const b = e.baseline;
  const o8 = e.rule('ato.outbound.connector_sender_spread');
  if (o8) {
    const count = input.windows.distinctSenders60m;
    const usual = b?.maxHourlySenders ?? 0;
    const threshold = Math.max(o8.s.params.minSenders!, o8.s.params.baselineMultiplier! * usual);
    if (count >= threshold) {
      e.hit(o8, { subject: 'account', evidence: { count, baseline: usual, threshold } });
    }
  }
  const o7 = e.rule('ato.outbound.new_client_ip');
  const prefix = obs.clientIpPrefix;
  if (
    o7 &&
    e.mature &&
    b &&
    prefix &&
    !b.clientPrefixes.has(prefix) &&
    !input.seen.clientPrefixes.has(prefix) &&
    !e.trustedPrefix(prefix)
  ) {
    e.hit(o7, {
      subject: prefix,
      evidence: { ipPrefix: prefix },
      seen: { kind: 'clientPrefixes', value: prefix },
    });
  }
}

function evaluateProvider(e: Evaluator, input: RuleInput): void {
  const obs = input.observation;
  if (obs.type !== 'provider') return;
  const m = obs.mailbox;
  if (m) {
    const m1 = e.rule('ato.mailbox.external_forwarding');
    if (m1 && m.change === 'forwarding_added' && m.targetDomain && !m.targetDomainKnown) {
      e.hit(m1, { subject: m.targetDomain, evidence: { domain: m.targetDomain.slice(0, 128) } });
    }
    const m2 = e.rule('ato.mailbox.suspicious_inbox_rule');
    const traits = m.ruleTraits.filter((t) =>
      (SUSPICIOUS_RULE_TRAITS as readonly string[]).includes(t),
    );
    if (
      m2 &&
      (m.change === 'inbox_rule_added' || m.change === 'inbox_rule_changed') &&
      traits.length > 0
    ) {
      e.hit(m2, {
        subject: m.ruleHash ?? obs.eventId,
        evidence: {
          ruleHash: (m.ruleHash ?? '').slice(0, 16) || null,
          codes: traits.map(safeCode),
        },
      });
    }
    const m3 = e.rule('ato.mailbox.delegation_added');
    if (m3 && (m.change === 'delegate_added' || m.change === 'permission_added')) {
      e.hit(m3, { subject: m.ruleHash ?? obs.eventId, evidence: {} });
    }
    const m4 = e.rule('ato.mailbox.unusual_access');
    if (m4 && m.change === 'access' && !m.clientTypeKnown) {
      e.hit(m4, { subject: 'account', evidence: {} });
    }
  }
  const o = obs.oauth;
  const q1 = e.rule('ato.oauth.risky_consent');
  if (q1 && o) {
    const risky =
      o.consentType === 'user' &&
      o.publisherVerified !== true &&
      o.scopes.some((s) => (RISKY_OAUTH_SCOPES as readonly string[]).includes(s));
    e.hit(q1, {
      subject: o.appIdHash,
      strength: risky ? 'strong' : 'moderate',
      weight: risky ? q1.s.params.strongWeight! : q1.s.weight,
      evidence: { codes: o.scopes.slice(0, 8).map(safeCode) },
    });
  }
  const q2 = e.rule('ato.oauth.token_anomaly');
  if (q2 && obs.tokenAnomaly) e.hit(q2, { subject: 'account', evidence: {} });
  const r1 = e.rule('ato.provider.risk_event');
  if (r1 && obs.riskLevel) {
    const level = obs.riskLevel;
    e.hit(r1, {
      subject: obs.eventId,
      strength: level === 'high' ? 'strong' : level === 'medium' ? 'moderate' : 'weak',
      weight:
        level === 'high'
          ? r1.s.weight
          : level === 'medium'
            ? r1.s.params.mediumWeight!
            : r1.s.params.lowWeight!,
      evidence: { provider: safeCode(obs.provider), action: level },
    });
  }
}

/**
 * `evaluateRules(input, settings, capabilities)`: every enabled, applicable and available rule
 * (correlation rules excluded) over one observation. Pure and deterministic.
 */
export function evaluateRules(
  input: RuleInput,
  settings: Pick<ResolvedAtoSettings, 'rules' | 'geo' | 'baselines'>,
  capabilities: CapabilitySet,
): SignalCandidate[] {
  const e = new Evaluator(input, settings, capabilities);
  switch (input.observation.type) {
    case 'auth':
      evaluateAuth(e, input.observation, input, settings);
      break;
    case 'account_change':
      evaluateAccountChange(e, input);
      break;
    case 'outbound_message':
      evaluateOutbound(e, input, settings);
      break;
    case 'smtp_submission':
      evaluateSubmission(e, input);
      break;
    case 'provider':
      evaluateProvider(e, input);
      break;
  }
  return e.out;
}

// ------------------------------------------------------------------ correlation

const ACCESS_CATEGORIES: readonly SignalCategory[] = [
  'access_context',
  'geography',
  'threat_intel',
];
const OUTBOUND_CATEGORIES: readonly SignalCategory[] = ['outbound_behaviour', 'outbound_content'];
const SUCCESS_CODES = new Set([
  'ato.auth.success_after_failures',
  'ato.access.new_ip_prefix',
  'ato.access.new_asn',
  'ato.access.new_device',
  'ato.access.unusual_hour',
  'ato.access.channel_change',
  'ato.access.concurrent_ips',
  'ato.geo.new_country',
  'ato.geo.impossible_travel',
  'ato.geo.inconsistent_sessions',
  'ato.geo.anonymizer',
  'ato.ti.malicious_ip_success',
  'ato.ti.dnsbl_listed_success',
  'ato.ti.attack_source_success',
]);
const CONNECTOR_ANOMALY_CODES = new Set([
  'ato.access.new_ip_prefix',
  'ato.geo.new_country',
  'ato.ti.malicious_ip_success',
  'ato.ti.attack_source_success',
  'ato.auth.success_after_failures',
]);
const CONFIG_CODES = new Set([
  'ato.mailbox.external_forwarding',
  'ato.mailbox.suspicious_inbox_rule',
  'ato.mailbox.delegation_added',
  'ato.oauth.risky_consent',
]);

interface CorrelationSignal {
  code: string;
  category: SignalCategory;
  strength: SignalStrength;
  at: Date;
  fresh: boolean;
}

/**
 * `evaluateCorrelation(input, settings)` (D10 X1–X5): over the account's recent active signals
 * (and its linked accounts') plus the fresh candidates. A correlation fires only when at least one
 * signal of the pattern is fresh, so old evidence alone never produces new correlation signals.
 */
export function evaluateCorrelation(
  input: CorrelationInput,
  settings: Pick<ResolvedAtoSettings, 'rules'>,
): SignalCandidate[] {
  const out: SignalCandidate[] = [];
  const kind = input.account.kind;
  const signals: CorrelationSignal[] = [
    ...input.recent
      .filter((s) => s.status === 'active' && s.category !== 'correlation')
      .map((s) => ({
        code: s.code,
        category: s.category,
        strength: s.strength,
        at: s.lastOccurredAt,
        fresh: false,
      })),
    ...input.fresh
      .filter((c) => !c.informational && c.category !== 'correlation')
      .map((c) => ({
        code: c.code,
        category: c.category,
        strength: c.strength,
        at: c.occurredAt,
        fresh: true,
      })),
  ].sort((a, b) => a.at.getTime() - b.at.getTime());
  if (signals.length === 0 || !signals.some((s) => s.fresh)) return out;

  const enabled = (code: string) => {
    const rule = ruleByCode(code);
    const s = settings.rules[code];
    if (!rule || !s || !s.enabled || !rule.kinds.includes(kind)) return null;
    return { rule, s };
  };
  const push = (code: string, codes: string[], extra: Record<string, unknown>) => {
    const r = enabled(code)!;
    const evidence = { codes: [...new Set(codes)].slice(0, 8), ...extra };
    assertEvidenceSafe(evidence);
    out.push({
      code,
      category: r.rule.category,
      strength: r.rule.strength,
      weight: r.s.weight,
      dedupeKey: signalDedupeKey(
        code,
        input.account.id,
        'account',
        String(Math.floor(input.now.getTime() / (DEDUPE_BUCKET_MINUTES.day * 60_000))),
      ),
      dedupeWindowMinutes: DEDUPE_BUCKET_MINUTES.day,
      evidence,
      sourceKind: 'correlation',
      sourceRef: null,
      messageRef: null,
      authEventRef: null,
      informational: false,
      seen: null,
    });
  };
  const moderateOrStrong = (s: CorrelationSignal) => s.strength !== 'weak';

  // X1: a moderate/strong access, geography or threat-intel signal ≤ 24 h before an outbound one.
  const x1 = enabled('ato.correlation.login_then_outbound');
  if (x1) {
    const win = x1.s.params.windowHours! * 3_600_000;
    for (const o of signals.filter((s) => OUTBOUND_CATEGORIES.includes(s.category))) {
      const a = signals.find(
        (s) =>
          ACCESS_CATEGORIES.includes(s.category) &&
          moderateOrStrong(s) &&
          s.at <= o.at &&
          o.at.getTime() - s.at.getTime() <= win &&
          (s.fresh || o.fresh),
      );
      if (a) {
        push(x1.rule.code, [a.code, o.code], {
          windowMinutes: Math.round((o.at.getTime() - a.at.getTime()) / 60_000),
        });
        break;
      }
    }
  }

  // X2: an authentication signal, then a success, then an account change within 2 h.
  const x2 = enabled('ato.correlation.attack_then_change');
  if (x2) {
    const win = x2.s.params.windowMinutes! * 60_000;
    const successes = [
      ...signals.filter((s) => SUCCESS_CODES.has(s.code)).map((s) => s.at),
      ...input.successTimes,
    ];
    outer: for (const change of signals.filter((s) => s.category === 'account_change')) {
      for (const attack of signals.filter((s) => s.category === 'authentication')) {
        if (attack.at > change.at || change.at.getTime() - attack.at.getTime() > win) continue;
        if (!attack.fresh && !change.fresh) continue;
        const success = successes.some((t) => t >= attack.at && t <= change.at);
        if (success) {
          push(x2.rule.code, [attack.code, change.code], {
            windowMinutes: x2.s.params.windowMinutes!,
          });
          break outer;
        }
      }
    }
  }

  // X3: a connector authentication anomaly then an attributed outbound signal within 2 h.
  const x3 = enabled('ato.correlation.connector_compromise');
  if (x3) {
    const win = x3.s.params.windowMinutes! * 60_000;
    outer3: for (const o of signals.filter((s) => OUTBOUND_CATEGORIES.includes(s.category))) {
      for (const a of signals.filter((s) => CONNECTOR_ANOMALY_CODES.has(s.code))) {
        if (a.at <= o.at && o.at.getTime() - a.at.getTime() <= win && (a.fresh || o.fresh)) {
          push(x3.rule.code, [a.code, o.code], { windowMinutes: x3.s.params.windowMinutes! });
          break outer3;
        }
      }
    }
  }

  // X4: moderate or strong signals in ≥ 3 categories within 24 h.
  const x4 = enabled('ato.correlation.multi_category');
  if (x4) {
    const since = input.now.getTime() - x4.s.params.windowHours! * 3_600_000;
    const recent = signals.filter((s) => moderateOrStrong(s) && s.at.getTime() >= since);
    const categories = [...new Set(recent.map((s) => s.category))].sort();
    if (categories.length >= x4.s.params.minCategories! && recent.some((s) => s.fresh)) {
      push(
        x4.rule.code,
        recent.map((s) => s.code),
        { count: categories.length, categories },
      );
    }
  }

  // X5: M1–M3 or Q1 within 24 h after an access, geography or threat-intel signal.
  const x5 = enabled('ato.correlation.config_change_after_login');
  if (x5) {
    const win = x5.s.params.windowHours! * 3_600_000;
    outer5: for (const c of signals.filter((s) => CONFIG_CODES.has(s.code))) {
      for (const a of signals.filter((s) => ACCESS_CATEGORIES.includes(s.category))) {
        if (a.at <= c.at && c.at.getTime() - a.at.getTime() <= win && (a.fresh || c.fresh)) {
          push(x5.rule.code, [a.code, c.code], {});
          break outer5;
        }
      }
    }
  }
  return out;
}

/** Rules of the catalogue that are correlation rules. */
export const CORRELATION_RULE_CODES: readonly string[] = ATO_RULES.filter((r) => r.correlation).map(
  (r) => r.code,
);
