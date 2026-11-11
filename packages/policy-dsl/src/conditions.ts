import { RISK_ACTIONS, RISK_LEVELS } from '@email-gateway/risk-scoring';
import type { RE2JS } from 're2js';
import {
  regexSpecOf,
  type DateRangeValue,
  type LeafNode,
  type PolicyNode,
  type TimeWindowValue,
} from './definition';
import {
  POLICY_FIELDS,
  type PolicyFieldDefinition,
  type PolicyFieldName,
  type PolicyFieldScope,
} from './fields';
import type { PolicyInput, RiskFacts } from './input';
import {
  cidrContains,
  compileRegex,
  domainIn,
  globMatch,
  normalizeAddress,
  normalizeDomain,
  parseCidr,
  parseIp,
  regexFind,
  type IpValue,
} from './matchers';
import { parseHhMm, withinDateRange, withinWindow } from './time';

/**
 * Three-valued (Kleene) condition evaluation (step 5.2 P3; ADR-0043 decision 2). A leaf on a
 * missing fact is unknown; `all`/`any`/`not` follow Kleene logic; quantifiers over empty or
 * truncated lists never turn into a definite true. Patterns are pre-compiled once per snapshot.
 */

/** Kleene truth values ordered false < unknown < true (and = min, or = max, not = 2 − x). */
export const FALSE = 0;
export const UNKNOWN = 1;
export const TRUE = 2;
export type Tri = 0 | 1 | 2;

export const triName = (t: Tri): 'false' | 'unknown' | 'true' =>
  t === TRUE ? 'true' : t === FALSE ? 'false' : 'unknown';

type FactValue = string | number | boolean | readonly string[] | IpValue | null | undefined;
type Test = (value: FactValue) => Tri;

export interface CompiledLeaf {
  kind: 'leaf';
  path: string;
  field: PolicyFieldName;
  op: LeafNode['op'];
  def: PolicyFieldDefinition;
  quantifier: 'any' | 'all';
  test: Test;
}

export type CompiledNode =
  | { kind: 'all' | 'any'; path: string; children: CompiledNode[] }
  | { kind: 'not'; path: string; child: CompiledNode }
  | CompiledLeaf;

const tri = (b: boolean): Tri => (b ? TRUE : FALSE);
const isMissing = (v: FactValue): v is null | undefined => v === null || v === undefined;

function normalizeScalar(def: PolicyFieldDefinition, v: unknown): string {
  const text = String(v);
  if (def.type === 'address') return normalizeAddress(text).address;
  if (def.type === 'domain') return normalizeDomain(text) ?? text.toLowerCase();
  if (def.type === 'enum' || def.type === 'id') return text;
  return text.normalize('NFC').toLowerCase();
}

function rankOf(def: PolicyFieldDefinition, v: unknown): number {
  return typeof v === 'string' && def.values ? def.values.indexOf(v) : -1;
}

/** Builds the test of one leaf (the value was validated by `validatePolicyDefinition`). */
export function compileLeafTest(def: PolicyFieldDefinition, leaf: LeafNode): Test {
  const value = leaf.value;
  switch (leaf.op) {
    case 'exists':
      return (v) => tri(!isMissing(v) && !(Array.isArray(v) && v.length === 0));
    case 'is':
      return (v) => (isMissing(v) ? UNKNOWN : tri(v === value));
    case 'equals': {
      if (def.type === 'ip') {
        const ip = parseIp(String(value))!;
        return (v) => {
          if (isMissing(v)) return UNKNOWN;
          const x = v as IpValue;
          return tri(x.family === ip.family && x.value === ip.value);
        };
      }
      const expected = normalizeScalar(def, value);
      return (v) => (isMissing(v) ? UNKNOWN : tri(v === expected));
    }
    case 'in':
    case 'not_in': {
      const negate = leaf.op === 'not_in';
      const set = new Set((value as unknown[]).map((x) => normalizeScalar(def, x)));
      if (def.type === 'id') {
        return (v) => {
          if (isMissing(v)) return UNKNOWN;
          const hit = (v as readonly string[]).some((id) => set.has(id));
          return tri(negate ? !hit : hit);
        };
      }
      return (v) => {
        if (isMissing(v)) return UNKNOWN;
        const hit = set.has(v as string);
        return tri(negate ? !hit : hit);
      };
    }
    case 'domain_in': {
      const suffixes = (value as string[]).map((d) => normalizeDomain(d)!);
      return (v) => (isMissing(v) ? UNKNOWN : tri(suffixes.some((s) => domainIn(v as string, s))));
    }
    case 'glob': {
      const patterns = (value as string[]).map((p) => p.normalize('NFC').toLowerCase());
      return (v) => {
        if (isMissing(v)) return UNKNOWN;
        const subject = (v as string).toLowerCase();
        return tri(patterns.some((p) => globMatch(p, subject)));
      };
    }
    case 'regex': {
      const res: RE2JS[] = (value as unknown[]).map((item) => {
        const compiled = compileRegex(regexSpecOf(item)!);
        if (!compiled.ok) throw new Error('regex was validated');
        return compiled.re;
      });
      return (v) => (isMissing(v) ? UNKNOWN : tri(res.some((re) => regexFind(re, v as string))));
    }
    case 'in_cidr': {
      const cidrs = (value as string[]).map((c) => parseCidr(c)!);
      return (v) =>
        isMissing(v) ? UNKNOWN : tri(cidrs.some((c) => cidrContains(c, v as IpValue)));
    }
    case 'eq':
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      const ordered = def.type === 'enum';
      const bound = ordered ? rankOf(def, value) : (value as number);
      const cmp = (x: number): boolean => {
        switch (leaf.op) {
          case 'eq':
            return x === bound;
          case 'gt':
            return x > bound;
          case 'gte':
            return x >= bound;
          case 'lt':
            return x < bound;
          default:
            return x <= bound;
        }
      };
      return (v) => {
        if (isMissing(v)) return UNKNOWN;
        return tri(cmp(ordered ? rankOf(def, v) : (v as number)));
      };
    }
    case 'between': {
      const [lo, hi] = value as [number, number];
      return (v) => (isMissing(v) ? UNKNOWN : tri((v as number) >= lo && (v as number) <= hi));
    }
    case 'contains_any':
    case 'contains_all': {
      const codes = value as string[];
      const all = leaf.op === 'contains_all';
      return (v) => {
        if (isMissing(v)) return UNKNOWN;
        const set = new Set(v as readonly string[]);
        return tri(all ? codes.every((c) => set.has(c)) : codes.some((c) => set.has(c)));
      };
    }
    case 'within': {
      if (leaf.field === 'time.window') {
        const w = value as TimeWindowValue;
        const window = {
          timeZone: w.timeZone,
          days: w.days,
          from: parseHhMm(w.from)!,
          to: parseHhMm(w.to, true)!,
        };
        return (v) => (isMissing(v) ? UNKNOWN : tri(withinWindow(v as number, window)));
      }
      const r = value as DateRangeValue;
      return (v) => (isMissing(v) ? UNKNOWN : tri(withinDateRange(v as number, r)));
    }
    default:
      return () => UNKNOWN;
  }
}

/** Compiles a validated node tree; `path` is the JSON path of the node in the definition. */
export function compileNode(node: PolicyNode, path: string): CompiledNode {
  if ('all' in node) {
    return {
      kind: 'all',
      path,
      children: node.all.map((c, i) => compileNode(c, `${path}.all[${i}]`)),
    };
  }
  if ('any' in node) {
    return {
      kind: 'any',
      path,
      children: node.any.map((c, i) => compileNode(c, `${path}.any[${i}]`)),
    };
  }
  if ('not' in node) return { kind: 'not', path, child: compileNode(node.not, `${path}.not`) };
  const def = POLICY_FIELDS[node.field];
  return {
    kind: 'leaf',
    path,
    field: node.field,
    op: node.op,
    def,
    quantifier: node.quantifier ?? 'any',
    test: compileLeafTest(def, node),
  };
}

export function* leavesOf(node: CompiledNode): Generator<CompiledLeaf> {
  if (node.kind === 'leaf') yield node;
  else if (node.kind === 'not') yield* leavesOf(node.child);
  else for (const c of node.children) yield* leavesOf(c);
}

// ---------------------------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------------------------

type ElementFacts = Readonly<Record<string, FactValue>>;

export interface Facts {
  message: Readonly<Record<string, FactValue>>;
  lists: Readonly<
    Record<Exclude<PolicyFieldScope, 'message'>, { items: ElementFacts[]; truncated: boolean }>
  >;
}

const maxBy = <T extends string>(values: readonly T[], order: readonly T[]): T | null => {
  let best: T | null = null;
  for (const v of values) if (best === null || order.indexOf(v) > order.indexOf(best)) best = v;
  return best;
};

/** The revision whose verdict decides (P10): revision 1 when its level is strictly higher. */
export function decisiveRevision(input: PolicyInput): RiskFacts | null {
  const { rev0, rev1 } = input.risk;
  if (rev0 === null) return rev1;
  if (rev1 === null) return rev0;
  return RISK_LEVELS.indexOf(rev1.level) > RISK_LEVELS.indexOf(rev0.level) ? rev1 : rev0;
}

export function presentRevisions(input: PolicyInput): Array<{ revision: 0 | 1; facts: RiskFacts }> {
  const out: Array<{ revision: 0 | 1; facts: RiskFacts }> = [];
  if (input.risk.rev0) out.push({ revision: 0, facts: input.risk.rev0 });
  if (input.risk.rev1) out.push({ revision: 1, facts: input.risk.rev1 });
  return out;
}

/** Facts of one input, keyed by field name (P3 semantics). */
export function buildFacts(input: PolicyInput): Facts {
  const env = input.sender.envelope;
  const hf = input.sender.headerFrom;
  const au = input.sender.authenticated;
  const revs = presentRevisions(input).map((r) => r.facts);
  const decisive = decisiveRevision(input);
  const directoryKnown = input.direction !== 'inbound' && au !== null;
  const notScanned = input.scan.outcome === 'not_scanned';
  const union = (lists: Array<readonly string[]>) => [...new Set(lists.flat())].sort();
  const message: Record<string, FactValue> = {
    direction: input.direction,
    'sender.envelope.address': env?.address,
    'sender.envelope.domain': env?.domain,
    'sender.envelope.local_part': env?.localPart,
    'sender.header_from.address': hf?.address,
    'sender.header_from.domain': hf?.domain,
    'sender.authenticated.address': au?.address,
    'sender.authenticated.domain': au?.domain,
    'sender.trusted': input.sender.trusted,
    'sender.department': directoryKnown ? input.sender.departments : null,
    'sender.user': directoryKnown ? input.sender.users : null,
    'recipients.count': input.message.recipientCount,
    'client.ip': input.client.ip === null ? null : parseIp(input.client.ip),
    'client.hostname': input.client.hostname,
    'auth.spf': input.auth?.spf,
    'auth.dkim': input.auth?.dkim,
    'auth.dmarc': input.auth?.dmarc,
    'auth.arc': input.auth?.arc,
    'auth.dmarc_policy': input.auth?.dmarcPolicy,
    'message.size_bytes': input.message.sizeBytes,
    'attachments.count': input.attachments.count,
    'attachments.total_bytes': input.attachments.totalBytes,
    'attachments.truncated': input.attachments.truncated,
    'urls.count': input.urls.count,
    'urls.truncated': input.urls.truncated,
    'urls.rewrite_status': input.urls.rewriteStatus,
    'risk.present': input.risk.rev0 !== null,
    'risk.score': revs.length ? Math.max(...revs.map((r) => r.score)) : null,
    'risk.level': maxBy(
      revs.map((r) => r.level),
      RISK_LEVELS,
    ),
    'risk.verdict': decisive?.verdict,
    'risk.recommended_action': maxBy(
      revs.map((r) => r.recommendedAction),
      RISK_ACTIONS,
    ),
    'risk.hard_blocks': revs.length ? union(revs.map((r) => r.hardBlocks.map((h) => h.id))) : null,
    'risk.reason_codes': revs.length ? union(revs.map((r) => r.reasonCodes)) : null,
    'risk.status': revs.length
      ? revs.some((r) => r.status === 'error')
        ? 'error'
        : 'scored'
      : null,
    'risk.sandbox_outcome': input.risk.rev1?.sandboxOutcome,
    'dlp.present': input.dlp !== null,
    'dlp.action': input.dlp?.action,
    'dlp.verdict': input.dlp?.verdict,
    'dlp.coverage': input.dlp?.coverage,
    'dlp.max_severity': input.dlp?.maxSeverity,
    'dlp.categories': input.dlp?.categories,
    'dlp.detector_codes': input.dlp?.detectorCodes,
    'bec.deterministic_verdict': input.bec?.deterministicVerdict,
    'bec.rule_codes': input.bec?.ruleCodes,
    'bec.verdict': input.bec?.verdict,
    'bec.ai_raised': input.bec?.aiRaised,
    'scan.outcome': input.scan.outcome,
    'scan.verdict': input.scan.verdict,
    'scan.reason_codes': notScanned ? null : input.scan.reasonCodes,
    'scan.failed_engines': notScanned
      ? null
      : input.scan.engines
          .filter((e) => ['timeout', 'error', 'missing'].includes(e.outcome))
          .map((e) => e.engine),
    'scan.unknown_engines': notScanned
      ? null
      : input.scan.engines.filter((e) => e.outcome === 'unknown').map((e) => e.engine),
    'time.window': Date.parse(input.evaluationTime),
    'time.date_range': Date.parse(input.evaluationTime),
  };
  return {
    message,
    lists: {
      recipients: {
        truncated: input.recipientsTruncated,
        items: input.recipients.map((r) => ({
          'recipient.address': r.address,
          'recipient.domain': r.domain,
          'recipient.local_part': r.localPart,
          'recipient.department': r.departments,
          'recipient.user': r.users,
        })),
      },
      attachments: {
        truncated: input.attachments.truncated,
        items: input.attachments.items.map((a) => ({
          'attachment.extension': a.extension,
          'attachment.filename': a.filename,
          'attachment.declared_type': a.declaredType?.toLowerCase(),
          'attachment.detected_type': a.detectedType?.toLowerCase(),
          'attachment.type_family': a.typeFamily,
          'attachment.size_bytes': a.sizeBytes,
          'attachment.sha256': a.sha256,
          'attachment.verdict': a.verdict,
          'attachment.reason_codes': a.reasonCodes,
          'attachment.is_archive': a.isArchive,
          'attachment.encrypted': a.encrypted,
          'attachment.type_mismatch': a.typeMismatch,
        })),
      },
      urls: {
        truncated: input.urls.truncated,
        items: input.urls.items.map((u) => ({
          'url.host': u.host,
          'url.domain': u.domain,
          'url.scheme': u.scheme,
          'url.host_kind': u.hostKind,
          'url.verdict': u.verdict,
          'url.reason_codes': u.reasonCodes,
        })),
      },
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------------------------

export interface NodeResult {
  value: Tri;
  /** The leaf that decided the value (first decisive leaf). */
  leaf: CompiledLeaf;
}

/** Quantifier semantics over a list (P3). */
export function quantify(
  results: readonly Tri[],
  quantifier: 'any' | 'all',
  truncated: boolean,
): Tri {
  if (quantifier === 'any') {
    if (results.includes(TRUE)) return TRUE;
    if (truncated || results.includes(UNKNOWN)) return UNKNOWN;
    return FALSE;
  }
  if (results.length === 0) return truncated ? UNKNOWN : FALSE;
  if (results.includes(FALSE)) return FALSE;
  if (truncated || results.includes(UNKNOWN)) return UNKNOWN;
  return TRUE;
}

export function evalLeaf(leaf: CompiledLeaf, facts: Facts): Tri {
  if (leaf.def.scope === 'message') return leaf.test(facts.message[leaf.field]);
  const list = facts.lists[leaf.def.scope];
  return quantify(
    list.items.map((item) => leaf.test(item[leaf.field])),
    leaf.quantifier,
    list.truncated,
  );
}

/**
 * Kleene evaluation with the decisive leaf: `all` → the first false child (else the first
 * unknown, else the last); `any` → the first true child (else the first unknown, else the last);
 * `not` → its child's leaf.
 */
export function evalNode(node: CompiledNode, facts: Facts): NodeResult {
  if (node.kind === 'leaf') return { value: evalLeaf(node, facts), leaf: node };
  if (node.kind === 'not') {
    const r = evalNode(node.child, facts);
    return { value: (2 - r.value) as Tri, leaf: r.leaf };
  }
  const isAll = node.kind === 'all';
  const stopAt: Tri = isAll ? FALSE : TRUE;
  let firstUnknown: NodeResult | null = null;
  let last: NodeResult | null = null;
  for (const child of node.children) {
    const r = evalNode(child, facts);
    if (r.value === stopAt) return r;
    if (r.value === UNKNOWN && firstUnknown === null) firstUnknown = r;
    last = r;
  }
  if (firstUnknown) return firstUnknown;
  return last!;
}
