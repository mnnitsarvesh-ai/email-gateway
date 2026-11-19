import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { isPlainObject } from './model';

/**
 * Synthetic facts of `POST /policies/test` (design B7) and the server's answer. The portal only
 * builds the request; the evaluation happens on the server.
 */
export type SyntheticFacts = NonNullable<RequestBody<'PolicyToolsController_test_v1'>['facts']>;
export type PolicyTestResponse = SuccessBody<'PolicyToolsController_test_v1'>;

type Obj = Record<string, unknown>;
export type FactPath = ReadonlyArray<string | number>;

const isEmpty = (value: unknown): boolean =>
  isPlainObject(value) && Object.keys(value).length === 0;

/**
 * Sets (or with `undefined` removes) the value at `path`; objects left empty are removed (list
 * items stay), so the facts hold only the keys the user set.
 */
export function setFact(facts: SyntheticFacts, path: FactPath, value: unknown): SyntheticFacts {
  return setIn(facts, path, value) as SyntheticFacts;
}

function setIn(container: Obj | unknown[], path: FactPath, value: unknown): Obj | unknown[] {
  const [head, ...rest] = path;
  if (head === undefined) return container;
  const current: unknown = Array.isArray(container)
    ? container[Number(head)]
    : container[String(head)];
  let next: unknown = value;
  if (rest.length > 0) {
    const child: Obj | unknown[] =
      Array.isArray(current) || isPlainObject(current)
        ? current
        : typeof rest[0] === 'number'
          ? []
          : {};
    next = setIn(child, rest, value);
    // An emptied object is removed, except a list item (an attachment with only defaults stays).
    if (isEmpty(next) && !Array.isArray(container)) next = undefined;
  }
  if (Array.isArray(container)) {
    const copy = [...container];
    if (next === undefined) copy.splice(Number(head), 1);
    else copy[Number(head)] = next;
    return copy;
  }
  const copy: Obj = { ...container };
  if (next === undefined) delete copy[String(head)];
  else copy[String(head)] = next;
  return copy;
}

export function getFact(facts: SyntheticFacts, path: FactPath): unknown {
  let node: unknown = facts;
  for (const segment of path) {
    if (Array.isArray(node) && typeof segment === 'number') node = node[segment];
    else if (isPlainObject(node) && typeof segment === 'string') node = node[segment];
    else return undefined;
  }
  return node;
}

/**
 * The facts' `trigger` for a catalogue `scan.outcome` value: the DSL names a parse failure
 * `not_scanned` (the field) and `parse_failed` (the evaluation trigger); the others are equal.
 */
export const triggerOfOutcome = (outcome: string): string =>
  outcome === 'not_scanned' ? 'parse_failed' : outcome;
export const outcomeOfTrigger = (trigger: string): string =>
  trigger === 'parse_failed' ? 'not_scanned' : trigger;

/**
 * Id of the "Outbound from a high-risk account" example; equal to the ATO library's
 * `ATO_POLICY_PRESET`, which recommendations carry as `preset` (step 8.4 D13, D23).
 */
export const ATO_HIGH_RISK_PRESET_ID = 'outbound_high_risk_account';

/** The example with this id (`null` for an unknown id). */
export function factPresetById(id: string | null | undefined) {
  return FACT_PRESETS.find((preset) => preset.id === id) ?? null;
}

/**
 * Example facts for the test panel (design B7): data only; what a policy decides for them is
 * the server's answer. Domains are reserved example names.
 */
export const FACT_PRESETS: ReadonlyArray<{
  id: string;
  label: string;
  description: string;
  facts: SyntheticFacts;
}> = [
  {
    id: 'clean-inbound',
    label: 'Clean inbound message',
    description: 'An inbound message from a partner that authenticates, with a clean scan.',
    facts: {
      direction: 'inbound',
      sender: { envelope: 'billing@partner.example', headerFrom: 'billing@partner.example' },
      recipients: [{ address: 'ap@corp.example' }],
      auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject' },
      risk: { rev0: { score: 40, level: 'none', verdict: 'clean', recommendedAction: 'deliver' } },
      scan: { verdict: 'clean' },
    },
  },
  {
    id: 'outbound-confidential',
    label: 'Outbound confidential data',
    description:
      'An outbound message to an external recipient in which DLP found confidential data.',
    facts: {
      direction: 'outbound',
      sender: { envelope: 'analyst@corp.example', authenticated: true },
      recipients: [{ address: 'contact@customer.example' }],
      dlp: {
        action: 'alert',
        verdict: 'suspicious',
        categories: ['confidential'],
        maxSeverity: 'high',
      },
      scan: { verdict: 'clean' },
    },
  },
  {
    id: 'phishing-url',
    label: 'Phishing link',
    description: 'An inbound message that fails DMARC with a link the URL engine rated malicious.',
    facts: {
      direction: 'inbound',
      sender: { envelope: 'security@account-verify.example' },
      recipients: [{ address: 'user@corp.example' }],
      auth: { spf: 'fail', dkim: 'none', dmarc: 'fail', dmarcPolicy: 'none' },
      urls: [
        {
          host: 'login.account-verify.example',
          scheme: 'https',
          verdict: 'malicious',
          reasonCodes: ['url.dnsbl_phishing'],
        },
      ],
      risk: {
        rev0: {
          score: 900,
          level: 'critical',
          verdict: 'phishing',
          recommendedAction: 'quarantine',
          hardBlocks: [{ id: 'hb.known_phishing', action: 'quarantine' }],
        },
      },
      scan: { verdict: 'malicious' },
    },
  },
  {
    id: 'malware-attachment',
    label: 'Malware attachment',
    description: 'An inbound message whose attachment the antivirus engine matched as malware.',
    facts: {
      direction: 'inbound',
      sender: { envelope: 'accounts@supplier.example' },
      recipients: [{ address: 'ap@corp.example' }],
      attachments: [
        {
          filename: 'invoice-2026-11.pdf.exe',
          typeFamily: 'executable',
          verdict: 'malicious',
          sizeBytes: 482304,
          reasonCodes: ['attachment.clamav_match'],
        },
      ],
      risk: {
        rev0: {
          score: 950,
          level: 'critical',
          verdict: 'malware',
          recommendedAction: 'block',
          hardBlocks: [{ id: 'hb.malware_attachment', action: 'block' }],
        },
      },
      scan: { verdict: 'malicious' },
    },
  },
  {
    id: 'executable-attachment',
    label: 'Executable attachment',
    description: 'An inbound message with an executable attachment that no engine flagged.',
    facts: {
      direction: 'inbound',
      sender: { envelope: 'it-support@vendor.example' },
      recipients: [{ address: 'user@corp.example' }],
      attachments: [
        { filename: 'setup.exe', typeFamily: 'executable', verdict: 'clean', sizeBytes: 1048576 },
      ],
      risk: { rev0: { score: 120, level: 'low', verdict: 'clean', recommendedAction: 'deliver' } },
      scan: { verdict: 'clean' },
    },
  },
  {
    // Step 8.4 D23: linked by the ATO recommendation ("hold outbound mail of high-risk
    // accounts") and the ATO settings' delivery-policy tab (`?testPreset=` on /policies/new).
    id: ATO_HIGH_RISK_PRESET_ID,
    label: 'Outbound from a high-risk account',
    description:
      'An outbound message sent by a mailbox whose account takeover risk is high (no active incident).',
    facts: {
      direction: 'outbound',
      sender: { envelope: 'finance@corp.example', authenticated: true },
      recipients: [{ address: 'payments@supplier.example' }],
      ato: { riskScore: 65, riskLevel: 'high' },
      scan: { verdict: 'clean' },
    },
  },
];
