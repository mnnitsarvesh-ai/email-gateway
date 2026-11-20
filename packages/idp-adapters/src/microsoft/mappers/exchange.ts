/**
 * Office 365 `Audit.Exchange` records → observations (design note §3.2). Only the allow-listed
 * operations (`EXCHANGE_AUDIT_OPERATIONS`) are kept; owner (non-admin, non-delegate) mailbox access
 * and every other operation are dropped (`dropped_operation`). The adapter resolves the mailbox
 * owner through Graph and turns observations into events and mailbox items.
 */
import { canonicalIp, isoUtc } from '../../core/normalize';
import type { RuleDefinition } from '../../core/traits';
import { EXCHANGE_AUDIT_OPERATIONS, type ExchangeAuditOperation } from '../constants';
import { exchangeRecordSchema, type ExchangeRecord } from '../schemas';
import { auditRuleDefinition, auditRuleName } from './rules';

interface Base {
  recordId: string;
  occurredAt: string;
  /** UPN, object id or name of the mailbox owner (resolved through Graph). */
  ownerKey: string;
  ip?: string;
}

export type ExchangeObservation =
  | (Base & { type: 'access'; clientType: string })
  | (Base & {
      type: 'inbox_rule';
      change: 'added' | 'changed';
      ruleName: string | null;
      definition: RuleDefinition;
      /** The record carries rule parameters (New-InboxRule / Set-InboxRule). */
      hasParameters: boolean;
    })
  | (Base & { type: 'forwarding'; target: string | null })
  | (Base & {
      type: 'permission';
      kind: 'mailbox_permission' | 'send_as' | 'delegate';
      grantee: string;
    })
  | { type: 'dropped' }
  | { type: 'invalid' };

const LOGON_ADMIN = 1;
const LOGON_DELEGATE = 2;

/** Client family of `ClientInfoString` (≤ 32). */
export function clientType(info: string | null | undefined): string {
  const text = (info ?? '').toLowerCase();
  if (text.includes('client=owa')) return 'owa';
  if (text.includes('activesync')) return 'activesync';
  if (text.includes('client=rest') || text.includes('rest')) return 'rest';
  if (text.includes('ews') || text.includes('webservices')) return 'ews';
  if (text.includes('imap')) return 'imap';
  if (text.includes('pop3')) return 'pop';
  if (text.includes('mapi') || text.includes('outlook')) return 'mapi';
  return text ? 'other' : 'unknown';
}

function param(record: ExchangeRecord, name: string): string | undefined {
  const found = record.Parameters?.find((p) => p.Name === name);
  return found ? (found.Value ?? '') : undefined;
}

function ownerKey(record: ExchangeRecord): string | null {
  const candidates = [
    record.MailboxOwnerUPN,
    param(record, 'Identity'),
    param(record, 'Mailbox'),
    record.ObjectId?.split('\\')[0],
  ];
  for (const candidate of candidates) {
    const value = candidate?.trim();
    if (value) return value.slice(0, 320);
  }
  return null;
}

function addressOf(value: string): string {
  const bracket = /\[(?:smtp|SMTP):([^\]]+)\]/.exec(value);
  if (bracket) return (bracket[1] as string).trim();
  return value.replace(/^smtp:/i, '').trim();
}

export function mapExchangeRecord(raw: unknown): ExchangeObservation {
  const parsed = exchangeRecordSchema.safeParse(raw);
  if (!parsed.success) return { type: 'invalid' };
  const record = parsed.data;
  if (!(EXCHANGE_AUDIT_OPERATIONS as readonly string[]).includes(record.Operation))
    return { type: 'dropped' };
  const operation = record.Operation as ExchangeAuditOperation;
  const occurredAt = isoUtc(record.CreationTime);
  const owner = ownerKey(record);
  if (!occurredAt || !owner) return { type: 'invalid' };
  const ip = canonicalIp(record.ClientIP ?? record.ClientIPAddress);
  const base: Base = { recordId: record.Id, occurredAt, ownerKey: owner, ...(ip ? { ip } : {}) };
  const parameters = record.Parameters ?? [];

  switch (operation) {
    case 'MailboxLogin':
    case 'MailItemsAccessed':
      if (record.LogonType !== LOGON_ADMIN && record.LogonType !== LOGON_DELEGATE)
        return { type: 'dropped' };
      return { ...base, type: 'access', clientType: clientType(record.ClientInfoString) };
    case 'New-InboxRule':
    case 'Set-InboxRule':
    case 'UpdateInboxRules':
      return {
        ...base,
        type: 'inbox_rule',
        change: operation === 'New-InboxRule' ? 'added' : 'changed',
        ruleName: auditRuleName(parameters),
        definition: auditRuleDefinition(parameters),
        hasParameters: parameters.length > 0,
      };
    case 'Set-Mailbox': {
      const smtp = param(record, 'ForwardingSmtpAddress');
      const address = param(record, 'ForwardingAddress');
      const sendOnBehalf = param(record, 'GrantSendOnBehalfTo');
      if (smtp !== undefined || address !== undefined) {
        const value = (smtp ?? address ?? '').trim();
        return { ...base, type: 'forwarding', target: value ? addressOf(value) : null };
      }
      if (sendOnBehalf) {
        return { ...base, type: 'permission', kind: 'delegate', grantee: addressOf(sendOnBehalf) };
      }
      return { type: 'dropped' };
    }
    case 'Add-MailboxPermission': {
      const rights = (param(record, 'AccessRights') ?? '').toLowerCase();
      const user = param(record, 'User');
      if (!rights.includes('fullaccess') || !user) return { type: 'dropped' };
      return { ...base, type: 'permission', kind: 'mailbox_permission', grantee: addressOf(user) };
    }
    case 'Add-RecipientPermission': {
      const rights = (param(record, 'AccessRights') ?? '').toLowerCase();
      const trustee = param(record, 'Trustee');
      if (!rights.includes('sendas') || !trustee) return { type: 'dropped' };
      return { ...base, type: 'permission', kind: 'send_as', grantee: addressOf(trustee) };
    }
  }
}
