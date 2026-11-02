import type { DnsRecordPurpose, DnsRecordStatus, DomainStatus } from '@email-gateway/database';

/** Status groups of `DomainStatusView.checks` (§4). */
export type CheckGroup = 'ownership' | 'mx' | 'spf' | 'dkim' | 'dmarc';

const SEVERITY: Readonly<Record<DnsRecordStatus, number>> = {
  valid: 0,
  pending: 1,
  missing: 2,
  invalid: 3,
};

/**
 * Summary status of a group of records: the worst of its rows (`invalid` > `missing` >
 * `pending` > `valid`). A group without rows is `pending` (nothing has been checked).
 */
export function worstOf(statuses: Iterable<DnsRecordStatus>): DnsRecordStatus {
  let worst: DnsRecordStatus | null = null;
  for (const status of statuses) {
    if (worst === null || SEVERITY[status] > SEVERITY[worst]) worst = status;
  }
  return worst ?? 'pending';
}

/** The `checks` group a record belongs to, or null for purposes this step does not generate. */
export function groupOf(purpose: DnsRecordPurpose): CheckGroup | null {
  switch (purpose) {
    case 'verification':
      return 'ownership';
    case 'mx':
    case 'spf':
    case 'dkim':
    case 'dmarc':
      return purpose;
    default:
      return null;
  }
}

/** Activation needs ownership only (D3): the customer activates before switching MX. */
export function readyForActivation(status: DomainStatus): boolean {
  return status === 'verified';
}

/** Mail flows through the gateway: the domain is active and its MX points at the gateway. */
export function mailFlowReady(status: DomainStatus, mx: DnsRecordStatus): boolean {
  return status === 'active' && mx === 'valid';
}

/** Every record is `valid` (D11: decides between the incomplete and the healthy interval). */
export function allRecordsValid(statuses: readonly DnsRecordStatus[]): boolean {
  return statuses.length > 0 && statuses.every((status) => status === 'valid');
}
