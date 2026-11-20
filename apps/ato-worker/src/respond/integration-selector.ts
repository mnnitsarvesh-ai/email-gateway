import type {
  AtoAccount,
  AtoProviderIntegration,
  AtoResponseAction,
  PrismaClient,
} from '@email-gateway/database';
import { domainOf } from '@email-gateway/idp-adapters';
import { directoryDomainsOf } from '../provider/idp-runtime';
import { IDP_KINDS } from '../provider/provider-context';
import { InconsistentReadError } from '../shared/errors';

/** Why no provider action can run (D9.2, inv. 4); codes go to `result_code`. */
export type SelectionRefusal =
  | { outcome: 'unsupported'; code: 'not_a_mailbox_account' | 'no_integration' }
  | {
      outcome: 'failed';
      code:
        | 'ambiguous_integration'
        | 'integration_disabled'
        | 'integration_paused'
        | 'domain_not_linked';
    };

export type IntegrationSelection =
  | { ok: true; integration: AtoProviderIntegration; domain: string }
  | ({ ok: false } & SelectionRefusal);

const LIVE = ['active', 'error', 'paused'] as const;

/**
 * Integration selection of a provider action (step 8.5 D9.2, ADR-0085), outside any transaction:
 *
 * 1. only `mailbox` accounts receive provider actions (`gateway_user`, `smtp_connector` ⇒
 *    `unsupported` `not_a_mailbox_account`);
 * 2. an action that already ran on an integration (`integration_id`: retries, confirmations,
 *    rollbacks) stays on it;
 * 3. candidates = the non-disabled integrations of the account's `ato_account_identities` rows,
 *    else the organization's non-disabled integrations whose provider-verified linked domains
 *    (`directory_domains`, written by the probe from 8.2's verified domains) contain the address
 *    domain; none ⇒ `unsupported` `no_integration` (`failed` `integration_disabled` when only a
 *    disabled integration matches); several ⇒ `failed` `ambiguous_integration` (never retried);
 * 4. the chosen integration must not be disabled (`integration_disabled`) or paused
 *    (`integration_paused`), and the linked-domain guard (inv. 4) must pass: the address domain is
 *    one of its provider-verified linked domains (`domain_not_linked`).
 *
 * Every read is scoped by the action's organization and echo-checked.
 */
export async function selectIntegration(
  prisma: PrismaClient,
  action: Pick<AtoResponseAction, 'organizationId' | 'accountId' | 'integrationId'>,
  account: Pick<AtoAccount, 'organizationId' | 'kind' | 'address'>,
): Promise<IntegrationSelection> {
  const organizationId = action.organizationId;
  if (account.organizationId !== organizationId) throw new InconsistentReadError('ato_account');
  if (account.kind !== 'mailbox' || !account.address) {
    return { ok: false, outcome: 'unsupported', code: 'not_a_mailbox_account' };
  }
  const domain = domainOf(account.address);
  if (domain === null) return { ok: false, outcome: 'unsupported', code: 'not_a_mailbox_account' };

  const echo = (rows: AtoProviderIntegration[]) => {
    for (const r of rows) {
      if (r.organizationId !== organizationId) {
        throw new InconsistentReadError('ato_provider_integrations');
      }
    }
    return rows.filter((r) => IDP_KINDS.has(r.provider));
  };

  let chosen: AtoProviderIntegration | null = null;
  if (action.integrationId !== null) {
    const [row] = echo(
      await prisma.atoProviderIntegration.findMany({
        where: { id: action.integrationId, organizationId },
      }),
    );
    if (!row) return { ok: false, outcome: 'failed', code: 'integration_disabled' };
    chosen = row;
  } else {
    const identities = await prisma.atoAccountIdentity.findMany({
      where: { organizationId, accountId: action.accountId, integrationId: { not: null } },
      select: { organizationId: true, integrationId: true },
      take: 20,
    });
    if (identities.some((i) => i.organizationId !== organizationId)) {
      throw new InconsistentReadError('ato_account_identities');
    }
    const ids = [...new Set(identities.map((i) => i.integrationId!))];
    const mapped =
      ids.length > 0
        ? echo(
            await prisma.atoProviderIntegration.findMany({
              where: { id: { in: ids }, organizationId },
            }),
          )
        : [];
    let candidates = mapped.filter((r) => (LIVE as readonly string[]).includes(r.status));
    let disabledMatch = mapped.some((r) => r.status === 'disabled');
    if (candidates.length === 0) {
      const all = echo(
        await prisma.atoProviderIntegration.findMany({
          where: { organizationId },
          orderBy: { id: 'asc' },
          take: 100,
        }),
      );
      const byDomain = all.filter((r) => directoryDomainsOf(r.directoryDomains).includes(domain));
      candidates = byDomain.filter((r) => (LIVE as readonly string[]).includes(r.status));
      disabledMatch = disabledMatch || byDomain.some((r) => r.status === 'disabled');
    }
    if (candidates.length === 0) {
      return disabledMatch
        ? { ok: false, outcome: 'failed', code: 'integration_disabled' }
        : { ok: false, outcome: 'unsupported', code: 'no_integration' };
    }
    if (candidates.length > 1)
      return { ok: false, outcome: 'failed', code: 'ambiguous_integration' };
    chosen = candidates[0]!;
  }
  if (chosen.status === 'disabled')
    return { ok: false, outcome: 'failed', code: 'integration_disabled' };
  if (chosen.status === 'paused')
    return { ok: false, outcome: 'failed', code: 'integration_paused' };
  // Linked-domain guard (inv. 4): TXT-verified at the gateway and verified in the provider tenant.
  if (!directoryDomainsOf(chosen.directoryDomains).includes(domain)) {
    return { ok: false, outcome: 'failed', code: 'domain_not_linked' };
  }
  return { ok: true, integration: chosen, domain };
}
