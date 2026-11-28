import type { Prisma } from '@email-gateway/database';
import {
  type AtoPolicyFactsRow,
  buildPolicyInput,
  type CompiledSnapshot,
  type PolicyInput,
  referencedDirectoryIds,
} from '@email-gateway/policy-dsl';
import {
  type DirectoryMaps,
  type DirectoryRepository,
  EMPTY_DIRECTORY,
} from './directory.repository';
import type { RoundFacts } from './facts.repository';

/**
 * Reads the ATO facts of an authenticated outbound/internal sender (step 8.4 D23); null = none.
 * The policy-engine passes `AtoFactsRepository` (inside the evaluation transaction).
 */
export interface AtoFactsSource {
  read(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    senderAddress: string,
  ): Promise<AtoPolicyFactsRow | null>;
  notApplicable(): void;
}

/**
 * `buildPolicyInput` with the directory of the snapshot's references (P5): a first pass without
 * directory yields the normalized addresses (envelope recipients and the authenticated sender),
 * then only the referenced departments and users are resolved for them. Throws
 * `PolicyInputError` for malformed rows (the caller decides what that means).
 *
 * Step 8.4 D23: with an `ato` source, an outbound or internal round with an authenticated sender
 * also gets the sender's ATO facts (whether or not a policy references `ato.*`, so a stored
 * evaluation always shows what ATO said); inbound rounds and rounds without an authenticated
 * sender never read them.
 */
export async function buildInputWithDirectory(
  tx: Prisma.TransactionClient,
  directory: Pick<DirectoryRepository, 'resolve'>,
  organizationId: bigint,
  facts: RoundFacts,
  compiled: CompiledSnapshot,
  guard: <T>(fn: () => T) => T = (fn) => fn(),
  ato?: AtoFactsSource,
): Promise<PolicyInput> {
  let input: PolicyInput = guard(() => buildPolicyInput({ ...facts, directory: EMPTY_DIRECTORY }));
  let rows: RoundFacts = facts;
  if (ato !== undefined) {
    const sender = input.sender.authenticated?.address ?? null;
    if (input.direction === 'inbound' || sender === null) {
      ato.notApplicable();
    } else {
      const found = await ato.read(tx, organizationId, sender);
      if (found !== null) {
        rows = { ...facts, ato: found };
        input = guard(() => buildPolicyInput({ ...rows, directory: EMPTY_DIRECTORY }));
      }
    }
  }
  const references = referencedDirectoryIds(compiled);
  if (references.departmentIds.length > 0 || references.userIds.length > 0) {
    const addresses = input.recipients.map((r) => r.address);
    if (input.sender.authenticated !== null) addresses.push(input.sender.authenticated.address);
    const maps: DirectoryMaps = await directory.resolve(tx, organizationId, references, addresses);
    input = guard(() => buildPolicyInput({ ...rows, directory: maps }));
  }
  return input;
}
