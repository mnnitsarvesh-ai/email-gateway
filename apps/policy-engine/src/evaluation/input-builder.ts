import type { Prisma } from '@email-gateway/database';
import {
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
 * `buildPolicyInput` with the directory of the snapshot's references (P5): a first pass without
 * directory yields the normalized addresses (envelope recipients and the authenticated sender),
 * then only the referenced departments and users are resolved for them. Throws
 * `PolicyInputError` for malformed rows (the caller decides what that means).
 */
export async function buildInputWithDirectory(
  tx: Prisma.TransactionClient,
  directory: Pick<DirectoryRepository, 'resolve'>,
  organizationId: bigint,
  facts: RoundFacts,
  compiled: CompiledSnapshot,
  guard: <T>(fn: () => T) => T = (fn) => fn(),
): Promise<PolicyInput> {
  let input: PolicyInput = guard(() => buildPolicyInput({ ...facts, directory: EMPTY_DIRECTORY }));
  const references = referencedDirectoryIds(compiled);
  if (references.departmentIds.length > 0 || references.userIds.length > 0) {
    const addresses = input.recipients.map((r) => r.address);
    if (input.sender.authenticated !== null) addresses.push(input.sender.authenticated.address);
    const maps: DirectoryMaps = await directory.resolve(tx, organizationId, references, addresses);
    input = guard(() => buildPolicyInput({ ...facts, directory: maps }));
  }
  return input;
}
