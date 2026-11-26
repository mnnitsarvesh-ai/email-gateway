/**
 * Typed synthetic dataset of the simulators (design note D12). The shapes live next to the
 * simulators (`simulators/types.ts`, which may import only `node:*` and each other); this module
 * re-exports them for the testing entry and adds dataset helpers.
 */
import type { SimDataset } from './simulators/types';

export type {
  MicrosoftSimData,
  MsAuditBlob,
  MsDirectory,
  MsDirectoryAudit,
  MsExchangeRecord,
  MsGroup,
  MsMessageRule,
  MsOAuthGrant,
  MsRiskDetection,
  MsServicePrincipal,
  MsSignIn,
  MsSubscription,
  MsUser,
  SimDataset,
  SimMailbox,
  SimMailMessage,
  SimLicense,
} from './simulators/types';

/** A deep copy (the simulators mutate their dataset on writes). */
export function cloneDataset(dataset: SimDataset): SimDataset {
  return structuredClone(dataset);
}
