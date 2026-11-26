import { MAIL_FLOW_PROFILES } from './mail-flow';
import { registerPermissionProfiles } from './registry';

// Step 8.2 registers its two read-only mail-flow profiles at module load (D1).
registerPermissionProfiles(MAIL_FLOW_PROFILES);
// Step 8.5's six ATO profiles (D1, D6; docs/plan/steps/26-ato-provider-adapters.md D5).
export * from './ato';
// Step API-1's two mailbox-access profiles (docs/plan/steps/35-api-mode-protection.md D4).
export * from './mailbox';

export * from './types';
export * from './deny-list';
export * from './mail-flow';
export * from './registry';
