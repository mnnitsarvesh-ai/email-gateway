import { MAIL_FLOW_PROFILES } from './mail-flow';
import { registerPermissionProfiles } from './registry';

// Step 8.2 registers its two read-only mail-flow profiles at module load (D1).
registerPermissionProfiles(MAIL_FLOW_PROFILES);
// Step 8.5 adds its profiles with one import line here: `import './ato';` (D1, D6).

export * from './types';
export * from './deny-list';
export * from './mail-flow';
export * from './registry';
