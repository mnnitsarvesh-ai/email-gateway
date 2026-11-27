/**
 * Test-only entry `@email-gateway/idp-adapters/testing` (design note §5.1, D12): in-process
 * provider simulators, synthetic datasets, in-memory ports and wired Microsoft and Google
 * testbeds. Never imported by production code.
 */
export * from './dataset';
export * from './datasets/microsoft';
export * from './datasets/google';
export * from './datasets/mail';
export * from './harness';
export * from './google-harness';
export * from './in-memory-connections';
export * from './in-memory-stores';
export { GraphSimulator, createGraphSimulator } from './simulators/graph';
export { O365ManagementSimulator, createO365Simulator } from './simulators/o365';
export {
  GOOGLE_SIMULATORS,
  GOOGLE_SIM_SCOPES,
  GmailSimulator,
  GoogleSimulator,
  createGmailSimulator,
  createGoogleSimulator,
  googleErrorBody,
} from './simulators/google';
export type {
  GoogleSimData,
  GsActivity,
  GsActivityEvent,
  GsActivityParameter,
  GsAutoForwarding,
  GsCustomer,
  GsDelegate,
  GsFilter,
  GsGmailSettings,
  GsOrgUnit,
  GsToken,
  GsUser,
} from './simulators/google-types';
export {
  ALL_SIMULATORS,
  runStandalone,
  startSimulators,
  type RunningSimulators,
} from './simulators/main';
export {
  SimScript,
  type SimCall,
  type SimInjection,
  type SimNotification,
} from './simulators/script';
export {
  GRAPH_SUBSCRIPTION_MAX_MINUTES,
  LIFECYCLE_EVENTS,
  SimMailboxNotFoundError,
  deliverMessage,
  expireCursors,
  findMailboxOwner,
  isLocalCallbackTarget,
  messageLocation,
  pushLifecycle,
  removeMessage,
  GRAPH_WELL_KNOWN_FOLDERS as SIM_GRAPH_WELL_KNOWN_FOLDERS,
  type SimMessageLocation,
  type DeliverMessageInput,
  type DeliverMessageResult,
  type LifecycleEvent,
} from './simulators/mail';
export { GMAIL_MAIL_SCOPES } from './simulators/gmail-mail';
export { GRAPH_MAIL_READ_PERMISSIONS } from './simulators/graph-mail';
export { GRAPH_MAIL_WRITE_PERMISSIONS } from './simulators/graph-mail-write';
export { GMAIL_SYSTEM_LABEL_IDS } from './simulators/gmail-mail-write';
export {
  SimulatorServer,
  json,
  type Simulator,
  type SimulatorFactory,
  type SimRequest,
  type SimResponse,
} from './simulators/server';
export {
  ALL_PERMISSIONS,
  SimTokenRegistry,
  hasPermission,
  type ResolvedToken,
  type SimTokenInfo,
  type SimTokenResource,
} from './simulators/tokens';
