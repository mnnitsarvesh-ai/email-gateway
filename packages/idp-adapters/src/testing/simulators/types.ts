/**
 * Synthetic dataset types of the provider simulators (design note D12). Shapes follow the provider
 * JSON the adapters read (Graph v1.0, Office 365 Management Activity API). Synthetic data only:
 * documentation IP ranges (RFC 5737 / RFC 3849), `.example` domains, no real tenant or user.
 *
 * Simulator sources import only `node:*` modules and each other (import-guard test), so the
 * compiled `dist/testing/simulators` runs standalone in `node:22-alpine`.
 */
import type { GoogleSimData } from './google-types';

export interface MsGeo {
  city?: string | null;
  state?: string | null;
  countryOrRegion?: string | null;
  geoCoordinates?: { latitude?: number | null; longitude?: number | null } | null;
}

export interface MsUser {
  id: string;
  userPrincipalName: string;
  mail: string | null;
  displayName: string;
  accountEnabled: boolean;
  onPremisesSyncEnabled: boolean | null;
  proxyAddresses: string[];
  /** Holds a privileged directory role: password and enable/disable writes need a role (403). */
  privileged?: boolean;
  passwordProfile?: { forceChangePasswordNextSignIn: boolean };
}

export interface MsSignIn {
  id: string;
  createdDateTime: string;
  userId: string;
  userPrincipalName: string;
  appDisplayName?: string;
  ipAddress: string;
  clientAppUsed?: string;
  status: { errorCode: number; failureReason?: string | null };
  deviceDetail?: {
    deviceId?: string | null;
    displayName?: string | null;
    operatingSystem?: string | null;
    browser?: string | null;
  } | null;
  location?: MsGeo | null;
  riskLevelDuringSignIn?: string | null;
}

export interface MsRiskDetection {
  id: string;
  riskEventType: string;
  riskLevel: string;
  riskState: string;
  riskDetail?: string | null;
  detectedDateTime: string;
  lastUpdatedDateTime: string;
  activityDateTime?: string;
  userId: string;
  userPrincipalName: string;
  ipAddress?: string | null;
  location?: MsGeo | null;
}

export interface MsModifiedProperty {
  displayName: string;
  oldValue?: string | null;
  newValue?: string | null;
}

export interface MsDirectoryAudit {
  id: string;
  activityDateTime: string;
  activityDisplayName: string;
  category: string;
  result: string;
  initiatedBy: {
    user?: { id: string; userPrincipalName: string; ipAddress?: string | null } | null;
    app?: { appId?: string | null; displayName?: string | null } | null;
  };
  targetResources: {
    id: string;
    displayName?: string | null;
    type?: string | null;
    modifiedProperties?: MsModifiedProperty[];
  }[];
}

/** One Office 365 Management `Audit.Exchange` record (a subset of the common schema). */
export interface MsExchangeRecord {
  Id: string;
  CreationTime: string;
  Operation: string;
  Workload: string;
  RecordType?: number;
  UserId: string;
  ResultStatus?: string;
  ClientIP?: string;
  ClientIPAddress?: string;
  ObjectId?: string;
  MailboxOwnerUPN?: string;
  MailboxGuid?: string;
  /** 0 owner, 1 admin, 2 delegate. */
  LogonType?: number;
  ClientInfoString?: string;
  Parameters?: { Name: string; Value: string }[];
}

export interface MsAuditBlob {
  contentId: string;
  contentCreated: string;
  records: MsExchangeRecord[];
}

export interface MsRecipient {
  emailAddress: { address: string; name?: string };
}

export interface MsMessageRule {
  id: string;
  displayName: string;
  sequence: number;
  isEnabled: boolean;
  conditions?: {
    subjectContains?: string[];
    bodyContains?: string[];
    bodyOrSubjectContains?: string[];
    senderContains?: string[];
    fromAddresses?: MsRecipient[];
  } | null;
  actions?: {
    forwardTo?: MsRecipient[];
    redirectTo?: MsRecipient[];
    forwardAsAttachmentTo?: MsRecipient[];
    delete?: boolean;
    permanentDelete?: boolean;
    moveToFolder?: string | null;
    markAsRead?: boolean;
    stopProcessingRules?: boolean;
  } | null;
}

export interface MsMailFolder {
  id: string;
  displayName: string;
}

export interface MsGroup {
  id: string;
  displayName: string;
  members: string[];
}

export interface MsOAuthGrant {
  id: string;
  /** Object id of the client service principal. */
  clientId: string;
  consentType: string;
  principalId: string | null;
  resourceId: string;
  scope: string;
}

export interface MsServicePrincipal {
  id: string;
  appId: string;
  displayName: string;
  verifiedPublisher: { displayName: string | null; verifiedPublisherId: string | null };
}

/**
 * One message of a simulated mailbox (step API-1 D13): the Graph Inbox or the Gmail mailbox of a
 * user. Synthetic EMLs only, stored base64 (standard alphabet) so a dataset stays JSON.
 */
export interface SimMailMessage {
  /** Graph message id / Gmail message id. */
  id: string;
  /** Gmail thread id (Graph: unused). */
  threadId?: string;
  /** The `Message-ID` header value (with angle brackets), or null. */
  internetMessageId: string | null;
  emlBase64: string;
  /** Graph `receivedDateTime` / Gmail `internalDate` (ISO 8601). */
  receivedAt: string;
  isDraft?: boolean;
  /** Gmail labels (default `INBOX`, `UNREAD`). */
  labelIds?: string[];
  /** Graph delta sequence / Gmail history id of the change that added the message. */
  seq: number;
  /**
   * Sequence of the change that removed the message (under this id) from the mailbox: Graph
   * `@removed` in the Inbox delta when it was in the Inbox; the id then answers `404`.
   */
  removedSeq?: number;
  /** Step API-2: Graph folder id (absent = the Inbox). */
  folderId?: string;
  /** Step API-2: Graph categories. */
  categories?: string[];
  /** Step API-2: Graph move — the id the message got (the old id answers `404`). */
  movedToId?: string;
  /** Step API-2: permanently deleted (Graph `permanentDelete`, Gmail `messages.delete`). */
  deleted?: boolean;
}

/** Step API-2: a Graph mail folder of a simulated mailbox (well-known or created). */
export interface SimMailFolder {
  id: string;
  displayName: string;
  parentFolderId: string | null;
  /** Well-known name (`inbox`, `junkemail`, …), null for created folders. */
  wellKnownName: string | null;
  isHidden: boolean;
}

/** Step API-2: a Gmail user label of a simulated mailbox. */
export interface SimGmailLabel {
  id: string;
  name: string;
  labelListVisibility: 'labelShow' | 'labelShowIfUnread' | 'labelHide';
  messageListVisibility: 'show' | 'hide';
}

/** Change state of one simulated mailbox. */
export interface SimMailbox {
  /** Last change sequence (Graph delta state) / current Gmail history id. */
  seq: number;
  /**
   * Cursors (Graph delta/skip tokens, Gmail start history ids) below this sequence are expired:
   * Graph answers `410 syncStateNotFound`, Gmail `404`.
   */
  cursorFloor: number;
  messages: SimMailMessage[];
  /** Step API-2: Graph folders (well-known created on first use, plus created folders). */
  folders?: SimMailFolder[];
  /** Step API-2: Gmail user labels. */
  labels?: SimGmailLabel[];
  /** Step API-2: counter for created folder / label ids. */
  createdCount?: number;
}

/** A Graph change-notification subscription (step API-1 D13). */
export interface MsSubscription {
  id: string;
  /** `users/{id}/mailFolders('inbox')/messages` as given. */
  resource: string;
  /** The user object id the resource names. */
  userId: string;
  changeType: string;
  notificationUrl: string;
  lifecycleNotificationUrl: string | null;
  clientState: string | null;
  expirationDateTime: string;
  latestSupportedTlsVersion: string | null;
}

export interface MsDirectory {
  tenantId: string;
  domains: string[];
  licenses: { entraP1: boolean; entraP2: boolean; unifiedAudit: boolean };
  users: MsUser[];
  signIns: MsSignIn[];
  riskDetections: MsRiskDetection[];
  directoryAudits: MsDirectoryAudit[];
  exchange: { subscribed: boolean; blobs: MsAuditBlob[]; listingPageSize?: number };
  /** Inbox rules per user object id. */
  messageRules: Record<string, MsMessageRule[]>;
  /** Mail folders per user object id (destination names of move rules). */
  mailFolders?: Record<string, MsMailFolder[]>;
  groups: MsGroup[];
  oauth2PermissionGrants: MsOAuthGrant[];
  servicePrincipals: MsServicePrincipal[];
  /** Step API-1: Inbox state per user object id (created on first use). */
  mailboxes?: Record<string, SimMailbox>;
  /** Step API-1: change-notification subscriptions. */
  subscriptions?: MsSubscription[];
}

export interface MicrosoftSimData {
  directories: MsDirectory[];
}

/** The whole synthetic dataset (Google part: `google-types.ts`, WP2). */
export interface SimDataset {
  microsoft?: MicrosoftSimData;
  google?: GoogleSimData;
}

export type SimLicense = 'entraP1' | 'entraP2' | 'unifiedAudit';
