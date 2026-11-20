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
