/**
 * Response schemas of the Microsoft endpoints (design note D2): every field the adapter reads is
 * typed and bounded; `looseObject` only where the provider adds fields. Collections are validated
 * as a page of unknown records; each record is validated by its mapper (malformed records are
 * dropped and counted `invalid`, never a page failure).
 */
import { z } from 'zod';

const str = (max: number) => z.string().max(max);

export const graphPageSchema = z.looseObject({
  value: z.array(z.unknown()).max(1000),
  '@odata.nextLink': str(4096).optional(),
});
export type GraphPage = z.infer<typeof graphPageSchema>;

const geoSchema = z
  .looseObject({
    city: str(256).nullish(),
    countryOrRegion: str(64).nullish(),
    geoCoordinates: z
      .looseObject({ latitude: z.number().nullish(), longitude: z.number().nullish() })
      .nullish(),
  })
  .nullish();

export const signInSchema = z.looseObject({
  id: str(128).min(1),
  createdDateTime: z.iso.datetime({ offset: true }),
  userId: str(128).min(1),
  userPrincipalName: str(256).nullish(),
  ipAddress: str(64).nullish(),
  status: z.looseObject({ errorCode: z.number().int() }),
  deviceDetail: z
    .looseObject({
      deviceId: str(256).nullish(),
      operatingSystem: str(128).nullish(),
      browser: str(128).nullish(),
    })
    .nullish(),
  location: geoSchema,
  riskLevelDuringSignIn: str(32).nullish(),
});
export type GraphSignIn = z.infer<typeof signInSchema>;

export const riskDetectionSchema = z.looseObject({
  id: str(128).min(1),
  riskEventType: str(128).min(1),
  riskLevel: str(32).nullish(),
  riskState: str(64).nullish(),
  detectedDateTime: z.iso.datetime({ offset: true }).nullish(),
  activityDateTime: z.iso.datetime({ offset: true }).nullish(),
  lastUpdatedDateTime: z.iso.datetime({ offset: true }),
  userId: str(128).min(1),
  userPrincipalName: str(256).nullish(),
  ipAddress: str(64).nullish(),
  location: geoSchema,
});
export type GraphRiskDetection = z.infer<typeof riskDetectionSchema>;

export const directoryAuditSchema = z.looseObject({
  id: str(256).min(1),
  activityDateTime: z.iso.datetime({ offset: true }),
  activityDisplayName: str(256),
  result: str(64).nullish(),
  initiatedBy: z.looseObject({
    user: z
      .looseObject({
        id: str(128).min(1),
        userPrincipalName: str(256).nullish(),
        ipAddress: str(64).nullish(),
      })
      .nullish(),
  }),
  targetResources: z
    .array(
      z.looseObject({
        id: str(128).nullish(),
        displayName: str(512).nullish(),
        type: str(64).nullish(),
        modifiedProperties: z
          .array(
            z.looseObject({
              displayName: str(256).nullish(),
              newValue: str(16_384).nullish(),
            }),
          )
          .max(100)
          .nullish(),
      }),
    )
    .max(50),
});
export type GraphDirectoryAudit = z.infer<typeof directoryAuditSchema>;

export const servicePrincipalSchema = z.looseObject({
  id: str(128),
  verifiedPublisher: z
    .looseObject({ verifiedPublisherId: str(128).nullish(), displayName: str(256).nullish() })
    .nullish(),
});

export const graphUserSchema = z.looseObject({
  id: str(128).min(1),
  userPrincipalName: str(256).nullish(),
  mail: str(256).nullish(),
  accountEnabled: z.boolean().nullish(),
  onPremisesSyncEnabled: z.boolean().nullish(),
});
export type GraphUser = z.infer<typeof graphUserSchema>;

const recipientSchema = z.looseObject({
  emailAddress: z.looseObject({ address: str(320).nullish() }).nullish(),
});

export const messageRuleSchema = z.looseObject({
  id: str(512).min(1),
  displayName: str(512).nullish(),
  isEnabled: z.boolean().nullish(),
  conditions: z
    .looseObject({
      subjectContains: z.array(str(1024)).max(100).nullish(),
      bodyContains: z.array(str(1024)).max(100).nullish(),
      bodyOrSubjectContains: z.array(str(1024)).max(100).nullish(),
      senderContains: z.array(str(1024)).max(100).nullish(),
      fromAddresses: z.array(recipientSchema).max(100).nullish(),
    })
    .nullish(),
  actions: z
    .looseObject({
      forwardTo: z.array(recipientSchema).max(100).nullish(),
      redirectTo: z.array(recipientSchema).max(100).nullish(),
      forwardAsAttachmentTo: z.array(recipientSchema).max(100).nullish(),
      delete: z.boolean().nullish(),
      permanentDelete: z.boolean().nullish(),
      moveToFolder: str(512).nullish(),
      markAsRead: z.boolean().nullish(),
      stopProcessingRules: z.boolean().nullish(),
    })
    .nullish(),
});
export type GraphMessageRule = z.infer<typeof messageRuleSchema>;

export const messageRulesSchema = z.looseObject({ value: z.array(z.unknown()).max(1000) });

export const groupSchema = z.looseObject({ id: str(128) });
export const membersSchema = z.looseObject({
  value: z.array(z.looseObject({ id: str(128) })).max(1000),
});

export const oauthGrantSchema = z.looseObject({
  id: str(256).min(1),
  clientId: str(128).min(1),
});
export const oauthGrantsSchema = z.looseObject({
  value: z.array(oauthGrantSchema).max(1000),
  '@odata.nextLink': str(4096).optional(),
});

export const revokeSessionsSchema = z.looseObject({ value: z.boolean().optional() });

// Office 365 Management Activity API

export const o365ContentListSchema = z
  .array(
    z.looseObject({
      contentId: str(512).min(1),
      contentUri: str(4096).min(1),
      contentCreated: str(64).nullish(),
    }),
  )
  .max(10_000);
export type O365ContentList = z.infer<typeof o365ContentListSchema>;

export const o365BlobSchema = z.array(z.unknown()).max(100_000);

export const exchangeRecordSchema = z.looseObject({
  Id: str(128).min(1),
  CreationTime: str(64).min(1),
  Operation: str(128).min(1),
  UserId: str(320).nullish(),
  ObjectId: str(1024).nullish(),
  MailboxOwnerUPN: str(320).nullish(),
  LogonType: z.number().int().nullish(),
  ClientIP: str(128).nullish(),
  ClientIPAddress: str(128).nullish(),
  ClientInfoString: str(1024).nullish(),
  Parameters: z
    .array(z.looseObject({ Name: str(128), Value: str(16_384).nullish() }))
    .max(200)
    .nullish(),
});
export type ExchangeRecord = z.infer<typeof exchangeRecordSchema>;

export const o365SubscriptionSchema = z.looseObject({ status: str(64).optional() });
