/**
 * Response schemas of the Google endpoints (design note D2): every field the adapter reads is
 * typed and bounded; `looseObject` because Google adds fields. Collections are validated as a page
 * of unknown records; each record is validated by its mapper (malformed records are dropped and
 * counted `invalid`, never a page failure).
 */
import { z } from 'zod';

const str = (max: number) => z.string().max(max);

/** Reports `activities.list` page. */
export const activitiesPageSchema = z.looseObject({
  items: z.array(z.unknown()).max(1000).optional(),
  nextPageToken: str(2048).min(1).optional(),
});
export type ActivitiesPage = z.infer<typeof activitiesPageSchema>;

const parameterSchema = z.looseObject({
  name: str(128).min(1),
  value: str(2048).nullish(),
  multiValue: z.array(str(2048)).max(200).nullish(),
  boolValue: z.boolean().nullish(),
  intValue: z.union([str(32), z.number()]).nullish(),
});
export type ActivityParameter = z.infer<typeof parameterSchema>;

export const activitySchema = z.looseObject({
  id: z.looseObject({
    time: z.iso.datetime({ offset: true }),
    uniqueQualifier: z
      .union([str(64).regex(/^-?[A-Za-z0-9_]{1,64}$/), z.number().int()])
      .transform(String),
    applicationName: str(64).nullish(),
  }),
  actor: z
    .looseObject({
      email: str(256).nullish(),
      profileId: str(128).nullish(),
    })
    .nullish(),
  ipAddress: str(64).nullish(),
  networkInfo: z.looseObject({ regionCode: str(8).nullish() }).nullish(),
  events: z
    .array(
      z.looseObject({
        type: str(128).nullish(),
        name: str(128).min(1),
        parameters: z.array(parameterSchema).max(100).nullish(),
      }),
    )
    .max(50),
});
export type GoogleActivity = z.infer<typeof activitySchema>;
export type GoogleActivityEvent = GoogleActivity['events'][number];

/** Directory user (fields the adapter reads). */
export const directoryUserSchema = z.looseObject({
  id: str(128).min(1),
  primaryEmail: str(256).min(3),
  suspended: z.boolean().nullish(),
  archived: z.boolean().nullish(),
  orgUnitPath: str(512).nullish(),
  changePasswordAtNextLogin: z.boolean().nullish(),
});
export type DirectoryUser = z.infer<typeof directoryUserSchema>;

export const usersPageSchema = z.looseObject({
  users: z.array(z.unknown()).max(500).optional(),
  nextPageToken: str(2048).min(1).optional(),
});
export type UsersPage = z.infer<typeof usersPageSchema>;

export const tokensSchema = z.looseObject({
  items: z
    .array(
      z.looseObject({
        clientId: str(512).min(1),
        displayText: str(512).nullish(),
      }),
    )
    .max(1000)
    .optional(),
});
export type DirectoryToken = NonNullable<z.infer<typeof tokensSchema>['items']>[number];

export const orgUnitSchema = z.looseObject({
  orgUnitPath: str(512).min(1),
});

export const autoForwardingSchema = z.looseObject({
  enabled: z.boolean(),
  emailAddress: str(320).nullish(),
  disposition: str(64).nullish(),
});
export type AutoForwarding = z.infer<typeof autoForwardingSchema>;

export const filtersSchema = z.looseObject({
  filter: z.array(z.unknown()).max(1000).optional(),
});

export const filterSchema = z.looseObject({
  id: str(128).min(1),
  criteria: z
    .looseObject({
      from: str(1024).nullish(),
      to: str(1024).nullish(),
      subject: str(1024).nullish(),
      query: str(2048).nullish(),
      negatedQuery: str(2048).nullish(),
      hasAttachment: z.boolean().nullish(),
    })
    .nullish(),
  action: z
    .looseObject({
      addLabelIds: z.array(str(256)).max(100).nullish(),
      removeLabelIds: z.array(str(256)).max(100).nullish(),
      forward: str(320).nullish(),
    })
    .nullish(),
});
export type GmailFilter = z.infer<typeof filterSchema>;

export const delegatesSchema = z.looseObject({
  delegates: z
    .array(
      z.looseObject({
        delegateEmail: str(320).min(3),
        verificationStatus: str(64).nullish(),
      }),
    )
    .max(1000)
    .optional(),
});
