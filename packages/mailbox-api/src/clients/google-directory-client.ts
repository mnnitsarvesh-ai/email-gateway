/**
 * Google Directory client of API mode (design D9, D11.1; family `google_directory`): the users of
 * the customer for the mailbox inventory. The token impersonates the grant's delegated
 * administrator (`subject`).
 */
import type { TokenSource } from '@email-gateway/idp-adapters';
import { z } from 'zod';
import { enc, guardedCall, type MailboxClientContext } from './context';

const userSchema = z.object({
  id: z.string().min(1).max(64),
  primaryEmail: z.string().min(3).max(320),
  aliases: z.array(z.string().max(320)).max(1000).optional(),
  suspended: z.boolean().optional(),
  archived: z.boolean().optional(),
});
const usersSchema = z.object({
  users: z.array(userSchema).max(500).optional(),
  nextPageToken: z.string().min(1).max(4096).optional(),
});

export interface GoogleDirectoryUser {
  id: string;
  primaryEmail: string;
  aliases: string[];
  suspended: boolean;
  archived: boolean;
}

export interface GoogleUsersPage {
  users: GoogleDirectoryUser[];
  nextPageToken: string | null;
}

export class GoogleDirectoryClient {
  constructor(
    private readonly context: MailboxClientContext,
    private readonly token: TokenSource,
  ) {}

  /** `GET /admin/directory/v1/users?customer=my_customer&projection=basic&maxResults=500`. */
  listUsers(pageToken: string | undefined, signal: AbortSignal): Promise<GoogleUsersPage> {
    return guardedCall(this.context, 'google_directory', signal, async () => {
      const page = pageToken === undefined ? '' : `&pageToken=${enc(pageToken)}`;
      const response = await this.context.http.request({
        family: 'google_directory',
        method: 'GET',
        url: `/admin/directory/v1/users?customer=my_customer&projection=basic&maxResults=500${page}`,
        pathTemplate: '/admin/directory/v1/users',
        token: this.token,
        signal,
        schema: usersSchema,
      });
      return {
        users: (response.data.users ?? []).map((u) => ({
          id: u.id,
          primaryEmail: u.primaryEmail,
          aliases: u.aliases ?? [],
          suspended: u.suspended === true,
          archived: u.archived === true,
        })),
        nextPageToken: response.data.nextPageToken ?? null,
      };
    });
  }
}
