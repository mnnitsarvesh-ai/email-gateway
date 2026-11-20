/**
 * Google Reports `token` activities → `oauth_consents` events (design note §3.2): the `authorize`
 * event becomes `oauth { appIdHash = SHA-256(client_id), appDisplayName = app_name, scopes,
 * consentType 'user', publisherVerified undefined }`. Every other token event (`revoke`,
 * `request`, …) is dropped. The client id itself is never emitted, only its hash.
 */
import { appIdHash } from '../../core/hash';
import { safeDisplayText } from '../../core/normalize';
import { oauthScopeCodes } from '../../core/oauth-scopes';
import { looksSecretShaped } from '../../port/ato-port';
import { GOOGLE_PROVIDER, TOKEN_AUTHORIZE_EVENT } from '../constants';
import { activitySchema } from '../schemas';
import { activityEvent, multiParameter, parameter, type ActivityEventResult } from './activity';

const MAX_SCOPES = 50;
const MAX_SCOPE_LENGTH = 128;

export function mapTokenActivity(raw: unknown): ActivityEventResult[] {
  const parsed = activitySchema.safeParse(raw);
  if (!parsed.success) return [{ kind: 'invalid', stream: 'oauth_consents' }];
  const activity = parsed.data;
  return activity.events.map((source, index): ActivityEventResult => {
    if (source.name !== TOKEN_AUTHORIZE_EVENT) return { kind: 'dropped', stream: 'oauth_consents' };
    const clientId = parameter(source, 'client_id')?.trim();
    const event = activityEvent(activity, 'token', index, 'oauth_consents');
    if (!event || !clientId) return { kind: 'invalid', stream: 'oauth_consents' };
    const scopes = oauthScopeCodes(GOOGLE_PROVIDER, [
      ...new Set(
        multiParameter(source, 'scope')
          .map((scope) => scope.trim())
          .filter(
            (scope) =>
              scope.length > 0 && scope.length <= MAX_SCOPE_LENGTH && !looksSecretShaped(scope),
          ),
      ),
    ]).slice(0, MAX_SCOPES);
    const name = safeDisplayText(parameter(source, 'app_name'), 128);
    event.oauth = {
      appIdHash: appIdHash(clientId),
      ...(name ? { appDisplayName: name } : {}),
      scopes,
      consentType: 'user',
    };
    return { kind: 'event', event };
  });
}
