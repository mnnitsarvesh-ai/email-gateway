import { describe, expect, it } from 'vitest';
import { appIdHash, mailboxItemHash } from '../../core/hash';
import { isValidEvent } from '../../core/normalize';
import { GS_CLIENTS, GS_USERS, gsActivity } from '../../testing/datasets/google';
import type { ActivityEventResult } from './activity';
import { googleRiskLevel, mapLoginActivity } from './login';
import { autoForwardingItem, delegateItem, filterItem, gmailFilterDefinition } from './settings';
import { mapTokenActivity } from './token';

const now = new Date('2026-11-10T12:00:00.000Z');
const events = (results: ActivityEventResult[]) =>
  results.flatMap((r) => (r.kind === 'event' ? [r.event] : []));

describe('Google login mapper (§3.2)', () => {
  it('maps success, failure with its type, failed and passed challenges', () => {
    const [success] = events(
      mapLoginActivity(
        gsActivity(now, {
          user: 'alex',
          ip: '192.0.2.10',
          regionCode: 'de',
          uniqueQualifier: '-42',
          events: [{ name: 'login_success' }],
        }),
      ),
    );
    expect(success).toEqual({
      provider: 'google_workspace',
      eventId: `gws:login:${Date.parse('2026-11-10T11:50:00.000Z')}:-42:0`,
      stream: 'sign_ins',
      occurredAt: '2026-11-10T11:50:00.000Z',
      identity: {
        provider: 'google_workspace',
        externalId: GS_USERS.alex,
        primaryEmail: 'alex@fabrikam-it.example',
      },
      outcome: 'success',
      ip: '192.0.2.10',
      providerLocation: { countryCode: 'DE' },
    });
    expect(success && isValidEvent(success)).toBe(true);
    const failure = events(
      mapLoginActivity(
        gsActivity(now, {
          events: [
            {
              name: 'login_failure',
              parameters: [{ name: 'login_failure_type', value: 'login_failure_invalid_password' }],
            },
            { name: 'login_failure' },
          ],
        }),
      ),
    );
    expect(failure.map((e) => [e.outcome, e.failureCode])).toEqual([
      ['failure', 'gws_login_failure_invalid_password'],
      ['failure', 'gws_unknown'],
    ]);
    expect(failure.map((e) => e.eventId.endsWith(':0') || e.eventId.endsWith(':1'))).toEqual([
      true,
      true,
    ]);
    const challenges = events(
      mapLoginActivity(
        gsActivity(now, {
          events: [
            {
              name: 'login_challenge',
              parameters: [{ name: 'login_challenge_status', value: 'Challenge Failed' }],
            },
            {
              name: 'login_challenge',
              parameters: [{ name: 'login_challenge_status', value: 'Challenge Passed' }],
            },
          ],
        }),
      ),
    );
    expect(challenges.map((e) => [e.outcome, e.failureCode])).toEqual([
      ['failure', 'gws_challenge_failed'],
      ['interrupted', undefined],
    ]);
  });

  it('maps every risk event name to risk_events with its level and detail', () => {
    const names = {
      suspicious_login: 'medium',
      suspicious_login_less_secure_app: 'low',
      suspicious_programmatic_login: 'medium',
      gov_attack_warning: 'high',
      account_disabled_password_leak: 'high',
      account_disabled_hijacked: 'high',
      account_disabled_spamming: 'medium',
      account_disabled_spamming_through_relay: 'medium',
    } as const;
    for (const [name, level] of Object.entries(names)) {
      const [event] = events(mapLoginActivity(gsActivity(now, { events: [{ name }] })));
      expect(event).toMatchObject({ stream: 'risk_events', riskLevel: level, riskDetail: name });
      expect(event && isValidEvent(event)).toBe(true);
    }
    expect(googleRiskLevel('login_success')).toBeNull();
    expect(googleRiskLevel('toString')).toBeNull();
  });

  it('drops logout and unrelated events, and counts activities without identity as invalid', () => {
    expect(
      mapLoginActivity(
        gsActivity(now, {
          events: [{ name: 'logout' }, { name: 'login_verification' }, { name: '2sv_disable' }],
        }),
      ),
    ).toEqual([
      { kind: 'dropped', stream: 'sign_ins' },
      { kind: 'dropped', stream: 'sign_ins' },
      { kind: 'dropped', stream: 'sign_ins' },
    ]);
    expect(
      mapLoginActivity(gsActivity(now, { user: null, events: [{ name: 'login_success' }] })),
    ).toEqual([{ kind: 'invalid', stream: 'sign_ins' }]);
    expect(mapLoginActivity({ id: { time: 'yesterday' }, events: [] })).toEqual([
      { kind: 'invalid', stream: 'sign_ins' },
    ]);
    // IPv6 is canonicalized; an unparsable IP is omitted (never fails the event).
    const [v6] = events(
      mapLoginActivity(
        gsActivity(now, { ip: '2001:DB8:0::1', events: [{ name: 'login_success' }] }),
      ),
    );
    expect(v6?.ip).toBe('2001:db8::1');
    const [noIp] = events(
      mapLoginActivity(gsActivity(now, { ip: 'not-an-ip', events: [{ name: 'login_success' }] })),
    );
    expect(noIp?.ip).toBeUndefined();
  });
});

describe('Google token mapper (§3.2)', () => {
  it('maps authorize to an OAuth consent with the client id hashed, never emitted', () => {
    const [event] = events(
      mapTokenActivity(
        gsActivity(now, {
          application: 'token',
          events: [
            {
              name: 'authorize',
              parameters: [
                { name: 'client_id', value: GS_CLIENTS.mailSync },
                { name: 'app_name', value: '  Mail Sync Pro (example)  ' },
                {
                  name: 'scope',
                  multiValue: [
                    'https://mail.google.com/',
                    'https://mail.google.com/',
                    `https://example.invalid/${'x'.repeat(200)}`,
                  ],
                },
              ],
            },
          ],
        }),
      ),
    );
    expect(event).toMatchObject({
      stream: 'oauth_consents',
      oauth: {
        appIdHash: appIdHash(GS_CLIENTS.mailSync),
        appDisplayName: 'Mail Sync Pro (example)',
        scopes: ['full_access'], // 8.4 scope class (WP3-2)
        consentType: 'user',
      },
    });
    expect(event?.oauth?.publisherVerified).toBeUndefined();
    expect(JSON.stringify(event)).not.toContain(GS_CLIENTS.mailSync);
    expect(event && isValidEvent(event)).toBe(true);
  });

  it('drops other token events and counts an authorize without client id as invalid', () => {
    expect(
      mapTokenActivity(
        gsActivity(now, {
          application: 'token',
          events: [{ name: 'revoke' }, { name: 'request' }, { name: 'authorize' }],
        }),
      ),
    ).toEqual([
      { kind: 'dropped', stream: 'oauth_consents' },
      { kind: 'dropped', stream: 'oauth_consents' },
      { kind: 'invalid', stream: 'oauth_consents' },
    ]);
    const [spaceSeparated] = events(
      mapTokenActivity(
        gsActivity(now, {
          application: 'token',
          events: [
            {
              name: 'authorize',
              parameters: [
                { name: 'client_id', value: GS_CLIENTS.notes },
                { name: 'scope', value: 'openid email' },
              ],
            },
          ],
        }),
      ),
    );
    expect(spaceSeparated?.oauth?.scopes).toEqual(['openid', 'email']);
  });
});

describe('Gmail settings mapper (D8.3)', () => {
  const context = { directoryDomains: ['fabrikam-it.example'] };

  it('classifies filters by forward, labels and criteria keywords (keywords never kept)', () => {
    const item = filterItem(
      GS_USERS.alex,
      {
        id: 'F1',
        criteria: { subject: 'Invoice payment' },
        action: {
          forward: 'pay@exfil-mail.example',
          removeLabelIds: ['INBOX', 'UNREAD'],
          addLabelIds: ['TRASH'],
        },
      },
      context,
    );
    expect(item).toEqual({
      kind: 'inbox_rule',
      itemHash: mailboxItemHash('google_workspace', GS_USERS.alex, 'inbox_rule', 'F1'),
      providerItemRef: 'F1',
      targetDomain: 'exfil-mail.example',
      traits: [
        'forwards',
        'forwards_external',
        'deletes',
        'moves_to_folder',
        'moves_to_rarely_used_folder',
        'marks_read',
        'matches_finance_keywords',
      ],
      enabled: true,
      source: 'snapshot',
    });
    expect(JSON.stringify(item)).not.toMatch(/invoice|pay@/i);
    expect(
      filterItem(GS_USERS.alex, { id: 'F2', action: { addLabelIds: ['SPAM'] } }, context)?.traits,
    ).toEqual(['moves_to_folder', 'moves_to_rarely_used_folder', 'matches_all_messages']);
    expect(
      filterItem(
        GS_USERS.alex,
        { id: 'F3', criteria: { query: 'password reset' }, action: { addLabelIds: ['Label_7'] } },
        context,
      )?.traits,
    ).toEqual(['matches_security_keywords']);
    expect(
      gmailFilterDefinition({ id: 'F4', criteria: { hasAttachment: true } }).hasNoConditions,
    ).toBe(false);
    expect(filterItem(GS_USERS.alex, { action: {} }, context)).toBeNull();
  });

  it('turns enabled auto-forwarding into a forwarding item keyed by the hashed target', () => {
    const item = autoForwardingItem(
      GS_USERS.blake,
      { enabled: true, emailAddress: 'Drop@Exfil-Mail.example', disposition: 'trash' },
      context,
    );
    expect(item).toMatchObject({
      kind: 'forwarding',
      providerItemRef: null,
      targetDomain: 'exfil-mail.example',
      traits: ['forwards', 'forwards_external', 'deletes', 'matches_all_messages'],
    });
    expect(item?.itemHash).toBe(
      mailboxItemHash(
        'google_workspace',
        GS_USERS.blake,
        'forwarding',
        'auto_forwarding|drop@exfil-mail.example',
      ),
    );
    expect(
      autoForwardingItem(
        GS_USERS.blake,
        { enabled: true, emailAddress: 'x@fabrikam-it.example', disposition: 'archive' },
        context,
      )?.traits,
    ).toEqual([
      'forwards',
      'moves_to_folder',
      'moves_to_rarely_used_folder',
      'matches_all_messages',
    ]);
    expect(autoForwardingItem(GS_USERS.blake, { enabled: false }, context)).toBeNull();
    expect(autoForwardingItem(GS_USERS.blake, { enabled: true }, context)).toBeNull();
  });

  it('keeps only accepted delegates (domain, never the address)', () => {
    expect(
      delegateItem(GS_USERS.erin, {
        delegateEmail: 'Alex@Fabrikam-IT.example',
        verificationStatus: 'accepted',
      }),
    ).toMatchObject({ kind: 'delegate', targetDomain: 'fabrikam-it.example', traits: [] });
    for (const status of ['pending', 'rejected', 'expired', null]) {
      expect(
        delegateItem(GS_USERS.erin, {
          delegateEmail: 'p@fabrikam-it.example',
          verificationStatus: status,
        }),
      ).toBeNull();
    }
  });
});
