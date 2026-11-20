import { describe, expect, it } from 'vitest';
import { appIdHash, deviceIdHash } from '../../core/hash';
import { providerEventSchema } from '../../port/ato-port';
import {
  MS_IPS,
  MS_SERVICE_PRINCIPALS,
  MS_USERS,
  msConsentAudit,
  msExchangeRecord,
  msRiskDetection,
  msSignIn,
} from '../../testing/datasets/microsoft';
import { ENTRA_INTERRUPT_CODES, EXCHANGE_AUDIT_OPERATIONS } from '../constants';
import { mapDirectoryAudit, parseConsentScopes } from './audits';
import { clientType, mapExchangeRecord } from './exchange';
import { mapRiskDetection } from './risk';
import { auditRuleDefinition, graphRuleDefinition, parseGraphRule } from './rules';
import { deviceLabel, mapSignIn } from './sign-ins';

const NOW = new Date('2026-11-10T12:00:00.000Z');

describe('Entra sign-ins (§3.2)', () => {
  it('maps success with device hash, PX1 label, location and IP', () => {
    const event = mapSignIn(msSignIn(NOW, { riskLevelDuringSignIn: 'low' }));
    expect(event).toMatchObject({
      provider: 'microsoft_entra',
      stream: 'sign_ins',
      outcome: 'success',
      ip: MS_IPS.office,
      deviceIdHash: deviceIdHash('EXAMPLE-device-0001'),
      deviceLabel: 'Edge 120.0 · Windows 10',
      providerLocation: { countryCode: 'DE', city: 'Example City', lat: 52.5, lon: 13.4 },
      riskLevel: 'low',
      identity: {
        externalId: MS_USERS.alex,
        userPrincipalName: 'alex@contoso-it.example',
        primaryEmail: 'alex@contoso-it.example',
      },
    });
    expect(event?.eventId).toMatch(/^entra:/);
    expect(event?.userAgent).toBeUndefined();
    expect(providerEventSchema.safeParse(event).success).toBe(true);
  });

  it.each([...ENTRA_INTERRUPT_CODES])('maps MFA/CA interruption %i to interrupted', (code) => {
    expect(mapSignIn(msSignIn(NOW, { status: { errorCode: code } }))?.outcome).toBe('interrupted');
  });

  it('maps other codes to failure entra_<code> and omits hidden/none risk levels', () => {
    for (const code of [50126, 50053, 53004, 1]) {
      const event = mapSignIn(
        msSignIn(NOW, { status: { errorCode: code }, riskLevelDuringSignIn: 'hidden' }),
      );
      expect(event).toMatchObject({ outcome: 'failure', failureCode: `entra_${code}` });
      expect(event?.riskLevel).toBeUndefined();
    }
    expect(mapSignIn(msSignIn(NOW, { riskLevelDuringSignIn: 'none' }))?.riskLevel).toBeUndefined();
  });

  it('canonicalizes IPv6, drops invalid IPs, empty device data and (0,0) coordinates', () => {
    const event = mapSignIn(
      msSignIn(NOW, {
        ipAddress: '2001:DB8:0:0::1',
        deviceDetail: { deviceId: '', browser: null, operatingSystem: null },
        location: { countryOrRegion: 'zz1', geoCoordinates: { latitude: 0, longitude: 0 } },
      }),
    );
    expect(event?.ip).toBe('2001:db8::1');
    expect(event?.deviceIdHash).toBeUndefined();
    expect(event?.deviceLabel).toBeUndefined();
    expect(event?.providerLocation).toBeUndefined();
    expect(mapSignIn(msSignIn(NOW, { ipAddress: 'garbage' }))?.ip).toBeUndefined();
    expect(deviceLabel('B'.repeat(80), 'O'.repeat(80))?.length).toBeLessThanOrEqual(96);
  });

  it('drops malformed records', () => {
    expect(mapSignIn({ id: 'x' })).toBeNull();
    expect(mapSignIn({ ...msSignIn(NOW), userId: '' })).toBeNull();
    expect(mapSignIn('nope')).toBeNull();
  });
});

describe('Entra risk detections (§3.2)', () => {
  it('routes token risk types to session_events and others to risk_events', () => {
    for (const type of [
      'anomalousToken',
      'tokenIssuerAnomaly',
      'attackerinTheMiddle',
      'suspiciousAPITraffic',
    ]) {
      const result = mapRiskDetection(msRiskDetection(NOW, { riskEventType: type }));
      expect(result.kind === 'event' && result.event).toMatchObject({
        stream: 'session_events',
        riskDetail: 'token_anomaly', // 8.4 rule Q2 (WP3-2)
      });
    }
    for (const type of [
      'unfamiliarFeatures',
      'leakedCredentials',
      'impossibleTravel',
      'passwordSpray',
    ]) {
      const result = mapRiskDetection(msRiskDetection(NOW, { riskEventType: type }));
      expect(result.kind === 'event' && result.event).toMatchObject({
        stream: 'risk_events',
        riskDetail: type.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase(), // 8.4 lower-case code
        riskLevel: 'high',
      });
    }
  });

  it('drops dismissed detections and omits hidden levels', () => {
    expect(mapRiskDetection(msRiskDetection(NOW, { riskState: 'dismissed' })).kind).toBe('dropped');
    const hidden = mapRiskDetection(msRiskDetection(NOW, { riskLevel: 'hidden' }));
    expect(hidden.kind === 'event' && hidden.event.riskLevel).toBeUndefined();
    expect(mapRiskDetection({}).kind).toBe('invalid');
  });
});

describe('Entra consent audits (§3.2)', () => {
  it('maps a user consent with scopes, app hash and identity', () => {
    const result = mapDirectoryAudit(msConsentAudit(NOW));
    expect(result.kind).toBe('event');
    if (result.kind !== 'event') return;
    expect(result.servicePrincipalId).toBe(MS_SERVICE_PRINCIPALS.unverified);
    expect(result.event).toMatchObject({
      stream: 'oauth_consents',
      ip: MS_IPS.attacker,
      identity: { externalId: MS_USERS.alex },
      oauth: {
        appIdHash: appIdHash(MS_SERVICE_PRINCIPALS.unverified),
        appDisplayName: 'Mail Helper Example',
        scopes: ['mail_read', 'mail_send', 'offline_access'],
        consentType: 'user',
      },
    });
    expect(providerEventSchema.safeParse(result.event).success).toBe(true);
  });

  it('maps admin consent and drops other activities and failures', () => {
    const admin = mapDirectoryAudit(
      msConsentAudit(NOW, {
        activity: 'Add app role assignment to service principal',
        adminConsent: true,
      }),
    );
    expect(admin.kind === 'event' && admin.event.oauth?.consentType).toBe('admin');
    expect(mapDirectoryAudit(msConsentAudit(NOW, { activity: 'Update user' })).kind).toBe(
      'dropped',
    );
    expect(mapDirectoryAudit(msConsentAudit(NOW, { result: 'failure' })).kind).toBe('dropped');
    expect(mapDirectoryAudit({}).kind).toBe('invalid');
  });

  it('parses and bounds scopes', () => {
    expect(parseConsentScopes(['Scope: a b, Scope: c', 'nothing'])).toEqual(['a', 'b', 'c']);
    const many = Array.from({ length: 80 }, (_, i) => `s${i}`).join(' ');
    expect(parseConsentScopes([`Scope: ${many}`])).toHaveLength(50);
    expect(parseConsentScopes(['Scope: bad<script> ok.Scope'])).toEqual(['ok.Scope']);
  });
});

describe('Exchange audit records (§3.2)', () => {
  it('keeps only allow-listed operations', () => {
    expect(EXCHANGE_AUDIT_OPERATIONS).toContain('New-InboxRule');
    expect(mapExchangeRecord(msExchangeRecord(NOW, { Operation: 'Send' })).type).toBe('dropped');
    expect(mapExchangeRecord(msExchangeRecord(NOW, { Operation: 'HardDelete' })).type).toBe(
      'dropped',
    );
    expect(mapExchangeRecord({ Id: 'x' }).type).toBe('invalid');
  });

  it('keeps admin and delegate mailbox access only (owner access dropped, PQ4)', () => {
    expect(
      mapExchangeRecord(msExchangeRecord(NOW, { Operation: 'MailboxLogin', LogonType: 0 })).type,
    ).toBe('dropped');
    const delegate = mapExchangeRecord(
      msExchangeRecord(NOW, {
        Operation: 'MailItemsAccessed',
        LogonType: 2,
        ClientInfoString: 'Client=OWA',
      }),
    );
    expect(delegate).toMatchObject({
      type: 'access',
      clientType: 'owa',
      ip: MS_IPS.attacker,
      ownerKey: 'alex@contoso-it.example',
    });
    expect(
      mapExchangeRecord(msExchangeRecord(NOW, { Operation: 'MailboxLogin', LogonType: 1 })).type,
    ).toBe('access');
  });

  it('maps inbox rule, forwarding, permission, send-as and send-on-behalf records', () => {
    const rule = mapExchangeRecord(
      msExchangeRecord(NOW, {
        Operation: 'Set-InboxRule',
        Parameters: [
          { Name: 'Identity', Value: 'alex@contoso-it.example\\Hide' },
          { Name: 'RedirectTo', Value: '"Ext" [SMTP:collector@evil-mail.example]' },
          { Name: 'DeleteMessage', Value: 'True' },
        ],
      }),
    );
    expect(rule).toMatchObject({ type: 'inbox_rule', change: 'changed', hasParameters: true });
    const forwarding = mapExchangeRecord(
      msExchangeRecord(NOW, {
        Operation: 'Set-Mailbox',
        Parameters: [{ Name: 'ForwardingSmtpAddress', Value: 'smtp:c@evil-mail.example' }],
      }),
    );
    expect(forwarding).toMatchObject({ type: 'forwarding', target: 'c@evil-mail.example' });
    const cleared = mapExchangeRecord(
      msExchangeRecord(NOW, {
        Operation: 'Set-Mailbox',
        Parameters: [{ Name: 'ForwardingSmtpAddress', Value: '' }],
      }),
    );
    expect(cleared).toMatchObject({ type: 'forwarding', target: null });
    expect(
      mapExchangeRecord(
        msExchangeRecord(NOW, {
          Operation: 'Add-MailboxPermission',
          Parameters: [
            { Name: 'User', Value: 'b@x.example' },
            { Name: 'AccessRights', Value: 'ReadPermission' },
          ],
        }),
      ).type,
    ).toBe('dropped');
    expect(
      mapExchangeRecord(
        msExchangeRecord(NOW, {
          Operation: 'Add-RecipientPermission',
          Parameters: [
            { Name: 'Trustee', Value: 'b@x.example' },
            { Name: 'AccessRights', Value: 'SendAs' },
          ],
        }),
      ),
    ).toMatchObject({ type: 'permission', kind: 'send_as', grantee: 'b@x.example' });
    expect(
      mapExchangeRecord(
        msExchangeRecord(NOW, {
          Operation: 'Set-Mailbox',
          Parameters: [{ Name: 'GrantSendOnBehalfTo', Value: 'b@x.example' }],
        }),
      ),
    ).toMatchObject({ type: 'permission', kind: 'delegate' });
    expect(
      mapExchangeRecord(
        msExchangeRecord(NOW, {
          Operation: 'Set-Mailbox',
          Parameters: [{ Name: 'Other', Value: '1' }],
        }),
      ).type,
    ).toBe('dropped');
  });

  it('classifies client families', () => {
    expect(clientType('Client=REST;Client=RESTSystem')).toBe('rest');
    expect(clientType('Client=Exchange ActiveSync')).toBe('activesync');
    expect(clientType('Client=MSExchangeRPC Outlook')).toBe('mapi');
    expect(clientType('IMAP4')).toBe('imap');
    expect(clientType(null)).toBe('unknown');
    expect(clientType('something')).toBe('other');
  });
});

describe('rule definitions (D8.3)', () => {
  it('reads Graph rules and audit parameters', () => {
    const graph = parseGraphRule({
      id: 'r1',
      isEnabled: true,
      conditions: { subjectContains: ['invoice'], hasAttachments: true },
      actions: {
        forwardAsAttachmentTo: [{ emailAddress: { address: 'c@evil-mail.example' } }],
        permanentDelete: true,
      },
    });
    expect(graph && graphRuleDefinition(graph)).toMatchObject({
      forwardAsAttachmentTo: ['c@evil-mail.example'],
      deletes: true,
      conditionWords: ['invoice'],
      hasNoConditions: false,
    });
    expect(parseGraphRule({ id: '' })).toBeNull();
    const audit = auditRuleDefinition([
      { Name: 'Name', Value: 'x' },
      { Name: 'ForwardTo', Value: '' },
      { Name: 'MoveToFolder', Value: 'alex\\Deleted Items' },
      { Name: 'StopProcessingRules', Value: 'False' },
    ]);
    expect(audit).toMatchObject({
      forwardTo: ['unknown'],
      moveToFolder: 'Deleted Items',
      stopsProcessing: false,
      hasNoConditions: true,
    });
  });
});
