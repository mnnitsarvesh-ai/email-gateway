import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { ALL_TOOLS, findTool } from '../registry/registry';
import type { OperationTool } from '../registry/types';
import {
  effectiveRisk,
  escalationMatches,
  escalationNote,
  maxRisk,
  type RiskEscalation,
} from './escalation';
import { AI4_WRITES_TESTED_BY } from '../registry/manifest';
import {
  AI4_ESCALATION_WARNINGS,
  CONFIRMATION_SPECS,
  ESCALATION_WARNINGS,
  confirmationSpecOf,
} from './specs';
import { CONFIRMATION_RISKS, type ConfirmationRisk } from './types';

const tool = (name: string): OperationTool => findTool(name)!;
const risk = (name: string, args: Record<string, unknown>) =>
  effectiveRisk(tool(name), confirmationSpecOf(tool(name).operationId), args);
const ORDER: Record<ConfirmationRisk, number> = { low: 0, medium: 1, high: 2 };

describe('conditional risk escalation (design 30 D4)', () => {
  it('has the escalations of the design table', () => {
    const table = CONFIRMATION_SPECS.filter(
      (s) => s.escalate && !(s.operationId in AI4_WRITES_TESTED_BY),
    ).flatMap((s) => s.escalate!.map((e) => [s.operationId, escalationNote(e), e.warning]));
    expect(table).toEqual([
      ['UsersController_update_v1', '↑ high when body.email', ESCALATION_WARNINGS.userEmail],
      [
        'OrganizationsController_create_v1',
        '↑ high when body.initialAdmin',
        ESCALATION_WARNINGS.initialAdmin,
      ],
      [
        'OrganizationsController_update_v1',
        '↑ high when body.planCode',
        ESCALATION_WARNINGS.planCode,
      ],
      [
        'OrganizationConfigurationController_updateSettings_v1',
        '↑ high when body.mfaRequired = false',
        ESCALATION_WARNINGS.mfaOff,
      ],
      [
        'OrganizationConfigurationController_updateSettings_v1',
        '↑ high when body.notificationEmail',
        ESCALATION_WARNINGS.notificationEmail,
      ],
      [
        'SmtpConnectorsController_update_v1',
        '↑ high when body.networks',
        ESCALATION_WARNINGS.smtpNetworks,
      ],
      [
        'SmtpConnectorsController_update_v1',
        '↑ high when body.requireTls = false',
        ESCALATION_WARNINGS.smtpTls,
      ],
      ['WebhooksController_update_v1', '↑ high when body.url', ESCALATION_WARNINGS.webhookUrl],
    ]);
    expect(ESCALATION_WARNINGS).toEqual({
      userEmail:
        'Changing the email address sends sign-in, invitation and password-reset mail to the new address.',
      smtpNetworks: 'Changes which networks may relay mail through the gateway.',
      smtpTls: 'Allows sessions without TLS on this connector.',
      webhookUrl: "Sends this webhook's event data to a new address.",
      initialAdmin: 'Invites an administrator with full access to the new organization.',
      planCode: "Changes the plan, and with it the organization's features and limits.",
      mfaOff: 'Users of the organization will no longer have to use MFA.',
      notificationEmail: 'Organization notifications go to a new address.',
    });
  });

  it('each table row escalates; harmless fields keep the registry risk', () => {
    const id = '0193aaaa-0000-7000-8000-000000000001';
    expect(risk('users_update', { id, body: { displayName: 'B' } })).toEqual({
      risk: 'low',
      warnings: [],
      escalatedFrom: null,
    });
    expect(risk('users_update', { id, body: { email: 'b@example.com' } })).toEqual({
      risk: 'high',
      warnings: [ESCALATION_WARNINGS.userEmail],
      escalatedFrom: 'low',
    });
    expect(risk('smtp_connectors_update', { id, body: { name: 'x' } }).risk).toBe('medium');
    expect(risk('smtp_connectors_update', { id, body: { networks: [] } }).risk).toBe('high');
    expect(risk('smtp_connectors_update', { id, body: { requireTls: true } }).risk).toBe('medium');
    expect(risk('smtp_connectors_update', { id, body: { requireTls: false } })).toEqual({
      risk: 'high',
      warnings: [ESCALATION_WARNINGS.smtpTls],
      escalatedFrom: 'medium',
    });
    expect(
      risk('webhooks_update', {
        webhookId: id,
        body: { url: 'https://x.example', expectedRowVersion: 1 },
      }).risk,
    ).toBe('high');
    expect(
      risk('webhooks_update', { webhookId: id, body: { name: 'n', expectedRowVersion: 1 } }).risk,
    ).toBe('low');
    expect(risk('organizations_create', { body: { initialAdmin: { email: 'a' } } }).risk).toBe(
      'high',
    );
    expect(risk('organizations_create', { body: { name: 'n' } }).risk).toBe('medium');
    expect(risk('organizations_update', { id, body: { name: 'n', planCode: 'p' } }).risk).toBe(
      'high',
    );
    expect(risk('organizations_update', { id, body: { name: 'n' } }).risk).toBe('medium');
    const settings = 'organization_configuration_update_settings';
    expect(risk(settings, { id, body: { mfaRequired: true } }).risk).toBe('medium');
    expect(risk(settings, { id, body: { mfaRequired: false } }).risk).toBe('high');
    // An explicit null is present (clearing the notification email also escalates).
    expect(risk(settings, { id, body: { notificationEmail: null } }).risk).toBe('high');
  });

  it('max of several escalations; warnings deduplicated in table order', () => {
    expect(
      risk('smtp_connectors_update', {
        id: 'x',
        body: { requireTls: false, networks: ['192.0.2.0/24'] },
      }),
    ).toEqual({
      risk: 'high',
      warnings: [ESCALATION_WARNINGS.smtpNetworks, ESCALATION_WARNINGS.smtpTls],
      escalatedFrom: 'medium',
    });
    const duplicate: RiskEscalation[] = [
      { when: { present: 'body.a' }, risk: 'medium', warning: 'W' },
      { when: { present: 'body.b' }, risk: 'high', warning: 'W' },
    ];
    expect(
      effectiveRisk({ name: 't', risk: 'low' }, { escalate: duplicate }, { body: { a: 1, b: 2 } }),
    ).toEqual({ risk: 'high', warnings: ['W'], escalatedFrom: 'low' });
    expect(
      effectiveRisk({ name: 't', risk: 'high' }, { escalate: duplicate }, { body: { a: 1 } }),
    ).toEqual({ risk: 'high', warnings: ['W'], escalatedFrom: null });
    expect(effectiveRisk({ name: 't', risk: 'medium' }, undefined, {})).toEqual({
      risk: 'medium',
      warnings: [],
      escalatedFrom: null,
    });
    expect(() => effectiveRisk({ name: 'r', risk: 'read' }, undefined, {})).toThrow(
      /non-confirmable/,
    );
    expect(maxRisk('medium', 'low')).toBe('medium');
    expect(escalationMatches({ equals: { path: 'body.x', value: null } }, { body: {} })).toBe(
      false,
    );
    expect(
      escalationMatches({ equals: { path: 'body.x', value: null } }, { body: { x: null } }),
    ).toBe(true);
  });

  it('property: never below the registry risk; adding an escalating field never lowers it', () => {
    const escalated = CONFIRMATION_SPECS.filter((s) => s.escalate && s.escalate.length > 0);
    const arbValue = fc.oneof(
      fc.constant(false),
      fc.constant(true),
      fc.constant(null),
      fc.string({ maxLength: 8 }),
      fc.integer(),
    );
    fc.assert(
      fc.property(
        fc.constantFrom(...escalated),
        fc.constantFrom(...CONFIRMATION_RISKS),
        fc.dictionary(
          fc.constantFrom(
            'name',
            'url',
            'email',
            'networks',
            'requireTls',
            'mfaRequired',
            'planCode',
            'notificationEmail',
            'initialAdmin',
            'other',
          ),
          arbValue,
        ),
        fc.nat(),
        arbValue,
        (spec, base, body, pick, value) => {
          const t = { name: 't', risk: base };
          const first = effectiveRisk(t, spec, { body });
          expect(ORDER[first.risk]).toBeGreaterThanOrEqual(ORDER[base]);
          const escalation = spec.escalate![pick % spec.escalate!.length]!;
          const path =
            'present' in escalation.when ? escalation.when.present : escalation.when.equals.path;
          const key = path.replace(/^body\./, '');
          const added = effectiveRisk(t, spec, {
            body: {
              ...body,
              [key]: 'present' in escalation.when ? value : escalation.when.equals.value,
            },
          });
          // Adding the field (with a matching value) reaches at least that escalation's risk and
          // never lowers the result of the other fields' escalations.
          expect(ORDER[added.risk]).toBeGreaterThanOrEqual(ORDER[escalation.risk]);
          expect(ORDER[added.risk]).toBeGreaterThanOrEqual(ORDER[base]);
          if (!(key in body)) expect(ORDER[added.risk]).toBeGreaterThanOrEqual(ORDER[first.risk]);
        },
      ),
      { numRuns: 500 },
    );
  });
});

describe('conditional risk escalation of step AI-4 (design 32 D4, I20)', () => {
  const W = AI4_ESCALATION_WARNINGS;
  const ID = '0193aaaa-0000-7000-8000-000000000101';

  it('has the escalations of the design table, with its fixed warnings', () => {
    const table = CONFIRMATION_SPECS.filter(
      (s) => s.escalate && s.operationId in AI4_WRITES_TESTED_BY,
    ).flatMap((s) =>
      s.escalate!.map((e) => [findToolName(s.operationId), escalationNote(e), e.warning]),
    );
    expect(table).toEqual([
      ['ato_accounts_update', '↑ high when body.protected = true', W.atoProtected],
      ['ato_accounts_set_override', '↑ high when body.verdict = benign', W.atoBenign],
      ['ato_providers_create', '↑ high when body.settings', W.idpSettings],
      ['incidents_update', '↑ medium when body.status = resolved', W.incidentResolved],
      ['incidents_update', '↑ high when body.status = false_positive', W.incidentFalsePositive],
      ['incidents_update', '↑ high when body.categoryFeedback', W.incidentFeedback],
      ['bec_executives_create', '↑ high when body.knownAddresses', W.executiveAddresses],
      ['bec_executives_update', '↑ high when body.enabled = false', W.executiveDisabled],
      ['bec_executives_update', '↑ high when body.knownAddresses', W.executiveAddresses],
      ['bec_trusted_senders_update', '↑ high when body.expiresAt', W.trustedSenderExpiry],
      ['bec_vendors_create', '↑ high when body.knownSenders', W.vendorSenders],
      ['bec_vendors_create', '↑ high when body.domains', W.vendorSenders],
      [
        'bec_vendors_create',
        '↑ high when body.paymentChangeSensitive = false',
        W.vendorPaymentChange,
      ],
      ['bec_vendors_update', '↑ high when body.enabled = false', W.vendorDisabled],
      ['bec_vendors_update', '↑ high when body.knownSenders', W.vendorSenders],
      ['bec_vendors_update', '↑ high when body.domains', W.vendorSenders],
      [
        'bec_vendors_update',
        '↑ high when body.paymentChangeSensitive = false',
        W.vendorPaymentChange,
      ],
      ['bec_message_feedback_record', '↑ high when body.suppress', W.becSuppress],
      ['dlp_dictionaries_update', '↑ high when body.enabled = false', W.dlpDetectorDisabled],
      ['dlp_exceptions_update', '↑ high when body.enabled = true', W.dlpExceptionWidened],
      ['dlp_exceptions_update', '↑ high when body.expiresAt', W.dlpExceptionWidened],
      ['dlp_exceptions_update', '↑ high when body.filters', W.dlpExceptionWidened],
      ['dlp_patterns_update', '↑ high when body.enabled = false', W.dlpDetectorDisabled],
      ['dlp_patterns_update', '↑ medium when body.pattern', W.dlpPatternChanged],
      ['dlp_policies_update', '↑ high when body.enabled = false', W.dlpPolicyDisabled],
      ['dlp_policies_update', '↑ high when body.mode = monitor', W.dlpPolicyMonitor],
      ['dlp_policies_create_rule', '↑ high when body.action = allow', W.dlpAllowRule],
      ['dlp_policies_update_rule', '↑ high when body.action = allow', W.dlpAllowRule],
      ['dlp_policies_update_rule', '↑ high when body.enabled = false', W.dlpRuleDisabled],
    ]);
    expect(AI4_ESCALATION_WARNINGS).toEqual({
      atoProtected:
        'Automated responses will never act on this account, even when it is compromised.',
      atoBenign:
        "The account's risk is held below the medium band and automation never acts on it until a strong new signal arrives.",
      idpSettings:
        'Sets which data the gateway reads and which response actions it may take in the identity provider.',
      incidentResolved: 'The incident is closed and cannot be re-opened.',
      incidentFalsePositive:
        'Marks the incident a false positive: its signals are dismissed and the account is rescored.',
      incidentFeedback:
        'Feedback can add trusted contexts for the account and dismiss its signals.',
      becSuppress: 'Suppresses these BEC findings for the sender scope for the given days.',
      trustedSenderExpiry: 'Changes how long this sender stays trusted (null: no expiry).',
      executiveDisabled: 'Impersonation of this executive is no longer detected.',
      executiveAddresses: "Mail from these addresses is treated as the executive's own.",
      vendorDisabled: 'Impersonation of this vendor is no longer detected.',
      vendorSenders: "Mail from these senders or domains is treated as the vendor's own.",
      vendorPaymentChange: 'Payment-change requests from this vendor are no longer flagged.',
      dlpPolicyDisabled: 'This DLP policy stops evaluating mail.',
      dlpPolicyMonitor: 'Matches are only recorded; mail is no longer blocked or held.',
      dlpAllowRule: 'Matching mail is allowed without further DLP action.',
      dlpRuleDisabled: 'This rule stops matching.',
      dlpDetectorDisabled: 'This detector stops matching in every policy that uses it.',
      dlpPatternChanged: 'Changes what the detector matches.',
      dlpExceptionWidened: 'Widens or extends who is exempt from DLP.',
    });
  });

  it('each row escalates; harmless changes keep the registry risk', () => {
    const rows: Array<[string, Record<string, unknown>, ConfirmationRisk, ConfirmationRisk]> = [
      // [tool, arguments, registry risk, effective risk]
      ['ato_accounts_update', { accountId: ID, body: { protected: true } }, 'low', 'high'],
      ['ato_accounts_update', { accountId: ID, body: { protected: false } }, 'low', 'low'],
      [
        'ato_accounts_set_override',
        { accountId: ID, body: { verdict: 'benign' } },
        'medium',
        'high',
      ],
      [
        'ato_accounts_set_override',
        { accountId: ID, body: { verdict: 'compromised' } },
        'medium',
        'medium',
      ],
      ['ato_providers_create', { body: { connectionId: ID, settings: {} } }, 'medium', 'high'],
      ['ato_providers_create', { body: { connectionId: ID } }, 'medium', 'medium'],
      ['incidents_update', { incidentId: ID, body: { status: 'resolved' } }, 'low', 'medium'],
      ['incidents_update', { incidentId: ID, body: { status: 'false_positive' } }, 'low', 'high'],
      ['incidents_update', { incidentId: ID, body: { categoryFeedback: {} } }, 'low', 'high'],
      ['incidents_update', { incidentId: ID, body: { status: 'investigating' } }, 'low', 'low'],
      ['bec_executives_create', { body: { displayName: 'CEO' } }, 'low', 'low'],
      ['bec_executives_create', { body: { displayName: 'CEO', enabled: false } }, 'low', 'low'],
      [
        'bec_executives_create',
        { body: { displayName: 'CEO', knownAddresses: ['ceo@freemail.test'] } },
        'low',
        'high',
      ],
      ['bec_executives_update', { id: ID, body: { enabled: false } }, 'low', 'high'],
      ['bec_executives_update', { id: ID, body: { knownAddresses: [] } }, 'low', 'high'],
      ['bec_executives_update', { id: ID, body: { title: 'CFO' } }, 'low', 'low'],
      ['bec_trusted_senders_update', { id: ID, body: { expiresAt: null } }, 'low', 'high'],
      ['bec_trusted_senders_update', { id: ID, body: { reason: 'r' } }, 'low', 'low'],
      ['bec_vendors_create', { body: { name: 'Acme' } }, 'low', 'low'],
      [
        'bec_vendors_create',
        { body: { name: 'Acme', paymentChangeSensitive: true } },
        'low',
        'low',
      ],
      ['bec_vendors_create', { body: { name: 'Acme', knownSenders: ['a@x.test'] } }, 'low', 'high'],
      ['bec_vendors_create', { body: { name: 'Acme', domains: ['x.test'] } }, 'low', 'high'],
      [
        'bec_vendors_create',
        { body: { name: 'Acme', paymentChangeSensitive: false } },
        'low',
        'high',
      ],
      ['bec_vendors_update', { id: ID, body: { enabled: false } }, 'low', 'high'],
      ['bec_vendors_update', { id: ID, body: { knownSenders: ['a@x.test'] } }, 'low', 'high'],
      ['bec_vendors_update', { id: ID, body: { domains: ['x.test'] } }, 'low', 'high'],
      ['bec_vendors_update', { id: ID, body: { paymentChangeSensitive: false } }, 'low', 'high'],
      ['bec_vendors_update', { id: ID, body: { paymentChangeSensitive: true } }, 'low', 'low'],
      ['bec_message_feedback_record', { body: { kind: 'false_positive' } }, 'low', 'low'],
      ['bec_message_feedback_record', { body: { suppress: {} } }, 'low', 'high'],
      ['dlp_dictionaries_update', { id: ID, body: { enabled: false } }, 'low', 'high'],
      ['dlp_dictionaries_update', { id: ID, body: { name: 'n' } }, 'low', 'low'],
      ['dlp_exceptions_update', { id: ID, body: { enabled: true } }, 'low', 'high'],
      ['dlp_exceptions_update', { id: ID, body: { enabled: false } }, 'low', 'low'],
      ['dlp_exceptions_update', { id: ID, body: { expiresAt: 'x' } }, 'low', 'high'],
      ['dlp_exceptions_update', { id: ID, body: { filters: null } }, 'low', 'high'],
      ['dlp_patterns_update', { id: ID, body: { enabled: false } }, 'low', 'high'],
      ['dlp_patterns_update', { id: ID, body: { pattern: 'x' } }, 'low', 'medium'],
      ['dlp_patterns_update', { id: ID, body: { severity: 'high' } }, 'low', 'low'],
      ['dlp_policies_update', { id: ID, body: { enabled: false } }, 'low', 'high'],
      ['dlp_policies_update', { id: ID, body: { mode: 'monitor' } }, 'low', 'high'],
      ['dlp_policies_update', { id: ID, body: { mode: 'enforce' } }, 'low', 'low'],
      ['dlp_policies_create_rule', { id: ID, body: { action: 'allow' } }, 'low', 'high'],
      ['dlp_policies_create_rule', { id: ID, body: { action: 'block' } }, 'low', 'low'],
      ['dlp_policies_update_rule', { id: ID, body: { action: 'allow' } }, 'low', 'high'],
      ['dlp_policies_update_rule', { id: ID, body: { enabled: false } }, 'low', 'high'],
      ['dlp_policies_update_rule', { id: ID, body: { name: 'n' } }, 'low', 'low'],
    ];
    for (const [name, args, base, expected] of rows) {
      expect(tool(name).risk, name).toBe(base);
      const result = risk(name, args);
      expect(result.risk, `${name} ${JSON.stringify(args)}`).toBe(expected);
      expect(result.escalatedFrom).toBe(expected === base ? null : base);
      expect(result.warnings.length > 0).toBe(expected !== base);
    }
  });

  it('several escalations: the maximum, warnings deduplicated in table order', () => {
    expect(
      risk('incidents_update', {
        incidentId: ID,
        body: { status: 'false_positive', categoryFeedback: {} },
      }),
    ).toEqual({
      risk: 'high',
      warnings: [W.incidentFalsePositive, W.incidentFeedback],
      escalatedFrom: 'low',
    });
    expect(
      risk('bec_vendors_update', {
        id: ID,
        body: { knownSenders: ['a@x.test'], domains: ['x.test'], enabled: false },
      }),
    ).toEqual({
      risk: 'high',
      warnings: [W.vendorDisabled, W.vendorSenders],
      escalatedFrom: 'low',
    });
    expect(
      risk('dlp_exceptions_update', {
        id: ID,
        body: { enabled: true, expiresAt: 'x', filters: null },
      }),
    ).toEqual({ risk: 'high', warnings: [W.dlpExceptionWidened], escalatedFrom: 'low' });
    expect(risk('dlp_patterns_update', { id: ID, body: { pattern: 'x', enabled: false } })).toEqual(
      {
        risk: 'high',
        warnings: [W.dlpDetectorDisabled, W.dlpPatternChanged],
        escalatedFrom: 'low',
      },
    );
  });

  it('the trust and exception creates, ATO settings and IdP settings are high without escalation', () => {
    for (const name of [
      'ato_accounts_add_trusted_context',
      'bec_trusted_senders_create',
      'dlp_exceptions_create',
      'ato_settings_update',
      'ato_providers_update',
      'ato_responses_request',
      'ato_responses_approve',
      'ato_responses_rollback',
    ])
      expect(tool(name).risk, name).toBe('high');
  });

  it('property: the effective risk is never below the registry risk (every enabled write)', () => {
    const specs = CONFIRMATION_SPECS.filter((s) => !s.native);
    const paths = [
      ...new Set(
        specs.flatMap((s) =>
          (s.escalate ?? []).map((e) =>
            ('present' in e.when ? e.when.present : e.when.equals.path).replace(/^body\./, ''),
          ),
        ),
      ),
    ];
    const arbValue = fc.oneof(
      fc.boolean(),
      fc.constant(null),
      fc.constantFrom('benign', 'resolved', 'false_positive', 'monitor', 'allow', 'enforce'),
      fc.string({ maxLength: 6 }),
      fc.integer(),
      fc.constant({}),
    );
    fc.assert(
      fc.property(
        fc.constantFrom(...specs),
        fc.dictionary(fc.constantFrom(...paths, 'name', 'reason'), arbValue),
        (spec, body) => {
          const write = findOperationTool(spec.operationId);
          const result = effectiveRisk(write, spec, { body });
          expect(ORDER[result.risk]).toBeGreaterThanOrEqual(ORDER[write.risk as ConfirmationRisk]);
          if (result.escalatedFrom !== null) expect(result.escalatedFrom).toBe(write.risk);
        },
      ),
      { numRuns: 1000 },
    );
  });
});

function findToolName(operationId: string): string {
  return findOperationTool(operationId).name;
}

function findOperationTool(operationId: string): OperationTool {
  const found = ALL_TOOLS.find((t) => t.operationId === operationId);
  if (!found) throw new Error(operationId);
  return found;
}
