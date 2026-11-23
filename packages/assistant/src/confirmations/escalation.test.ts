import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { findTool } from '../registry/registry';
import type { OperationTool } from '../registry/types';
import {
  effectiveRisk,
  escalationMatches,
  escalationNote,
  maxRisk,
  type RiskEscalation,
} from './escalation';
import { CONFIRMATION_SPECS, ESCALATION_WARNINGS, confirmationSpecOf } from './specs';
import { CONFIRMATION_RISKS, type ConfirmationRisk } from './types';

const tool = (name: string): OperationTool => findTool(name)!;
const risk = (name: string, args: Record<string, unknown>) =>
  effectiveRisk(tool(name), confirmationSpecOf(tool(name).operationId), args);
const ORDER: Record<ConfirmationRisk, number> = { low: 0, medium: 1, high: 2 };

describe('conditional risk escalation (design 30 D4)', () => {
  it('has the escalations of the design table', () => {
    const table = CONFIRMATION_SPECS.filter((s) => s.escalate).flatMap((s) =>
      s.escalate!.map((e) => [s.operationId, escalationNote(e), e.warning]),
    );
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
