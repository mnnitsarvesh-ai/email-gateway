import 'server-only';
import type { SuccessBody } from '@/lib/api/types';
import { SCAN_SETTINGS } from '@/features/settings/test-data';
import { apiError, ok, type FixtureHandlers } from '../types';
import { bodyOf, withPrincipal } from './reports';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Notification settings, personal preferences and scan settings (WP3). Scan settings start
 * from the synthetic engine views shared with the component tests; PUT replaces the override
 * (version check, bounds check for Rspamd scores), DELETE resets it. State per organization on
 * globalThis.
 */

type Notifications = SuccessBody<'NotificationsController_settings_v1'>;
type Preferences = SuccessBody<'NotificationsController_preferences_v1'>;
type EngineView = SuccessBody<'ScanSettingsController_list_v1'>['data'][number];

interface SettingsState {
  notifications: Map<string, Notifications>;
  preferences: Map<string, Preferences>;
  scan: Map<string, EngineView[]>;
}
const store = globalThis as typeof globalThis & { __egDevFixtureSettingsState?: SettingsState };
const state: SettingsState = (store.__egDevFixtureSettingsState ??= {
  notifications: new Map(),
  preferences: new Map(),
  scan: new Map(),
});

const DEFAULT_ALERTS: Notifications['settings']['alerts'] = {
  threatDetected: { enabled: true, minSeverity: 'high', throttleMinutes: 60 },
  domainDnsFailed: { enabled: true, throttleMinutes: 1440 },
  webhookDisabled: { enabled: true, throttleMinutes: 1440 },
  includeOrganizationContact: false,
};

function notificationsOf(orgId: string): Notifications {
  let view = state.notifications.get(orgId);
  if (!view) {
    view = {
      settings: { alerts: structuredClone(DEFAULT_ALERTS) },
      stored: null,
      invalidStored: false,
      rowVersion: 0,
      updatedAt: null,
      defaults: { alerts: structuredClone(DEFAULT_ALERTS) },
      bounds: {
        threatDetected: { minThrottleMinutes: 15, maxThrottleMinutes: 1440 },
        domainDnsFailed: { minThrottleMinutes: 60, maxThrottleMinutes: 10080 },
        webhookDisabled: { minThrottleMinutes: 60, maxThrottleMinutes: 10080 },
      },
    };
    state.notifications.set(orgId, view);
  }
  return view;
}

function preferencesOf(key: string): Preferences {
  let view = state.preferences.get(key);
  if (!view) {
    view = {
      optOut: [],
      quarantineDigestOptOut: false,
      quarantineDigestOptOutAllowed: true,
      kinds: [
        'threat_detected',
        'domain_dns_failed',
        'webhook_disabled',
        'policy_alert',
        'quarantine_admin_alert',
        'quarantine_approval_requested',
      ],
      invalidStored: false,
    };
    state.preferences.set(key, view);
  }
  return view;
}

function leafPaths(value: unknown, prefix = ''): string[] {
  if (value === null || typeof value !== 'object' || Array.isArray(value))
    return prefix ? [prefix] : [];
  return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) =>
    leafPaths(v, prefix ? `${prefix}.${k}` : k),
  );
}
function getPath(source: unknown, path: string): unknown {
  return path
    .split('.')
    .reduce<unknown>(
      (node, part) =>
        node && typeof node === 'object' ? (node as Record<string, unknown>)[part] : undefined,
      source,
    );
}
function setPath(target: Record<string, unknown>, path: string, value: unknown) {
  const parts = path.split('.');
  let node = target;
  for (const part of parts.slice(0, -1)) node = (node[part] ??= {}) as Record<string, unknown>;
  node[parts.at(-1) as string] = value;
}

/** The effective values without any override (platform values where the view has them). */
function baseEffective(view: EngineView): Record<string, unknown> {
  const base = structuredClone(view.effective) as Record<string, unknown>;
  for (const path of leafPaths(view.override)) {
    const platform = getPath(view.platform, path);
    const current = getPath(base, path);
    setPath(base, path, platform !== undefined ? platform : Array.isArray(current) ? [] : current);
  }
  return base;
}
const BASES = new Map(SCAN_SETTINGS.data.map((view) => [view.engine, baseEffective(view)]));

function scanOf(orgId: string): EngineView[] {
  let views = state.scan.get(orgId);
  if (!views) {
    views = structuredClone(SCAN_SETTINGS.data);
    state.scan.set(orgId, views);
  }
  return views;
}

function applyOverride(view: EngineView, override: Record<string, unknown> | null): EngineView {
  const effective = structuredClone<Record<string, unknown>>(BASES.get(view.engine) ?? {});
  for (const path of leafPaths(override)) setPath(effective, path, getPath(override, path));
  return {
    ...view,
    override: override as never,
    effective: effective as never,
    overrideApplied: override !== null,
    violations: [],
    version: view.version + 1,
    updatedAt: new Date().toISOString(),
  };
}

export const fixtures: FixtureHandlers = {
  NotificationsController_settings_v1: (request) =>
    withPrincipal(request, (p) =>
      ok('NotificationsController_settings_v1', notificationsOf(p.organizationId)),
    ),

  NotificationsController_putSettings_v1: (request) =>
    withPrincipal(request, (p) => {
      const view = notificationsOf(p.organizationId);
      const b = bodyOf(request);
      if (b.expectedRowVersion !== view.rowVersion) {
        return apiError(
          409,
          'version_conflict',
          `The settings changed since rowVersion ${String(b.expectedRowVersion)}`,
          { currentRowVersion: view.rowVersion },
        );
      }
      const stored = (b.settings ?? {}) as Notifications['stored'] & object;
      const alerts = structuredClone(DEFAULT_ALERTS);
      const s = stored.alerts ?? {};
      Object.assign(alerts.threatDetected, s.threatDetected ?? {});
      Object.assign(alerts.domainDnsFailed, s.domainDnsFailed ?? {});
      Object.assign(alerts.webhookDisabled, s.webhookDisabled ?? {});
      if (typeof s.includeOrganizationContact === 'boolean')
        alerts.includeOrganizationContact = s.includeOrganizationContact;
      const next: Notifications = {
        ...view,
        settings: { alerts },
        stored,
        rowVersion: view.rowVersion + 1,
        updatedAt: new Date().toISOString(),
      };
      state.notifications.set(p.organizationId, next);
      return ok('NotificationsController_putSettings_v1', next);
    }),

  NotificationsController_preferences_v1: (request) =>
    withPrincipal(request, (p) =>
      ok('NotificationsController_preferences_v1', preferencesOf(`${p.organizationId}:${p.role}`)),
    ),

  NotificationsController_putPreferences_v1: (request) =>
    withPrincipal(request, (p) => {
      const key = `${p.organizationId}:${p.role}`;
      const b = bodyOf(request);
      const current = preferencesOf(key);
      const next: Preferences = {
        ...current,
        optOut: Array.isArray(b.optOut) ? (b.optOut as Preferences['optOut']) : current.optOut,
        quarantineDigestOptOut: b.quarantineDigestOptOut === true,
      };
      state.preferences.set(key, next);
      return ok('NotificationsController_putPreferences_v1', next);
    }),

  ScanSettingsController_list_v1: (request) =>
    withPrincipal(request, (p) =>
      ok('ScanSettingsController_list_v1', {
        data: scanOf(p.organizationId),
        note: SCAN_SETTINGS.note,
      }),
    ),

  ScanSettingsController_replace_v1: (request) =>
    withPrincipal(request, (p) => {
      const views = scanOf(p.organizationId);
      const index = views.findIndex((v) => v.engine === request.params.engine);
      const view = views[index];
      if (!view) return apiError(404, 'scan_engine_not_found', 'Unknown engine');
      const b = bodyOf(request);
      if (b.expectedVersion !== view.version) {
        return apiError(
          409,
          'version_conflict',
          `The settings changed (current version ${view.version})`,
          { currentVersion: view.version },
        );
      }
      const settings = (b.settings ?? {}) as Record<string, unknown>;
      if (view.engine === 'rspamd') {
        const spam = (settings.spamScore as number | undefined) ?? view.platform.spamScore;
        const suspicious =
          (settings.suspiciousScore as number | undefined) ?? view.platform.suspiciousScore;
        if (suspicious >= spam) {
          return apiError(422, 'scan_settings_invalid', 'The settings are not valid', {
            violations: [
              {
                path: 'suspiciousScore',
                code: 'threshold_order',
                message: 'Must be lower than the spam score',
              },
            ],
          });
        }
      }
      const next = applyOverride(view, Object.keys(settings).length > 0 ? settings : null);
      views[index] = next;
      return ok('ScanSettingsController_replace_v1', {
        ...next,
        note: SCAN_SETTINGS.note,
      });
    }),

  ScanSettingsController_reset_v1: (request) =>
    withPrincipal(request, (p) => {
      const views = scanOf(p.organizationId);
      const index = views.findIndex((v) => v.engine === request.params.engine);
      const view = views[index];
      if (!view) return apiError(404, 'scan_engine_not_found', 'Unknown engine');
      if (Number(request.query.get('expectedVersion')) !== view.version) {
        return apiError(
          409,
          'version_conflict',
          `The settings changed (current version ${view.version})`,
          { currentVersion: view.version },
        );
      }
      const next = applyOverride(view, null);
      views[index] = next;
      return ok('ScanSettingsController_reset_v1', { ...next, note: SCAN_SETTINGS.note });
    }),
};
