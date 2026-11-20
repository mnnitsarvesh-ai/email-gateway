/**
 * The step 8.4 contract kit (`describeProviderAdapterContract`, D15) run against both 8.5
 * adapters on their in-process simulators (design note §11.2, merge note M1; ADR-0086 decision 4:
 * a release gate). Each factory call returns a fresh adapter over the same simulators and stores
 * (another worker process), probed first so `capabilities()` is the effective set.
 */
import { describeProviderAdapterContract } from '@email-gateway/ato-detection/testing';
import { afterAll, beforeAll } from 'vitest';
import type { IdpAdapter } from '../adapter-types';
import { googleCustomer, GS_USERS } from './datasets/google';
import { MS_USERS } from './datasets/microsoft';
import { createGoogleTestbed, type GoogleTestbed } from './google-harness';
import { createMicrosoftTestbed, type MicrosoftTestbed } from './harness';

const signal = () => new AbortController().signal;

async function probed(adapter: IdpAdapter): Promise<IdpAdapter> {
  await adapter.probe(signal());
  return adapter;
}

let microsoft: MicrosoftTestbed;
let google: GoogleTestbed;

beforeAll(async () => {
  microsoft = await createMicrosoftTestbed();
  google = await createGoogleTestbed({
    // A third OAuth authorization (the default dataset has two), so the kit's ingest assertions
    // have at least three `oauth_consents` events.
    customer: (now) => {
      const customer = googleCustomer(now);
      const template = customer.activities.find(
        (a) => a.id.applicationName === 'token' && a.events.some((e) => e.name === 'authorize'),
      );
      if (template) {
        const extra = structuredClone(template);
        extra.id.uniqueQualifier = '-7700001';
        extra.id.time = new Date(now.getTime() - 11 * 60_000).toISOString();
        customer.activities.push(extra);
      }
      return customer;
    },
  });
});

afterAll(async () => {
  await microsoft?.stop();
  await google?.stop();
});

describeProviderAdapterContract('msgraph-ato/1', () => probed(microsoft.newAdapter()), {
  identity: {
    provider: 'microsoft_entra',
    externalId: MS_USERS.blake,
    userPrincipalName: 'blake@contoso-it.example',
    primaryEmail: 'blake@contoso-it.example',
  },
  address: 'blake@contoso-it.example',
  streamsWithEvents: ['sign_ins'],
  injectIngestFailure: () =>
    microsoft.sims.script.inject({
      simulator: 'graph',
      path: '/v1.0/auditLogs/signIns',
      status: 503,
    }),
  injectThrottle: () =>
    microsoft.sims.script.inject({
      simulator: 'graph',
      path: '/v1.0/auditLogs/signIns',
      status: 429,
      retryAfter: '3',
    }),
  maxPolls: 10,
});

describeProviderAdapterContract('gws-ato/1', () => probed(google.newAdapter()), {
  identity: {
    provider: 'google_workspace',
    externalId: GS_USERS.blake,
    primaryEmail: 'blake@fabrikam-it.example',
  },
  address: 'blake@fabrikam-it.example',
  // The Reports `login` feed also carries its `risk_events` companion events (D3), while the kit
  // expects every event of a drained stream to be of that stream: the single-stream `token`
  // feed is the Google subject here (sign-ins are covered by the conformance suite).
  streamsWithEvents: ['oauth_consents'],
  injectIngestFailure: () =>
    google.sims.script.inject({
      simulator: 'google-admin',
      path: '/admin/reports/v1/activity',
      status: 503,
    }),
  injectThrottle: () =>
    google.sims.script.inject({
      simulator: 'google-admin',
      path: '/admin/reports/v1/activity',
      status: 429,
      retryAfter: '3',
    }),
  maxPolls: 10,
});
