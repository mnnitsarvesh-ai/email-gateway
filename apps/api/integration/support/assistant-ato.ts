/**
 * ATO fixtures of the step AI-4 assistant suites (docs/plan/steps/32-ai-chat-security-
 * operations.md §9 item 3): a synthetic `it-ato-*` organization with `ato_detection` on (the
 * step 8.4 `AtoSeeder`, rows written by the api's own library stores) whose assistant is enabled
 * through the documented path, two chat analysts (A requests, B decides) holding every tenant
 * permission with MFA sessions, and small helpers around the ATO response routes. Nothing here
 * is used by production code; tests never reach an LLM or a provider endpoint.
 */
import { randomUUID } from 'node:crypto';
import type { AtoResponseAction } from '@email-gateway/database';
import type { IntegrationApp } from './app';
import {
  ALL_TENANT_PERMISSIONS,
  call,
  enableAssistant,
  type Member,
  memberWith,
  waitForRead,
} from './assistant';
import { AtoSeeder, type AtoTenant } from './ato';
import type { FixtureOrganization, Fixtures } from './fixtures';
import { idem } from './http';

export const ATO = '/api/v1/ato';

export interface AtoChat {
  seed: AtoSeeder;
  tenant: AtoTenant;
  org: FixtureOrganization;
  /** Requests responses (and is refused deciding them). */
  analystA: Member;
  /** Decides A's requests. */
  analystB: Member;
}

/**
 * An ATO organization with the assistant on: the seeder's tenant (its analysts, admin, auditor
 * and API key stay unused by chat), two chat analysts with every tenant permission (a custom
 * role with `assistant:use`) and the feature + tenant setting enabled by `operator`.
 */
export async function atoChatTenant(
  ctx: IntegrationApp,
  fx: Fixtures,
  operator: Member,
): Promise<AtoChat> {
  const seed = new AtoSeeder(ctx, fx);
  const tenant = await seed.tenant();
  const grant = { permissions: [...ALL_TENANT_PERMISSIONS] };
  const analystA = await memberWith(ctx, fx, tenant.org, grant, {
    displayName: 'Analyst A (requester)',
  });
  const analystB = await memberWith(ctx, fx, tenant.org, grant, {
    displayName: 'Analyst B (approver)',
  });
  await enableAssistant(ctx, operator, tenant.org, analystA);
  return { seed, tenant, org: tenant.org, analystA, analystB };
}

/** `POST /ato/incidents/{incidentId}/responses` directly (with an `Idempotency-Key`). */
export function requestResponse(
  ctx: IntegrationApp,
  headers: Record<string, string>,
  incidentId: string,
  body: Record<string, unknown>,
) {
  return call(ctx, headers, 'post', `${ATO}/incidents/${incidentId}/responses`, body).set(idem());
}

/** `POST /ato/responses/{responseId}/<verb>` directly (with an `Idempotency-Key`). */
export function decideDirectly(
  ctx: IntegrationApp,
  headers: Record<string, string>,
  responseId: string,
  verb: 'approve' | 'reject' | 'cancel' | 'rollback',
  body: Record<string, unknown> = {},
) {
  return call(ctx, headers, 'post', `${ATO}/responses/${responseId}/${verb}`, body).set(idem());
}

/** The response row (writer). */
export function responseRow(ctx: IntegrationApp, publicId: string): Promise<AtoResponseAction> {
  return ctx.prisma.atoResponseAction.findUniqueOrThrow({ where: { publicId } });
}

/**
 * Waits until `who` reads the response on the replica in `status` (the precondition read of
 * the chat tools is a replica read).
 */
export function responseVisible(
  ctx: IntegrationApp,
  who: Member,
  responseId: string,
  status: string,
): Promise<Record<string, unknown>> {
  return waitForRead(ctx, who, `${ATO}/responses/${responseId}`, (b) => b.status === status);
}

/** A unique label for a synthetic mailbox (`<label>@it-ato.example.test`). */
export const mailboxLabel = (prefix: string): string => `${prefix}-${randomUUID().slice(0, 6)}`;
