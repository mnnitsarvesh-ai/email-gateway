/**
 * Category handlers (D24, ADR-0075): each incident category plugs into the shared model with its
 * subject types, its read/manage permissions, its subject resolution, its detail, an optional
 * transition hook, a feedback schema for the generic PATCH and its report sections. ATO registers
 * `account_takeover` (`@email-gateway/ato-detection` `atoIncidentHandler`); ATP-4 appends its own.
 * The generic routes derive their permission lists from the registry, so a category's incidents
 * are visible only to holders of that category's read permission.
 */
import type { Prisma } from '@email-gateway/database';
import type {
  SecurityIncidentCategory,
  SecurityIncidentStatus,
  SecurityIncidentSubjectType,
} from '@email-gateway/security-contracts';
import type { z } from 'zod';
import type { IncidentRow } from './rows';
import type { IncidentActor } from './vocabulary';

/** A permission key such as `ato:read` (the api's `PermissionKey`). */
export type PermissionKey = string;

export type IncidentTx = Prisma.TransactionClient;

export interface ResolvedSubject {
  refId: bigint;
  refTime: Date | null;
  publicId: string;
}

export interface IncidentReportSection {
  id: string;
  title: string;
  data: unknown;
}

export interface IncidentCategoryHandler {
  readonly category: SecurityIncidentCategory;
  readonly subjectTypes: readonly SecurityIncidentSubjectType[];
  readonly permissions: { read: PermissionKey; manage: PermissionKey };
  /** Resolves a manual-creation subject reference inside the tenant (null = not found). */
  resolveSubject(
    tx: IncidentTx,
    organizationId: bigint,
    ref: { type: string; publicId: string },
  ): Promise<ResolvedSubject | null>;
  /** Category-specific detail for reads and the report (bounded, no message content). */
  loadDetail(tx: IncidentTx, incident: IncidentRow): Promise<Record<string, unknown>>;
  /**
   * Locks the incident's subject rows before the incident row (`IncidentStore.lockForUpdate`), so
   * every writer takes subject → incident in one global order. ATO: the account row, which the
   * detect role locks before it locks the account's incident and which `onTransition` updates.
   */
  lockSubject?(tx: IncidentTx, incident: IncidentRow): Promise<void>;
  /** Hook inside the transition transaction (ATO: dismiss signals and rescore on false_positive). */
  onTransition?(
    tx: IncidentTx,
    incident: IncidentRow,
    from: SecurityIncidentStatus,
    to: SecurityIncidentStatus,
    actor: IncidentActor,
    feedback: unknown,
  ): Promise<void>;
  /** Strict zod schema of the category's PATCH `categoryFeedback` (null = none accepted). */
  readonly feedbackSchema: z.ZodType | null;
  reportSections(tx: IncidentTx, incident: IncidentRow): Promise<IncidentReportSection[]>;
}

const PERMISSION_PATTERN = /^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$/;

/** The registry of category handlers (one per category). */
export class IncidentCategoryRegistry {
  private readonly handlers = new Map<string, IncidentCategoryHandler>();

  constructor(handlers: readonly IncidentCategoryHandler[] = []) {
    for (const handler of handlers) this.register(handler);
  }

  /** Registers a handler. Throws on a duplicate category or malformed permissions. */
  register(handler: IncidentCategoryHandler): this {
    if (this.handlers.has(handler.category)) {
      throw new Error(`Incident category ${handler.category} is already registered`);
    }
    if (
      !PERMISSION_PATTERN.test(handler.permissions.read) ||
      !PERMISSION_PATTERN.test(handler.permissions.manage)
    ) {
      throw new Error(`Incident category ${handler.category} has malformed permissions`);
    }
    if (handler.subjectTypes.length === 0) {
      throw new Error(`Incident category ${handler.category} declares no subject type`);
    }
    this.handlers.set(handler.category, handler);
    return this;
  }

  has(category: string): boolean {
    return this.handlers.has(category);
  }

  /** The handler of `category`, or undefined when it is not registered. */
  find(category: string): IncidentCategoryHandler | undefined {
    return this.handlers.get(category);
  }

  /** The handler of `category`. Throws when it is not registered. */
  get(category: string): IncidentCategoryHandler {
    const handler = this.handlers.get(category);
    if (!handler) throw new Error(`Incident category ${category} is not registered`);
    return handler;
  }

  /** Registered categories in registration order. */
  categories(): SecurityIncidentCategory[] {
    return [...this.handlers.keys()] as SecurityIncidentCategory[];
  }

  /** Every category's read permission, unique and sorted (`RequireAnyPermission` lists). */
  readPermissions(): PermissionKey[] {
    return [...new Set([...this.handlers.values()].map((h) => h.permissions.read))].sort();
  }

  /** Every category's manage permission, unique and sorted. */
  managePermissions(): PermissionKey[] {
    return [...new Set([...this.handlers.values()].map((h) => h.permissions.manage))].sort();
  }

  /** Categories whose read permission is among `permissions` (registration order). */
  categoriesReadableBy(permissions: Iterable<PermissionKey>): SecurityIncidentCategory[] {
    const held = new Set(permissions);
    return [...this.handlers.values()]
      .filter((h) => held.has(h.permissions.read))
      .map((h) => h.category);
  }

  /** Categories whose manage permission is among `permissions` (registration order). */
  categoriesManageableBy(permissions: Iterable<PermissionKey>): SecurityIncidentCategory[] {
    const held = new Set(permissions);
    return [...this.handlers.values()]
      .filter((h) => held.has(h.permissions.manage))
      .map((h) => h.category);
  }
}
