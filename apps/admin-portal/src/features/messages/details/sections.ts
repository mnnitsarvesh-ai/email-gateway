import { z } from 'zod';
import type { OperationId } from '@/lib/api/types';
import { canPerform, describeRequirement } from '@/lib/auth/permissions';

/**
 * The 14 sections of Email Details (step 7.2 §1.4, §2 E11): ids in §1.4 order, labels and the
 * gate of each section. A section is listed only when the user satisfies its gate; a direct
 * `?section=` without it renders the forbidden state of that panel. UI only: the api decides.
 */
export const SECTION_IDS = [
  'summary',
  'people',
  'headers',
  'authentication',
  'spam',
  'phishing',
  'urls',
  'attachments',
  'dlp',
  'risk',
  'policy',
  'delivery',
  'quarantine',
  'audit',
] as const;

export type SectionId = (typeof SECTION_IDS)[number];

export interface SectionDefinition {
  readonly id: SectionId;
  readonly label: string;
  /** Every operation's `x-eg-permissions` must hold (the section's main reads). */
  readonly operations: readonly OperationId[];
  /** Extra permissions that are not one operation's requirement (`dlp:read` for DLP results). */
  readonly permissions?: readonly string[];
  /** Sections 4–10 show one scan round (newest by default, `?round=`). */
  readonly roundScoped: boolean;
}

const SCANS: OperationId = 'MessageScansController_scansOf_v1';

export const SECTIONS: readonly SectionDefinition[] = [
  {
    id: 'summary',
    label: 'Message summary',
    operations: ['MessagesController_detail_v1', 'MessageLifecycleController_lifecycle_v1'],
    roundScoped: false,
  },
  {
    id: 'people',
    label: 'Sender and recipients',
    operations: ['MessagesController_recipients_v1'],
    roundScoped: false,
  },
  {
    id: 'headers',
    label: 'Email headers',
    operations: ['MessageHeadersController_headers_v1'],
    roundScoped: false,
  },
  { id: 'authentication', label: 'Authentication results', operations: [SCANS], roundScoped: true },
  { id: 'spam', label: 'Spam score', operations: [SCANS], roundScoped: true },
  { id: 'phishing', label: 'Phishing analysis', operations: [SCANS], roundScoped: true },
  {
    id: 'urls',
    label: 'URL analysis',
    operations: ['UrlProtectionController_ofMessage_v1', SCANS],
    roundScoped: true,
  },
  {
    id: 'attachments',
    label: 'Attachment analysis',
    operations: ['AttachmentsController_ofMessage_v1', SCANS],
    roundScoped: true,
  },
  {
    id: 'dlp',
    label: 'DLP results',
    operations: [SCANS],
    permissions: ['dlp:read'],
    roundScoped: true,
  },
  { id: 'risk', label: 'Risk score', operations: [SCANS], roundScoped: true },
  {
    id: 'policy',
    label: 'Policy decisions',
    operations: ['PolicyMessagesController_evaluations_v1'],
    roundScoped: false,
  },
  {
    id: 'delivery',
    label: 'Delivery timeline',
    operations: ['DeliveriesController_forMessage_v1'],
    roundScoped: false,
  },
  {
    id: 'quarantine',
    label: 'Quarantine actions',
    operations: ['QuarantineEntriesController_search_v1'],
    roundScoped: false,
  },
  {
    id: 'audit',
    label: 'Audit history',
    operations: ['AuditLogsController_search_v1'],
    roundScoped: false,
  },
];

const BY_ID = new Map(SECTIONS.map((section) => [section.id, section]));

export function sectionById(id: SectionId): SectionDefinition {
  const section = BY_ID.get(id);
  if (!section) throw new Error(`Unknown section ${id}`);
  return section;
}

/** Whether the permissions satisfy a section's gate. */
export function sectionAllowed(
  section: SectionDefinition,
  permissions: ReadonlySet<string>,
): boolean {
  return (
    section.operations.every((op) => canPerform(op, permissions)) &&
    (section.permissions ?? []).every((permission) => permissions.has(permission))
  );
}

/** The permissions a section needs, for the forbidden state (`message:read`, `dlp:read`). */
export function sectionRequirement(section: SectionDefinition): string[] {
  return [
    ...new Set([
      ...section.operations.flatMap((op) => describeRequirement(op)),
      ...(section.permissions ?? []),
    ]),
  ];
}

/** URL state of the details page (§3.6): `section` (default `summary`) and `round`. */
export const DETAIL_URL_SHAPE = {
  section: z.enum(SECTION_IDS).default('summary').catch('summary'),
  round: z.coerce.number().int().min(0).max(65_535).optional().catch(undefined),
};
