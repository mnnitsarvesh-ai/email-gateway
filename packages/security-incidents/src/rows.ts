import type { SecurityIncident, SecurityIncidentEvent } from '@email-gateway/database';

/** A `security_incidents` row (the Prisma model). */
export type IncidentRow = SecurityIncident;

/** A `security_incident_events` row (timeline and audit trail). */
export type IncidentEventRow = SecurityIncidentEvent;
