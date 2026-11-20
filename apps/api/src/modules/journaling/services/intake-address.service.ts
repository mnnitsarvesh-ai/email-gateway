import { Inject, Injectable } from '@nestjs/common';
import {
  deriveIntakeAddressToken,
  deriveIntakeHeaderToken,
  intakeAddress,
  intakeAddressHash,
  intakeHeaderTokenHash,
  intakeLocalPart,
  maskIntakeAddress,
  maskIntakeHeaderToken,
  parseIntakeAddressSecret,
} from '@email-gateway/archive';
import { API_CONFIG } from '../../../api-config.token';
import type { JournalingConfig } from '../journaling.constants';
import { journalIntakeUnavailable } from '../journaling.errors';

/** The credentials of one source and address version. */
export interface IntakeCredentials {
  address: string;
  addressHash: string;
  /** Google Workspace sources only. */
  headerToken: string | null;
  headerTokenHash: string | null;
}

/**
 * Intake address and header-token derivation (step 8.6 D1, ADR-0087): `journal-<token>@<domain>`
 * with `token` = HMAC-SHA256(JOURNAL_INTAKE_ADDRESS_SECRET, label ‖ source public id ‖ address
 * version) in base32 (WP2 `@email-gateway/archive` helpers). Only the api holds the secret; the
 * database and the smtp-adapter hold SHA-256 hashes. With no intake domain (intake off) nothing
 * can be derived: creation and rotation answer `503 journal_intake_unavailable` and views show a
 * null address. The secret never reaches a log line, an audit row or an idempotency row.
 */
@Injectable()
export class IntakeAddressService {
  private readonly key: Buffer | null;
  private readonly domain: string | null;

  constructor(
    @Inject(API_CONFIG)
    config: Pick<JournalingConfig, 'JOURNAL_INTAKE_DOMAIN' | 'JOURNAL_INTAKE_ADDRESS_SECRET'>,
  ) {
    this.domain = config.JOURNAL_INTAKE_DOMAIN ?? null;
    this.key =
      this.domain !== null && config.JOURNAL_INTAKE_ADDRESS_SECRET !== undefined
        ? parseIntakeAddressSecret(config.JOURNAL_INTAKE_ADDRESS_SECRET)
        : null;
  }

  /** The platform intake domain is configured (intake on). */
  get available(): boolean {
    return this.key !== null && this.domain !== null;
  }

  /** The intake domain, or null when intake is off. */
  get intakeDomain(): string | null {
    return this.domain;
  }

  /** The credentials of a source version; `503` when intake is off. */
  derive(sourcePublicId: string, version: number, google: boolean): IntakeCredentials {
    if (this.key === null || this.domain === null) throw journalIntakeUnavailable();
    const token = deriveIntakeAddressToken(this.key, sourcePublicId, version);
    const headerToken = google ? deriveIntakeHeaderToken(this.key, sourcePublicId, version) : null;
    return {
      address: intakeAddress(token, this.domain),
      addressHash: intakeAddressHash(intakeLocalPart(token)),
      headerToken,
      headerTokenHash: headerToken === null ? null : intakeHeaderTokenHash(headerToken),
    };
  }

  /** The values a view shows: in clear only when `reveal`; null when intake is off. */
  shown(
    sourcePublicId: string,
    version: number,
    google: boolean,
    reveal: boolean,
  ): { address: string | null; headerToken: string | null } {
    if (!this.available) return { address: null, headerToken: null };
    const c = this.derive(sourcePublicId, version, google);
    return reveal
      ? { address: c.address, headerToken: c.headerToken }
      : {
          address: maskIntakeAddress(c.address),
          headerToken: c.headerToken === null ? null : maskIntakeHeaderToken(c.headerToken),
        };
  }
}
