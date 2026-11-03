import { ConflictException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';

export const CONNECTOR_NOT_FOUND = 'SMTP connector not found';
export const CONNECTOR_NAME_EXISTS = 'SMTP connector name already exists';
/** Deliberately says nothing about the other connector or its organization (D10). */
export const NETWORK_OVERLAP = 'Network overlaps an existing connector network';
export const FINGERPRINT_EXISTS = 'Certificate fingerprint is already registered';
export const NOT_SASL = 'Only sasl connectors have a secret';
export const NETWORK_LOCK_BUSY = 'Connector networks are being changed, try again';

export const connectorNotFound = (): NotFoundException =>
  new NotFoundException(CONNECTOR_NOT_FOUND);
export const connectorNameExists = (): ConflictException =>
  new ConflictException(CONNECTOR_NAME_EXISTS);
export const networkOverlap = (): ConflictException => new ConflictException(NETWORK_OVERLAP);
export const fingerprintExists = (): ConflictException => new ConflictException(FINGERPRINT_EXISTS);
export const connectorLimitReached = (max: number): ConflictException =>
  new ConflictException(`SMTP connector limit reached: at most ${max} per organization`);
export const networkLockBusy = (): ServiceUnavailableException =>
  new ServiceUnavailableException(NETWORK_LOCK_BUSY);
