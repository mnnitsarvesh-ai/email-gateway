/**
 * The EICAR anti-virus test file (https://www.eicar.org/download-anti-malware-testfile/),
 * assembled at run time from fragments so the 68-byte string never appears verbatim in the
 * repository, its build output or a package tarball (scanners on developer machines and CI
 * would quarantine the file otherwise). It is harmless by definition: every scanner reports it.
 */
const FRAGMENTS = [
  'X5O!P%@AP[4\\PZX54(P^)7CC)7}',
  '$EICAR-',
  'STANDARD-ANTIVIRUS-',
  'TEST-FILE!',
  '$H+H*',
] as const;

/** SHA-256 of the 68-byte EICAR file. */
export const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

/** ClamAV's signature name for EICAR (clamd 1.4 with the official databases). */
export const EICAR_CLAMAV_SIGNATURE = 'Eicar-Test-Signature';

/** A fresh Buffer with the 68 EICAR bytes. */
export function eicar(): Buffer {
  return Buffer.from(FRAGMENTS.join(''), 'latin1');
}
