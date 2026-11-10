/**
 * Why a sandbox envelope could not be opened: `malformed` (not the format), `unauthentic` (no
 * key unwraps it, wrong ids/AAD or tampered bytes), `integrity` (decrypted, but the plaintext
 * SHA-256 differs from the expected hash). Carries no value, no key and no plaintext.
 */
export type SandboxEnvelopeFailure = 'malformed' | 'unauthentic' | 'integrity';

export class SandboxEnvelopeError extends Error {
  constructor(readonly reason: SandboxEnvelopeFailure) {
    super(`Unable to open the sandbox envelope (${reason})`);
    this.name = 'SandboxEnvelopeError';
  }
}
