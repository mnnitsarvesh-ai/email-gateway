import { randomBytes } from 'node:crypto';

let lastMs = -1;
let sequence = 0;

/**
 * RFC 9562 UUID version 7: 48-bit Unix milliseconds, version 7, 12 bits of a per-millisecond
 * counter (monotonic within this process), variant 10, 62 random bits. Used for outbox event
 * ids written by the workers and for delivery-worker's `delivery_reinjections.public_id` (its
 * token `dw1-<32 hex>` is the XFORWARD IDENT and ENVID).
 */
export function uuidv7(now: number = Date.now()): string {
  let ms = Math.max(0, Math.floor(now));
  if (ms <= lastMs) {
    sequence += 1;
    if (sequence > 0xfff) {
      // Counter exhausted within one millisecond: borrow the next millisecond.
      lastMs += 1;
      sequence = 0;
    }
    ms = lastMs;
  } else {
    lastMs = ms;
    sequence = randomBytes(2).readUInt16BE(0) & 0x3ff; // leave headroom for increments
  }
  const bytes = randomBytes(16);
  bytes.writeUIntBE(ms, 0, 6);
  bytes[6] = 0x70 | ((sequence >> 8) & 0x0f);
  bytes[7] = sequence & 0xff;
  bytes[8] = 0x80 | (bytes[8]! & 0x3f);
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
