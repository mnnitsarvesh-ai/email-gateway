/**
 * MS-OVBA 2.4.1 decompression of a VBA `CompressedContainer` (bounded). Used for the `dir`
 * stream and the module source of a VBA project (step 4.6 X4 `ole`). Pure; throws
 * `OvbaError` on malformed input or when the output would exceed `maxOutput`.
 */

export class OvbaError extends Error {
  override readonly name = 'OvbaError';
  constructor(readonly code: 'signature' | 'chunk' | 'token' | 'limit') {
    super(`MS-OVBA decompression failed: ${code}`);
  }
}

const CHUNK_DECOMPRESSED = 4096;

/** Decompresses `input[offset..]` (a CompressedContainer starting with 0x01). */
export function decompressOvba(input: Buffer, offset = 0, maxOutput = 4 * 1024 * 1024): Buffer {
  if (input[offset] !== 0x01) throw new OvbaError('signature');
  const out: number[] = [];
  let pos = offset + 1;
  while (pos + 2 <= input.length) {
    const header = input.readUInt16LE(pos);
    const chunkSize = (header & 0x0fff) + 3;
    const signature = (header >> 12) & 0x07;
    const compressed = (header & 0x8000) !== 0;
    if (signature !== 0b011) throw new OvbaError('chunk');
    const chunkEnd = Math.min(input.length, pos + chunkSize);
    const chunkStart = out.length;
    pos += 2;
    if (!compressed) {
      // A raw chunk: exactly 4096 bytes (fewer at the end of the stream).
      const end = Math.min(input.length, pos + CHUNK_DECOMPRESSED);
      if (out.length + (end - pos) > maxOutput) throw new OvbaError('limit');
      for (let i = pos; i < end; i += 1) out.push(input[i] as number);
      pos = end;
      continue;
    }
    while (pos < chunkEnd) {
      const flags = input[pos] as number;
      pos += 1;
      for (let bit = 0; bit < 8 && pos < chunkEnd; bit += 1) {
        if ((flags & (1 << bit)) === 0) {
          if (out.length >= maxOutput) throw new OvbaError('limit');
          out.push(input[pos] as number);
          pos += 1;
          continue;
        }
        if (pos + 2 > chunkEnd) throw new OvbaError('token');
        const token = input.readUInt16LE(pos);
        pos += 2;
        const difference = out.length - chunkStart;
        if (difference <= 0) throw new OvbaError('token');
        let bitCount = 4;
        while (1 << bitCount < difference) bitCount += 1;
        bitCount = Math.max(bitCount, 4);
        const lengthMask = 0xffff >> bitCount;
        const length = (token & lengthMask) + 3;
        const offsetValue = ((token & ~lengthMask & 0xffff) >> (16 - bitCount)) + 1;
        const from = out.length - offsetValue;
        if (from < chunkStart) throw new OvbaError('token');
        if (out.length + length > maxOutput) throw new OvbaError('limit');
        for (let i = 0; i < length; i += 1) out.push(out[from + i] as number);
      }
    }
    pos = chunkEnd;
  }
  return Buffer.from(out);
}
