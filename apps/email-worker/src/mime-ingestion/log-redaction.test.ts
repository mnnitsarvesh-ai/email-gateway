import { Writable } from 'node:stream';
import { Prisma } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import { emlMessage, harness, multipartEml, receivedEvent } from './fakes.test-support';

/** Unique strings planted in every content field the worker must never log (design M15). */
const MARKERS = {
  subject: 'MRKSUBJ7f3a9e',
  filename: 'MRKFILE91bc0d.pdf',
  from: 'MRKFROM55de <mrkfrom55de@example.org>',
  body: 'MRKBODYc0ffee',
  header: 'spf=pass smtp.mailfrom=MRKHDRab12cd',
};
const NEEDLES = ['mrksubj7f3a9e', 'mrkfile91bc0d', 'mrkfrom55de', 'mrkbodyc0ffee', 'mrkhdrab12cd'];

function capturedLogger() {
  const lines: string[] = [];
  const destination = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      lines.push(...chunk.toString('utf8').split('\n').filter(Boolean));
      callback();
    },
  });
  const logger = createLogger({
    service: 'email-worker-redaction-test',
    level: 'trace',
    destination,
  });
  return { logger, lines };
}

const expectNoMarker = (lines: string[]) => {
  for (const line of lines) {
    const lower = line.toLowerCase();
    for (const needle of NEEDLES) expect(lower, `log line leaks ${needle}`).not.toContain(needle);
  }
};

describe('MIME ingestion log redaction (design M15)', () => {
  it('never logs subject, filename, addresses, header values or bodies', async () => {
    const { logger, lines } = capturedLogger();
    const h = harness({ logger });
    const eml = multipartEml(MARKERS);

    // 1. A successful parse.
    const ok = h.store.add(emlMessage(eml));
    h.source.put(ok.emlObjectKey, eml);
    await expect(h.service.handle(receivedEvent(ok))).resolves.toBe('handled');
    expect(h.store.parses.get(ok.id)?.status).toBe('parsed');
    // The markers really were parsed (so the test would catch a leak).
    expect(h.store.subjects.get(ok.id)).toContain('MRKSUBJ7f3a9e');
    expect(h.store.headers.some((x) => x.value.includes('MRKHDRab12cd'))).toBe(true);

    // 2. A failing parse (integrity mismatch) with the same content.
    const bad = h.store.add(emlMessage(eml, { emlSha256: 'f'.repeat(64) }));
    h.source.put(bad.emlObjectKey, eml);
    await h.service.handle(receivedEvent(bad));
    expect(h.store.parses.get(bad.id)?.status).toBe('parse_failed');

    // 3. Infrastructure retries whose error messages quote content (S3, sink and DB).
    const retry = h.store.add(emlMessage(eml));
    h.source.put(retry.emlObjectKey, eml);
    h.source.failOpen = Object.assign(
      new Error(`GetObject failed for ${MARKERS.subject} ${MARKERS.from}`),
      {
        name: 'NetworkingError',
        code: 'ECONNRESET',
        $metadata: {},
      },
    );
    await expect(h.service.handle(receivedEvent(retry))).rejects.toThrow();
    h.objects.failWrite = Object.assign(
      new Error(`upload of ${MARKERS.filename} failed: ${MARKERS.body}`),
      {
        name: 'InternalError',
      },
    );
    await expect(h.service.handle(receivedEvent(retry))).rejects.toThrow();
    h.store.failFinalize = new Prisma.PrismaClientKnownRequestError(
      `Data too long for column 'subject' value '${MARKERS.subject}' ${MARKERS.header}`,
      { code: 'P2000', clientVersion: 'test' },
    );
    await expect(h.service.handle(receivedEvent(retry))).rejects.toThrow();
    await expect(h.service.handle(receivedEvent(retry))).resolves.toBe('handled');

    // 4. A duplicate and a missing message.
    await h.service.handle(receivedEvent(ok));
    await h.service.handle(receivedEvent(emlMessage(eml)));

    expect(lines.length).toBeGreaterThanOrEqual(8);
    expectNoMarker(lines);
    // The retry lines carry the error class and code only.
    const retries = lines.filter((l) => l.includes('MIME ingestion attempt failed'));
    expect(retries).toHaveLength(3);
    // The S3 outage gives its attempt back; the sink and data errors count toward the guard.
    expect(retries.map((l) => l.includes('"transient":true'))).toEqual([true, false, false]);
    expect(retries[0]).toContain('"errName":"NetworkingError"');
    expect(retries[0]).toContain('"errCode":"ECONNRESET"');
    expect(retries[2]).toContain('"errCode":"P2000"');
    for (const line of retries) expect(line).not.toContain('"err":');
  });
});
