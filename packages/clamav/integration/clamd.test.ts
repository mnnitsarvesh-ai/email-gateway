import { createServer, type AddressInfo } from 'node:net';
import { Readable } from 'node:stream';
import {
  EICAR_CLAMAV_SIGNATURE,
  eicar,
  encryptedZip,
  gzip,
  largeFile,
  nestedZip,
  pdfLike,
  tgz,
  zip,
} from '@email-gateway/attachment-corpus';
import { beforeAll, describe, expect, it } from 'vitest';
import { ClamdSizeLimitError, ClamdUnavailableError } from '../src';
import { clamdHost, makeClient, requireClamd } from './support/env';

/**
 * The real clamd (clamav/clamav-debian:1.4, infrastructure/clamav/clamd.conf) through
 * ClamdClient: PING, VERSION, INSTREAM inside IDSESSION, EICAR generated at test time (plain,
 * zip, nested zip, gzip, tgz, streamed), clean files near ATTACHMENT_MAX_BYTES, the
 * StreamMaxLength refusal and the configured AlertEncrypted no.
 */
const client = makeClient();
const MiB = 1024 * 1024;

beforeAll(requireClamd);

describe('clamd through ClamdClient', () => {
  it('answers PING', async () => {
    await expect(client.ping()).resolves.toBeUndefined();
  });

  it('reports ClamAV 1.4.x with a loaded daily database', async () => {
    const version = await client.version();
    expect(version.engine).toMatch(/^1\.4\.\d+$/);
    expect(version.dbVersion).toBeGreaterThan(27_000);
    expect(version.dbTime.getTime()).toBeLessThanOrEqual(Date.now() + 86_400_000);
    expect(version.dbTime.getUTCFullYear()).toBeGreaterThanOrEqual(2026);
  });

  it('scans a clean buffer as clean with the version of the same session', async () => {
    const version = await client.version();
    const result = await client.scan(Buffer.from('Quarterly report, nothing to see here.\n'));
    expect(result.status).toBe('clean');
    expect(result.engine).toBe(version.engine);
    // A freshclam update between the two calls changes the database; never the engine.
    expect(result.dbVersion).toBeGreaterThanOrEqual(version.dbVersion);
  });

  it('finds EICAR', async () => {
    const result = await client.scan(eicar());
    expect(result).toMatchObject({ status: 'found', signature: EICAR_CLAMAV_SIGNATURE });
  });

  it('finds EICAR streamed from a Readable in small pieces', async () => {
    const bytes = eicar();
    const result = await client.scan(Readable.from([bytes.subarray(0, 10), bytes.subarray(10)]));
    expect(result).toMatchObject({ status: 'found', signature: EICAR_CLAMAV_SIGNATURE });
    expect(result.bytes).toBe(68);
  });

  it('finds EICAR inside a zip (yazl), a nested zip, a gzip and a tgz', async () => {
    const samples = {
      zip: await zip([
        { name: 'readme.txt', data: Buffer.from('hello\n') },
        { name: 'eicar.com', data: eicar() },
      ]),
      nested: await nestedZip(2, { name: 'eicar.com', data: eicar() }),
      gzip: gzip(eicar()),
      tgz: await tgz([{ name: 'eicar.com', data: eicar() }]),
    };
    for (const [name, data] of Object.entries(samples)) {
      const result = await client.scan(data);
      expect(result, name).toMatchObject({ status: 'found', signature: EICAR_CLAMAV_SIGNATURE });
    }
  });

  it('scans a clean zip as clean', async () => {
    const archive = await zip([{ name: 'notes.txt', data: Buffer.from('nothing\n') }]);
    await expect(client.scan(archive)).resolves.toMatchObject({ status: 'clean' });
  });

  it('does not alert on an encrypted zip (AlertEncrypted no; the inspector reports it)', async () => {
    await expect(client.scan(encryptedZip())).resolves.toMatchObject({ status: 'clean' });
  });

  it('scans a file just below ATTACHMENT_MAX_BYTES (25 MiB) in 64 KiB chunks', async () => {
    const result = await client.scan(pdfLike(25 * MiB - 1));
    expect(result.status).toBe('clean');
    expect(result.bytes).toBe(25 * MiB - 1);
  });

  it('throws ClamdSizeLimitError above StreamMaxLength (30M), with the version', async () => {
    const error = await client.scan(largeFile(31 * MiB)).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ClamdSizeLimitError);
    expect((error as ClamdSizeLimitError).version?.engine).toMatch(/^1\.4\./);
    // The connection is not reused: the next scan works.
    await expect(client.scan(Buffer.from('after'))).resolves.toMatchObject({ status: 'clean' });
  });

  it('runs concurrent scans within maxConnections', async () => {
    const concurrent = makeClient({ maxConnections: 2 });
    const inputs = Array.from({ length: 8 }, (_, i) =>
      i % 2 === 0 ? eicar() : Buffer.from(`clean ${i}`),
    );
    const results = await Promise.all(inputs.map((input) => concurrent.scan(input)));
    expect(results.map((r) => r.status)).toEqual([
      'found',
      'clean',
      'found',
      'clean',
      'found',
      'clean',
      'found',
      'clean',
    ]);
    expect(concurrent.connections).toEqual({ active: 0, waiting: 0 });
  });

  it('reports a closed port as unavailable', async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, clamdHost, resolve));
    const { port } = server.address() as AddressInfo;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    const error = await makeClient({ port, timeoutMs: 5_000 })
      .scan(eicar())
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ClamdUnavailableError);
    expect((error as ClamdUnavailableError).causeCode).toBe('ECONNREFUSED');
  });
});
