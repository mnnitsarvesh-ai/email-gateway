import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ObjectKeyRefusedError,
  PROBE_SAMPLE_KEY,
  SampleMissingError,
  SampleTooLargeError,
  SandboxS3,
  StorageUnavailableError,
} from './sandbox-s3';

/**
 * A local HTTP endpoint speaking just enough of the S3 REST error protocol to exercise the
 * classification (NoSuchKey vs outage vs credentials) and the size and key guards. The real
 * MinIO behaviour (policies, pause) is covered by the integration suite.
 */

type Handler = (req: IncomingMessage, res: ServerResponse) => void;
let server: Server;
let endpoint: string;
let handler: Handler = (_req, res) => res.end();
const requests: { method: string; url: string }[] = [];

const s3Error = (res: ServerResponse, status: number, code: string): void => {
  res.writeHead(status, { 'content-type': 'application/xml' });
  res.end(
    `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>m</Message><RequestId>r</RequestId></Error>`,
  );
};

beforeAll(async () => {
  server = createServer((req, res) => {
    requests.push({ method: req.method ?? '', url: req.url ?? '' });
    req.resume();
    req.on('end', () => handler(req, res));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  endpoint = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
});

afterAll(async () => {
  await new Promise((r) => server.close(r));
});

function client(timeoutMs = 2000): SandboxS3 {
  return new SandboxS3({
    bucket: 'email-gateway-sandbox',
    region: 'ap-south-1',
    endpoint,
    forcePathStyle: true,
    accessKeyId: 'eg-sandbox-controller',
    secretAccessKey: 'x'.repeat(40),
    timeoutMs,
  });
}

const SAMPLE = 'samples/2026/11/01890a5d-ac96-774b-bcce-b302099a8070.bin';
const ARTIFACT =
  'artifacts/2026/11/01890a5d-ac96-774b-bcce-b302099a8070/0123456789abcdef/0-static_report.bin';

describe('SandboxS3', () => {
  it('reads a sample and refuses keys outside samples/ and artifacts/ locally', async () => {
    handler = (_req, res) => {
      res.writeHead(200, { 'content-length': '5' });
      res.end('hello');
    };
    const s3 = client();
    expect((await s3.getSample(SAMPLE, 100)).toString()).toBe('hello');
    expect(requests.at(-1)).toEqual({
      method: 'GET',
      url: `/email-gateway-sandbox/${SAMPLE}?x-id=GetObject`,
    });
    await expect(s3.getSample('org/1/part/x', 10)).rejects.toBeInstanceOf(ObjectKeyRefusedError);
    await expect(s3.getSample(ARTIFACT, 10)).rejects.toBeInstanceOf(ObjectKeyRefusedError);
    await expect(s3.putArtifact(SAMPLE, Buffer.from('x'))).rejects.toBeInstanceOf(
      ObjectKeyRefusedError,
    );
    s3.close();
  });

  it('classifies NoSuchKey, oversize bodies and outages', async () => {
    const s3 = client();
    handler = (_req, res) => s3Error(res, 404, 'NoSuchKey');
    await expect(s3.getSample(SAMPLE, 100)).rejects.toBeInstanceOf(SampleMissingError);
    handler = (_req, res) => {
      res.writeHead(200, { 'content-length': '50' });
      res.end('x'.repeat(50));
    };
    await expect(s3.getSample(SAMPLE, 10)).rejects.toBeInstanceOf(SampleTooLargeError);
    handler = (_req, res) => s3Error(res, 503, 'ServiceUnavailable');
    await expect(s3.getSample(SAMPLE, 100)).rejects.toBeInstanceOf(StorageUnavailableError);
    handler = (_req, res) => s3Error(res, 403, 'AccessDenied');
    await expect(s3.getSample(SAMPLE, 100)).rejects.toMatchObject({
      name: 'StorageUnavailableError',
      op: 'get_sample',
      code: 'AccessDenied',
    });
    s3.close();
  });

  it('times out on an endpoint that never answers (a paused MinIO)', async () => {
    const s3 = client(300);
    handler = () => undefined;
    const started = Date.now();
    await expect(s3.getSample(SAMPLE, 100)).rejects.toBeInstanceOf(StorageUnavailableError);
    expect(Date.now() - started).toBeLessThan(5000);
    s3.close();
  });

  it('puts artifacts and maps put failures to outages', async () => {
    const s3 = client();
    handler = (_req, res) => res.end();
    await s3.putArtifact(ARTIFACT, Buffer.from('sealed'));
    expect(requests.at(-1)?.method).toBe('PUT');
    handler = (_req, res) => s3Error(res, 500, 'InternalError');
    await expect(s3.putArtifact(ARTIFACT, Buffer.from('sealed'))).rejects.toMatchObject({
      op: 'put_artifact',
    });
    s3.close();
  });

  it('probes readiness with a never-existing sample key', async () => {
    const s3 = client();
    handler = (_req, res) => s3Error(res, 404, 'NoSuchKey');
    await s3.probe();
    expect(requests.at(-1)?.url).toContain(PROBE_SAMPLE_KEY);
    handler = (_req, res) => s3Error(res, 403, 'AccessDenied');
    await s3.probe();
    handler = (_req, res) => s3Error(res, 403, 'SignatureDoesNotMatch');
    await expect(s3.probe()).rejects.toMatchObject({ code: 'SignatureDoesNotMatch' });
    handler = (_req, res) => s3Error(res, 404, 'NoSuchBucket');
    await expect(s3.probe()).rejects.toMatchObject({ code: 'NoSuchBucket' });
    s3.close();
  });
});
