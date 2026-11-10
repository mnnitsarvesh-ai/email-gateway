import { readFile } from 'node:fs/promises';
import { request } from 'node:https';

/**
 * A minimal in-cluster Kubernetes API client used ONLY by the `vm` backend preflight (step 4.6
 * X9): one authenticated `GET` with the pod's service-account token and the cluster CA over
 * `node:https` (no Kubernetes SDK). Bounded response, fixed timeout, TLS verification always on.
 * The token is never logged or returned.
 */

export const SERVICE_ACCOUNT_DIR = '/var/run/secrets/kubernetes.io/serviceaccount';
const MAX_RESPONSE_BYTES = 256 * 1024;

export interface KubernetesResponse {
  status: number;
  body: unknown;
}

/** What the vm preflight needs from Kubernetes (a fake in unit tests). */
export interface KubernetesClient {
  /** True when this process runs in a pod with a service-account token (step 1 of X9). */
  inCluster(): Promise<boolean>;
  get(path: string, signal: AbortSignal): Promise<KubernetesResponse>;
}

export interface InClusterOptions {
  host: string | undefined;
  port: number | undefined;
  serviceAccountDir?: string;
  timeoutMs?: number;
}

export class InClusterKubernetesClient implements KubernetesClient {
  private readonly dir: string;

  constructor(private readonly options: InClusterOptions) {
    this.dir = options.serviceAccountDir ?? SERVICE_ACCOUNT_DIR;
  }

  async inCluster(): Promise<boolean> {
    if (!this.options.host) return false;
    try {
      const token = await readFile(`${this.dir}/token`, 'utf8');
      return token.trim().length > 0;
    } catch {
      return false;
    }
  }

  async get(path: string, signal: AbortSignal): Promise<KubernetesResponse> {
    if (!/^\/apis?\/[A-Za-z0-9/._-]{1,256}$/.test(path))
      throw new Error('invalid Kubernetes API path');
    const [token, ca] = await Promise.all([
      readFile(`${this.dir}/token`, 'utf8'),
      readFile(`${this.dir}/ca.crt`),
    ]);
    const host = this.options.host as string;
    return new Promise<KubernetesResponse>((resolve, reject) => {
      const req = request(
        {
          host: host.includes(':') && !host.startsWith('[') ? `[${host}]` : host,
          port: this.options.port ?? 443,
          path,
          method: 'GET',
          ca,
          rejectUnauthorized: true,
          headers: { Authorization: `Bearer ${token.trim()}`, Accept: 'application/json' },
          timeout: this.options.timeoutMs ?? 5_000,
          signal,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let total = 0;
          res.on('data', (chunk: Buffer) => {
            total += chunk.length;
            if (total > MAX_RESPONSE_BYTES) {
              req.destroy(new Error('Kubernetes response too large'));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            let body: unknown = null;
            try {
              body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            } catch {
              body = null;
            }
            resolve({ status: res.statusCode ?? 0, body });
          });
          res.on('error', reject);
        },
      );
      req.on('timeout', () => req.destroy(new Error('Kubernetes request timed out')));
      req.on('error', reject);
      req.end();
    });
  }
}
