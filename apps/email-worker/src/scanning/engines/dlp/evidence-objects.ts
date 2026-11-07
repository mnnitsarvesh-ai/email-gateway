import { DeleteObjectCommand, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { uuidv7 } from '@email-gateway/common';

/**
 * The DLP evidence objects in the mail bucket (step 4.5 D16): ciphertext only (`dlp-evidence/1`),
 * under `org/<org>/dlp-evidence/<yyyy>/<mm>/<scanId>-<uuidv7>.bin`. An object without a committed
 * `dlp_evidence` row is undecryptable by construction (its data key exists only in the row);
 * the engine still deletes the object of a lost finalize (best effort) and the sweeper deletes
 * expired objects after crypto-shredding their rows.
 */

export interface EvidenceObjects {
  put(key: string, body: Buffer, sha256Hex: string, signal?: AbortSignal): Promise<void>;
  /** Resolves when the object is gone (deleting a missing object succeeds). */
  delete(key: string, signal?: AbortSignal): Promise<void>;
}

/** The key prefix every evidence object of an organization starts with. */
export const evidencePrefix = (organizationId: bigint): string =>
  `org/${organizationId.toString()}/dlp-evidence/`;

/** A new evidence object key (`<yyyy>/<mm>` of the message's `received_at`, UTC). */
export function evidenceObjectKey(
  organizationId: bigint,
  scanId: bigint,
  receivedAt: Date,
): string {
  const yyyy = String(receivedAt.getUTCFullYear());
  const mm = String(receivedAt.getUTCMonth() + 1).padStart(2, '0');
  return `${evidencePrefix(organizationId)}${yyyy}/${mm}/${scanId.toString()}-${uuidv7()}.bin`;
}

/** A key the repository and the sweeper accept for an organization. */
export const isEvidenceKey = (key: string, organizationId: bigint): boolean =>
  key.startsWith(evidencePrefix(organizationId)) &&
  !key.includes('..') &&
  /^org\/[0-9]+\/dlp-evidence\/[0-9]{4}\/[0-9]{2}\/[0-9]+-[0-9a-f-]{36}\.bin$/.test(key);

export class S3EvidenceObjects implements EvidenceObjects {
  constructor(
    private readonly client: S3Client,
    private readonly bucket: string,
    private readonly timeoutMs: number,
  ) {}

  private signal(signal?: AbortSignal): AbortSignal {
    const timeout = AbortSignal.timeout(this.timeoutMs);
    return signal ? AbortSignal.any([signal, timeout]) : timeout;
  }

  async put(key: string, body: Buffer, sha256Hex: string, signal?: AbortSignal): Promise<void> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: 'application/octet-stream',
        ChecksumSHA256: Buffer.from(sha256Hex, 'hex').toString('base64'),
      }),
      { abortSignal: this.signal(signal) },
    );
  }

  async delete(key: string, signal?: AbortSignal): Promise<void> {
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }), {
      abortSignal: this.signal(signal),
    });
  }
}

/**
 * Best-effort delete of an evidence object without a committed row (D3 step 9): the object is
 * undecryptable either way; `dlp_evidence_writes_total{result="orphan_deleted"|"orphan_left"}`.
 * A key outside the organization's prefix is never touched.
 */
export async function deleteUncommittedEvidence(
  objects: EvidenceObjects,
  record: (result: 'orphan_deleted' | 'orphan_left') => void,
  key: string,
  organizationId: bigint,
): Promise<boolean> {
  if (!isEvidenceKey(key, organizationId)) {
    record('orphan_left');
    return false;
  }
  try {
    await objects.delete(key);
    record('orphan_deleted');
    return true;
  } catch {
    record('orphan_left');
    return false;
  }
}
