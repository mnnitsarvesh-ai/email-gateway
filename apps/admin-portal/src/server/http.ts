import 'server-only';

/** Headers on every BFF response (P3, P5). */
export const BFF_RESPONSE_HEADERS: Readonly<Record<string, string>> = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};

const STATUS_TEXT: Record<number, string> = {
  400: 'BAD_REQUEST',
  401: 'UNAUTHORIZED',
  403: 'FORBIDDEN',
  404: 'NOT_FOUND',
  405: 'METHOD_NOT_ALLOWED',
  409: 'CONFLICT',
  413: 'PAYLOAD_TOO_LARGE',
  415: 'UNSUPPORTED_MEDIA_TYPE',
  422: 'UNPROCESSABLE_ENTITY',
  429: 'TOO_MANY_REQUESTS',
  500: 'INTERNAL_SERVER_ERROR',
  501: 'NOT_IMPLEMENTED',
  502: 'BAD_GATEWAY',
  503: 'SERVICE_UNAVAILABLE',
  504: 'GATEWAY_TIMEOUT',
};

/** Portal-coded errors use the API envelope `{ statusCode, error, code, message, requestId? }`. */
export interface PortalErrorBody {
  statusCode: number;
  error: string;
  code: string;
  message: string;
  requestId?: string;
}

export function portalError(
  status: number,
  code: string,
  message: string,
  extraHeaders: HeadersInit = {},
): Response {
  const body: PortalErrorBody = {
    statusCode: status,
    error: STATUS_TEXT[status] ?? 'ERROR',
    code,
    message,
  };
  const headers = new Headers({ ...BFF_RESPONSE_HEADERS, 'content-type': 'application/json' });
  new Headers(extraHeaders).forEach((value, key) => headers.append(key, value));
  return new Response(JSON.stringify(body), { status, headers });
}

export function jsonResponse(
  body: unknown,
  status = 200,
  setCookies: readonly string[] = [],
): Response {
  const headers = new Headers({ ...BFF_RESPONSE_HEADERS, 'content-type': 'application/json' });
  for (const cookie of setCookies) headers.append('set-cookie', cookie);
  return new Response(JSON.stringify(body), { status, headers });
}

export function emptyResponse(status = 204, setCookies: readonly string[] = []): Response {
  const headers = new Headers(BFF_RESPONSE_HEADERS);
  for (const cookie of setCookies) headers.append('set-cookie', cookie);
  return new Response(null, { status, headers });
}

/** Reads a JSON body with a byte limit; `null` for an empty body. */
export async function readJsonBody(
  request: Request,
  limitBytes: number,
): Promise<{ ok: true; value: unknown } | { ok: false; response: Response }> {
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (declared > limitBytes) {
    return { ok: false, response: portalError(413, 'payload_too_large', 'Request body too large') };
  }
  const buffer = await readLimited(request.body, limitBytes);
  if (buffer === 'too_large') {
    return { ok: false, response: portalError(413, 'payload_too_large', 'Request body too large') };
  }
  if (buffer.length === 0) return { ok: true, value: null };
  try {
    return { ok: true, value: JSON.parse(new TextDecoder().decode(buffer)) as unknown };
  } catch {
    return {
      ok: false,
      response: portalError(400, 'validation_failed', 'Request body is not valid JSON'),
    };
  }
}

/** Buffers a stream up to `limitBytes`; `'too_large'` once the limit is crossed. */
export async function readLimited(
  body: ReadableStream<Uint8Array> | null,
  limitBytes: number,
): Promise<Uint8Array<ArrayBuffer> | 'too_large'> {
  if (!body) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limitBytes) {
      await reader.cancel();
      return 'too_large';
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}
