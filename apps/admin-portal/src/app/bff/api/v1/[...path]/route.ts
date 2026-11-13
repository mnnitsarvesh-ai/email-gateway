import { bffRoute } from '@/server/bff/route';
import { handleProxy } from '@/server/proxy';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/** Generic proxy to the api (design P5): only operations of docs/api/openapi.json. */
const handler = bffRoute(handleProxy);

export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const PATCH = handler;
export const DELETE = handler;
