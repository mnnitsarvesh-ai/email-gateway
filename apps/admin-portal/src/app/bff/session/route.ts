import { bffRoute } from '@/server/bff/route';
import { getSession } from '@/server/bff/session-routes';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const GET = bffRoute(getSession);
