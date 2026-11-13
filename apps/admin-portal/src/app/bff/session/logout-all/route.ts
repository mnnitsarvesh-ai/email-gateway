import { bffRoute } from '@/server/bff/route';
import { logoutAll } from '@/server/bff/session-routes';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const POST = bffRoute(logoutAll);
