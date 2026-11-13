import { bffRoute } from '@/server/bff/route';
import { logout } from '@/server/bff/session-routes';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const POST = bffRoute(logout);
