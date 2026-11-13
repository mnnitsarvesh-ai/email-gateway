import { ToneBadge } from '@/components/domain/tone-badge';
import type { ListItem } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';

export type User = ListItem<'UsersController_list_v1'>;
export type UserStatus = User['status'];

export const USER_STATUSES: readonly UserStatus[] = ['invited', 'active', 'disabled', 'locked'];

const TONE: Record<UserStatus, Tone> = {
  invited: 'info',
  active: 'success',
  disabled: 'neutral',
  locked: 'warning',
};
export const USER_STATUS_LABEL: Record<UserStatus, string> = {
  invited: 'Invited',
  active: 'Active',
  disabled: 'Disabled',
  locked: 'Locked',
};

export function UserStatusBadge({ status }: { status: UserStatus }) {
  return (
    <ToneBadge tone={TONE[status] ?? 'neutral'}>{USER_STATUS_LABEL[status] ?? status}</ToneBadge>
  );
}

/** Explanation of the api's no-escalation refusals (docs/security/rbac.md). */
export const NO_ESCALATION_HINT =
  'You can only grant roles whose permissions you hold yourself, and only act on users who hold no permission you lack. Platform roles exist only in the platform organization, and the last administrator cannot be removed.';

/** Role key pattern of the request schemas (`roleKeys` items). */
export const ROLE_KEY = /^[a-z][a-z0-9_]{1,63}$/;
