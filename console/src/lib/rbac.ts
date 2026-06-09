import type { UserRole } from '../types/index.ts';

/** Server-side RBAC. The console only renders UI elements; the engine enforces. */
export const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  viewer: ['read:verdicts', 'read:policies', 'read:audit', 'read:approvals'],
  responder: ['read:verdicts', 'read:policies', 'read:audit', 'read:approvals', 'write:approvals'],
  admin: [
    'read:verdicts', 'read:policies', 'read:audit', 'read:approvals',
    'write:approvals', 'write:policies', 'write:verdicts', 'manage:known-malicious',
  ],
};

export function can(role: UserRole, permission: string): boolean {
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false;
}
