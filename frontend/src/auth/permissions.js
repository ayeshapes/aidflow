// Client-side copy of the capability table in backend/app/core/permissions.py.
//
// This is for USER INTERFACE decisions only (which page to show, which link to
// display). The server is the real authority: it re-checks the role on every
// request, so editing this file in the browser grants no access to anything.
//
// The backend does not expose its table yet, so this is a hand-kept mirror.
// When PERMISSIONS in permissions.py changes, change this table in the same
// pull request.
export const PERMISSIONS = Object.freeze({
  manage_users: ["admin"],
  edit_donations: ["admin"],
  view_donations: ["admin", "warehouse", "auditor"],
  manage_procurement: ["warehouse"],
  view_purchases: ["admin", "warehouse", "auditor"],
  verify_receipt_hash: ["admin", "warehouse", "auditor"],
  record_stock_movements: ["warehouse"],
  view_inventory: ["admin", "warehouse", "field", "auditor"],
  register_beneficiary: ["admin", "field"],
  assign_beneficiary: ["admin"],
  view_beneficiary: ["admin", "field", "auditor"],
  sign_distribution: ["field"],
  verify_distribution_signature: ["admin", "field", "auditor"],
  view_audit_log: ["admin", "auditor"],
  view_certificates: ["admin", "field", "auditor"],
  revoke_certificates: ["admin"],
  manage_backups: ["admin"],
});

// True if the user's role holds the capability. No user means no.
// An unknown capability name is a programming error (a typo would otherwise
// silently lock everyone out), so it throws, like the backend does.
export function hasCapability(user, capability) {
  if (!Object.hasOwn(PERMISSIONS, capability)) {
    throw new Error(`Unknown capability "${capability}"; add it to PERMISSIONS`);
  }
  return Boolean(user) && PERMISSIONS[capability].includes(user.role);
}
