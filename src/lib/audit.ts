import db from "../db";

export type AuditAction =
  | "item.create"
  | "item.update"
  | "item.delete"
  | "item.bulk_import"
  | "category.create"
  | "category.update"
  | "category.delete"
  | "submission.approve"
  | "submission.reject"
  | "admin.create"
  | "admin.delete"
  | "admin.role_change"
  | "admin.password_change";

export interface AuditEntry {
  id: number;
  admin_id: number | null;
  admin_username: string;
  action: AuditAction;
  target_type: string;
  target_id: number | null;
  target_name: string | null;
  details: string | null;
  created_at: string;
}

const insert = db.prepare(
  `INSERT INTO audit_logs (admin_id, admin_username, action, target_type, target_id, target_name, details)
   VALUES (?, ?, ?, ?, ?, ?, ?)`
);

export function logAudit(params: {
  adminId: number;
  adminUsername: string;
  action: AuditAction;
  targetType: string;
  targetId?: number | null;
  targetName?: string | null;
  details?: Record<string, unknown> | null;
}) {
  try {
    insert.run(
      params.adminId,
      params.adminUsername,
      params.action,
      params.targetType,
      params.targetId ?? null,
      params.targetName ?? null,
      params.details ? JSON.stringify(params.details) : null
    );
  } catch (e) {
    console.error("[audit] Failed to write log entry:", e);
  }
}
