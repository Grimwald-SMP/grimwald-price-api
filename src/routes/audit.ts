import { Router } from "express";
import db from "../db";
import { requireStaff } from "../middleware/auth";
import type { AuditEntry } from "../lib/audit";

const router = Router();

const MAX_LIMIT = 200;
const DEFAULT_LIMIT = 50;

// Staff+: paginated audit log, newest first
router.get("/", requireStaff, (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit as string) || DEFAULT_LIMIT, 1), MAX_LIMIT);
  const offset = Math.max(parseInt(req.query.offset as string) || 0, 0);
  const action = req.query.action as string | undefined;

  const where = action ? "WHERE action = ?" : "";
  const args = action ? [action, limit, offset] : [limit, offset];

  const entries = db
    .prepare(`SELECT * FROM audit_logs ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .all(...args) as AuditEntry[];

  const { total } = db
    .prepare(`SELECT COUNT(*) as total FROM audit_logs ${where}`)
    .get(...(action ? [action] : [])) as { total: number };

  res.json({ entries, total, limit, offset });
});

export default router;
