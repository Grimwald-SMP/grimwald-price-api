import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import db from "../db";
import { requireAdmin, requireStaff, requireOwner, type Role } from "../middleware/auth";
import { logAudit } from "../lib/audit";

const router = Router();

const ROLE_RANK: Record<Role, number> = { helper: 0, staff: 1, owner: 2 };

function parseId(raw: string | string[]): number | null {
  const s = Array.isArray(raw) ? raw[0] : raw;
  const n = parseInt(s, 10);
  return Number.isInteger(n) && n > 0 ? n : null;
}

const CreateSchema = z.object({
  username: z
    .string()
    .min(2, "Username must be at least 2 characters")
    .max(50)
    .regex(/^[a-zA-Z0-9_-]+$/, "Only letters, numbers, _ and - allowed"),
  password: z.string().min(8, "Password must be at least 8 characters"),
  role: z.enum(["owner", "staff", "helper"]).default("staff"),
});

const RoleSchema = z.object({
  role: z.enum(["owner", "staff", "helper"]),
});

interface AdminRow {
  id: number;
  username: string;
  role: Role;
  created_at: string;
}

// List all admins — staff+
router.get("/", requireStaff, (_req, res) => {
  const admins = db
    .prepare("SELECT id, username, role, created_at FROM admins ORDER BY created_at ASC")
    .all() as AdminRow[];
  res.json(admins);
});

// Create a new admin — owner only
router.post("/", requireOwner, async (req, res) => {
  const parsed = CreateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request" });
    return;
  }

  const { username, password, role } = parsed.data;

  const existing = db.prepare("SELECT id FROM admins WHERE username = ?").get(username);
  if (existing) {
    res.status(409).json({ error: "Username already taken" });
    return;
  }

  const hash = await bcrypt.hash(password, 10);
  const result = db
    .prepare("INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)")
    .run(username, hash, role);

  const created = db
    .prepare("SELECT id, username, role, created_at FROM admins WHERE id = ?")
    .get(result.lastInsertRowid) as AdminRow;

  logAudit({
    adminId: req.admin!.adminId,
    adminUsername: req.admin!.username,
    action: "admin.create",
    targetType: "admin",
    targetId: created.id,
    targetName: created.username,
    details: { role: created.role },
  });
  res.status(201).json(created);
});

// Delete an admin — owner only
router.delete("/:id", requireOwner, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) { res.status(400).json({ error: "Invalid id" }); return; }

  if (req.admin?.adminId === id) {
    res.status(400).json({ error: "You cannot delete your own account" });
    return;
  }

  // Must keep at least one admin
  const count = (db.prepare("SELECT COUNT(*) as n FROM admins").get() as { n: number }).n;
  if (count <= 1) {
    res.status(400).json({ error: "Cannot delete the last admin account" });
    return;
  }

  // Must keep at least one owner
  const target = db.prepare("SELECT role FROM admins WHERE id = ?").get(id) as { role: Role } | undefined;
  if (target?.role === "owner") {
    const ownerCount = (db.prepare("SELECT COUNT(*) as n FROM admins WHERE role = 'owner'").get() as { n: number }).n;
    if (ownerCount <= 1) {
      res.status(400).json({ error: "Cannot delete the last owner account" });
      return;
    }
  }

  const toDelete = db.prepare("SELECT username, role FROM admins WHERE id = ?").get(id) as AdminRow | undefined;
  const info = db.prepare("DELETE FROM admins WHERE id = ?").run(id);
  if (info.changes === 0) {
    res.status(404).json({ error: "Admin not found" });
    return;
  }
  logAudit({
    adminId: req.admin!.adminId,
    adminUsername: req.admin!.username,
    action: "admin.delete",
    targetType: "admin",
    targetId: id,
    targetName: toDelete?.username ?? null,
  });
  res.json({ ok: true });
});

// Change role — owner only, can't change own role, must keep at least one owner
router.put("/:id/role", requireOwner, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) { res.status(400).json({ error: "Invalid id" }); return; }

  if (req.admin?.adminId === id) {
    res.status(400).json({ error: "You cannot change your own role" });
    return;
  }

  const parsed = RoleSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request" });
    return;
  }

  const { role } = parsed.data;

  const beforeAdmin = db.prepare("SELECT role FROM admins WHERE id = ?").get(id) as { role: Role } | undefined;
  const beforeRole = beforeAdmin?.role ?? null;

  // Prevent demoting the last owner
  if (role !== "owner" && beforeRole === "owner") {
    const ownerCount = (db.prepare("SELECT COUNT(*) as n FROM admins WHERE role = 'owner'").get() as { n: number }).n;
    if (ownerCount <= 1) {
      res.status(400).json({ error: "Cannot demote the last owner" });
      return;
    }
  }

  const info = db.prepare("UPDATE admins SET role = ? WHERE id = ?").run(role, id);
  if (info.changes === 0) {
    res.status(404).json({ error: "Admin not found" });
    return;
  }

  const updated = db
    .prepare("SELECT id, username, role, created_at FROM admins WHERE id = ?")
    .get(id) as AdminRow;
  logAudit({
    adminId: req.admin!.adminId,
    adminUsername: req.admin!.username,
    action: "admin.role_change",
    targetType: "admin",
    targetId: id,
    targetName: updated.username,
    details: { from_role: beforeRole, to_role: role },
  });
  res.json(updated);
});

// Change password — any admin for self (requires currentPassword), owner for others
router.put("/:id/password", requireAdmin, async (req, res) => {
  const id = parseId(req.params.id);
  if (!id) { res.status(400).json({ error: "Invalid id" }); return; }

  const isSelf = req.admin?.adminId === id;

  if (!isSelf && ROLE_RANK[req.admin!.role] < ROLE_RANK["owner"]) {
    res.status(403).json({ error: "Only owners can change another admin's password" });
    return;
  }

  const Schema = isSelf
    ? z.object({
        currentPassword: z.string().min(1, "Current password is required"),
        password: z.string().min(8, "Password must be at least 8 characters"),
      })
    : z.object({
        password: z.string().min(8, "Password must be at least 8 characters"),
      });

  const parsed = Schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request" });
    return;
  }

  if (isSelf) {
    const admin = db
      .prepare("SELECT password_hash FROM admins WHERE id = ?")
      .get(id) as { password_hash: string } | undefined;
    if (!admin) {
      res.status(404).json({ error: "Admin not found" });
      return;
    }
    const currentOk = await bcrypt.compare(
      (parsed.data as unknown as { currentPassword: string }).currentPassword,
      admin.password_hash
    );
    if (!currentOk) {
      res.status(403).json({ error: "Current password is incorrect" });
      return;
    }
  }

  const targetAdmin = db.prepare("SELECT username FROM admins WHERE id = ?").get(id) as { username: string } | undefined;
  const hash = await bcrypt.hash(parsed.data.password, 10);
  const info = db.prepare("UPDATE admins SET password_hash = ? WHERE id = ?").run(hash, id);
  if (info.changes === 0) {
    res.status(404).json({ error: "Admin not found" });
    return;
  }
  logAudit({
    adminId: req.admin!.adminId,
    adminUsername: req.admin!.username,
    action: "admin.password_change",
    targetType: "admin",
    targetId: id,
    targetName: targetAdmin?.username ?? null,
    details: { self: isSelf },
  });
  res.json({ ok: true });
});

export default router;
