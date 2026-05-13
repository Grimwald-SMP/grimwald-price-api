import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import db from "../db";
import { requireAdmin } from "../middleware/auth";

const router = Router();

const CreateSchema = z.object({
  username: z
    .string()
    .min(2, "Username must be at least 2 characters")
    .max(50)
    .regex(/^[a-zA-Z0-9_-]+$/, "Only letters, numbers, _ and - allowed"),
  password: z.string().min(8, "Password must be at least 8 characters"),
});

interface AdminRow {
  id: number;
  username: string;
  created_at: string;
}

// List all admins (no password hashes)
router.get("/", requireAdmin, (_req, res) => {
  const admins = db
    .prepare("SELECT id, username, created_at FROM admins ORDER BY created_at ASC")
    .all() as AdminRow[];
  res.json(admins);
});

// Create a new admin
router.post("/", requireAdmin, async (req, res) => {
  const parsed = CreateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten().fieldErrors });
    return;
  }

  const { username, password } = parsed.data;

  const existing = db.prepare("SELECT id FROM admins WHERE username = ?").get(username);
  if (existing) {
    res.status(409).json({ error: "Username already taken" });
    return;
  }

  const hash = await bcrypt.hash(password, 10);
  const result = db
    .prepare("INSERT INTO admins (username, password_hash) VALUES (?, ?)")
    .run(username, hash);

  const created = db
    .prepare("SELECT id, username, created_at FROM admins WHERE id = ?")
    .get(result.lastInsertRowid) as AdminRow;

  res.status(201).json(created);
});

// Delete an admin
router.delete("/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  // Can't delete yourself
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

  const info = db.prepare("DELETE FROM admins WHERE id = ?").run(id);
  if (info.changes === 0) {
    res.status(404).json({ error: "Admin not found" });
    return;
  }

  res.json({ ok: true });
});

// Change an admin's password (self or any admin)
router.put("/:id/password", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const parsed = z
    .object({ password: z.string().min(8, "Password must be at least 8 characters") })
    .safeParse(req.body);

  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten().fieldErrors });
    return;
  }

  const hash = await bcrypt.hash(parsed.data.password, 10);
  const info = db.prepare("UPDATE admins SET password_hash = ? WHERE id = ?").run(hash, id);
  if (info.changes === 0) {
    res.status(404).json({ error: "Admin not found" });
    return;
  }

  res.json({ ok: true });
});

export default router;
