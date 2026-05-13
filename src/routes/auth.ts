import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import db from "../db";

const router = Router();

const LoginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

interface AdminRow {
  id: number;
  username: string;
  password_hash: string;
}

router.post("/login", async (req, res) => {
  const parsed = LoginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Username and password are required" });
    return;
  }

  const { username, password } = parsed.data;
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    res.status(500).json({ error: "JWT_SECRET not configured" });
    return;
  }

  const admin = db
    .prepare("SELECT id, username, password_hash FROM admins WHERE username = ?")
    .get(username) as AdminRow | undefined;

  if (!admin || !(await bcrypt.compare(password, admin.password_hash))) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  const token = jwt.sign(
    { role: "admin", adminId: admin.id, username: admin.username },
    secret,
    { expiresIn: "7d" }
  );

  res.cookie("admin_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.json({ ok: true, username: admin.username });
});

router.post("/logout", (_req, res) => {
  res.clearCookie("admin_token");
  res.json({ ok: true });
});

export default router;
