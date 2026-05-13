import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface AdminPayload {
  role: "admin";
  adminId: number;
  username: string;
}

// Augment Express Request so routes can read the decoded admin
declare global {
  namespace Express {
    interface Request {
      admin?: AdminPayload;
    }
  }
}

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const token =
    req.cookies?.admin_token ?? req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const secret = process.env.JWT_SECRET;
    if (!secret) throw new Error("JWT_SECRET not configured");
    req.admin = jwt.verify(token, secret) as AdminPayload;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}
