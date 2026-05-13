import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export type Role = "owner" | "staff" | "helper";

const ROLE_RANK: Record<Role, number> = { helper: 0, staff: 1, owner: 2 };

export interface AdminPayload {
  role: Role;
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

export function requireRole(minRole: Role) {
  return (req: Request, res: Response, next: NextFunction) => {
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
      if (ROLE_RANK[req.admin.role] < ROLE_RANK[minRole]) {
        res.status(403).json({ error: "Insufficient permissions" });
        return;
      }
      next();
    } catch {
      res.status(401).json({ error: "Invalid or expired token" });
    }
  };
}

// Convenience aliases
export const requireAdmin = requireRole("helper");
export const requireStaff = requireRole("staff");
export const requireOwner = requireRole("owner");
