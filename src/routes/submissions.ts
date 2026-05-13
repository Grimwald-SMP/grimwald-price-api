import { Router } from "express";
import { z } from "zod";
import db from "../db";
import { requireAdmin } from "../middleware/auth";
import { logAudit } from "../lib/audit";

const router = Router();

const SubmitSchema = z.object({
  item_id: z.number().int().nullable().optional(),
  item_name: z.string().min(1).max(100),
  suggested_price: z.number().positive().nullable().optional(),
  suggested_category_id: z.number().int().nullable().optional(),
  reasoning: z.string().max(1000).nullable().optional(),
  submitter_username: z.string().min(1).max(50),
});

const ReviewSchema = z.object({
  status: z.enum(["approved", "rejected"]),
  admin_notes: z.string().max(500).nullable().optional(),
});

// Public: submit a price suggestion
router.post("/", (req, res) => {
  const parsed = SubmitSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const d = parsed.data;
  const result = db
    .prepare(
      `INSERT INTO submissions (item_id, item_name, suggested_price, suggested_category_id, reasoning, submitter_username)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(
      d.item_id ?? null,
      d.item_name,
      d.suggested_price ?? null,
      d.suggested_category_id ?? null,
      d.reasoning ?? null,
      d.submitter_username
    );
  res.status(201).json({ id: result.lastInsertRowid });
});

const SELECT_SUBMISSIONS = `
  SELECT s.*, c.name AS suggested_category_name, c.color AS suggested_category_color
  FROM submissions s
  LEFT JOIN categories c ON s.suggested_category_id = c.id
`;

// Admin: list all submissions (optionally filter by status)
router.get("/", requireAdmin, (req, res) => {
  const status = req.query.status as string | undefined;
  const submissions = status
    ? db.prepare(`${SELECT_SUBMISSIONS} WHERE s.status = ? ORDER BY s.created_at DESC`).all(status)
    : db.prepare(`${SELECT_SUBMISSIONS} ORDER BY s.created_at DESC`).all();
  res.json(submissions);
});

function parseId(raw: string | string[]): number | null {
  const s = Array.isArray(raw) ? raw[0] : raw;
  const n = parseInt(s, 10);
  return Number.isInteger(n) && n > 0 ? n : null;
}

// Admin: approve or reject a submission
router.put("/:id", requireAdmin, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) { res.status(400).json({ error: "Invalid id" }); return; }
  const parsed = ReviewSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const { status, admin_notes } = parsed.data;

  const sub = db.prepare("SELECT * FROM submissions WHERE id = ?").get(id) as
    | {
        item_id: number | null;
        item_name: string;
        suggested_price: number | null;
        suggested_category_id: number | null;
      }
    | undefined;

  if (!sub) {
    res.status(404).json({ error: "Submission not found" });
    return;
  }

  db.transaction(() => {
    db.prepare("UPDATE submissions SET status=?, admin_notes=? WHERE id=?")
      .run(status, admin_notes ?? null, id);

    if (status === "approved") {
      if (sub.item_id != null) {
        // Update existing item
        const updates: string[] = ["updated_at=CURRENT_TIMESTAMP"];
        const params: (number | null)[] = [];
        if (sub.suggested_price != null) {
          updates.push("diamond_price=?");
          params.push(sub.suggested_price);
        }
        if (sub.suggested_category_id !== undefined) {
          updates.push("category_id=?");
          params.push(sub.suggested_category_id);
        }
        if (updates.length > 1) {
          params.push(sub.item_id);
          db.prepare(`UPDATE items SET ${updates.join(", ")} WHERE id=?`).run(...params);
        }
      } else {
        // Create new item from the submission
        db.prepare(
          "INSERT INTO items (name, diamond_price, category_id) VALUES (?, ?, ?)"
        ).run(
          sub.item_name,
          sub.suggested_price ?? null,
          sub.suggested_category_id ?? null
        );
      }
    }
  })();

  logAudit({
    adminId: req.admin!.adminId,
    adminUsername: req.admin!.username,
    action: status === "approved" ? "submission.approve" : "submission.reject",
    targetType: "submission",
    targetId: id,
    targetName: sub.item_name,
    details: {
      suggested_price: sub.suggested_price,
      admin_notes: admin_notes ?? null,
    },
  });

  res.json(
    db
      .prepare(`${SELECT_SUBMISSIONS} WHERE s.id = ?`)
      .get(id)
  );
});

export default router;
