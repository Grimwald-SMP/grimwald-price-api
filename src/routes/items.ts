import { Router } from "express";
import { z } from "zod";
import db from "../db";
import { requireStaff } from "../middleware/auth";
import { logAudit } from "../lib/audit";

const router = Router();

const ItemSchema = z.object({
  name: z.string().min(1).max(100),
  category_id: z.number().int().nullable().optional(),
  diamond_price: z.number().positive().nullable().optional(),
  notes: z.string().max(500).nullable().optional(),
  stack_size: z.number().int().min(1).max(64).optional(),
});

const CategorySchema = z.object({
  name: z.string().min(1).max(50),
  color: z.string().regex(/^#[0-9a-fA-F]{6}$/),
});

interface ItemRow {
  id: number;
  name: string;
  category_id: number | null;
  diamond_price: number | null;
  notes: string | null;
  stack_size: number;
}

interface CategoryRow {
  id: number;
  name: string;
  color: string;
}

// Public: get all items with their category
router.get("/", (_req, res) => {
  const items = db
    .prepare(
      `SELECT i.*, c.name AS category_name, c.color AS category_color
       FROM items i
       LEFT JOIN categories c ON i.category_id = c.id
       ORDER BY i.name ASC`
    )
    .all();
  res.json(items);
});

// Public: get all categories
router.get("/categories", (_req, res) => {
  const categories = db.prepare("SELECT * FROM categories ORDER BY name ASC").all();
  res.json(categories);
});

// Admin: add item
router.post("/", requireStaff, (req, res) => {
  const parsed = ItemSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const d = parsed.data;
  const result = db
    .prepare("INSERT INTO items (name, category_id, diamond_price, notes, stack_size) VALUES (?, ?, ?, ?, ?)")
    .run(d.name, d.category_id ?? null, d.diamond_price ?? null, d.notes ?? null, d.stack_size ?? 64);
  const item = db.prepare("SELECT * FROM items WHERE id = ?").get(result.lastInsertRowid) as ItemRow;
  logAudit({
    adminId: req.admin!.adminId,
    adminUsername: req.admin!.username,
    action: "item.create",
    targetType: "item",
    targetId: item.id,
    targetName: item.name,
    details: { diamond_price: item.diamond_price, category_id: item.category_id, stack_size: item.stack_size },
  });
  res.status(201).json(item);
});

function parseId(raw: string | string[]): number | null {
  const s = Array.isArray(raw) ? raw[0] : raw;
  const n = parseInt(s, 10);
  return Number.isInteger(n) && n > 0 ? n : null;
}

// Admin: update item
router.put("/:id", requireStaff, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) { res.status(400).json({ error: "Invalid id" }); return; }
  const parsed = ItemSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const before = db.prepare("SELECT * FROM items WHERE id = ?").get(id) as ItemRow | undefined;
  if (!before) { res.status(404).json({ error: "Item not found" }); return; }

  const d = parsed.data;
  db.prepare(
    "UPDATE items SET name=?, category_id=?, diamond_price=?, notes=?, stack_size=?, updated_at=CURRENT_TIMESTAMP WHERE id=?"
  ).run(d.name, d.category_id ?? null, d.diamond_price ?? null, d.notes ?? null, d.stack_size ?? before.stack_size, id);
  const item = db.prepare("SELECT * FROM items WHERE id = ?").get(id) as ItemRow;

  // Build a diff of changed fields only
  const changes: Record<string, { from: unknown; to: unknown }> = {};
  for (const field of ["name", "diamond_price", "category_id", "notes", "stack_size"] as const) {
    const from = before[field], to = item[field];
    if (from !== to) changes[field] = { from, to };
  }
  if (Object.keys(changes).length > 0) {
    logAudit({
      adminId: req.admin!.adminId,
      adminUsername: req.admin!.username,
      action: "item.update",
      targetType: "item",
      targetId: id,
      targetName: item.name,
      details: { changes },
    });
  }
  res.json(item);
});

// Admin: delete item
router.delete("/:id", requireStaff, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) { res.status(400).json({ error: "Invalid id" }); return; }
  const item = db.prepare("SELECT name FROM items WHERE id = ?").get(id) as { name: string } | undefined;
  const info = db.prepare("DELETE FROM items WHERE id = ?").run(id);
  if (info.changes === 0) {
    res.status(404).json({ error: "Item not found" });
    return;
  }
  logAudit({
    adminId: req.admin!.adminId,
    adminUsername: req.admin!.username,
    action: "item.delete",
    targetType: "item",
    targetId: id,
    targetName: item?.name ?? null,
  });
  res.json({ ok: true });
});

// Admin: add category
router.post("/categories", requireStaff, (req, res) => {
  const parsed = CategorySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const result = db
    .prepare("INSERT INTO categories (name, color) VALUES (?, ?)")
    .run(parsed.data.name, parsed.data.color);
  const cat = db.prepare("SELECT * FROM categories WHERE id = ?").get(result.lastInsertRowid) as CategoryRow;
  logAudit({
    adminId: req.admin!.adminId,
    adminUsername: req.admin!.username,
    action: "category.create",
    targetType: "category",
    targetId: cat.id,
    targetName: cat.name,
    details: { color: cat.color },
  });
  res.status(201).json(cat);
});

// Admin: update category
router.put("/categories/:id", requireStaff, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) { res.status(400).json({ error: "Invalid id" }); return; }
  const parsed = CategorySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const before = db.prepare("SELECT * FROM categories WHERE id = ?").get(id) as CategoryRow | undefined;
  db.prepare("UPDATE categories SET name=?, color=? WHERE id=?").run(
    parsed.data.name,
    parsed.data.color,
    id
  );
  const cat = db.prepare("SELECT * FROM categories WHERE id = ?").get(id) as CategoryRow | undefined;
  if (!cat) {
    res.status(404).json({ error: "Category not found" });
    return;
  }
  if (before) {
    const changes: Record<string, { from: unknown; to: unknown }> = {};
    if (before.name !== cat.name) changes.name = { from: before.name, to: cat.name };
    if (before.color !== cat.color) changes.color = { from: before.color, to: cat.color };
    if (Object.keys(changes).length > 0) {
      logAudit({
        adminId: req.admin!.adminId,
        adminUsername: req.admin!.username,
        action: "category.update",
        targetType: "category",
        targetId: id,
        targetName: cat.name,
        details: { changes },
      });
    }
  }
  res.json(cat);
});

// Admin: delete category
router.delete("/categories/:id", requireStaff, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) { res.status(400).json({ error: "Invalid id" }); return; }
  const cat = db.prepare("SELECT name FROM categories WHERE id = ?").get(id) as { name: string } | undefined;
  const info = db.prepare("DELETE FROM categories WHERE id = ?").run(id);
  if (info.changes === 0) {
    res.status(404).json({ error: "Category not found" });
    return;
  }
  logAudit({
    adminId: req.admin!.adminId,
    adminUsername: req.admin!.username,
    action: "category.delete",
    targetType: "category",
    targetId: id,
    targetName: cat?.name ?? null,
  });
  res.json({ ok: true });
});

// Admin: bulk import
router.post("/bulk", requireStaff, (req, res) => {
  const rows = z.array(ItemSchema).safeParse(req.body);
  if (!rows.success) {
    res.status(400).json({ error: rows.error.flatten() });
    return;
  }
  const insert = db.prepare(
    "INSERT INTO items (name, category_id, diamond_price, notes, stack_size) VALUES (?, ?, ?, ?, ?)"
  );
  const insertMany = db.transaction((items: typeof rows.data) => {
    for (const d of items) {
      insert.run(d.name, d.category_id ?? null, d.diamond_price ?? null, d.notes ?? null, d.stack_size ?? 64);
    }
  });
  insertMany(rows.data);
  logAudit({
    adminId: req.admin!.adminId,
    adminUsername: req.admin!.username,
    action: "item.bulk_import",
    targetType: "item",
    details: { count: rows.data.length },
  });
  res.json({ inserted: rows.data.length });
});

export default router;
